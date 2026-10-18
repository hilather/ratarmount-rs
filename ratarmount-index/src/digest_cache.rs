//! Full base digests, cached only in an existing writable archive index.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, UNIX_EPOCH};

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

/// Appended to the index path to name the advisory lock that serializes the
/// first hash of an archive across processes. Hidden from a directory base's
/// digest by the shared sidecar predicate.
pub const DIGEST_LOCK_SUFFIX: &str = ".digest-lock";

/// How long a cache write waits for a busy index before it is reported.
const WRITE_BUSY_TIMEOUT: Duration = Duration::from_secs(5);
const CREATE_BUSY_TIMEOUT: Duration = Duration::from_secs(2);
const LOCK_POLL: Duration = Duration::from_millis(20);

fn never_cancelled() -> std::io::Result<()> {
    Ok(())
}

/// SHA-256 of every archive byte (unlike tarstats, no small-file policy cap).
/// Uses the same streaming hasher as `archive_full_hash`. Cache failures are
/// optional optimizations; neither a missing index nor its parent is created.
pub fn cached_archive_digest(path: &Path, index: Option<&Path>) -> Result<String> {
    cached_with(path, index, false, &never_cancelled, |path| {
        Ok(sha256_hex_stream(&mut fs::File::open(path)?)?)
    })
}

/// The cached SHA-256 of `path`, or `None` on a miss. Never hashes the archive
/// and never waits: it takes neither the in-process entry nor the cross-process
/// lock, so a mount that only peeks is ready while another mount is hashing.
pub fn peek_archive_digest(path: &Path, index: Option<&Path>) -> Result<Option<String>> {
    let path = path.canonicalize()?;
    let stamp = ArchiveDigestStamp::read(&path)?;
    let Some(cache) = open_cache(index, false) else {
        return Ok(None);
    };
    Ok(lookup(&cache, path.as_os_str().as_encoded_bytes(), &stamp))
}

/// Like [`cached_archive_digest`], but the caller supplies the hashing (for
/// example a cancellable stream). The result is cached like any other.
pub fn cached_archive_digest_with(
    path: &Path,
    index: Option<&Path>,
    hash: impl FnOnce(&Path) -> std::io::Result<String>,
) -> Result<String> {
    cached_archive_digest_cancellable(path, index, &never_cancelled, hash)
}

/// [`cached_archive_digest_with`] where waiting for another hasher of the same
/// archive (in this process or another) polls `check`; an error from it
/// abandons the wait, so a shutdown is never stuck behind a long hash.
pub fn cached_archive_digest_cancellable(
    path: &Path,
    index: Option<&Path>,
    check: &dyn Fn() -> std::io::Result<()>,
    hash: impl FnOnce(&Path) -> std::io::Result<String>,
) -> Result<String> {
    cached_with(path, index, false, check, |path| Ok(hash(path)?))
}

/// Rehash after an intentional archive commit and replace its cached identity.
/// Unlike `cached_archive_digest`, this never trusts a pre-commit cache hit.
pub fn refresh_archive_digest(path: &Path, index: Option<&Path>) -> Result<String> {
    cached_with(path, index, true, &never_cancelled, |path| {
        Ok(sha256_hex_stream(&mut fs::File::open(path)?)?)
    })
}

/// True when a digest hashed now would be stored: `index` is an existing
/// writable, unpublished index with a `files` table, and its lock file can be
/// created. When false, a mount must leave the digest pending rather than
/// rehash the archive on every mount.
pub fn archive_digest_cache_available(index: Option<&Path>) -> bool {
    open_cache(index, true).is_some_and(|cache| open_lock_file(&cache.index).is_some())
}

struct Cache {
    conn: Connection,
    index: PathBuf,
}

/// `create_table`: false for a read-only peek, which must not wait out another
/// mount creating the table (a missing table is simply a miss).
fn open_cache(index: Option<&Path>, create_table: bool) -> Option<Cache> {
    let index = index?;
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
    let conn = Connection::open_with_flags(&index, OpenFlags::SQLITE_OPEN_READ_WRITE).ok()?;
    // Lookups stay instant on a busy index; only the write waits (below).
    conn.busy_timeout(Duration::ZERO).ok()?;
    let has_files: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='files')",
            [],
            |row| row.get(0),
        )
        .ok()?;
    if !has_files {
        return None;
    }
    let has_table: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='overlay_base_digests')",
            [],
            |row| row.get(0),
        )
        .ok()?;
    if !has_table {
        if !create_table {
            return None;
        }
        // Concurrent first mounts all create it; wait out the winner instead
        // of mistaking its write lock for "no cache".
        conn.busy_timeout(CREATE_BUSY_TIMEOUT).ok()?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS overlay_base_digests (
                path BLOB PRIMARY KEY, size TEXT NOT NULL, mtime_ns TEXT NOT NULL,
                inode TEXT NOT NULL, sha256 TEXT NOT NULL
            );",
        )
        .ok()?;
        conn.busy_timeout(Duration::ZERO).ok()?;
    }
    Some(Cache { conn, index })
}

fn open_lock_file(index: &Path) -> Option<fs::File> {
    let mut name = index.as_os_str().to_owned();
    name.push(DIGEST_LOCK_SUFFIX);
    fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(name)
        .ok()
}

/// Archives being hashed by a thread of this process.
static HASHING: Mutex<BTreeSet<PathBuf>> = Mutex::new(BTreeSet::new());

/// Exclusive right to hash one archive: a per-path entry in this process plus
/// an advisory `flock` on the index's lock file for other processes.
struct HashGuard {
    path: PathBuf,
    _file: Option<fs::File>,
}

impl HashGuard {
    fn acquire(
        path: &Path,
        index: &Path,
        check: &dyn Fn() -> std::io::Result<()>,
    ) -> std::io::Result<Self> {
        loop {
            check()?;
            let mut held = HASHING.lock().unwrap_or_else(|e| e.into_inner());
            if held.insert(path.to_path_buf()) {
                break;
            }
            drop(held);
            std::thread::sleep(LOCK_POLL);
        }
        // From here `Drop` releases the in-process entry on every exit.
        let mut guard = Self {
            path: path.to_path_buf(),
            _file: None,
        };
        match open_lock_file(index) {
            Some(file) => {
                loop {
                    check()?;
                    if try_flock(&file)? {
                        break;
                    }
                    std::thread::sleep(LOCK_POLL);
                }
                guard._file = Some(file);
            }
            None => log::warn!(
                "cannot create the digest lock beside {}; concurrent mounts may each hash the archive",
                index.display()
            ),
        }
        Ok(guard)
    }
}

impl Drop for HashGuard {
    fn drop(&mut self) {
        HASHING
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.path);
        // Closing `_file` releases the flock.
    }
}

#[cfg(unix)]
fn try_flock(file: &fs::File) -> std::io::Result<bool> {
    use std::os::fd::AsRawFd;
    loop {
        // SAFETY: `file` owns a valid descriptor for the call's duration.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
            return Ok(true);
        }
        let err = std::io::Error::last_os_error();
        match err.kind() {
            std::io::ErrorKind::WouldBlock => return Ok(false),
            std::io::ErrorKind::Interrupted => {}
            _ => return Err(err),
        }
    }
}

/// No portable advisory lock without a new dependency: processes on these
/// platforms rely on the in-process entry alone.
#[cfg(not(unix))]
fn try_flock(_file: &fs::File) -> std::io::Result<bool> {
    Ok(true)
}

fn lookup(cache: &Cache, key: &[u8], stamp: &ArchiveDigestStamp) -> Option<String> {
    let digest: String = cache
        .conn
        .query_row(
            "SELECT sha256 FROM overlay_base_digests
             WHERE path=?1 AND size=?2 AND mtime_ns=?3 AND inode=?4",
            params![
                key,
                stamp.size.to_string(),
                stamp.mtime_ns.to_string(),
                stamp.inode.to_string()
            ],
            |row| row.get(0),
        )
        .optional()
        .ok()
        .flatten()?;
    (digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| format!("sha256:{digest}"))
}

/// Double-checked: read the cache, and on a miss take the per-archive lock,
/// read it again (another mount may have hashed while this one waited), and
/// only then hash and store. `check` is polled while waiting for the lock.
fn cached_with(
    path: &Path,
    index: Option<&Path>,
    refresh: bool,
    check: &dyn Fn() -> std::io::Result<()>,
    hash: impl FnOnce(&Path) -> Result<String>,
) -> Result<String> {
    let path = path.canonicalize()?;
    let stamp = ArchiveDigestStamp::read(&path)?;
    // Keep raw OS bytes: two non-UTF-8 paths must not share a lossy cache key.
    let key = path.as_os_str().as_encoded_bytes();
    let cache = open_cache(index, true);
    if let (Some(cache), false) = (&cache, refresh) {
        if let Some(hit) = lookup(cache, key, &stamp) {
            return Ok(hit);
        }
    }
    let _guard = match &cache {
        Some(cache) => {
            let guard = HashGuard::acquire(&path, &cache.index, check)?;
            if !refresh {
                // The hash we waited for just committed; a busy moment is not a miss.
                let _ = cache.conn.busy_timeout(WRITE_BUSY_TIMEOUT);
                if let Some(hit) = lookup(cache, key, &stamp) {
                    return Ok(hit);
                }
            }
            Some(guard)
        }
        None => None,
    };
    let digest = hash(&path)?;
    if ArchiveDigestStamp::read(&path)? != stamp {
        return Err(IndexError::Io(std::io::Error::other(
            "base changed while hashing",
        )));
    }
    if let Some(cache) = &cache {
        let stored = cache.conn.busy_timeout(WRITE_BUSY_TIMEOUT).and_then(|()| {
            cache.conn.execute(
                "INSERT OR REPLACE INTO overlay_base_digests VALUES (?1, ?2, ?3, ?4, ?5)",
                params![
                    key,
                    stamp.size.to_string(),
                    stamp.mtime_ns.to_string(),
                    stamp.inode.to_string(),
                    digest
                ],
            )
        });
        if let Err(e) = stored {
            log::warn!(
                "cannot cache the digest of {} in {}; the next mount will hash it again: {e}",
                path.display(),
                cache.index.display()
            );
        }
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
            cached_with(&archive, Some(&index), false, &never_cancelled, |_| panic!(
                "cache miss"
            ))
            .unwrap(),
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
            cached_with(&archive, Some(&index), false, &never_cancelled, |_| panic!(
                "cache miss"
            ))
            .unwrap(),
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

    fn index_with_files(dir: &Path) -> std::path::PathBuf {
        let index = dir.join("a.tar.index.sqlite");
        Connection::open(&index)
            .unwrap()
            .execute_batch("CREATE TABLE files (name TEXT);")
            .unwrap();
        index
    }

    /// Regression: C3, an archive is hashed once and cached; the second to
    /// eighth sequential mount reads the cache.
    #[test]
    fn regression_digest_once_sequential_mounts_hash_once() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        fs::write(&archive, vec![7u8; 4096]).unwrap();
        let index = index_with_files(dir.path());
        let hashes = std::sync::atomic::AtomicUsize::new(0);
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..8 {
            seen.insert(
                cached_archive_digest_with(&archive, Some(&index), |p| {
                    hashes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    sha256_hex_stream(&mut fs::File::open(p)?)
                })
                .unwrap(),
            );
        }
        assert_eq!(seen.len(), 1);
        assert_eq!(hashes.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// Regression: C3, eight first mounts racing on one uncached archive all
    /// ran sha256 over it (check, hash, insert had no mutual exclusion).
    #[test]
    fn regression_digest_once_concurrent_first_mounts_hash_once() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        fs::write(&archive, vec![7u8; 4096]).unwrap();
        let index = index_with_files(dir.path());
        let hashes = std::sync::atomic::AtomicUsize::new(0);
        let barrier = std::sync::Barrier::new(8);
        let digests: Vec<String> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        barrier.wait();
                        cached_archive_digest_with(&archive, Some(&index), |p| {
                            hashes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            // Widen the window the way a large archive would.
                            std::thread::sleep(std::time::Duration::from_millis(200));
                            sha256_hex_stream(&mut fs::File::open(p)?)
                        })
                        .unwrap()
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(digests.windows(2).all(|w| w[0] == w[1]));
        assert_eq!(hashes.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// Regression: C3, the cache INSERT ran with busy timeout zero and its
    /// result was dropped, so a briefly busy index lost the write and every
    /// later mount rehashed.
    #[test]
    fn regression_digest_once_busy_index_still_caches() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        fs::write(&archive, vec![7u8; 4096]).unwrap();
        let index = index_with_files(dir.path());
        // Create the cache table up front so only the INSERT contends.
        cached_archive_digest_with(&dir.path().join("a.tar"), Some(&index), |_| {
            Ok("0".repeat(64))
        })
        .unwrap();
        Connection::open(&index)
            .unwrap()
            .execute_batch("DELETE FROM overlay_base_digests")
            .unwrap();
        let hashes = std::sync::atomic::AtomicUsize::new(0);
        for _ in 0..3 {
            cached_archive_digest_with(&archive, Some(&index), |p| {
                hashes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // Another writer holds the index while this hash finishes.
                let holder = Connection::open(&index).unwrap();
                holder.execute_batch("BEGIN IMMEDIATE").unwrap();
                std::thread::spawn(move || {
                    std::thread::sleep(std::time::Duration::from_millis(300));
                    holder.execute_batch("COMMIT").unwrap();
                });
                sha256_hex_stream(&mut fs::File::open(p)?)
            })
            .unwrap();
        }
        assert_eq!(hashes.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    /// Regression: C3, a hasher waiting on another process's lock must still be
    /// cancellable (unmount cannot hang behind someone else's long hash).
    #[cfg(unix)]
    #[test]
    fn regression_digest_once_lock_wait_is_cancellable() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        fs::write(&archive, b"abc").unwrap();
        let index = index_with_files(dir.path());
        let canonical = index.canonicalize().unwrap();
        let other_process = open_lock_file(&canonical).unwrap();
        assert!(try_flock(&other_process).unwrap());
        let start = std::time::Instant::now();
        let result = cached_archive_digest_cancellable(
            &archive,
            Some(&index),
            &|| {
                if start.elapsed() > Duration::from_millis(150) {
                    Err(std::io::Error::new(std::io::ErrorKind::Interrupted, "stop"))
                } else {
                    Ok(())
                }
            },
            |_| panic!("hashed while another process held the lock"),
        );
        assert!(
            matches!(result, Err(IndexError::Io(e)) if e.kind() == std::io::ErrorKind::Interrupted)
        );
        // The cancelled wait left no in-process entry behind.
        drop(other_process);
        cached_archive_digest(&archive, Some(&index)).unwrap();
    }

    /// Regression: a mount's cache peek waited on the lock another mount held
    /// while hashing, so the second mount was not ready until the first hash
    /// finished. The peek must return a miss at once and the archive is still
    /// hashed exactly once.
    #[test]
    fn regression_peek_does_not_wait_for_a_running_hash() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::mpsc::channel;
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        fs::write(&archive, vec![7u8; 4096]).unwrap();
        let index = index_with_files(dir.path());
        let hashes = AtomicUsize::new(0);
        let (started_tx, started) = channel::<()>();
        let (release, release_rx) = channel::<()>();
        std::thread::scope(|scope| {
            let (hashes, archive, index) = (&hashes, &archive, &index);
            let hasher = scope.spawn(move || {
                cached_archive_digest_with(archive, Some(index), |p| {
                    hashes.fetch_add(1, Ordering::SeqCst);
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    sha256_hex_stream(&mut fs::File::open(p)?)
                })
                .unwrap()
            });
            started.recv().unwrap();
            let (done_tx, done) = channel();
            let (archive2, index2) = (archive.clone(), index.clone());
            std::thread::spawn(move || {
                done_tx
                    .send(peek_archive_digest(&archive2, Some(&index2)))
                    .ok();
            });
            let peeked = done.recv_timeout(Duration::from_secs(5));
            release.send(()).unwrap();
            let digest = hasher.join().unwrap();
            assert!(
                matches!(peeked, Ok(Ok(None))),
                "peek blocked or hit while the hash was running: {peeked:?}"
            );
            // After the hash lands, the peek is a hit and nothing hashes again.
            assert_eq!(
                peek_archive_digest(&archive, Some(&index)).unwrap(),
                Some(digest)
            );
        });
        assert_eq!(hashes.load(Ordering::SeqCst), 1);
    }

    /// The cache is available only for a writable, unpublished index.
    #[test]
    fn digest_cache_availability() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!archive_digest_cache_available(None));
        assert!(!archive_digest_cache_available(Some(
            &dir.path().join("none")
        )));
        let index = index_with_files(dir.path());
        assert!(archive_digest_cache_available(Some(&index)));
    }
}
