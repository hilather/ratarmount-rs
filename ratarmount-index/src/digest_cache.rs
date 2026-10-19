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

/// Wait up to [`WRITE_BUSY_TIMEOUT`] for another writer of the index.
#[cfg(not(test))]
fn set_write_busy(conn: &Connection) -> rusqlite::Result<()> {
    conn.busy_timeout(WRITE_BUSY_TIMEOUT)
}

/// Unit tests: the same wait as a handler that records which threads hit a busy
/// database, so a test can release the other writer exactly when this one is
/// waiting instead of sleeping and hoping.
#[cfg(test)]
fn set_write_busy(conn: &Connection) -> rusqlite::Result<()> {
    fn handler(attempt: i32) -> bool {
        let mut waiting = busy_probe::WAITING
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !waiting.contains(&std::thread::current().id()) {
            waiting.push(std::thread::current().id());
        }
        drop(waiting);
        std::thread::sleep(Duration::from_millis(1));
        i64::from(attempt) < WRITE_BUSY_TIMEOUT.as_millis() as i64
    }
    conn.busy_handler(Some(handler))
}

/// Wait up to [`CREATE_BUSY_TIMEOUT`] when opening for a hash, not at all for a peek.
#[cfg(not(test))]
fn set_open_busy(conn: &Connection, create_table: bool) -> rusqlite::Result<()> {
    conn.busy_timeout(if create_table {
        CREATE_BUSY_TIMEOUT
    } else {
        Duration::ZERO
    })
}

/// Unit tests: a hashing open waits through a handler that records the waiting
/// thread (see [`set_write_busy`]) and gives up after a per-thread number of
/// polls, so a test can hold the index "beyond the timeout" without sleeping
/// for it. A peek installs no handler, so it never appears in the probe.
#[cfg(test)]
fn set_open_busy(conn: &Connection, create_table: bool) -> rusqlite::Result<()> {
    fn handler(attempt: i32) -> bool {
        let mut waiting = busy_probe::WAITING
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if !waiting.contains(&std::thread::current().id()) {
            waiting.push(std::thread::current().id());
        }
        drop(waiting);
        std::thread::sleep(Duration::from_millis(1));
        attempt < busy_probe::OPEN_POLLS.with(|polls| polls.get())
    }
    if create_table {
        conn.busy_handler(Some(handler))
    } else {
        conn.busy_timeout(Duration::ZERO)
    }
}

#[cfg(test)]
mod busy_probe {
    use std::cell::Cell;
    pub static WAITING: std::sync::Mutex<Vec<std::thread::ThreadId>> =
        std::sync::Mutex::new(Vec::new());
    thread_local! {
        /// Busy polls a hashing open makes before it gives up (stands in for
        /// `CREATE_BUSY_TIMEOUT`); `CREATE_BUSY_TIMEOUT` worth of 1 ms polls unless a test lowers it.
        pub static OPEN_POLLS: Cell<i32> = const { Cell::new(super::CREATE_BUSY_TIMEOUT.as_millis() as i32) };
    }
}

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
///
/// The index is opened read-only (`SQLITE_OPEN_READ_ONLY`, zero busy wait) and
/// is never created, written, recreated or locked, so an index the caller may
/// not write (`chmod 444`, `--no-recreate-index`, an index folder it only reads)
/// still answers. A missing, unreadable, busy or table-less index is a miss.
pub fn peek_archive_digest(path: &Path, index: Option<&Path>) -> Result<Option<String>> {
    let path = path.canonicalize()?;
    let stamp = ArchiveDigestStamp::read(&path)?;
    let Some(cache) = open_cache_read_only(index) else {
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

/// The canonical path of an index that may carry a digest cache: an existing,
/// writable, unpublished regular file. Whether its database can be opened right
/// now (busy, no `files` table) is a separate question; the per-archive lock
/// depends only on this one.
fn cache_target(index: Option<&Path>) -> Option<PathBuf> {
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
    Some(index)
}

/// The index a read-only peek may read: an existing regular file. Unlike
/// [`cache_target`] (write eligibility), permissions and publication do not
/// matter, because nothing is written.
fn cache_read_target(index: Option<&Path>) -> Option<PathBuf> {
    let index = index?;
    if !fs::metadata(index).ok()?.is_file() {
        return None;
    }
    index.canonicalize().ok()
}

fn open_cache_read_only(index: Option<&Path>) -> Option<Cache> {
    let index = cache_read_target(index)?;
    // A peek is a pure lookup: it must not create `-wal` / `-shm` beside the
    // index of a WAL sidecar (see `open_lookup_connection`).
    let conn = crate::open_lookup_connection(&index).ok()?;
    conn.busy_timeout(Duration::ZERO).ok()?;
    let has_cache: bool = conn
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='overlay_base_digests')
             AND EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='files')",
            [],
            |row| row.get(0),
        )
        .ok()?;
    has_cache.then_some(Cache { conn, index })
}

/// `create_table`: false for a read-only peek, which must not wait out another
/// mount creating the table (a missing table is simply a miss).
fn open_cache(index: Option<&Path>, create_table: bool) -> Option<Cache> {
    open_cache_at(cache_target(index)?, create_table)
}

fn open_cache_at(index: PathBuf, create_table: bool) -> Option<Cache> {
    let conn = Connection::open_with_flags(&index, OpenFlags::SQLITE_OPEN_READ_WRITE).ok()?;
    // A peek stays instant on a busy index. A caller that goes on to hash and
    // store must not mistake another mount's write lock for "no cache": that
    // would skip the per-archive lock and hash the archive again.
    set_open_busy(&conn, create_table).ok()?;
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
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS overlay_base_digests (
                path BLOB PRIMARY KEY, size TEXT NOT NULL, mtime_ns TEXT NOT NULL,
                inode TEXT NOT NULL, sha256 TEXT NOT NULL
            );",
        )
        .ok()?;
    }
    // Lookups stay instant on a busy index; only the write waits (below).
    conn.busy_timeout(Duration::ZERO).ok()?;
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
    let target = cache_target(index);
    let mut cache = target.clone().and_then(|t| open_cache_at(t, true));
    if let (Some(cache), false) = (&cache, refresh) {
        if let Some(hit) = lookup(cache, key, &stamp) {
            return Ok(hit);
        }
    }
    // The lock depends on the index existing, not on its database being open:
    // another mount's long write lock must not let this one hash unserialized.
    let _guard = match &target {
        Some(target) => {
            let guard = HashGuard::acquire(&path, target, check)?;
            if cache.is_none() {
                // Busy earlier; the holder may be gone by now.
                cache = open_cache_at(target.clone(), true);
            }
            if let (Some(cache), false) = (&cache, refresh) {
                // The hash we waited for just committed; a busy moment is not a miss.
                let _ = set_write_busy(&cache.conn);
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
        let stored = set_write_busy(&cache.conn).and_then(|()| {
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

    /// Regression: C3, opening the cache for a hash probed `sqlite_master` with
    /// busy timeout zero, so a mount that opened while another held the write
    /// lock got no cache, skipped the per-archive lock and hashed again (CI:
    /// "hashed 6 times, want 1").
    #[test]
    fn regression_digest_once_open_waits_for_busy_index() {
        let dir = tempfile::tempdir().unwrap();
        let index = index_with_files(dir.path());
        let holder = Connection::open(&index).unwrap();
        holder.execute_batch("BEGIN EXCLUSIVE").unwrap();
        let (id_tx, id_rx) = std::sync::mpsc::channel();
        let opener = {
            let index = index.clone();
            std::thread::spawn(move || {
                id_tx.send(std::thread::current().id()).unwrap();
                open_cache(Some(&index), true).is_some()
            })
        };
        // Release the lock only once the open has hit the busy database.
        let opener_id = id_rx.recv().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(60);
        while !busy_probe::WAITING.lock().unwrap().contains(&opener_id) {
            assert!(
                std::time::Instant::now() < deadline,
                "the open never waited on the busy index"
            );
            std::thread::yield_now();
        }
        holder.execute_batch("COMMIT").unwrap();
        assert!(opener.join().unwrap(), "the open gave up on a busy index");
        // A peek never waits: it installs no busy handler, so it is absent
        // from the probe and returns a miss while the index stays locked.
        holder.execute_batch("BEGIN EXCLUSIVE").unwrap();
        let me = std::thread::current().id();
        busy_probe::WAITING.lock().unwrap().retain(|id| *id != me);
        assert!(open_cache(Some(&index), false).is_none());
        assert!(!busy_probe::WAITING.lock().unwrap().contains(&me));
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
        let releasers = std::cell::RefCell::new(Vec::new());
        for _ in 0..3 {
            cached_archive_digest_with(&archive, Some(&index), |p| {
                hashes.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // Another writer holds the index while this hash finishes; it
                // commits only once this thread's INSERT has hit the busy
                // database (no sleeps, no timing guesses).
                let holder = Connection::open(&index).unwrap();
                holder.execute_batch("BEGIN IMMEDIATE").unwrap();
                let writer = std::thread::current().id();
                busy_probe::WAITING
                    .lock()
                    .unwrap()
                    .retain(|id| *id != writer);
                releasers.borrow_mut().push(std::thread::spawn(move || {
                    let deadline = std::time::Instant::now() + Duration::from_secs(60);
                    while !busy_probe::WAITING.lock().unwrap().contains(&writer) {
                        assert!(
                            std::time::Instant::now() < deadline,
                            "the digest INSERT never waited on the busy index"
                        );
                        std::thread::yield_now();
                    }
                    holder.execute_batch("COMMIT").unwrap();
                }));
                sha256_hex_stream(&mut fs::File::open(p)?)
            })
            .unwrap();
        }
        for releaser in releasers.into_inner() {
            releaser.join().unwrap();
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
        // Cancel on the Nth poll of the lock wait, not after a wall-clock delay.
        let polls = std::sync::atomic::AtomicUsize::new(0);
        let result = cached_archive_digest_cancellable(
            &archive,
            Some(&index),
            &|| {
                if polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) >= 5 {
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

    /// Regression: the peek went through the write-eligibility check, so a
    /// `chmod 444` index (or one under `--no-recreate-index`) never answered and
    /// a byte-identical copy of a strong base was refused. The peek opens the
    /// index read-only, writes and creates nothing, and a missing, table-less
    /// or non-file index is a plain miss.
    #[cfg(unix)]
    #[test]
    fn regression_digest_peek_reads_readonly_index() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        fs::write(&archive, vec![9u8; 4096]).unwrap();
        let index = index_with_files(dir.path());
        let digest = cached_archive_digest(&archive, Some(&index)).unwrap();
        fs::set_permissions(&index, fs::Permissions::from_mode(0o444)).unwrap();
        // Not a cache the digest could be stored into any more ...
        assert!(cache_target(Some(&index)).is_none());
        // ... but a peek still reads it.
        assert_eq!(
            peek_archive_digest(&archive, Some(&index)).unwrap(),
            Some(digest)
        );
        // Nothing is created for a missing index, and a non-file is a miss.
        let missing = dir.path().join("missing.sqlite");
        assert_eq!(peek_archive_digest(&archive, Some(&missing)).unwrap(), None);
        assert!(!missing.exists());
        assert_eq!(
            peek_archive_digest(&archive, Some(dir.path())).unwrap(),
            None
        );
        // A table-less database is a miss and stays table-less.
        let bare = dir.path().join("bare.sqlite");
        Connection::open(&bare)
            .unwrap()
            .execute_batch("CREATE TABLE files (name TEXT);")
            .unwrap();
        assert_eq!(peek_archive_digest(&archive, Some(&bare)).unwrap(), None);
        let tables: i64 = Connection::open(&bare)
            .unwrap()
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='overlay_base_digests'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0, "the peek must not create the cache table");
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
                peek_archive_digest(archive, Some(index)).unwrap(),
                Some(digest)
            );
        });
        assert_eq!(hashes.load(Ordering::SeqCst), 1);
    }

    /// Regression: an index write-locked for longer than the open timeout gave
    /// "no cache", which skipped the per-archive lock, so concurrent mounts
    /// hashed the same archive at once. The lock is taken whenever the index
    /// exists; the hash then runs under it (and is not stored).
    #[cfg(unix)]
    #[test]
    fn regression_digest_once_lock_held_when_index_stays_busy() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::mpsc::channel;
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        fs::write(&archive, vec![7u8; 4096]).unwrap();
        let index = index_with_files(dir.path());
        // Held for the whole test: every open times out.
        let holder = Connection::open(&index).unwrap();
        holder.execute_batch("BEGIN EXCLUSIVE").unwrap();
        let (hashes, in_flight, max_in_flight) = (
            AtomicUsize::new(0),
            AtomicUsize::new(0),
            AtomicUsize::new(0),
        );
        let (started_tx, started) = channel::<()>();
        let (release, release_rx) = channel::<()>();
        let (b_done_tx, b_done) = channel::<()>();
        let b_polls = AtomicUsize::new(0);
        std::thread::scope(|scope| {
            let (archive, index) = (&archive, &index);
            let (hashes, in_flight, max_in_flight) = (&hashes, &in_flight, &max_in_flight);
            let enter = move || {
                hashes.fetch_add(1, Ordering::SeqCst);
                let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                max_in_flight.fetch_max(now, Ordering::SeqCst);
            };
            let a = scope.spawn(move || {
                busy_probe::OPEN_POLLS.with(|polls| polls.set(3));
                cached_archive_digest_with(archive, Some(index), |p| {
                    enter();
                    started_tx.send(()).unwrap();
                    release_rx.recv().unwrap();
                    in_flight.fetch_sub(1, Ordering::SeqCst);
                    sha256_hex_stream(&mut fs::File::open(p)?)
                })
                .unwrap()
            });
            started.recv().unwrap();
            let b_polls = &b_polls;
            let b = scope.spawn(move || {
                busy_probe::OPEN_POLLS.with(|polls| polls.set(3));
                let digest = cached_archive_digest_cancellable(
                    archive,
                    Some(index),
                    &|| {
                        b_polls.fetch_add(1, Ordering::SeqCst);
                        Ok(())
                    },
                    |p| {
                        enter();
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                        sha256_hex_stream(&mut fs::File::open(p)?)
                    },
                )
                .unwrap();
                b_done_tx.send(()).unwrap();
                digest
            });
            // B must be waiting on A's lock (polling), not hashing beside it.
            let deadline = std::time::Instant::now() + Duration::from_secs(60);
            while b_polls.load(Ordering::SeqCst) < 5 && b_done.try_recv().is_err() {
                assert!(std::time::Instant::now() < deadline, "B never polled");
                std::thread::yield_now();
            }
            let overlapped = max_in_flight.load(Ordering::SeqCst);
            release.send(()).unwrap();
            let (da, db) = (a.join().unwrap(), b.join().unwrap());
            assert_eq!(da, db);
            assert_eq!(overlapped, 1, "two mounts hashed the archive at once");
        });
        assert_eq!(max_in_flight.load(Ordering::SeqCst), 1);
        // The index never accepted a row, so each hash ran (once per mount).
        assert_eq!(hashes.load(Ordering::SeqCst), 2);
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
