//! Internal reads of index-crate files keep this process's database locks
//! (#151, R11-S7): each mandatory read of S7's inventory, done while a
//! connection of this process holds a lock on the same inode (same name or a
//! hard link), leaves that lock in place; failure boundaries keep their
//! documented outcome.

use std::cell::Cell;
use std::io;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use rusqlite::Connection;

use crate::managed_read::lock_probe::other_process_sees_lock;
use crate::managed_read::{seams, Seam, VfsLockHolder};
use crate::meta_cache::MetaCache;
use crate::*;

fn tempdir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().canonicalize().unwrap();
    (dir, path)
}

fn database(path: &Path, wal: bool) {
    let c = Connection::open(path).unwrap();
    if wal {
        c.pragma_update(None, "journal_mode", "WAL").unwrap();
    }
    c.execute_batch(
        "CREATE TABLE t(x BLOB); INSERT INTO t VALUES (randomblob(200000)), (randomblob(3000));",
    )
    .unwrap();
}

/// A connection holding SHARED (an open read transaction).
fn holder(path: &Path) -> Connection {
    let c = Connection::open(path).unwrap();
    c.execute_batch("BEGIN").unwrap();
    let _: i64 = c
        .query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))
        .unwrap();
    c
}

/// A database at `dir/name` held by a connection, plus a hard link `alias`.
/// Read its bytes BEFORE calling this: a raw read afterwards releases the
/// holder's lock (that is the bug under test).
fn held(dir: &Path, name: &str, wal: bool) -> (PathBuf, PathBuf, Connection) {
    let db = dir.join(name);
    database(&db, wal);
    held_existing(dir, &db, name)
}

fn held_existing(dir: &Path, db: &Path, name: &str) -> (PathBuf, PathBuf, Connection) {
    let db = db.to_path_buf();
    let alias = dir.join(format!("{name}.alias"));
    std::fs::hard_link(&db, &alias).unwrap();
    let h = holder(&db);
    assert!(other_process_sees_lock(&db), "the holder must hold SHARED");
    (db, alias, h)
}

/// The oracle discriminates: a raw close releases the lock.
fn negative_control(path: &Path) {
    drop(std::fs::File::open(path).unwrap());
    assert!(!other_process_sees_lock(path), "raw close must release");
}

/// Fail the `n`th managed open (1-based) on this thread with `kind`.
fn fail_open(n: u32) -> impl FnMut(Seam) -> io::Result<()> {
    let mut opens = 0;
    move |s| {
        if s == Seam::AfterOpen {
            opens += 1;
            if opens == n {
                return Err(io::Error::other("injected open failure"));
            }
        }
        Ok(())
    }
}

/// Fail the `n`th managed read (1-based) on this thread.
fn fail_read(n: u32) -> impl FnMut(Seam) -> io::Result<()> {
    let mut reads = 0;
    move |s| {
        if s == Seam::BeforeRead {
            reads += 1;
            if reads == n {
                return Err(io::Error::other("injected read failure"));
            }
        }
        Ok(())
    }
}

/// Regression: reading `{archive}.index.ptr` that is another name of an open
/// index released the index's lock. A missing pointer stays `Ok(None)`.
#[test]
fn regression_index_pointer_read_keeps_aliased_database_lock() {
    let (_d, dir) = tempdir();
    let (db, alias, h) = held(&dir, "a.index.sqlite", false);
    assert!(load_index_pointer(&alias).is_err(), "not pointer JSON");
    assert!(other_process_sees_lock(&db));
    assert!(load_index_pointer(&dir.join("missing.ptr"))
        .unwrap()
        .is_none());
    negative_control(&db);
    drop(h);
}

/// Regression: hashing an index blob for its pointer id released the
/// index's lock.
#[test]
fn regression_index_blob_hash_keeps_index_lock() {
    let (_d, dir) = tempdir();
    let db = dir.join("a.index.sqlite");
    database(&db, true);
    let want = crate::sha256_hex(&std::fs::read(&db).unwrap());
    let (db, _alias, h) = held_existing(&dir, &db, "a.index.sqlite");
    let ptr = IndexPointer::for_blob(&db, None).unwrap();
    assert_eq!(ptr.index_id, want);
    assert!(other_process_sees_lock(&db));
    negative_control(&db);
    drop(h);
}

/// Regression: the copy fallback of `snapshot_index_id` (hard link refused:
/// an existing pin with other bytes) read the live index raw.
#[test]
fn regression_index_id_copy_fallback_keeps_index_lock() {
    let (_d, dir) = tempdir();
    let archive = dir.join("a.tar");
    std::fs::write(&archive, b"tar").unwrap();
    let db = dir.join("a.tar.index.sqlite");
    database(&db, true);
    let bytes = std::fs::read(&db).unwrap();
    let id = crate::sha256_hex(&bytes);
    let (db, _alias, h) = held_existing(&dir, &db, "a.tar.index.sqlite");
    let pin = index_id_path(&archive, &id).unwrap();
    std::fs::write(&pin, b"stale pin bytes").unwrap();
    assert_eq!(
        snapshot_index_id(&archive, &db, &id).unwrap(),
        Some(pin.clone())
    );
    assert_eq!(std::fs::read(&pin).unwrap(), bytes);
    assert!(other_process_sees_lock(&db));
    // The fallback copy itself, directly.
    crate::location::atomic_copy_file(&db, &dir.join("copy")).unwrap();
    assert!(other_process_sees_lock(&db));
    negative_control(&db);
    drop(h);
}

/// Regression: the compression probe of `materialize_index_file` read the
/// first bytes of a live index raw.
#[test]
fn regression_index_materialize_probe_keeps_index_lock() {
    let (_d, dir) = tempdir();
    let (db, alias, h) = held(&dir, "a.index.sqlite", false);
    assert_eq!(materialize_index_file(&alias).unwrap(), alias);
    assert!(other_process_sees_lock(&db));
    negative_control(&db);
    drop(h);
}

/// Regression: decompressing a compressed index read it through a raw
/// decoder input; the decoder now owns a managed cursor through completion
/// and through a decode error.
#[test]
fn regression_index_decompression_reader_keeps_aliased_database_lock() {
    use std::io::Write;
    let (_d, dir) = tempdir();
    let src = dir.join("plain.sqlite");
    database(&src, false);
    let gz = dir.join("a.index.sqlite.gz");
    let mut enc = flate2::write::GzEncoder::new(
        std::fs::File::create(&gz).unwrap(),
        flate2::Compression::fast(),
    );
    enc.write_all(&std::fs::read(&src).unwrap()).unwrap();
    enc.finish().unwrap();
    let alias = dir.join("alias.gz");
    std::fs::hard_link(&gz, &alias).unwrap();
    let lock = VfsLockHolder::shared(&gz).unwrap();
    assert!(other_process_sees_lock(&gz));
    let out = materialize_index_file(&alias).unwrap();
    assert_ne!(out, alias);
    assert_eq!(std::fs::read(&out).unwrap(), std::fs::read(&src).unwrap());
    std::fs::remove_file(&out).unwrap();
    assert!(other_process_sees_lock(&gz), "decoder close kept the lock");
    // A decode error (corrupt tail) also keeps it.
    let bad = dir.join("bad.index.sqlite.gz");
    let mut bytes = std::fs::read(&gz).unwrap();
    let n = bytes.len();
    bytes.truncate(n / 2);
    std::fs::write(&bad, &bytes).unwrap();
    let bad_lock = VfsLockHolder::shared(&bad).unwrap();
    assert!(materialize_index_file(&bad).is_err());
    assert!(other_process_sees_lock(&bad));
    drop(bad_lock);
    negative_control(&gz);
    drop(lock);
}

/// A meta-v3 cache in `dir` with a 64 MiB budget.
fn meta_cache(dir: &Path) -> MetaCache {
    MetaCache::with_dir(dir.join("meta-v3"), 64 << 20)
}

/// Regression: a meta-v3 cache hit hashed the cached blob (an index another
/// session of this process has open) and read its header raw.
#[test]
fn regression_meta_cache_lookup_keeps_index_lock() {
    let (_d, dir) = tempdir();
    let cache = meta_cache(&dir);
    let fetched = dir.join("fetched.sqlite");
    database(&fetched, true);
    let url = "http|https://example.invalid/a.index.sqlite";
    let blob = cache
        .get_or_fetch_path_with_etag::<io::Error, _>(url, None, || {
            Ok((fetched.clone(), Some("e1".into())))
        })
        .unwrap();
    assert_eq!(blob, cache.blob_path_for(url));
    let h = holder(&blob);
    assert!(other_process_sees_lock(&blob));
    let again = cache
        .get_or_fetch_path_with_etag::<io::Error, _>(url, Some("e1"), || {
            panic!("a hit must not refetch")
        })
        .unwrap();
    assert_eq!(again, blob);
    assert!(other_process_sees_lock(&blob), "lookup kept the lock");
    negative_control(&blob);
    drop(h);
}

/// Regression: installing a fetched index blob copied the live source raw;
/// the copy is exclusive-new staging with the source's exact mode, and the
/// installed digest is computed while copying.
#[test]
fn regression_meta_cache_install_keeps_source_index_lock() {
    use std::os::unix::fs::PermissionsExt;
    let (_d, dir) = tempdir();
    let cache = meta_cache(&dir);
    let fetched = dir.join("fetched.sqlite");
    database(&fetched, true);
    std::fs::set_permissions(&fetched, std::fs::Permissions::from_mode(0o600)).unwrap();
    let alias = dir.join("fetched.alias");
    std::fs::hard_link(&fetched, &alias).unwrap();
    let bytes = std::fs::read(&fetched).unwrap();
    let h = holder(&fetched);
    let url = "http|https://example.invalid/b.index.sqlite";
    let blob = cache
        .get_or_fetch_path_with_etag::<io::Error, _>(url, None, || Ok((alias.clone(), None)))
        .unwrap();
    assert_eq!(std::fs::read(&blob).unwrap(), bytes);
    assert_eq!(
        std::fs::metadata(&blob).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert!(other_process_sees_lock(&fetched), "install kept the lock");
    drop(h);
    // src == dest: the installed blob is re-hashed through a managed cursor.
    let h = holder(&blob);
    let again = cache
        .get_or_fetch_path_with_etag::<io::Error, _>("http|other", None, || {
            Ok((blob.clone(), None))
        })
        .unwrap();
    assert!(again.exists());
    assert!(other_process_sees_lock(&blob));
    negative_control(&blob);
    drop(h);
}

/// Regression: a read error of a cached entry (not a missing or malformed
/// one) invalidated the blob and refetched; it now propagates and the entry
/// stays. A blob evicted between the length check and the managed open takes
/// the missing-entry path (invalidate, refetch).
#[test]
fn regression_meta_cache_read_error_preserves_blob() {
    let (_d, dir) = tempdir();
    let cache = meta_cache(&dir);
    let fetched = dir.join("fetched.sqlite");
    database(&fetched, false);
    let url = "http|https://example.invalid/c.index.sqlite";
    let blob = cache
        .get_or_fetch_path_with_etag::<io::Error, _>(url, None, || Ok((fetched.clone(), None)))
        .unwrap();
    let bytes = std::fs::read(&blob).unwrap();
    for hook in [fail_open(1), fail_open(2)] {
        let got = seams::with(hook, || {
            cache.get_or_fetch_path_with_etag::<io::Error, _>(url, None, || {
                panic!("a read error must not refetch")
            })
        });
        assert!(got.unwrap_err().to_string().contains("injected"));
        assert_eq!(std::fs::read(&blob).unwrap(), bytes, "entry kept");
    }
    // Header I/O vs malformed JSON: a malformed header is a miss.
    let hdr = PathBuf::from(format!("{}.hdr", blob.display()));
    std::fs::write(&hdr, b"{not json").unwrap();
    let fetched2 = dir.join("fetched2.sqlite");
    database(&fetched2, false);
    let refetched = Cell::new(false);
    cache
        .get_or_fetch_path_with_etag::<io::Error, _>(url, None, || {
            refetched.set(true);
            Ok((fetched2.clone(), None))
        })
        .unwrap();
    assert!(refetched.get(), "malformed header is a miss");
    // Evicted after the metadata check: NotFound from the managed open.
    let (b2, refetched) = (blob.clone(), Rc::new(Cell::new(false)));
    let mut opens = 0;
    let got = seams::with(
        move |s| {
            if s == Seam::BeforeOpen {
                opens += 1;
                if opens == 2 {
                    std::fs::remove_file(&b2).unwrap();
                }
            }
            Ok(())
        },
        || {
            let r = Rc::clone(&refetched);
            let fetched3 = dir.join("fetched3.sqlite");
            database(&fetched3, false);
            let p = cache.get_or_fetch_path_with_etag::<io::Error, _>(url, None, move || {
                r.set(true);
                Ok((fetched3, None))
            });
            (p, refetched.get())
        },
    );
    assert!(got.0.is_ok(), "{:?}", got.0);
    assert!(got.1, "an evicted blob is refetched");
}

/// Regression: a read, hash or permission failure while installing left a
/// torn or invalidated cache entry; the existing blob stays unchanged, no
/// staging file is left, and through `get_or_fetch` the store failure falls
/// back to the fetched path.
#[test]
fn regression_meta_cache_install_read_error_preserves_existing_blob() {
    let (_d, dir) = tempdir();
    let cache = meta_cache(&dir);
    let first = dir.join("first.sqlite");
    database(&first, false);
    let url = "http|https://example.invalid/d.index.sqlite";
    let blob = cache.install_for(url, &first).unwrap();
    let before = std::fs::read(&blob).unwrap();
    let parts = || {
        std::fs::read_dir(dir.join("meta-v3"))
            .unwrap()
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".part"))
            .count()
    };
    for seam in [
        Seam::BeforeRead,
        Seam::BeforePermissions,
        Seam::BeforePublish,
    ] {
        let second = dir.join(format!("second-{seam:?}.sqlite"));
        database(&second, false);
        let fail = move |s| {
            if s == seam {
                Err(io::Error::other("injected"))
            } else {
                Ok(())
            }
        };
        let got = seams::with(fail, || cache.install_for(url, &second));
        assert!(got.is_err(), "{seam:?}");
        assert_eq!(std::fs::read(&blob).unwrap(), before, "{seam:?}: blob kept");
        assert_eq!(parts(), 0, "{seam:?}: no staging left");
        // A fresh entry through get_or_fetch: the fetched path is used.
        let fresh = format!("http|https://example.invalid/fresh-{seam:?}");
        let got = seams::with(fail, || {
            cache.get_or_fetch_path_with_etag::<io::Error, _>(&fresh, None, || {
                Ok((second.clone(), None))
            })
        });
        assert_eq!(got.unwrap(), second);
        assert_eq!(parts(), 0);
    }
}

/// Regression: archive digests (cached and refreshed) hashed an archive that
/// is an SQLAR open in this process through a raw `File`.
#[test]
fn regression_archive_digest_and_refresh_keep_sqlar_lock() {
    let (_d, dir) = tempdir();
    let db = dir.join("a.sqlar");
    database(&db, false);
    let want = format!("sha256:{}", crate::sha256_hex(&std::fs::read(&db).unwrap()));
    let (db, _alias, h) = held_existing(&dir, &db, "a.sqlar");
    assert_eq!(cached_archive_digest(&db, None).unwrap(), want);
    assert!(other_process_sees_lock(&db));
    assert_eq!(refresh_archive_digest(&db, None).unwrap(), want);
    assert!(other_process_sees_lock(&db));
    negative_control(&db);
    drop(h);
}

/// Regression: tarstats edge and full hashes read the archive raw.
#[test]
fn regression_archive_fingerprints_keep_sqlar_lock() {
    let (_d, dir) = tempdir();
    let (db, alias, h) = held(&dir, "a.sqlar", false);
    let stats = tar_stats_from_path(&alias).unwrap();
    assert!(stats.prefix512_sha256.is_some() && stats.full_sha256.is_some());
    archive_edge_hashes(&db).unwrap();
    assert!(other_process_sees_lock(&db));
    negative_control(&db);
    drop(h);
}

/// Regression: a failed edge/full hash still stores size/mtime (best
/// effort) and omits only the failed hashes.
#[test]
fn regression_tarstats_hash_failure_keeps_optional_stats() {
    let (_d, dir) = tempdir();
    let f = dir.join("a.tar");
    std::fs::write(&f, vec![5u8; 10_000]).unwrap();
    let stats = seams::with(fail_read(1), || tar_stats_from_path(&f)).unwrap();
    assert_eq!(stats.st_size, 10_000);
    assert!(stats.prefix512_sha256.is_none(), "failed edges omitted");
    assert!(stats.full_sha256.is_some(), "the full hash still ran");
    let stats = seams::with(fail_open(2), || tar_stats_from_path(&f)).unwrap();
    assert!(stats.prefix512_sha256.is_some());
    assert!(stats.full_sha256.is_none(), "failed full hash omitted");
}

/// Regression: the pointer's blob hash failing must fail the pointer; the
/// archive's optional tarstats failing keeps the pointer (partial stats from
/// `tar_stats_from_path` are accepted, a failed stat omits them).
#[test]
fn regression_index_pointer_optional_archive_failure_stays_optional() {
    let (_d, dir) = tempdir();
    let blob = dir.join("a.index.sqlite");
    database(&blob, false);
    let archive = dir.join("a.tar");
    std::fs::write(&archive, vec![1u8; 5000]).unwrap();
    let e = seams::with(fail_open(1), || {
        IndexPointer::for_blob(&blob, Some(&archive))
    });
    assert!(e.is_err(), "blob hash failure propagates");
    let ptr = seams::with(fail_open(2), || {
        IndexPointer::for_blob(&blob, Some(&archive))
    })
    .unwrap();
    let stats = ptr.archive_tarstats.expect("partial stats kept");
    assert!(stats.get("prefix512_sha256").is_none_or(|v| v.is_null()));
    assert!(stats.get("st_size").is_some());
}

/// An index with one 3000-byte member at offset 0 and one at 100000.
fn content_index(path: Option<&Path>) -> SqliteIndex {
    let idx = SqliteIndex::create_writable(path).unwrap();
    idx.insert_file(
        "", "a", 0, 0, 3000, 0.0, 0o100644, 0, "", 0, 0, true, false, false, 0,
    )
    .unwrap();
    idx.insert_file(
        "", "b", 1, 100_000, 3000, 0.0, 0o100644, 0, "", 0, 0, true, false, false, 0,
    )
    .unwrap();
    idx
}

/// Regression: content hashing read an archive that is a database open in
/// this process (here: the archive is a hard link of a live SQLAR) raw.
#[test]
fn regression_content_hashes_keep_aliased_database_lock() {
    let (_d, dir) = tempdir();
    let (db, alias, h) = held(&dir, "a.sqlar", false);
    let idx = content_index(None);
    fill_content_hashes(&idx, &alias, &["sha256".into()]).unwrap();
    assert_eq!(idx.list_xattr_keys(0).unwrap().len(), 1);
    assert!(other_process_sees_lock(&db));
    negative_control(&db);
    drop(h);
}

/// Regression: a member whose hash failed mid-stream must store no (partial)
/// digest; the other member still gets one; an initial open failure
/// propagates.
#[test]
fn regression_content_hash_failure_does_not_store_partial_digest() {
    let (_d, dir) = tempdir();
    let archive = dir.join("a.bin");
    std::fs::write(&archive, vec![9u8; 110_000]).unwrap();
    let idx = content_index(None);
    seams::with(fail_read(1), || {
        fill_content_hashes(&idx, &archive, &["sha256".into()])
    })
    .unwrap();
    let a = idx.list_xattr_keys(0).unwrap().len();
    let b = idx.list_xattr_keys(1).unwrap().len();
    assert_eq!(a + b, 1, "exactly the member that read fine has a digest");
    let idx = content_index(None);
    let e = seams::with(fail_open(1), || {
        fill_content_hashes(&idx, &archive, &["sha256".into()])
    });
    assert!(e.is_err());
    assert!(idx.list_xattr_keys(0).unwrap().is_empty());
}

/// Regression: a lookup of an index with a hot rollback journal snapshots
/// the main file and the journal into a private directory; those copies read
/// the live files raw and released the writer's RESERVED lock.
#[test]
fn regression_lookup_snapshot_main_copy_keeps_index_lock() {
    let (_d, dir) = tempdir();
    let db = dir.join("a.index.sqlite");
    database(&db, false);
    let w = Connection::open(&db).unwrap();
    w.execute_batch("BEGIN IMMEDIATE; INSERT INTO t VALUES (zeroblob(10));")
        .unwrap();
    let journal = PathBuf::from(format!("{}-journal", db.display()));
    assert!(journal.exists(), "a rollback journal exists");
    assert!(other_process_sees_lock(&db));
    let conn = crate::open_lookup_connection(&db).unwrap();
    let n: i64 = conn
        .query_row("SELECT count(*) FROM t", [], |r| r.get(0))
        .unwrap();
    assert_eq!(n, 2, "the snapshot rolled the journal back");
    drop(conn);
    assert!(other_process_sees_lock(&db), "writer's lock kept");
    w.execute_batch("ROLLBACK").unwrap();
}

/// Regression: `publish_tmp`'s sync reopened the temporary index raw; a
/// connection holding a lock on that inode lost it at the close. Here a
/// holder takes SHARED on the temporary index after the managed open; right
/// after the managed close another process still sees it. An injected sync
/// failure fails the publish before the rename.
#[test]
fn regression_index_publish_sync_keeps_aliased_database_lock() {
    let (_d, dir) = tempdir();
    let dest = dir.join("a.index.sqlite");
    let mut idx = content_index(Some(&dest));
    let slot: Rc<std::cell::RefCell<Option<(PathBuf, Connection)>>> = Rc::default();
    let seen: Rc<Cell<Option<bool>>> = Rc::default();
    let (h2, s2, d2) = (Rc::clone(&slot), Rc::clone(&seen), dir.clone());
    seams::with(
        move |s| {
            if s == Seam::AfterOpen && h2.borrow().is_none() {
                let tmp = std::fs::read_dir(&d2)
                    .unwrap()
                    .flatten()
                    .map(|e| e.path())
                    .find(|p| p != &d2.join("a.index.sqlite") && p.is_file())
                    .expect("temporary index");
                let c = holder(&tmp);
                *h2.borrow_mut() = Some((tmp, c));
            }
            if s == Seam::AfterClose {
                if let Some((tmp, c)) = h2.borrow_mut().take() {
                    s2.set(Some(other_process_sees_lock(&tmp)));
                    drop(c);
                }
            }
            Ok(())
        },
        || idx.publish_tmp().unwrap(),
    );
    assert_eq!(seen.get(), Some(true), "lock kept across the managed sync");
    assert!(dest.exists());

    let dest = dir.join("b.index.sqlite");
    let mut idx = content_index(Some(&dest));
    let e = seams::with(fail_open(1), || idx.publish_tmp());
    assert!(e.is_err(), "sync failure fails the publish");
    assert!(!dest.exists(), "nothing published");
}

/// Regression: a failed mandatory read never yields a successful result:
/// pointer loading, materialization probe, decompression, the snapshot copy
/// fallback.
#[test]
fn regression_index_input_read_failure_is_not_success() {
    use std::io::Write;
    let (_d, dir) = tempdir();
    let ptr = dir.join("a.tar.index.ptr");
    std::fs::write(&ptr, b"{}").unwrap();
    assert!(seams::with(fail_read(1), || load_index_pointer(&ptr)).is_err());
    let db = dir.join("a.index.sqlite");
    database(&db, false);
    assert!(seams::with(fail_open(1), || materialize_index_file(&db)).is_err());
    let gz = dir.join("b.index.sqlite.gz");
    let mut enc = flate2::write::GzEncoder::new(
        std::fs::File::create(&gz).unwrap(),
        flate2::Compression::fast(),
    );
    enc.write_all(&std::fs::read(&db).unwrap()).unwrap();
    enc.finish().unwrap();
    assert!(seams::with(fail_read(2), || materialize_index_file(&gz)).is_err());
    let archive = dir.join("a.tar");
    let id = crate::sha256_hex(&std::fs::read(&db).unwrap());
    let pin = index_id_path(&archive, &id).unwrap();
    std::fs::write(&pin, b"stale").unwrap();
    assert!(seams::with(fail_read(1), || snapshot_index_id(&archive, &db, &id)).is_err());
}
