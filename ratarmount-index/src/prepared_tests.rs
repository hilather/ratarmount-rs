use super::*;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (path.clone(), std::fs::read(path).unwrap())
        })
        .collect()
}

fn fixture(path: &Path, archive: &Path) {
    let index = SqliteIndex::create_writable(Some(path)).unwrap();
    index
        .store_metadata_key_value("backendName", "test")
        .unwrap();
    index.store_tarstats_for_path(archive).unwrap();
    drop(index.into_read_only().unwrap());
    SqliteIndex::finalize_prepared(path).unwrap();
}

/// Regression: a strict worker must refuse before creating, reaping or ticking a builder.
#[test]
fn regression_prepared_index_builder_refuses_before_any_write() {
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("index.sqlite");
    std::fs::write(&target, b"existing sentinel").unwrap();
    let stale = dir.path().join("index.sqlite.tmp.4294967294.0");
    std::fs::write(&stale, b"stale build sentinel").unwrap();
    let ticks = Arc::new(AtomicUsize::new(0));
    let mut options = OpenOptions {
        read_only_index: true,
        ..Default::default()
    };
    let seen = Arc::clone(&ticks);
    options.index_build.on_progress = Some(Arc::new(move |_| {
        seen.fetch_add(1, AtomicOrdering::Relaxed);
    }));
    let before = snapshot(dir.path());
    for path in [
        Some(target.as_path()),
        Some(dir.path().join("missing").as_path()),
        Some(dir.path().join("absent/child").as_path()),
        None,
    ] {
        for (memory, compact) in [(false, false), (true, false), (false, true), (true, true)] {
            options.index_in_memory = memory;
            options.index_compact_only = compact;
            let error = SqliteIndex::create_writable_for_open(path, &options)
                .err()
                .unwrap()
                .to_string();
            assert!(error.contains("--no-recreate-index"), "{error}");
            assert_eq!(snapshot(dir.path()), before);
        }
    }
    assert_eq!(ticks.load(AtomicOrdering::Relaxed), 0);
    let private = OpenOptions {
        read_only_index: true,
        index_compact_only: true,
        write_index: false,
        ..Default::default()
    };
    drop(SqliteIndex::create_writable_for_open(None, &private).unwrap());
    assert_eq!(snapshot(dir.path()), before);
}

/// Regression: prepared immutable readers must preserve a WAL header and leftover companions.
#[test]
fn regression_prepared_index_open_creates_no_companions() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("base");
    let index = dir.path().join("index");
    std::fs::write(&archive, b"base").unwrap();
    fixture(&index, &archive);
    for leftovers in [false, true] {
        if leftovers {
            std::fs::write(dir.path().join("index-wal"), []).unwrap();
            std::fs::write(
                dir.path().join("index-shm"),
                b"unlocked leftover shared memory",
            )
            .unwrap();
        }
        let before = snapshot(dir.path());
        let reader = SqliteIndex::open_read_only_for_open(
            &index,
            &OpenOptions {
                read_only_index: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(reader.backend_name().unwrap().as_deref(), Some("test"));
        assert_eq!(snapshot(dir.path()), before);
        drop(reader);
        assert_eq!(snapshot(dir.path()), before);
    }
}

/// Regression: a worker cannot recover or ignore an unfinished WAL/rollback journal.
#[test]
fn regression_prepared_index_refuses_uncheckpointed_wal_and_journal() {
    let dir = tempfile::tempdir().unwrap();
    let index = dir.path().join("index");
    let archive = dir.path().join("base");
    std::fs::write(&archive, b"base").unwrap();
    fixture(&index, &archive);
    let writer = Connection::open(&index).unwrap();
    writer.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; INSERT INTO metadata VALUES ('pending','row');").unwrap();
    #[cfg(unix)]
    {
        let alias = dir.path().join("alias");
        std::os::unix::fs::symlink(&index, &alias).unwrap();
        assert!(
            SqliteIndex::open_catalog_prepared(&alias).is_err(),
            "a symlink alias cannot hide its target WAL"
        );
    }
    let before = snapshot(dir.path());
    let error = SqliteIndex::open_catalog_prepared(&index)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("incomplete preparation"), "{error}");
    assert_eq!(snapshot(dir.path()), before);
    drop(writer);
    let writer = Connection::open(&index).unwrap();
    writer.execute_batch("PRAGMA journal_mode=DELETE; BEGIN IMMEDIATE; INSERT INTO metadata VALUES ('rollback','row');").unwrap();
    let before = snapshot(dir.path());
    assert!(SqliteIndex::open_catalog_prepared(&index).is_err());
    assert_eq!(snapshot(dir.path()), before);
    drop(writer);
}

/// Regression: strict native catalogs require backend and archive identity metadata.
#[test]
fn regression_prepared_index_missing_identity_metadata_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let index = dir.path().join("index");
    let archive = dir.path().join("base");
    std::fs::write(&archive, b"base").unwrap();
    for key in ["backendName", "tarstats"] {
        fixture(&index, &archive);
        let writer = Connection::open(&index).unwrap();
        writer
            .execute("DELETE FROM metadata WHERE key=?1", [key])
            .unwrap();
        drop(writer);
        SqliteIndex::finalize_prepared(&index).unwrap();
        let before = snapshot(dir.path());
        let opts = OpenOptions {
            read_only_index: true,
            ..Default::default()
        };
        let error = SqliteIndex::open_read_only_for_open(&index, &opts)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains(key), "{error}");
        assert_eq!(snapshot(dir.path()), before);
        drop(SqliteIndex::open_read_only_for_open(&index, &OpenOptions::default()).unwrap());
    }
}

/// Regression: preparation must checkpoint real WAL rows, refuse busy handoff and never CREATE.
#[test]
fn regression_prepared_index_finalization_checkpoints_before_handoff() {
    let dir = tempfile::tempdir().unwrap();
    let index = dir.path().join("index");
    let archive = dir.path().join("base");
    std::fs::write(&archive, b"base").unwrap();
    fixture(&index, &archive);
    let missing = dir.path().join("missing");
    assert!(SqliteIndex::finalize_prepared(&missing).is_err());
    assert!(!missing.exists());
    let writer = Connection::open(&index).unwrap();
    writer.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; INSERT INTO metadata VALUES ('required','visible');").unwrap();
    SqliteIndex::finalize_prepared(&index).unwrap();
    assert_eq!(
        SqliteIndex::open_catalog_prepared(&index)
            .unwrap()
            .metadata()
            .unwrap()
            .get("required")
            .map(String::as_str),
        Some("visible")
    );
    let reader = Connection::open(&index).unwrap();
    reader
        .execute_batch("BEGIN; SELECT * FROM metadata;")
        .unwrap();
    writer
        .execute_batch("INSERT INTO metadata VALUES ('later','blocked');")
        .unwrap();
    let error = SqliteIndex::finalize_prepared(&index)
        .unwrap_err()
        .to_string();
    assert!(error.contains("busy"), "{error}");
}

/// Regression: strict resolution cannot probe, create, escape configured order or use memory.
#[test]
fn regression_prepared_index_resolution_never_probes_or_falls_back() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("base");
    std::fs::write(&archive, b"base").unwrap();
    let excluded = default_index_path(&archive);
    fixture(&excluded, &archive);
    let absent = dir.path().join("absent");
    assert!(
        resolve_prepared_index_location(&archive, None, std::slice::from_ref(&absent)).is_err()
    );
    assert!(!absent.exists());
    for bytes in [b"".as_slice(), b"corrupt"] {
        let explicit = dir.path().join("explicit");
        std::fs::write(&explicit, bytes).unwrap();
        let before = snapshot(dir.path());
        let resolved = resolve_prepared_index_location(&archive, explicit.to_str(), &[]);
        if !bytes.is_empty() {
            let path = resolved.unwrap();
            assert!(SqliteIndex::open_catalog_prepared(path.as_path().unwrap()).is_err());
        } else {
            assert!(resolved.is_err());
        }
        assert_eq!(snapshot(dir.path()), before);
    }
    assert!(resolve_prepared_index_location(&archive, Some(":memory:"), &[]).is_err());
    let missing = dir.path().join("missing");
    assert!(resolve_prepared_index_location(&archive, missing.to_str(), &[]).is_err());
    let cache = dir.path().join("cache");
    std::fs::create_dir(&cache).unwrap();
    let selected = possible_index_paths(&archive, std::slice::from_ref(&cache)).remove(0);
    fixture(&selected, &archive);
    assert_eq!(
        resolve_prepared_index_location(&archive, None, &[cache]).unwrap(),
        IndexLocation::Path(selected)
    );
}

/// Regression: strict digest peeks cannot truncate zero-WAL leftover SHM.
#[test]
fn regression_prepared_index_digest_peek_preserves_zero_wal_and_shm() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("base");
    let index = dir.path().join("index");
    std::fs::write(&archive, b"base").unwrap();
    fixture(&index, &archive);
    let expected = cached_archive_digest(&archive, Some(&index)).unwrap();
    SqliteIndex::finalize_prepared(&index).unwrap();
    std::fs::write(dir.path().join("index-wal"), []).unwrap();
    std::fs::write(
        dir.path().join("index-shm"),
        b"unlocked leftover shared memory",
    )
    .unwrap();
    let before = snapshot(dir.path());
    let reader = SqliteIndex::open_catalog_prepared(&index).unwrap();
    assert_eq!(
        peek_archive_digest_for_open(&archive, Some(&index), true).unwrap(),
        Some(expected)
    );
    assert_eq!(snapshot(dir.path()), before);
    drop(reader);
    assert_eq!(snapshot(dir.path()), before);
}

/// Regression: optional digest absence is a miss, while incomplete selected state is an error.
#[test]
fn regression_prepared_index_identity_peek_refuses_incomplete_state() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("base");
    let index = dir.path().join("index");
    std::fs::write(&archive, b"base").unwrap();
    fixture(&index, &archive);
    assert_eq!(
        peek_archive_digest_for_open(&archive, Some(&index), true).unwrap(),
        None
    );
    for suffix in ["-wal", "-journal"] {
        let companion = dir.path().join(format!("index{suffix}"));
        std::fs::write(&companion, b"pending state").unwrap();
        let before = snapshot(dir.path());
        let error = peek_archive_digest_for_open(&archive, Some(&index), true)
            .unwrap_err()
            .to_string();
        assert!(error.contains("incomplete preparation"), "{error}");
        assert_eq!(snapshot(dir.path()), before);
        std::fs::remove_file(companion).unwrap();
    }
    let writer = Connection::open(&index).unwrap();
    writer
        .execute_batch("CREATE TABLE overlay_base_digests (bad TEXT)")
        .unwrap();
    drop(writer);
    SqliteIndex::finalize_prepared(&index).unwrap();
    let before = snapshot(dir.path());
    let error = peek_archive_digest_for_open(&archive, Some(&index), true)
        .unwrap_err()
        .to_string();
    assert!(error.contains("digest lookup failed"), "{error}");
    assert_eq!(snapshot(dir.path()), before);
}

/// Regression (#221 CI fix): a symlinked read-only index whose link name has a
/// dangling nonempty -wal must be refused, not validated past the WAL.
#[cfg(unix)]
#[test]
fn regression_finalize_refuses_read_only_alias_with_leftover_wal() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real.sqlite");
    let archive = dir.path().join("a.tar");
    std::fs::write(&archive, b"x").unwrap();
    fixture(&real, &archive);
    let alias = dir.path().join("alias.sqlite");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    std::fs::write(dir.path().join("alias.sqlite-wal"), b"uncheckpointed").unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o444)).unwrap();
    let error = SqliteIndex::finalize_prepared(&alias)
        .unwrap_err()
        .to_string();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(error.contains("leftover WAL/journal state"), "{error}");
}

/// Classifier cases that run on every OS (#221).
#[test]
fn regression_classify_companion_each_case() {
    let dir = tempfile::tempdir().unwrap();
    let lstat = |name: &str| std::fs::symlink_metadata(dir.path().join(name));
    assert_eq!(
        classify_companion(&lstat("missing")),
        CompanionState::Absent
    );
    std::fs::write(dir.path().join("empty"), b"").unwrap();
    assert_eq!(
        classify_companion(&lstat("empty")),
        CompanionState::EmptyRegular
    );
    std::fs::write(dir.path().join("full"), b"wal").unwrap();
    assert_eq!(classify_companion(&lstat("full")), CompanionState::Leftover);
    std::fs::create_dir(dir.path().join("dir")).unwrap();
    assert_eq!(classify_companion(&lstat("dir")), CompanionState::Leftover);
    let denied = Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
    assert_eq!(classify_companion(&denied), CompanionState::Leftover);
}

/// An lstat of a symlink companion, even to an empty regular file, is leftover.
#[cfg(unix)]
#[test]
fn regression_classify_companion_symlink_is_leftover() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("target"), b"").unwrap();
    std::os::unix::fs::symlink(dir.path().join("target"), dir.path().join("link")).unwrap();
    let meta = std::fs::symlink_metadata(dir.path().join("link"));
    assert_eq!(classify_companion(&meta), CompanionState::Leftover);
}

/// Regression (#221): alias.sqlite -> real.sqlite (read-only) with
/// alias.sqlite-wal -> pending.wal must be refused. Windows variant not added:
/// the CI runner's symlink privilege is unverified; the classifier tests above
/// cover the decision on every OS.
#[cfg(unix)]
#[test]
fn regression_finalize_refuses_read_only_alias_with_symlinked_wal() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real.sqlite");
    let archive = dir.path().join("a.tar");
    std::fs::write(&archive, b"x").unwrap();
    fixture(&real, &archive);
    let alias = dir.path().join("alias.sqlite");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    std::fs::write(dir.path().join("pending.wal"), b"").unwrap();
    std::os::unix::fs::symlink(
        dir.path().join("pending.wal"),
        dir.path().join("alias.sqlite-wal"),
    )
    .unwrap();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o444)).unwrap();
    let error = SqliteIndex::finalize_prepared(&alias)
        .unwrap_err()
        .to_string();
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(error.contains("leftover WAL/journal state"), "{error}");
}
