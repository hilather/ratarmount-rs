#![allow(clippy::disallowed_methods)]

use super::*;
use crate::types::SourceSpec;
use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};
use ratarmount_index::IndexError;
use std::io::Write;
use std::sync::atomic::Ordering;

fn member_file<'a>(path: &'a str, bytes: &'a [u8]) -> UstarMember<'a> {
    UstarMember {
        xattrs: &[],
        path,
        payload: UstarPayload::File { bytes },
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: 0,
    }
}

fn write_tar(path: &Path, members: &[UstarMember<'_>]) {
    let mut f = std::fs::File::create(path).unwrap();
    write_ustar_members(&mut f, members).unwrap();
    write_tar_eof(&mut f).unwrap();
    f.flush().unwrap();
}

fn open_tar(dir: &Path, name: &str, members: &[UstarMember<'_>]) -> Session {
    let tar = dir.join(name);
    write_tar(&tar, members);
    let idx = dir.join(format!("{name}.index.sqlite"));
    Session::open(OpenRequest {
        source: SourceSpec::Path(tar),
        index: IndexPolicy::Explicit,
        explicit_index: Some(idx),
        extra_dirs: Vec::new(),
        password: None,
        recursive: false,
        recursion_depth: None,
        parallelization: Default::default(),
        recreate: Recreate::IfInvalid,
    })
    .expect("Session::open")
}

/// Regression (R6-J4, audit D7): the `Recreate::Never` check and the
/// will-I-rebuild probe opened a WAL sidecar read-only and left `-wal` /
/// `-shm` beside the archive.
#[test]
fn regression_session_lookups_of_a_wal_sidecar_create_no_side_files() {
    let dir = tempfile::tempdir().unwrap();
    drop(open_tar(dir.path(), "a.tar", &[member_file("f", b"x")]));
    let tar = dir.path().join("a.tar");
    let index = dir.path().join("a.tar.index.sqlite");
    let mode: String = rusqlite::Connection::open(&index)
        .unwrap()
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    assert_eq!(mode, "wal", "the sidecar is a WAL database");
    for suffix in ["-wal", "-shm", "-journal"] {
        let _ = std::fs::remove_file(format!("{}{suffix}", index.display()));
    }
    let names = || {
        let mut all: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        all.sort();
        all
    };
    let (listing, bytes) = (names(), std::fs::read(&index).unwrap());
    let loc = CatalogLoc::Path(index.clone());
    check_recreate_never(&tar, &loc).unwrap();
    assert!(!will_cold_build(Recreate::IfInvalid, &tar, &loc));
    assert_eq!(names(), listing, "a lookup created files");
    assert!(std::fs::read(&index).unwrap() == bytes, "sidecar rewritten");
    // Regression (R6-K4): the catalog the Session HOLDS is a read too.
    let catalog = open_catalog_if_path(&loc).unwrap().expect("catalog");
    drop(catalog);
    assert_eq!(names(), listing, "open_catalog_if_path created files");
    assert!(std::fs::read(&index).unwrap() == bytes, "sidecar rewritten");
}

/// Regression: read-only Session/factory opens must repair a torn archive before probing.
#[cfg(unix)]
#[test]
fn append_journal_readonly_session_and_factory_recover() {
    for factory in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.tar");
        write_tar(&path, &[member_file("old", b"old contents")]);
        let old = std::fs::read(&path).unwrap();
        let alias = dir.path().join("alias.tar");
        std::fs::hard_link(&path, &alias).unwrap();
        let mut tail = tempfile::tempfile().unwrap();
        tail.write_all(b"new").unwrap();
        assert!(
            ratarmount_compress::commit_journal::replace_suffix_with_hook(
                &path,
                0,
                &mut tail,
                &mut |step| {
                    if step == "archive truncate" {
                        Err(std::io::Error::other("crash"))
                    } else {
                        Ok(())
                    }
                },
            )
            .is_err()
        );
        if factory {
            let source = crate::factory::open_path(
                &alias,
                &OpenOptions {
                    index_in_memory: true,
                    ..OpenOptions::default()
                },
                false,
            )
            .unwrap();
            assert!(source.lookup("/old", 0).is_some());
        } else {
            let mut req = never_req(alias, dir.path().join("index.sqlite"));
            req.index = IndexPolicy::Memory;
            req.recreate = Recreate::IfInvalid;
            let session = Session::open(req).unwrap();
            assert!(session.lookup("/old").unwrap().is_some());
        }
        assert_eq!(std::fs::read(&path).unwrap(), old);
    }
}

/// Regression: Session requests must reach OpenOptions instead of silently using one thread.
#[test]
fn parallelization_request_reaches_open_options() {
    let mut req = never_req(PathBuf::from("a.tar.zst"), PathBuf::from("a.sqlite"));
    let default = open_options(&req, &IndexBuildHooks::default());
    assert_eq!(default.threads_for("zstd"), 1);
    assert_eq!(default.threads_for("gzip"), 1);
    req.parallelization = ratarmount_core::ParallelizationSpec::new(4);
    let options = open_options(&req, &IndexBuildHooks::default());
    assert_eq!(options.threads_for("zstd"), 4);
    assert_eq!(options.threads_for("bzip2"), 4);
    req.parallelization = ratarmount_core::ParallelizationSpec::parse(":2,zstd:4").unwrap();
    let options = open_options(&req, &IndexBuildHooks::default());
    assert_eq!(options.threads_for("zstd"), 4);
    assert_eq!(options.threads_for("gzip"), 2);
}

/// Regression: Session is Send — embedders move it onto a worker thread (G5.1).
#[test]
fn session_send_across_thread() {
    let dir = tempfile::tempdir().unwrap();
    let session = open_tar(dir.path(), "send.tar", &[member_file("a.txt", b"hi")]);
    let handle = std::thread::spawn(move || {
        session
            .list_dirents_page("/", DirCursor::Start, 8)
            .expect("list on worker")
    });
    let page = handle.join().expect("worker panicked");
    assert_eq!(page.entries.len(), 1);
    assert_eq!(page.entries[0].name, "a.txt");
}

/// 1000 ustar members, page size 50 → 20 pages, no overlap/skip.
#[test]
fn list_dirents_page() {
    let dir = tempfile::tempdir().unwrap();
    let names: Vec<String> = (0..1000).map(|i| format!("f{i:04}.txt")).collect();
    let payload = b"x";
    let members: Vec<UstarMember<'_>> = names
        .iter()
        .map(|n| member_file(n.as_str(), payload))
        .collect();
    let session = open_tar(dir.path(), "page.tar", &members);

    let mut seen = Vec::new();
    let mut cursor = DirCursor::Start;
    let mut pages = 0u32;
    loop {
        let page = session.list_dirents_page("/", cursor, 50).expect("page");
        assert!(page.entries.len() <= 50);
        for e in &page.entries {
            assert!(!e.is_dir);
            assert!(e.path.starts_with('/'));
            assert!(!e.path.ends_with('/'));
            seen.push(e.name.clone());
        }
        pages += 1;
        match page.next_cursor {
            None => break,
            Some(next) => cursor = next,
        }
    }
    assert_eq!(pages, 20, "1000 / 50");
    assert_eq!(seen.len(), 1000);
    let mut uniq = seen.clone();
    uniq.sort();
    uniq.dedup();
    assert_eq!(uniq.len(), 1000, "no overlap");
    assert_eq!(seen, uniq, "name order");
    assert_eq!(seen.first().map(String::as_str), Some("f0000.txt"));
    assert_eq!(seen.last().map(String::as_str), Some("f0999.txt"));

    let last = session
        .list_dirents_page(
            "/",
            DirCursor::AfterName {
                name: "f0999.txt".into(),
            },
            50,
        )
        .unwrap();
    assert!(last.entries.is_empty());
    assert!(last.next_cursor.is_none());
}

/// GNU incremental dumpdir tombstone is absent from page 1.
#[test]
fn list_dirents_page_dumpdir() {
    fn oct_field(n: u64, width: usize) -> Vec<u8> {
        let s = format!("{:0width$o}", n, width = width.saturating_sub(1));
        let mut v = s.into_bytes();
        v.push(0);
        v.resize(width, 0);
        v
    }
    fn gnu_header(name: &str, size: u64, typeflag: u8) -> [u8; 512] {
        let mut h = [0u8; 512];
        let nb = name.as_bytes();
        h[..nb.len()].copy_from_slice(nb);
        h[100..108].copy_from_slice(&oct_field(0o700, 8));
        h[108..116].copy_from_slice(&oct_field(0, 8));
        h[116..124].copy_from_slice(&oct_field(0, 8));
        h[124..136].copy_from_slice(&oct_field(size, 12));
        h[136..148].copy_from_slice(&oct_field(0, 12));
        h[156] = typeflag;
        h[257..265].copy_from_slice(b"ustar  \0");
        h[148..156].copy_from_slice(b"        ");
        let csum: u32 = h.iter().map(|&b| b as u32).sum();
        let cs = format!("{csum:06o}\0 ");
        h[148..156].copy_from_slice(cs.as_bytes());
        h
    }
    fn pad_payload(p: &[u8]) -> Vec<u8> {
        let mut v = p.to_vec();
        let n = (512 - (v.len() % 512)) % 512;
        v.extend(std::iter::repeat_n(0u8, n));
        v
    }
    fn append_member(out: &mut Vec<u8>, name: &str, typeflag: u8, payload: &[u8]) {
        out.extend_from_slice(&gnu_header(name, payload.len() as u64, typeflag));
        out.extend(pad_payload(payload));
    }

    let mut tar = Vec::new();
    append_member(&mut tar, "foo/", b'D', b"Y1\0Y2\0Y3\0\0");
    append_member(&mut tar, "foo/1", b'0', b"one\n");
    append_member(&mut tar, "foo/2", b'0', b"two\n");
    append_member(&mut tar, "foo/3", b'0', b"three\n");
    append_member(&mut tar, "foo/", b'D', b"Y3\0Ymoved\0\0");
    append_member(&mut tar, "foo/3", b'0', b"THREE\n");
    append_member(&mut tar, "foo/moved", b'0', b"mv\n");
    tar.extend(std::iter::repeat_n(0u8, 1024));

    let dir = tempfile::tempdir().unwrap();
    let tar_path = dir.path().join("inc.tar");
    std::fs::write(&tar_path, &tar).unwrap();
    let idx = dir.path().join("inc.tar.index.sqlite");
    let session = Session::open(OpenRequest {
        source: SourceSpec::Path(tar_path),
        index: IndexPolicy::Explicit,
        explicit_index: Some(idx),
        extra_dirs: Vec::new(),
        password: None,
        recursive: false,
        recursion_depth: None,
        parallelization: Default::default(),
        recreate: Recreate::IfInvalid,
    })
    .expect("open dumpdir tar");

    let page = session
        .list_dirents_page("/foo", DirCursor::Start, 50)
        .expect("page 1");
    let names: Vec<&str> = page.entries.iter().map(|e| e.name.as_str()).collect();
    assert!(
        !names.contains(&"1") && !names.contains(&"2"),
        "dumpdir-deleted names must be absent: {names:?}"
    );
    assert!(names.contains(&"3"), "{names:?}");
    assert!(names.contains(&"moved"), "{names:?}");
}

/// Session::open of a tiny TAR emits one harness line; catalog has no MemIndex.
///
/// libtest captures `println!`, so the line count is asserted on a child
/// process of this test binary (`--nocapture`).
#[test]
fn catalog_open_silent() {
    let dir = tempfile::tempdir().unwrap();
    let payload = b"hi";
    let members = [member_file("a.txt", payload)];
    let tar = dir.path().join("tiny.tar");
    write_tar(&tar, &members);
    let idx = dir.path().join("tiny.tar.index.sqlite");
    let req = OpenRequest {
        source: SourceSpec::Path(tar),
        index: IndexPolicy::Explicit,
        explicit_index: Some(idx),
        extra_dirs: Vec::new(),
        password: None,
        recursive: false,
        recursion_depth: None,
        parallelization: Default::default(),
        recreate: Recreate::IfInvalid,
    };
    if std::env::var_os("RATARMOUNT_CATALOG_OPEN_CHILD").is_some() {
        let session = Session::open(req).expect("open tiny tar");
        assert_eq!(
            session.catalog_has_mem_index(),
            Some(false),
            "catalog must not load a second MemIndex"
        );
        let hit = session.lookup("/a.txt").unwrap().expect("a.txt");
        assert_eq!(hit.name, "a.txt");
        assert_eq!(hit.size, 2);
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .env("RATARMOUNT_CATALOG_OPEN_CHILD", "1")
        .args([
            "session::tests::catalog_open_silent",
            "--exact",
            "--nocapture",
        ])
        .output()
        .expect("spawn catalog_open_silent child");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "child failed: stdout={stdout} stderr={stderr}"
    );
    let n = stdout
        .matches("Successfully loaded offset dictionary")
        .count();
    assert_eq!(n, 1, "expected one harness line, got {n}: {stdout}");
}

fn never_req(tar: PathBuf, idx: PathBuf) -> OpenRequest {
    OpenRequest {
        source: SourceSpec::Path(tar),
        index: IndexPolicy::Explicit,
        explicit_index: Some(idx),
        extra_dirs: Vec::new(),
        password: None,
        recursive: false,
        recursion_depth: None,
        parallelization: Default::default(),
        recreate: Recreate::Never,
    }
}

/// Recreate::Never + missing sidecar → NotFound; no sqlite created.
#[test]
fn recreate_never_missing_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    let tar = dir.path().join("missing.tar");
    write_tar(&tar, &[member_file("a.txt", b"hi")]);
    let idx = dir.path().join("missing.tar.index.sqlite");
    let err = match Session::open(never_req(tar, idx.clone())) {
        Err(e) => e,
        Ok(_) => panic!("expected NotFound, open succeeded"),
    };
    assert!(
        matches!(err, Error::NotFound),
        "expected NotFound, got {err:?}"
    );
    assert!(
        !idx.exists(),
        "Never must not create a sidecar at {}",
        idx.display()
    );
}

/// Recreate::Never + tarstats mismatch → CorruptIndex; sidecar bytes unchanged.
#[test]
fn recreate_never_tarstats_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let tar = dir.path().join("stale.tar");
    write_tar(&tar, &[member_file("a.txt", b"old")]);
    let idx = dir.path().join("stale.tar.index.sqlite");
    drop(
        Session::open(OpenRequest {
            source: SourceSpec::Path(tar.clone()),
            index: IndexPolicy::Explicit,
            explicit_index: Some(idx.clone()),
            extra_dirs: Vec::new(),
            password: None,
            recursive: false,
            recursion_depth: None,
            parallelization: Default::default(),
            recreate: Recreate::IfInvalid,
        })
        .expect("seed sidecar"),
    );
    let before = std::fs::read(&idx).unwrap();
    write_tar(&tar, &[member_file("a.txt", b"new-payload-xxxx")]);
    let err = match Session::open(never_req(tar, idx.clone())) {
        Err(e) => e,
        Ok(_) => panic!("expected CorruptIndex, open succeeded"),
    };
    assert!(
        matches!(err, Error::CorruptIndex(_)),
        "expected CorruptIndex, got {err:?}"
    );
    let after = std::fs::read(&idx).unwrap();
    assert_eq!(before, after, "Never must not replace the sidecar");
}

/// Recreate::Never + backendName mismatch → CorruptIndex; no rebuild.
#[test]
fn recreate_never_backend_name_mismatch() {
    let dir = tempfile::tempdir().unwrap();
    let tar = dir.path().join("bn.tar");
    write_tar(&tar, &[member_file("a.txt", b"hi")]);
    let idx = dir.path().join("bn.tar.index.sqlite");
    drop(
        Session::open(OpenRequest {
            source: SourceSpec::Path(tar.clone()),
            index: IndexPolicy::Explicit,
            explicit_index: Some(idx.clone()),
            extra_dirs: Vec::new(),
            password: None,
            recursive: false,
            recursion_depth: None,
            parallelization: Default::default(),
            recreate: Recreate::IfInvalid,
        })
        .expect("seed sidecar"),
    );
    {
        let w = SqliteIndex::open_writable(&idx).expect("writable sidecar");
        w.store_metadata_key_value("backendName", "NotARealBackend")
            .unwrap();
    }
    let before = std::fs::read(&idx).unwrap();
    let err = match Session::open(never_req(tar, idx.clone())) {
        Err(e) => e,
        Ok(_) => panic!("expected CorruptIndex, open succeeded"),
    };
    assert!(
        matches!(err, Error::CorruptIndex(_)),
        "expected CorruptIndex, got {err:?}"
    );
    let after = std::fs::read(&idx).unwrap();
    assert_eq!(
        before, after,
        "Never must not rebuild on backendName mismatch"
    );
}

static TEMP_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn temp_sqlite_path(seq: u32) -> PathBuf {
    std::env::temp_dir()
        .join(format!("ratarmount-session-{}", std::process::id()))
        .join(format!("index-{seq}.sqlite"))
}

/// Temp open+drop removes the sqlite and journals.
#[test]
fn index_policy_temp_drop_unlinks() {
    let _g = TEMP_TEST_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let tar = dir.path().join("tmp.tar");
    write_tar(&tar, &[member_file("a.txt", b"hi")]);
    let seq = crate::resolve::TEMP_INDEX_SEQ.load(Ordering::Relaxed);
    let session = Session::open(OpenRequest {
        source: SourceSpec::Path(tar),
        index: IndexPolicy::Temp,
        explicit_index: None,
        extra_dirs: Vec::new(),
        password: None,
        recursive: false,
        recursion_depth: None,
        parallelization: Default::default(),
        recreate: Recreate::IfInvalid,
    })
    .expect("Temp open");
    let p = session
        .catalog_path()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| temp_sqlite_path(seq));
    assert!(
        p.exists(),
        "Temp sidecar should exist while Session is live"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Some(parent) = p.parent() {
            let mode = std::fs::metadata(parent).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o700, "Temp pid dir should be 0700");
        }
    }
    drop(session);
    assert!(!p.exists(), "Temp Drop must unlink {}", p.display());
    let s = p.to_string_lossy();
    assert!(!Path::new(&format!("{s}-wal")).exists());
    assert!(!Path::new(&format!("{s}-shm")).exists());
    assert!(!Path::new(&format!("{s}-journal")).exists());
}

/// Failed Temp open (catalog inject) must not leave index-*.sqlite.
#[test]
fn index_policy_temp_failed_open_unlinks() {
    let _g = TEMP_TEST_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let tar = dir.path().join("fail.tar");
    write_tar(&tar, &[member_file("a.txt", b"hi")]);
    let seq = crate::resolve::TEMP_INDEX_SEQ.load(Ordering::Relaxed);
    INJECT_CATALOG_OPEN_ERR.with(|c| c.set(true));
    let err = Session::open(OpenRequest {
        source: SourceSpec::Path(tar),
        index: IndexPolicy::Temp,
        explicit_index: None,
        extra_dirs: Vec::new(),
        password: None,
        recursive: false,
        recursion_depth: None,
        parallelization: Default::default(),
        recreate: Recreate::IfInvalid,
    });
    INJECT_CATALOG_OPEN_ERR.with(|c| c.set(false));
    assert!(err.is_err(), "injected catalog failure should error");
    let p = temp_sqlite_path(seq);
    assert!(!p.exists(), "failed Temp open must unlink {}", p.display());
}

#[test]
fn session_drop_closes_unique_arc() {
    use std::sync::atomic::AtomicBool;
    struct CloseSpy {
        closed: Arc<AtomicBool>,
    }
    impl MountSource for CloseSpy {
        fn list(&self, _path: &str) -> Option<ratarmount_core::ListResult> {
            None
        }
        fn lookup(&self, _path: &str, _file_version: i32) -> Option<FileInfo> {
            None
        }
        fn open(
            &self,
            _file_info: &FileInfo,
            _buffering: i32,
        ) -> std::io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Err(std::io::Error::other("spy"))
        }
        fn is_immutable(&self) -> bool {
            true
        }
        fn close(&mut self) {
            self.closed.store(true, Ordering::SeqCst);
        }
    }
    let closed = Arc::new(AtomicBool::new(false));
    {
        let session = Session::from_local_source(Arc::new(CloseSpy {
            closed: Arc::clone(&closed),
        }));
        drop(session);
    }
    assert!(closed.load(Ordering::SeqCst), "unique Arc Drop must close");
}

#[test]
fn map_factory_error_permission_denied_without_password_is_not_writable() {
    let e = map_factory_error(
        "Permission denied (os error 13)".into(),
        false,
        Path::new("/a.tar"),
    );
    match e {
        Error::NotWritable(p) => assert_eq!(p, Path::new("/a.tar")),
        other => panic!("expected NotWritable, got {other:?}"),
    }
}

#[test]
fn map_factory_error_permission_denied_with_password_is_bad_password() {
    let e = map_factory_error(
        "Permission denied (os error 13)".into(),
        true,
        Path::new("/a.tar"),
    );
    assert!(matches!(e, Error::BadPassword));
}

#[test]
fn map_factory_error_cancelled_in_path_is_not_found() {
    let e = map_factory_error(
        "not found: /tmp/cancelled/foo.tar".into(),
        false,
        Path::new("/tmp/cancelled/foo.tar"),
    );
    assert!(
        matches!(e, Error::NotFound),
        "path token cancelled must not map to Cancelled, got {e:?}"
    );
}

#[test]
fn map_factory_error_exact_cancelled() {
    let e = map_factory_error(
        IndexError::Cancelled.to_string(),
        false,
        Path::new("/a.tar"),
    );
    assert!(matches!(e, Error::Cancelled));
}

#[test]
fn open_chmod_000_without_password_is_not_writable() {
    let dir = tempfile::tempdir().unwrap();
    let tar = dir.path().join("ro.tar");
    write_tar(&tar, &[member_file("a.txt", b"hi")]);
    let idx = dir.path().join("ro.tar.index.sqlite");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tar, std::fs::Permissions::from_mode(0o000)).unwrap();
    }
    let err = Session::open(OpenRequest {
        source: SourceSpec::Path(tar.clone()),
        index: IndexPolicy::Explicit,
        explicit_index: Some(idx),
        extra_dirs: Vec::new(),
        password: None,
        recursive: false,
        recursion_depth: None,
        parallelization: Default::default(),
        recreate: Recreate::IfInvalid,
    });
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tar, std::fs::Permissions::from_mode(0o644));
    }
    match err {
        Err(Error::NotWritable(p)) => assert_eq!(p, tar),
        Ok(_) => eprintln!("skip: process can read chmod 000 archive (root?)"),
        Err(e) => panic!("expected NotWritable, got {e:?}"),
    }
}
