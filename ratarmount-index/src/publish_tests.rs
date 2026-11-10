//! Regression coverage for durable, immutable local publication.
use crate::location::{self, with_pin_hook, IndexWriteAccess, PinStep};
use crate::managed_read::{seams, Seam};
use crate::*;
use rusqlite::Connection;
use std::cell::RefCell;
use std::fs;
use std::io;
use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;

type Events = Rc<RefCell<Vec<String>>>;
fn temp() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}
fn chmod(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}
fn bytes(path: &Path) -> Vec<u8> {
    managed_read::read(path).unwrap()
}
fn hash(path: &Path) -> String {
    managed_read::sha256_hex(path).unwrap()
}
fn identity(path: &Path) -> (u64, u64) {
    let m = fs::metadata(path).unwrap();
    (m.dev(), m.ino())
}
fn companion(path: &Path, suffix: &str) -> PathBuf {
    crate::sqlite_path_companion(path, suffix)
}
fn no_companions(path: &Path) {
    for s in ["-wal", "-shm", "-journal"] {
        assert!(
            !companion(path, s).exists(),
            "{}",
            companion(path, s).display()
        );
    }
}
fn no_tmp(dir: &Path) {
    for e in fs::read_dir(dir).unwrap().flatten() {
        assert!(
            !e.file_name()
                .as_encoded_bytes()
                .starts_with(b".ratarmount-index-"),
            "{:?}",
            e.path()
        );
    }
}
fn catalog(path: &Path, n: i64) {
    let mut idx = SqliteIndex::create_writable(Some(path)).unwrap();
    idx.store_versions("0.2.1").unwrap();
    idx.with_conn(|c| {
        c.execute_batch("CREATE TABLE publication_rows(n INTEGER)")?;
        c.execute("INSERT INTO publication_rows VALUES (?)", [n])?;
        Ok(())
    })
    .unwrap();
    idx.publish_tmp().unwrap();
}
fn wal_source(path: &Path) -> Connection {
    catalog(path, 1);
    let c = Connection::open(path).unwrap();
    c.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; INSERT INTO publication_rows VALUES (2)").unwrap();
    assert!(fs::metadata(companion(path, "-wal")).unwrap().len() > 0);
    c
}
fn rows(path: &Path) -> i64 {
    let c = Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    c.query_row("SELECT count(*) FROM publication_rows", [], |r| r.get(0))
        .unwrap()
}
fn publish(base: &Path, source: &Path) -> IndexPointer {
    publish_index_pointer(base, source, None).unwrap()
}
fn ptr_bytes(base: &Path) -> Vec<u8> {
    bytes(&index_pointer_path(base))
}
fn pins(base: &Path) -> Vec<PathBuf> {
    let template = index_id_path(base, &"0".repeat(64)).unwrap();
    let prefix = template.file_name().unwrap().as_encoded_bytes();
    let prefix = &prefix[..prefix.len() - 71];
    fs::read_dir(
        template
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
    .unwrap()
    .flatten()
    .filter(|e| {
        let name = e.file_name();
        name.as_encoded_bytes().starts_with(prefix) && is_pin_file_name(&name)
    })
    .map(|e| e.path())
    .collect()
}
fn record(events: Events) -> impl FnMut(PinStep) -> io::Result<()> {
    move |s| {
        events.borrow_mut().push(format!("{s:?}"));
        Ok(())
    }
}
fn tree(dir: &Path) -> Vec<PathBuf> {
    fn walk(p: &Path, out: &mut Vec<PathBuf>) {
        for e in fs::read_dir(p).unwrap().flatten() {
            out.push(e.path());
            if e.file_type().unwrap().is_dir() {
                walk(&e.path(), out);
            }
        }
    }
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort();
    out
}

fn directories(dir: &Path) -> Vec<PathBuf> {
    tree(dir)
        .into_iter()
        .filter(|p| fs::symlink_metadata(p).unwrap().is_dir())
        .collect()
}

/// Regression: WAL-only rows must reach an independent, hash-stable read-only pin.
#[test]
fn regression_publish_pin_is_wal_complete_snapshot() {
    for (mode, want) in [(0o644, 0o444), (0o600, 0o400)] {
        let d = temp();
        let source = d.path().join("source.sqlite");
        let base = d.path().join("a");
        let c = wal_source(&source);
        chmod(&source, mode);
        let main = bytes(&source);
        let wal = bytes(&companion(&source, "-wal"));
        let p = publish(&base, &source);
        let pin = index_id_path(&base, &p.index_id).unwrap();
        assert_eq!(rows(&pin), 2);
        assert_eq!(hash(&pin), p.index_id);
        assert_eq!(&bytes(&pin)[18..20], &[1, 1]);
        assert_ne!(identity(&pin), identity(&source));
        let m = fs::metadata(&pin).unwrap();
        assert_eq!(m.nlink(), 1);
        assert_eq!(m.mode() & 0o777, want);
        no_companions(&pin);
        no_tmp(d.path());
        assert_eq!(bytes(&source), main);
        assert_eq!(bytes(&companion(&source, "-wal")), wal);
        c.execute_batch("PRAGMA wal_checkpoint(TRUNCATE)").unwrap();
        assert_eq!(hash(&pin), p.index_id);
    }
}

/// Regression: existing pin entries and companions are refused without replacement.
#[test]
fn regression_publish_pin_is_never_replaced() {
    let d = temp();
    let source = d.path().join("source.sqlite");
    catalog(&source, 1);
    let base = d.path().join("a");
    let p = publish(&base, &source);
    let pin = index_id_path(&base, &p.index_id).unwrap();
    let original = bytes(&pin);
    let inode = identity(&pin);
    assert_eq!(publish(&base, &source).index_id, p.index_id);
    assert_eq!(identity(&pin), inode);
    let pointer = ptr_bytes(&base);
    for case in 0..11 {
        fs::remove_file(&pin).unwrap();
        let mut extra = None;
        match case {
            0 => {
                fs::write(&pin, b"other bytes").unwrap();
                chmod(&pin, 0o400);
            }
            1 => {
                fs::write(&pin, &original).unwrap();
            }
            2 => fs::hard_link(&source, &pin).unwrap(),
            3 => symlink(&source, &pin).unwrap(),
            4 => fs::create_dir(&pin).unwrap(),
            _ => {
                if case < 8 {
                    fs::write(&pin, &original).unwrap();
                    chmod(&pin, 0o400);
                }
                let c = companion(&pin, ["-wal", "-shm", "-journal"][(case - 5) % 3]);
                fs::write(&c, b"leftover").unwrap();
                extra = Some(c);
            }
        }
        let meta = fs::symlink_metadata(&pin).ok();
        let saved = meta.as_ref().filter(|m| m.is_file()).map(|_| bytes(&pin));
        assert!(
            publish_index_pointer(&base, &source, None).is_err(),
            "case {case}"
        );
        assert_eq!(ptr_bytes(&base), pointer);
        no_tmp(d.path());
        if let Some(m) = meta {
            let now = fs::symlink_metadata(&pin).unwrap();
            assert_eq!((m.dev(), m.ino()), (now.dev(), now.ino()));
        }
        if let Some(saved) = saved {
            assert_eq!(bytes(&pin), saved);
        }
        if case == 4 {
            fs::remove_dir(&pin).unwrap();
        } else if fs::symlink_metadata(&pin).is_ok() {
            fs::remove_file(&pin).unwrap();
        }
        if let Some(c) = extra {
            assert_eq!(bytes(&c), b"leftover");
            fs::remove_file(c).unwrap();
        }
        fs::write(&pin, &original).unwrap();
        chmod(&pin, 0o400);
    }
    for identical in [false, true] {
        fs::remove_file(&pin).unwrap();
        let saved = original.clone();
        let race_inode = Rc::new(RefCell::new(None));
        let observed = race_inode.clone();
        let result = with_pin_hook(
            move |s| {
                if let PinStep::Install(p) = s {
                    fs::write(
                        &p,
                        if identical {
                            saved.as_slice()
                        } else {
                            b"racer"
                        },
                    )
                    .unwrap();
                    chmod(&p, 0o400);
                    *observed.borrow_mut() = Some(identity(&p));
                }
                Ok(())
            },
            || publish_index_pointer(&base, &source, None),
        );
        assert_eq!(result.is_ok(), identical);
        if !identical {
            assert_eq!(ptr_bytes(&base), pointer);
        }
        assert_eq!(Some(identity(&pin)), *race_inode.borrow());
        assert_eq!(
            bytes(&pin),
            if identical {
                original.clone()
            } else {
                b"racer".to_vec()
            }
        );
        no_tmp(d.path());
    }
    let from_pin = snapshot_index_id(&base, &pin).unwrap();
    assert_ne!(from_pin.id(), p.index_id);
    no_tmp(d.path());
}

/// Regression: failed snapshot, sync, hash, install and permission checks publish nothing.
#[test]
fn regression_publish_failures_leave_no_tmp_and_no_pointer() {
    for case in 0..5 {
        let d = temp();
        let source = d.path().join("source.sqlite");
        catalog(&source, 1);
        let base = d.path().join("a");
        let old = IndexPointer::for_id("a".repeat(64), None);
        store_index_pointer_atomic(&index_pointer_path(&base), &old).unwrap();
        let before = ptr_bytes(&base);
        if case == 0 {
            let mut data = fs::read(&source).unwrap();
            data[100..120].fill(0xff);
            fs::write(&source, data).unwrap();
        }
        let result = with_pin_hook(
            move |s| {
                match s {
                    PinStep::Install(_) if case == 3 => {
                        return Err(io::Error::other("install failure"))
                    }
                    PinStep::Mode(p) if case == 4 => chmod(&p, 0o600),
                    _ => {}
                }
                Ok(())
            },
            || {
                let mut reads = 0;
                seams::with(
                    move |s| {
                        if s == Seam::BeforeRead {
                            reads += 1;
                        }
                        if (case == 1 && s == Seam::BeforeSync)
                            || (case == 2 && s == Seam::BeforeRead && reads == 2)
                        {
                            Err(io::Error::other("managed failure"))
                        } else {
                            Ok(())
                        }
                    },
                    || publish_index_pointer(&base, &source, None),
                )
            },
        );
        let err = result.unwrap_err().to_string();
        if case == 3 {
            assert!(err.contains("exclusive rename"), "{err}");
        }
        assert_eq!(ptr_bytes(&base), before);
        assert!(pins(&base).is_empty());
        no_tmp(d.path());
    }
}

/// Regression: directory sync failures are errors, and every retry syncs again.
#[test]
fn regression_publish_directory_sync_failure_is_an_error() {
    for after_pointer in [false, true] {
        let d = temp();
        let source = d.path().join("source.sqlite");
        catalog(&source, 1);
        let base = d.path().join("a");
        let old = IndexPointer::for_id("a".repeat(64), None);
        store_index_pointer_atomic(&index_pointer_path(&base), &old).unwrap();
        let before = ptr_bytes(&base);
        let mut stored = false;
        let result = with_pin_hook(
            move |s| {
                if s == PinStep::PointerStored {
                    stored = true;
                }
                if matches!(s, PinStep::DirSync(_)) && stored == after_pointer {
                    return Err(io::Error::other("directory failure"));
                }
                Ok(())
            },
            || publish_index_pointer(&base, &source, None),
        );
        assert!(result.is_err());
        if !after_pointer {
            assert_eq!(ptr_bytes(&base), before);
        }
        let events = Events::default();
        with_pin_hook(record(events.clone()), || publish(&base, &source));
        assert_eq!(
            events
                .borrow()
                .iter()
                .filter(|s| s.starts_with("DirSync"))
                .count(),
            2
        );
    }
    if ratarmount_core::effective_uid() == 0 {
        eprintln!("skip: mode-0300 directory refusal requires a non-root user");
        return;
    }
    let d = temp();
    let source = d.path().join("source.sqlite");
    catalog(&source, 1);
    let out = d.path().join("drop");
    fs::create_dir(&out).unwrap();
    let base = out.join("a");
    chmod(&out, 0o300);
    for _ in 0..2 {
        let e = publish_index_pointer(&base, &source, None)
            .unwrap_err()
            .to_string();
        assert!(e.contains(&out.display().to_string()), "{e}");
        assert!(!index_pointer_path(&base).exists());
    }
    chmod(&out, 0o700);
    publish(&base, &source);
    eprintln!("mode-0300 directory refusal and retry passed");
}

/// Regression: a snapshot is synced before install, then its directory before the pointer.
#[test]
fn regression_publish_syncs_snapshot_before_install() {
    let d = temp();
    let source = d.path().join("source.sqlite");
    catalog(&source, 1);
    let base = d.path().join("a");
    let events = Events::default();
    let syncs = events.clone();
    seams::with(
        move |s| {
            if s == Seam::BeforeSync {
                syncs.borrow_mut().push("Sync".into());
            }
            Ok(())
        },
        || with_pin_hook(record(events.clone()), || publish(&base, &source)),
    );
    let events = events.borrow();
    let positions: Vec<_> = [
        "Sync",
        "Install(",
        "Installed(",
        "DirSync(",
        "Bind",
        "Prune(",
        "PointerStore",
        "PointerStored",
    ]
    .iter()
    .map(|prefix| events.iter().position(|s| s.starts_with(prefix)).unwrap())
    .collect();
    assert!(positions.windows(2).all(|w| w[0] < w[1]), "{events:?}");
    assert!(events.last().unwrap().starts_with("DirSync("));
}

fn assert_optional_writers_refuse(path: &Path) {
    assert!(
        !archive_digest_cache_available(Some(path)),
        "{}",
        path.display()
    );
    let idx = SqliteIndex::open_catalog_read_only(path).unwrap();
    idx.prepare_offset_order_index(true);
    let indexed = idx
        .with_conn(|c| {
            Ok(c.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='files_offsetheader'",
                [],
                |r| r.get::<_, i64>(0),
            )?)
        })
        .unwrap();
    assert_eq!(indexed, 0);
}

/// Regression: pin names, symlinks, URI spellings and read-only aliases cannot be written.
#[test]
fn regression_open_writable_refuses_index_pin() {
    let d = temp();
    let source = d.path().join("source.sqlite");
    catalog(&source, 1);
    let base = d.path().join("a");
    let p = publish(&base, &source);
    let pin = index_id_path(&base, &p.index_id).unwrap();
    let before = bytes(&pin);
    let link = d.path().join("link.sqlite");
    symlink(&pin, &link).unwrap();
    let named = d
        .path()
        .join(format!("symlink.index.{}.sqlite", "f".repeat(64)));
    symlink(&source, &named).unwrap();
    let bare = d.path().join(format!(".index.{}.sqlite", "f".repeat(64)));
    fs::copy(&source, &bare).unwrap();
    chmod(&bare, 0o600);
    for path in [&pin, &link, &named, &bare] {
        let err = SqliteIndex::open_writable(path).err().unwrap().to_string();
        assert!(err.contains("published index pin"), "{err}");
        assert_optional_writers_refuse(path);
    }
    for path in ["file:source.sqlite", "file:source.sqlite?mode=rw"] {
        let err = SqliteIndex::open_writable(path).err().unwrap().to_string();
        assert!(err.contains("file:"), "{err}");
        assert!(!archive_digest_cache_available(Some(Path::new(path))));
    }
    let alias = d.path().join("alias.sqlite");
    fs::hard_link(&pin, &alias).unwrap();
    assert!(SqliteIndex::open_writable(&alias).is_err());
    no_companions(&alias);
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStringExt;
        let mut name = b"pin-\xff.index.".to_vec();
        name.extend("a".repeat(64).as_bytes());
        name.extend(b".sqlite");
        let path = d.path().join(std::ffi::OsString::from_vec(name));
        fs::copy(&source, &path).unwrap();
        chmod(&path, 0o600);
        assert!(SqliteIndex::open_writable(&path)
            .err()
            .unwrap()
            .to_string()
            .contains("published index pin"));
        assert_optional_writers_refuse(&path);
    }
    assert_eq!(bytes(&pin), before);
    no_companions(&pin);
    let cache = d.path().join(format!("{}.sqlite", "f".repeat(64)));
    fs::copy(&source, &cache).unwrap();
    for control in [&source, &cache] {
        let idx = SqliteIndex::open_writable(control).unwrap();
        idx.store_metadata_key_value("control", "yes").unwrap();
    }
}

/// Regression: symlinked live WAL sources retain committed WAL rows.
#[test]
fn regression_publish_through_symlinked_source() {
    let d = temp();
    let source = d.path().join("source.sqlite");
    let _holder = wal_source(&source);
    let link = d.path().join("link.sqlite");
    symlink(&source, &link).unwrap();
    let base = d.path().join("a");
    let ptr = publish(&base, &link);
    assert_eq!(rows(&index_id_path(&base, &ptr.index_id).unwrap()), 2);
}

/// Regression: publication through an existing symlinked directory remains supported.
#[test]
fn publish_through_symlinked_parent_compat() {
    let d = temp();
    let real = d.path().join("real");
    fs::create_dir(&real).unwrap();
    let link = d.path().join("link");
    symlink(&real, &link).unwrap();
    let source = d.path().join("source.sqlite");
    catalog(&source, 1);
    let base = link.join("a");
    let ptr = publish(&base, &source);
    assert_eq!(
        hash(&index_id_path(&real.join("a"), &ptr.index_id).unwrap()),
        ptr.index_id
    );
}

/// Regression: missing directories, including paths through .. and symlinks, are never created.
#[test]
fn regression_publish_never_creates_a_directory() {
    for case in 0..6 {
        let d = temp();
        let t = d.path().join("T");
        let u = d.path().join("U");
        fs::create_dir(&t).unwrap();
        fs::create_dir(&u).unwrap();
        fs::create_dir(u.join("sub")).unwrap();
        let source = d.path().join("source.sqlite");
        catalog(&source, 1);
        let base = match case {
            0 => t.join("out/a"),
            1 => t.join("out/sub/a"),
            2 => {
                symlink(&u, t.join("link")).unwrap();
                t.join("new/../link/sub/a")
            }
            3 => t.join("a/b/../../out/x"),
            4 => {
                symlink(t.join("missing"), t.join("out")).unwrap();
                t.join("out/a")
            }
            _ => {
                fs::write(t.join("out"), b"file").unwrap();
                t.join("out/a")
            }
        };
        let before = tree(&t);
        let ubefore = tree(&u);
        let result = with_pin_hook(
            |s| panic!("unexpected step {s:?}"),
            || publish_index_pointer(&base, &source, None),
        );
        let err = result.unwrap_err().to_string();
        assert!(err.contains("directory"), "{err}");
        assert_eq!(tree(&t), before);
        assert_eq!(tree(&u), ubefore);
    }
    for case in [2, 3] {
        let d = temp();
        let t = d.path().join("T");
        let u = d.path().join("U");
        fs::create_dir(&t).unwrap();
        fs::create_dir(&u).unwrap();
        fs::create_dir(u.join("sub")).unwrap();
        let source = d.path().join("source.sqlite");
        catalog(&source, 1);
        let (base, physical) = if case == 2 {
            fs::create_dir(t.join("new")).unwrap();
            symlink(&u, t.join("link")).unwrap();
            (t.join("new/../link/sub/a"), u.join("sub"))
        } else {
            fs::create_dir_all(t.join("a/b")).unwrap();
            fs::create_dir(t.join("out")).unwrap();
            (t.join("a/b/../../out/x"), t.join("out"))
        };
        let before = (directories(&t), directories(&u));
        let events = Events::default();
        let pin = with_pin_hook(record(events.clone()), || {
            snapshot_index_id(&base, &source).unwrap()
        });
        assert_eq!(identity(pin.dir()), identity(&physical));
        publish_index_pointer_for_pin(&base, &pin, None).unwrap();
        let expected = format!("{:?}", PinStep::DirSync(pin.dir().to_path_buf()));
        assert!(events.borrow().contains(&expected));
        assert!(pin.path().exists());
        assert!(index_pointer_path(&base).exists());
        assert_eq!((directories(&t), directories(&u)), before);
    }
}

fn relative_child(test: &str, marker: &str, body: impl FnOnce()) -> Option<tempfile::TempDir> {
    if std::env::var_os(marker).is_some() {
        body();
        return None;
    }
    let _spawn = test_process::spawning();
    let d = temp();
    let out = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env(marker, "1")
        .current_dir(d.path())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    Some(d)
}

/// Regression: relative and bare archive paths publish into their existing directory.
#[test]
fn publish_relative_archive_paths_compat() {
    if let Some(d) = relative_child(
        "publish_tests::publish_relative_archive_paths_compat",
        "WALPUB_RELATIVE",
        || {
            fs::create_dir_all("out/sub").unwrap();
            catalog(Path::new("source.sqlite"), 1);
            for base in ["out/sub/a.tar", "b.tar"] {
                publish(Path::new(base), Path::new("source.sqlite"));
            }
        },
    ) {
        for base in [d.path().join("out/sub/a.tar"), d.path().join("b.tar")] {
            let p = load_index_pointer(&index_pointer_path(&base))
                .unwrap()
                .unwrap();
            assert_eq!(
                hash(&index_id_path(&base, &p.index_id).unwrap()),
                p.index_id
            );
        }
        for p in tree(d.path()) {
            assert!(!p
                .file_name()
                .unwrap()
                .as_encoded_bytes()
                .starts_with(b".ratarmount-index-"));
        }
    }
}

/// Regression: an identical existing pin must be synced before the pointer changes.
#[test]
fn regression_publish_existing_pin_is_synced_before_pointer() {
    let d = temp();
    let source = d.path().join("source.sqlite");
    catalog(&source, 1);
    let base = d.path().join("a");
    let p = publish(&base, &source);
    let pin = index_id_path(&base, &p.index_id).unwrap();
    let before = bytes(&pin);
    let inode = identity(&pin);
    let mode = fs::metadata(&pin).unwrap().mode();
    let z = IndexPointer::for_id("f".repeat(64), None);
    store_index_pointer_atomic(&index_pointer_path(&base), &z).unwrap();
    let old = ptr_bytes(&base);
    let canonical = pin.canonicalize().unwrap();
    let result = seams::with(
        move |s| {
            if s == Seam::BeforeSync && seams::opened_path() == Some(canonical.clone()) {
                Err(io::Error::other("pin fsync failed"))
            } else {
                Ok(())
            }
        },
        || publish_index_pointer(&base, &source, None),
    );
    assert!(result.is_err());
    assert_eq!(ptr_bytes(&base), old);
    assert_eq!(bytes(&pin), before);
    assert_eq!(identity(&pin), inode);
    assert_eq!(fs::metadata(&pin).unwrap().mode(), mode);
    no_tmp(d.path());
    let events = Events::default();
    let e = events.clone();
    let canonical = pin.canonicalize().unwrap();
    seams::with(
        move |s| {
            if s == Seam::BeforeSync && seams::opened_path() == Some(canonical.clone()) {
                e.borrow_mut().push("SyncExisting".into());
            }
            Ok(())
        },
        || with_pin_hook(record(events.clone()), || publish(&base, &source)),
    );
    let e = events.borrow();
    assert!(
        e.iter().position(|s| s == "SyncExisting").unwrap()
            < e.iter().position(|s| s == "PointerStore").unwrap()
    );
    assert_eq!(
        load_index_pointer(&index_pointer_path(&base))
            .unwrap()
            .unwrap()
            .index_id,
        p.index_id
    );
}

fn root_reexec(test: &str) {
    if ratarmount_core::effective_uid() == 0 || std::env::var_os("WALPUB_ROOT").is_some() {
        return;
    }
    let _spawn = test_process::spawning();
    match Command::new("unshare")
        .args(["--user", "--map-root-user", "true"])
        .output()
    {
        Ok(o) if o.status.success() => {}
        other => {
            eprintln!("skip: root-effective user namespace unavailable: {other:?}");
            return;
        }
    }
    let out = Command::new("unshare")
        .args(["--user", "--map-root-user"])
        .arg(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture"])
        .env("WALPUB_ROOT", "1")
        .output()
        .unwrap();
    eprintln!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(out.status.success());
}
fn privilege_control(alias: &Path, dir: &Path) {
    if ratarmount_core::effective_uid() != 0 {
        return;
    }
    assert_eq!(ratarmount_core::effective_uid(), 0);
    let control = dir.join("privilege-control.sqlite");
    fs::copy(alias, &control).unwrap();
    chmod(&control, 0o444);
    let c = Connection::open(&control).unwrap();
    c.execute_batch("PRAGMA journal_mode=WAL").unwrap();
    assert_eq!(&bytes(&control)[18..20], &[2, 2]);
    drop(c);
    eprintln!("root privilege control passed");
}
fn read_only_wal_body() {
    let d = temp();
    let source = d.path().join("source.sqlite");
    let _holder = wal_source(&source);
    chmod(&source, 0o444);
    let before = bytes(&source);
    let idx = SqliteIndex::open_writable(&source).unwrap();
    assert!(idx
        .with_conn(|c| Ok(c.is_readonly(rusqlite::MAIN_DB)?))
        .unwrap());
    assert_eq!(
        idx.with_conn(|c| Ok(c
            .query_row("SELECT count(*) FROM publication_rows", [], |r| r
                .get::<_, i64>(0))?))
            .unwrap(),
        2
    );
    assert!(idx.store_metadata_key_value("write", "no").is_err());
    assert_eq!(bytes(&source), before);
    drop(idx);
    chmod(&source, 0o644);
    let idx = SqliteIndex::open_writable(&source).unwrap();
    assert!(!idx
        .with_conn(|c| Ok(c.is_readonly(rusqlite::MAIN_DB)?))
        .unwrap());
    idx.store_metadata_key_value("write", "yes").unwrap();
    eprintln!(
        "read-only WAL connection row passed (euid {})",
        ratarmount_core::effective_uid()
    );
}

/// Regression: pin aliases remain protected after keep-last-two prunes the pin name.
#[test]
fn regression_pin_alias_stays_read_only_after_pin_name_is_pruned() {
    let d = temp();
    let base = d.path().join("a");
    let source = d.path().join("source.sqlite");
    catalog(&source, 1);
    let p = publish(&base, &source);
    let pin = index_id_path(&base, &p.index_id).unwrap();
    let alias = d.path().join("alias.sqlite");
    fs::hard_link(&pin, &alias).unwrap();
    privilege_control(&alias, d.path());
    for n in [2, 3] {
        let next = d.path().join(format!("source{n}.sqlite"));
        catalog(&next, n);
        publish(&base, &next);
    }
    assert!(!pin.exists());
    assert_eq!(pins(&base).len(), 2);
    assert_eq!(fs::metadata(&alias).unwrap().nlink(), 1);
    assert!(fs::metadata(&alias).unwrap().permissions().readonly());
    assert_eq!(hash(&alias), p.index_id);
    let before = bytes(&alias);
    let inode = identity(&alias);
    let mtime = fs::metadata(&alias).unwrap().modified().unwrap();
    for action in 0..4 {
        match action {
            0 => {
                assert_eq!(
                    location::index_write_access(&alias),
                    IndexWriteAccess::ReadOnly
                );
                assert!(SqliteIndex::open_writable(&alias).is_err());
            }
            1 => assert_optional_writers_refuse(&alias),
            2 => assert!(!archive_digest_cache_available(Some(&alias))),
            _ => SqliteIndex::finalize_prepared(&alias).unwrap(),
        }
        assert_eq!(bytes(&alias), before);
        assert_eq!(identity(&alias), inode);
        assert_eq!(fs::metadata(&alias).unwrap().modified().unwrap(), mtime);
        no_companions(&alias);
    }
    eprintln!(
        "pruned alias row passed (euid {})",
        ratarmount_core::effective_uid()
    );
    if std::env::var_os("WALPUB_ROOT").is_some() {
        read_only_wal_body();
    }
    root_reexec("publish_tests::regression_pin_alias_stays_read_only_after_pin_name_is_pruned");
}

/// Regression: read-only WAL files are never opened read-write, including as root.
#[test]
fn regression_open_writable_read_only_file_gets_read_only_connection() {
    read_only_wal_body();
    root_reexec("publish_tests::regression_open_writable_read_only_file_gets_read_only_connection");
}

/// Regression: a token cannot publish a pointer at another absolute path or for a replacement inode.
#[test]
fn regression_published_pin_is_bound_to_its_absolute_path() {
    let d = temp();
    let a = d.path().join("a");
    let b = d.path().join("b");
    fs::create_dir(&a).unwrap();
    fs::create_dir(&b).unwrap();
    let abase = a.join("x.tar");
    let bbase = b.join("x.tar");
    let source = d.path().join("source.sqlite");
    catalog(&source, 1);
    let token = snapshot_index_id(&abase, &source).unwrap();
    let other = index_id_path(&bbase, token.id()).unwrap();
    fs::write(&other, b"other bytes").unwrap();
    chmod(&other, 0o400);
    let spare = index_id_path(&bbase, &"f".repeat(64)).unwrap();
    fs::write(&spare, b"spare").unwrap();
    let events = Events::default();
    assert!(
        with_pin_hook(record(events.clone()), || publish_index_pointer_for_pin(
            &bbase, &token, None
        ))
        .is_err()
    );
    assert_eq!(*events.borrow(), ["Bind"]);
    assert!(!index_pointer_path(&bbase).exists());
    assert_eq!(bytes(&other), b"other bytes");
    assert!(spare.exists());
    publish_index_pointer_for_pin(&abase, &token, None).unwrap();
    publish_index_pointer_for_pin(&a.join("./x.tar"), &token, None).unwrap();
    let old = ptr_bytes(&abase);
    let pin = token.path().to_path_buf();
    let saved = bytes(&pin);
    let replacement = a.join("replacement");
    let err = with_pin_hook(
        move |s| {
            if matches!(s, PinStep::Prune(_)) {
                fs::write(&replacement, &saved).unwrap();
                chmod(&replacement, 0o400);
                assert_ne!(identity(&replacement), identity(&pin));
                fs::rename(&replacement, &pin).unwrap();
            }
            Ok(())
        },
        || publish_index_pointer_for_pin(&abase, &token, None),
    )
    .unwrap_err();
    assert!(err.to_string().contains("pruned or replaced"));
    assert_eq!(ptr_bytes(&abase), old);
    let token = snapshot_index_id(&abase, &source).unwrap();
    let pin = token.path().to_path_buf();
    with_pin_hook(
        move |s| {
            if s == PinStep::PointerStore {
                fs::remove_file(&pin).unwrap();
            }
            Ok(())
        },
        || publish_index_pointer_for_pin(&abase, &token, None),
    )
    .unwrap();
    assert_eq!(
        load_index_pointer(&index_pointer_path(&abase))
            .unwrap()
            .unwrap()
            .index_id,
        token.id()
    );
    assert!(resolve_index_id_path(&abase, token.id()).is_err());
    let token = snapshot_index_id(&abase, &source).unwrap();
    let moved = d.path().join("moved");
    let adir = a.clone();
    assert!(with_pin_hook(
        move |s| {
            if s == PinStep::PointerStore {
                fs::rename(&adir, &moved).unwrap();
            }
            Ok(())
        },
        || publish_index_pointer_for_pin(&abase, &token, None)
    )
    .is_err());
    assert!(!a.exists());
}
fn generation(dir: &Path, n: i64) -> PathBuf {
    let path = dir.join(format!("generation{n}.sqlite"));
    catalog(&path, n);
    path
}
fn rotate(base: &Path, dir: &Path, count: i64) -> Vec<String> {
    let mut ids = Vec::new();
    for n in 1..=count {
        ids.push(publish(base, &generation(dir, n)).index_id);
    }
    ids
}

/// Regression: a trailing-separator base prunes only pins inside its own directory.
#[test]
fn regression_prune_scope_is_the_pin_directory() {
    let d = temp();
    let out = d.path().join("out");
    fs::create_dir(&out).unwrap();
    let sources = d.path().join("sources");
    fs::create_dir(&sources).unwrap();
    let independent = rotate(&out, &sources, 2);
    let old = ptr_bytes(&out);
    let nested = d.path().join("out/");
    let inner = d.path().join("inner");
    fs::create_dir(&inner).unwrap();
    let mut ids = Vec::new();
    for n in 1..=3 {
        ids.push(publish(&nested, &generation(&inner, n)).index_id);
        assert_eq!(ptr_bytes(&out), old);
        for id in &independent {
            assert!(resolve_index_id_path(&out, id).is_ok());
        }
    }
    assert_eq!(pins(&nested).len(), 2);
    assert!(!index_id_path(&nested, &ids[0]).unwrap().exists());
    assert_eq!(
        load_index_pointer(&index_pointer_path(&nested))
            .unwrap()
            .unwrap()
            .index_id,
        ids[2]
    );
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::ffi::OsStringExt;
        let a = d
            .path()
            .join(std::ffi::OsString::from_vec(b"x-\xff".to_vec()));
        let b = d
            .path()
            .join(std::ffi::OsString::from_vec(b"x-\xfe".to_vec()));
        let a_ids = rotate(
            &a,
            &{
                let p = d.path().join("sa");
                fs::create_dir(&p).unwrap();
                p
            },
            2,
        );
        rotate(
            &b,
            &{
                let p = d.path().join("sb");
                fs::create_dir(&p).unwrap();
                p
            },
            3,
        );
        for id in a_ids {
            assert!(resolve_index_id_path(&a, &id).is_ok());
        }
    }
}

/// Regression: an empty base rotates .index pins in the current directory only.
#[test]
fn regression_prune_bare_base_in_working_directory() {
    if let Some(d) = relative_child(
        "publish_tests::regression_prune_bare_base_in_working_directory",
        "WALPUB_BARE",
        || {
            fs::create_dir("sources").unwrap();
            let ids = rotate(Path::new("x.tar"), Path::new("sources"), 2);
            fs::create_dir("inner").unwrap();
            let bare = rotate(Path::new(""), Path::new("inner"), 3);
            for id in ids {
                assert!(resolve_index_id_path(Path::new("x.tar"), &id).is_ok());
            }
            assert!(!index_id_path(Path::new(""), &bare[0]).unwrap().exists());
            assert_eq!(pins(Path::new("")).len(), 2);
        },
    ) {
        assert!(d.path().join(".index.ptr").exists());
    }
}

#[cfg(target_os = "linux")]
fn non_utf8_path(dir: &Path, tail: &[u8]) -> PathBuf {
    use std::os::unix::ffi::OsStringExt;
    dir.join(std::ffi::OsString::from_vec(tail.to_vec()))
}

/// Regression: a non-Unicode destination base is not rewritten through U+FFFD.
#[cfg(target_os = "linux")]
#[test]
fn regression_index_base_strip_non_utf8() {
    let input = non_utf8_path(Path::new(""), b"out-\xff/sub/a-\xfe.index.sqlite");
    let expected = non_utf8_path(Path::new(""), b"out-\xff/sub/a-\xfe");
    assert_eq!(
        archive_base_from_index_path(&input)
            .as_os_str()
            .as_encoded_bytes(),
        expected.as_os_str().as_encoded_bytes()
    );
    assert_eq!(
        index_pointer_path_for_index_file(&input).parent(),
        input.parent()
    );
}

/// Regression: pin, pointer and directory sync use exactly the supplied path bytes.
#[cfg(target_os = "linux")]
#[test]
fn regression_publish_non_utf8_directory_is_used_byte_for_byte() {
    for exists in [false, true] {
        let d = temp();
        let t = d.path().join("T");
        fs::create_dir(&t).unwrap();
        let out = non_utf8_path(&t, b"out-\xff/sub");
        if exists {
            fs::create_dir_all(&out).unwrap();
        }
        let source = d.path().join("source.sqlite");
        catalog(&source, 1);
        let base = out.join("a");
        let events = Events::default();
        let result = with_pin_hook(record(events.clone()), || {
            publish_index_pointer(&base, &source, None)
        });
        if exists {
            let p = result.unwrap();
            assert_eq!(
                hash(&index_id_path(&base, &p.index_id).unwrap()),
                p.index_id
            );
            assert_eq!(fs::read_dir(&t).unwrap().count(), 1);
            assert_eq!(
                events
                    .borrow()
                    .iter()
                    .filter(|s| s.starts_with("DirSync"))
                    .count(),
                2
            );
            let events = events.borrow();
            let expected = format!("{:?}", PinStep::DirSync(std::path::absolute(&out).unwrap()));
            assert_eq!(events.iter().filter(|s| **s == expected).count(), 2);
            let installed = events
                .iter()
                .position(|s| s.starts_with("Installed"))
                .unwrap();
            let stored = events.iter().position(|s| s == "PointerStored").unwrap();
            let syncs: Vec<_> = events
                .iter()
                .enumerate()
                .filter_map(|(i, s)| (s == &expected).then_some(i))
                .collect();
            assert!(installed < syncs[0] && stored < syncs[1]);
        } else {
            assert!(result.is_err());
            assert_eq!(fs::read_dir(&t).unwrap().count(), 0);
            assert!(events.borrow().is_empty());
        }
    }
}

/// Regression: publishers of different archives share no durability marker or state.
#[test]
fn regression_publish_two_archives_in_one_directory_share_no_state() {
    let d = temp();
    let a = d.path().join("a.tar");
    let b = d.path().join("b.tar");
    fs::write(&a, b"a").unwrap();
    fs::write(&b, b"b").unwrap();
    let sa = d.path().join("sa.sqlite");
    let sb = d.path().join("sb.sqlite");
    catalog(&sa, 1);
    catalog(&sb, 2);
    for source in [&sa, &sb] {
        Connection::open(source)
            .unwrap()
            .execute_batch("PRAGMA journal_mode=DELETE")
            .unwrap();
    }
    assert!(with_pin_hook(
        |s| if matches!(s, PinStep::DirSync(_)) {
            Err(io::Error::other("interrupted"))
        } else {
            Ok(())
        },
        || publish_index_pointer(&a, &sa, None)
    )
    .is_err());
    assert!(!index_pointer_path(&a).exists());
    let apin = pins(&a).pop().unwrap();
    let old = bytes(&apin);
    let b_events = Events::default();
    with_pin_hook(record(b_events.clone()), || publish(&b, &sb));
    assert_eq!(bytes(&apin), old);
    assert_eq!(
        b_events
            .borrow()
            .iter()
            .filter(|s| s.starts_with("DirSync"))
            .count(),
        2
    );
    let events = Events::default();
    let e = events.clone();
    let canonical = apin.canonicalize().unwrap();
    seams::with(
        move |s| {
            if s == Seam::BeforeSync && seams::opened_path() == Some(canonical.clone()) {
                e.borrow_mut().push("SyncExisting".into());
            }
            Ok(())
        },
        || with_pin_hook(record(events.clone()), || publish(&a, &sa)),
    );
    assert!(
        events
            .borrow()
            .iter()
            .position(|s| s == "SyncExisting")
            .unwrap()
            < events
                .borrow()
                .iter()
                .position(|s| s.starts_with("DirSync"))
                .unwrap()
    );
    let events = Events::default();
    let e = events.clone();
    let b2 = b.clone();
    let sb2 = sb.clone();
    with_pin_hook(
        move |s| {
            if matches!(s, PinStep::Installed(_)) {
                publish(&b2, &sb2);
                e.borrow_mut().push("B finished".into());
            }
            e.borrow_mut().push(format!("{s:?}"));
            Ok(())
        },
        || publish(&a, &sa),
    );
    let e = events.borrow();
    let done = e.iter().position(|s| s == "B finished").unwrap();
    assert_eq!(
        e.iter()
            .enumerate()
            .filter(|(_, s)| s.starts_with("DirSync"))
            .count(),
        2
    );
    assert!(e
        .iter()
        .enumerate()
        .filter(|(_, s)| s.starts_with("DirSync"))
        .all(|(i, _)| i > done));
    assert_eq!(fs::read_dir(d.path()).unwrap().count(), 8);
    no_tmp(d.path());
}
