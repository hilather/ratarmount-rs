//! Local index publication pins a complete snapshot, never the live WAL index.
//!
//! Regression (WAL sidecar publish defect): `--publish-index` hashed and
//! hard-linked the live index's main file while its newest rows (the zstd seek
//! table, `--hashes` rows) were still in its `-wal`. The pin lacked those rows,
//! its bytes drifted from its id on the next checkpoint, published copies were
//! incomplete, and a writer through the pin's name lost rows through the
//! shared inode. These run the real CLI with `--no-mount`.
#![cfg(target_os = "linux")]

use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const FILES: usize = 400;

fn tar_bytes() -> Vec<u8> {
    let names: Vec<String> = (0..FILES).map(|i| format!("d/f{i}")).collect();
    let bodies: Vec<Vec<u8>> = (0..FILES)
        .map(|i| format!("file {i} {}\n", i * 7919 % 1009).into_bytes())
        .collect();
    let members: Vec<UstarMember<'_>> = names
        .iter()
        .zip(&bodies)
        .map(|(path, bytes)| UstarMember {
            path,
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            xattrs: &[],
            payload: UstarPayload::File { bytes },
        })
        .collect();
    let mut out = Vec::new();
    write_ustar_members(&mut out, &members).unwrap();
    write_tar_eof(&mut out).unwrap();
    out
}

fn tar_zst(path: &Path) {
    fs::write(path, zstd::encode_all(&tar_bytes()[..], 19).unwrap()).unwrap();
}

fn run(home: &Path, args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(args)
        .env_remove("RUST_LOG")
        .env("HOME", home)
        .env("XDG_CACHE_HOME", home.join("xdg"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(120);
    while child.try_wait().unwrap().is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            let out = child.wait_with_output().unwrap();
            panic!(
                "CLI timeout {args:?}: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
    child.wait_with_output().unwrap()
}

fn ok(home: &Path, args: &[&str]) {
    let out = run(home, args);
    assert!(
        out.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn sha(path: &Path) -> String {
    ratarmount_index::sha256_hex(&fs::read(path).unwrap())
}

fn pointer_id(base: &Path) -> String {
    ratarmount_index::load_index_pointer(&ratarmount_index::index_pointer_path(base))
        .unwrap()
        .expect("index pointer")
        .index_id
}

fn pin(base: &Path) -> (PathBuf, String) {
    let id = pointer_id(base);
    (ratarmount_index::index_id_path(base, &id).unwrap(), id)
}

/// Open `path` read-only. `immutable` reads its main file alone: what a copy
/// without companions, or a hash of the file, sees.
fn db(path: &Path, immutable: bool) -> rusqlite::Connection {
    let mode = if immutable { "immutable=1" } else { "mode=ro" };
    rusqlite::Connection::open_with_flags(
        format!("file:{}?{mode}", path.display()),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_URI,
    )
    .unwrap()
}

fn count(c: &rusqlite::Connection, table: &str) -> i64 {
    c.query_row(&format!("SELECT count(*) FROM \"{table}\""), [], |r| {
        r.get(0)
    })
    .unwrap()
}

fn hash_keys(c: &rusqlite::Connection) -> Vec<String> {
    let mut q = c
        .prepare("SELECT name FROM xattrkeys ORDER BY name")
        .unwrap();
    q.query_map([], |r| r.get(0))
        .unwrap()
        .map(|r| r.unwrap())
        .filter(|k: &String| k.starts_with("user.hash."))
        .collect()
}

fn integrity(c: &rusqlite::Connection) -> String {
    c.query_row("PRAGMA integrity_check", [], |r| r.get(0))
        .unwrap()
}

/// Assert `published` is a complete, self-contained index publication named
/// by `id`: its main file alone holds the seek table and hash rows.
fn assert_complete(published: &Path, id: &str, hash: Option<&str>, zstd: bool) {
    assert_eq!(sha(published), id, "{} hash is its id", published.display());
    let c = db(published, true);
    assert_eq!(integrity(&c), "ok");
    assert!(count(&c, "files") >= FILES as i64);
    if zstd {
        assert!(
            count(&c, "zstdblocks") > 0,
            "zstdblocks rows in {}",
            published.display()
        );
    }
    if let Some(alg) = hash {
        assert_eq!(hash_keys(&c), [format!("user.hash.{alg}")]);
        assert_eq!(count(&c, "xattrsdata"), FILES as i64);
    }
}

fn assert_own_inode(pin: &Path, live: &Path) {
    let p = fs::metadata(pin).unwrap();
    let l = fs::metadata(live).unwrap();
    assert_ne!(
        (p.dev(), p.ino()),
        (l.dev(), l.ino()),
        "pin hard-linked to live index"
    );
    assert_eq!(p.nlink(), 1);
    assert!(p.permissions().readonly(), "pin is read-only");
}

/// Regression: P1: `--publish-index` (dest == sidecar) on `.tar.zst`: the pin's hash is
/// its content, it holds the zstdblocks rows, `--index-id` binds it, and a
/// later reopen does not change it.
#[test]
fn regression_publish_index_pin_is_complete_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let archive = dir.path().join("A.tar.zst");
    tar_zst(&archive);
    let a = archive.to_str().unwrap();
    ok(home, &["--no-mount", "--publish-index", a]);
    let (pin, id) = pin(&archive);
    assert_complete(&pin, &id, None, true);
    assert_own_inode(&pin, &ratarmount_index::default_index_path(&archive));
    ok(home, &["--no-mount", "--index-id", &id, a]);
    ok(home, &["--no-mount", a]);
    assert_eq!(sha(&pin), id, "pin bytes drifted");
    for companion in ["-wal", "-shm", "-journal"] {
        let p = PathBuf::from(format!("{}{companion}", pin.display()));
        assert!(!p.exists(), "{}", p.display());
    }
}

/// Regression: P2: `--publish-index-to` on `.tar.zst`: the published copy keeps the
/// zstdblocks rows and is the pinned snapshot.
#[test]
fn regression_publish_index_to_copy_keeps_zstd_blocks() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let archive = dir.path().join("A.tar.zst");
    tar_zst(&archive);
    let out = dir.path().join("pub");
    fs::create_dir(&out).unwrap();
    let dest = out.join("A.tar.zst.index.sqlite");
    ok(
        home,
        &[
            "--no-mount",
            "--publish-index-to",
            dest.to_str().unwrap(),
            archive.to_str().unwrap(),
        ],
    );
    let base = out.join("A.tar.zst");
    let (pin, id) = pin(&base);
    assert_ne!(
        fs::metadata(&dest).unwrap().ino(),
        fs::metadata(&pin).unwrap().ino()
    );
    assert_complete(&dest, &id, None, true);
    assert_complete(&pin, &id, None, true);
    assert_own_inode(&pin, &ratarmount_index::default_index_path(&archive));
    let before = fs::read(&dest).unwrap();
    let rejected = run(
        home,
        &[
            "--no-mount",
            "--publish-index-to",
            dest.to_str().unwrap(),
            archive.to_str().unwrap(),
        ],
    );
    assert_eq!(rejected.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("already exists"));
    assert_eq!(fs::read(&dest).unwrap(), before);
    fs::remove_file(&dest).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&out, &link).unwrap();
    let via_link = link.join("A.tar.zst.index.sqlite");
    ok(
        home,
        &[
            "--no-mount",
            "--publish-index-to",
            via_link.to_str().unwrap(),
            archive.to_str().unwrap(),
        ],
    );
    assert_eq!(pointer_id(&base), id);
    assert_complete(&dest, &id, None, true);
    for companion in ["-wal", "-shm", "-journal"] {
        assert!(!PathBuf::from(format!("{}{companion}", dest.display())).exists());
    }
}

/// Regression: P3: `--hashes sha256 --publish-index-to` on `.tar`: the published copy
/// keeps every `--hashes` row.
#[test]
fn regression_publish_index_to_copy_keeps_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let archive = dir.path().join("A.tar");
    fs::write(&archive, tar_bytes()).unwrap();
    let out = dir.path().join("pub");
    fs::create_dir(&out).unwrap();
    let dest = out.join("A.tar.index.sqlite");
    ok(
        home,
        &[
            "--no-mount",
            "--hashes",
            "sha256",
            "--publish-index-to",
            dest.to_str().unwrap(),
            archive.to_str().unwrap(),
        ],
    );
    let (pin, id) = pin(&out.join("A.tar"));
    assert_complete(&pin, &id, Some("sha256"), false);
    assert_complete(&dest, &id, Some("sha256"), false);
}

/// Regression: sev6: after `--hashes sha256 --publish-index`, a writer through the pin's
/// name (`--hashes md5 --index-file PIN`) used to write into the inode shared
/// with the live index, whose next checkpoint then lost those rows. The pin
/// is never written: its bytes stay its id, the live index keeps its rows,
/// and both stay consistent.
#[test]
fn regression_publish_index_pin_never_written_by_later_writer() {
    let dir = tempfile::tempdir().unwrap();
    let home = dir.path();
    let archive = dir.path().join("A.tar.zst");
    tar_zst(&archive);
    let a = archive.to_str().unwrap();
    let live = ratarmount_index::default_index_path(&archive);
    ok(
        home,
        &["--no-mount", "--hashes", "sha256", "--publish-index", a],
    );
    let (pin, id) = pin(&archive);
    let before = fs::read(&pin).unwrap();
    let identity = fs::metadata(&pin).unwrap();

    let b = run(
        home,
        &[
            "--no-mount",
            "--hashes",
            "md5",
            "--index-file",
            pin.to_str().unwrap(),
            a,
        ],
    );
    assert_eq!(
        fs::read(&pin).unwrap(),
        before,
        "writer through the pin changed it"
    );
    let wal = PathBuf::from(format!("{}-wal", pin.display()));
    assert!(
        fs::metadata(&wal).map_or(true, |m| m.len() == 0),
        "frames written for the pin"
    );
    assert_complete(&pin, &id, Some("sha256"), true);
    assert!(b.status.success(), "{}", String::from_utf8_lossy(&b.stderr));
    assert!(String::from_utf8_lossy(&b.stderr).contains("pins are never modified"));
    let after = fs::metadata(&pin).unwrap();
    assert_eq!(
        (identity.ino(), identity.nlink()),
        (after.ino(), after.nlink())
    );
    for suffix in ["-wal", "-shm", "-journal"] {
        assert!(!PathBuf::from(format!("{}{suffix}", pin.display())).exists());
    }

    ok(home, &["--no-mount", a]);
    assert_eq!(fs::read(&pin).unwrap(), before);
    assert_eq!(pointer_id(&archive), id);
    let c = db(&live, false);
    assert_eq!(integrity(&c), "ok");
    assert!(hash_keys(&c).contains(&"user.hash.sha256".to_string()));
    assert_eq!(count(&c, "xattrsdata"), FILES as i64);
    assert_eq!(
        count(&c, "zstdblocks"),
        count(&db(&pin, true), "zstdblocks")
    );
}

fn run_at(home: &Path, cwd: &Path, args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(args)
        .current_dir(cwd)
        .env_remove("RUST_LOG")
        .env("HOME", home)
        .env("XDG_CACHE_HOME", home.join("xdg"))
        .stdin(Stdio::null())
        .output()
        .unwrap()
}
fn args(values: &[&str]) -> Vec<std::ffi::OsString> {
    values.iter().map(std::ffi::OsString::from).collect()
}
fn at(home: &Path, cwd: &Path, values: &[std::ffi::OsString]) -> Output {
    run_at(
        home,
        cwd,
        &values.iter().map(|s| s.as_os_str()).collect::<Vec<_>>(),
    )
}
fn assert_ok(out: &Output) {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}
fn no_temporary(dir: &Path) {
    for e in fs::read_dir(dir).unwrap().flatten() {
        assert!(
            !e.file_name()
                .as_encoded_bytes()
                .starts_with(b".ratarmount-index-"),
            "{:?}",
            e.path()
        );
        if e.file_type().unwrap().is_dir() {
            no_temporary(&e.path());
        }
    }
}

/// Regression: bare relative archives and existing relative publication directories work.
#[test]
fn publish_index_relative_paths_compat() {
    let d = tempfile::tempdir().unwrap();
    let archive = d.path().join("a.tar");
    fs::write(&archive, tar_bytes()).unwrap();
    assert_ok(&at(
        d.path(),
        d.path(),
        &args(&["--no-mount", "--publish-index", "a.tar"]),
    ));
    let (p, id) = pin(&archive);
    assert_eq!(sha(&p), id);
    fs::create_dir_all(d.path().join("out/sub")).unwrap();
    assert_ok(&at(
        d.path(),
        d.path(),
        &args(&[
            "--no-mount",
            "--publish-index-to",
            "out/sub/a.tar.index.sqlite",
            "a.tar",
        ]),
    ));
    let base = d.path().join("out/sub/a.tar");
    let (p, id) = pin(&base);
    assert_eq!(sha(&p), id);
    assert_eq!(sha(&d.path().join("out/sub/a.tar.index.sqlite")), id);
    no_temporary(d.path());
}

/// Regression: directory and bare bases rotate only their own pins.
#[test]
fn regression_publish_index_to_bare_and_directory_bases_rotate_their_own_pins() {
    let d = tempfile::tempdir().unwrap();
    fs::write(d.path().join("a.tar"), tar_bytes()).unwrap();
    fs::create_dir(d.path().join("out")).unwrap();
    let mut independent: Vec<String> = Vec::new();
    for (dest, source, rounds) in [
        ("out.index.sqlite", "independent.sqlite", 2),
        ("out/.index.sqlite", "directory.sqlite", 3),
        (".index.sqlite", "bare.sqlite", 3),
    ] {
        let mut ids = Vec::new();
        for alg in ["md5", "sha1", "sha256"].into_iter().take(rounds) {
            let path = d.path().join(dest);
            if path.exists() {
                fs::remove_file(&path).unwrap();
            }
            assert_ok(&at(
                d.path(),
                d.path(),
                &args(&[
                    "--no-mount",
                    "--index-file",
                    source,
                    "--hashes",
                    alg,
                    "--publish-index-to",
                    dest,
                    "a.tar",
                ]),
            ));
            let base = ratarmount_index::archive_base_from_index_path(&path);
            let (p, id) = pin(&base);
            assert_eq!(sha(&p), id);
            assert!(!ids.contains(&id));
            ids.push(id);
            for id in &independent {
                assert!(ratarmount_index::resolve_index_id_path(&d.path().join("out"), id).is_ok());
            }
        }
        if rounds == 2 {
            independent = ids;
        } else {
            let base = ratarmount_index::archive_base_from_index_path(&d.path().join(dest));
            assert!(!ratarmount_index::index_id_path(&base, &ids[0])
                .unwrap()
                .exists());
            let dir = if dest.starts_with("out/") {
                d.path().join("out")
            } else {
                d.path().to_path_buf()
            };
            assert_eq!(
                fs::read_dir(dir)
                    .unwrap()
                    .flatten()
                    .filter(|e| e.file_name().as_encoded_bytes().starts_with(b".index.")
                        && e.file_name().as_encoded_bytes().len() == 78
                        && e.file_name().as_encoded_bytes().ends_with(b".sqlite"))
                    .count(),
                2
            );
            assert_eq!(pointer_id(&base), ids[2]);
        }
    }
    no_temporary(d.path());
}

/// Regression: non-Unicode archive and destination names put artifacts beside the exact name.
#[test]
fn regression_publish_index_non_utf8_paths_place_pin_and_pointer_beside_dest() {
    use std::os::unix::ffi::OsStringExt;
    let d = tempfile::tempdir().unwrap();
    let archive = d.path().join("a.tar");
    fs::write(&archive, tar_bytes()).unwrap();
    let out = d
        .path()
        .join(std::ffi::OsString::from_vec(b"out-\xff/sub".to_vec()));
    fs::create_dir_all(&out).unwrap();
    let dest = out.join("a.tar.index.sqlite");
    let mut a = args(&["--no-mount", "--publish-index-to"]);
    a.push(dest.as_os_str().to_owned());
    a.push(archive.as_os_str().to_owned());
    assert_ok(&at(d.path(), d.path(), &a));
    let (p, id) = pin(&out.join("a.tar"));
    assert_eq!(sha(&p), id);
    assert_eq!(sha(&dest), id);
    assert!(!d.path().join("out-�").exists());
    let archive = d
        .path()
        .join(std::ffi::OsString::from_vec(b"b-\xff.tar".to_vec()));
    fs::write(&archive, tar_bytes()).unwrap();
    let mut a = args(&["--no-mount", "--publish-index"]);
    a.push(archive.as_os_str().to_owned());
    assert_ok(&at(d.path(), d.path(), &a));
    let (p, id) = pin(&archive);
    assert_eq!(sha(&p), id);
    assert!(!d.path().join("b-�.tar.index.ptr").exists());
}

/// Regression: missing directories refuse at CLI validation before building an index.
#[test]
fn regression_publish_index_to_missing_directory_is_refused_and_creates_nothing() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    for spelling in [
        "missing/sub/a.tar.index.sqlite",
        "new/../link/sub/a.tar.index.sqlite",
        "a/b/../../out/x.index.sqlite",
    ] {
        let d = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let archive = d.path().join("a.tar");
        fs::write(&archive, tar_bytes()).unwrap();
        let t = d.path().join("T");
        fs::create_dir(&t).unwrap();
        let u = d.path().join("U");
        fs::create_dir(&u).unwrap();
        fs::create_dir(u.join("sub")).unwrap();
        if spelling.starts_with("new/") {
            symlink(&u, t.join("link")).unwrap();
        }
        let dest = t.join(spelling);
        let mut a = args(&["--no-mount", "--publish-index-to"]);
        a.push(dest.as_os_str().to_owned());
        a.push(archive.as_os_str().to_owned());
        let out = at(home.path(), d.path(), &a);
        assert_eq!(
            out.status.code(),
            Some(2),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            err.contains("create it first") && err.contains("directory"),
            "{err}"
        );
        assert!(!ratarmount_index::default_index_path(&archive).exists());
        assert_eq!(
            fs::read_dir(&t).unwrap().count(),
            usize::from(spelling.starts_with("new/"))
        );
        assert_eq!(fs::read_dir(u.join("sub")).unwrap().count(), 0);
        if spelling.starts_with("missing/") {
            fs::create_dir_all(dest.parent().unwrap()).unwrap();
            assert_ok(&at(home.path(), d.path(), &a));
            let base = ratarmount_index::archive_base_from_index_path(&dest);
            let (p, id) = pin(&base);
            assert_eq!(sha(&p), id);
            assert_eq!(sha(&dest), id);
        }
    }
    let d = tempfile::tempdir().unwrap();
    let home = tempfile::tempdir().unwrap();
    let archive = d.path().join("a.tar");
    fs::write(&archive, tar_bytes()).unwrap();
    let out = d.path().join("drop");
    fs::create_dir(&out).unwrap();
    fs::set_permissions(&out, fs::Permissions::from_mode(0o300)).unwrap();
    if fs::File::open(&out).is_ok() {
        fs::set_permissions(&out, fs::Permissions::from_mode(0o700)).unwrap();
        eprintln!("skip: mode-0300 directory refusal requires a non-root user");
        return;
    }
    let dest = out.join("a.tar.index.sqlite");
    let mut a = args(&["--no-mount", "--publish-index-to"]);
    a.push(dest.as_os_str().to_owned());
    a.push(archive.as_os_str().to_owned());
    for _ in 0..2 {
        let result = at(home.path(), d.path(), &a);
        assert_eq!(result.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&result.stderr).contains(&out.display().to_string()));
    }
    fs::set_permissions(&out, fs::Permissions::from_mode(0o700)).unwrap();
    assert_ok(&at(home.path(), d.path(), &a));
    assert_eq!(fs::read_dir(&out).unwrap().count(), 3);
    eprintln!("mode-0300 CLI refusal and retry passed");
}
