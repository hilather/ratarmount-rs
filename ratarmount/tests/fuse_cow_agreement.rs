//! Regression: an overlay written through a real FUSE mount, where editing an
//! existing file leaves no `files` row, must give one canonical hash in diff,
//! fsck, seal, verify, pack and unpack, before and after sealing.
#![cfg(target_os = "linux")]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use ratarmount_compositing::HIDDEN_DB;

fn available() -> bool {
    if !Path::new("/dev/fuse").exists() {
        eprintln!("skip: /dev/fuse unavailable");
        return false;
    }
    if Command::new("fusermount3")
        .arg("--version")
        .output()
        .is_err()
    {
        eprintln!("skip: fusermount3 unavailable");
        return false;
    }
    true
}

fn run(args: &[&Path], cache: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .env("XDG_CACHE_HOME", cache)
        .args(args)
        .output()
        .unwrap()
}

fn expect(out: Output, code: i32) -> String {
    assert_eq!(
        out.status.code(),
        Some(code),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

fn base_tar(path: &Path) {
    let mut tar = tar::Builder::new(fs::File::create(path).unwrap());
    let mut add = |name: &str, mode: u32, body: &[u8]| {
        let mut header = tar::Header::new_gnu();
        header.set_size(body.len() as u64);
        header.set_mode(mode);
        header.set_mtime(1_700_000_000);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        tar.append_data(&mut header, name, body).unwrap();
    };
    add("src/a.c", 0o644, b"int a(void) { return 1; }\n");
    add("src/b.c", 0o644, b"int b(void) { return 2; }\n");
    add("docs/keep.txt", 0o644, b"keep\n");
    add("docs/gone.txt", 0o644, b"gone\n");
    add("bin/tool", 0o644, b"#!/bin/sh\necho tool\n");
    add("Makefile", 0o644, b"all:\n");
    tar.finish().unwrap();
}

struct Mount {
    child: Child,
    path: PathBuf,
}
impl Mount {
    fn start(base: &Path, overlay: &Path, path: &Path) -> Self {
        fs::create_dir(path).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
            .args([
                "-f",
                "--passthrough",
                "off",
                "--index-file",
                ":memory:",
                "-w",
            ])
            .arg(overlay)
            .arg(base)
            .arg(path)
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let mut mount = Self {
            child,
            path: path.into(),
        };
        let deadline = Instant::now() + Duration::from_secs(20);
        while !path.join("Makefile").exists() {
            assert!(mount.child.try_wait().unwrap().is_none(), "mount exited");
            assert!(Instant::now() < deadline, "mount timeout");
            std::thread::sleep(Duration::from_millis(50));
        }
        mount
    }
    fn unmount(mut self) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !Command::new("fusermount3")
            .arg("-u")
            .arg(&self.path)
            .status()
            .unwrap()
            .success()
        {
            assert!(Instant::now() < deadline, "unmount stayed busy");
            std::thread::sleep(Duration::from_millis(100));
        }
        let status = self.child.wait().unwrap();
        assert!(status.success(), "mount exited {status}");
        std::mem::forget(self);
    }
}
impl Drop for Mount {
    fn drop(&mut self) {
        let _ = Command::new("fusermount3")
            .arg("-uz")
            .arg(&self.path)
            .status();
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn files_rows(overlay: &Path) -> Vec<(String, String, bool)> {
    let conn = rusqlite::Connection::open_with_flags(
        overlay.join(HIDDEN_DB),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let mut stmt = conn
        .prepare("SELECT path, name, deleted FROM files ORDER BY path, name")
        .unwrap();
    stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? != 0)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap()
}

fn make_writable(path: &Path) {
    for entry in walk(path) {
        let meta = fs::symlink_metadata(&entry).unwrap();
        if !meta.file_type().is_symlink() {
            let mode = meta.permissions().mode() | 0o200;
            fs::set_permissions(&entry, fs::Permissions::from_mode(mode)).unwrap();
        }
    }
}

fn walk(path: &Path) -> Vec<PathBuf> {
    let mut out = vec![path.to_path_buf()];
    if fs::symlink_metadata(path).unwrap().is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            out.extend(walk(&entry.unwrap().path()));
        }
    }
    out
}

/// Regression: copy-on-write edits made through FUSE create no `files` row;
/// every subcommand must still see them and agree on one hash.
#[test]
fn regression_fuse_cow_edits_agree_across_diff_fsck_seal_verify_pack() {
    if !available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    // Seal makes the tree read-only; restore write access even on failure so
    // TempDir can remove it.
    struct Writable<'a>(&'a Path);
    impl Drop for Writable<'_> {
        fn drop(&mut self) {
            make_writable(self.0);
        }
    }
    let _writable = Writable(tmp.path());
    let root = tmp.path();
    let cache = root.join("cache");
    let base = root.join("base.tar");
    base_tar(&base);
    let overlay = root.join("overlay");
    let mnt = root.join("mnt");

    let mount = Mount::start(&base, &overlay, &mnt);
    // Truncating rewrite and append of existing members: COW, no row.
    fs::write(mnt.join("src/a.c"), b"int a(void) { return 10; }\n").unwrap();
    fs::OpenOptions::new()
        .append(true)
        .open(mnt.join("src/b.c"))
        .unwrap()
        .write_all(b"int c(void) { return 3; }\n")
        .unwrap();
    // New file, delete inside an untouched directory, mode-only change, new dir.
    fs::write(mnt.join("new.txt"), b"new\n").unwrap();
    fs::remove_file(mnt.join("docs/gone.txt")).unwrap();
    fs::set_permissions(mnt.join("bin/tool"), fs::Permissions::from_mode(0o755)).unwrap();
    fs::create_dir(mnt.join("gen")).unwrap();
    fs::write(mnt.join("gen/out.o"), b"\x7fELF\0\0binary").unwrap();
    // Symlink rows carry no mode in the canonical hash (format 2).
    std::os::unix::fs::symlink("../src/a.c", mnt.join("gen/a.c")).unwrap();
    mount.unmount();

    // The precondition this test exists for: COW edits have host bytes but no row.
    let rows = files_rows(&overlay);
    for (parent, name) in [("/src", "a.c"), ("/src", "b.c")] {
        assert!(
            !rows.iter().any(|(p, n, _)| p == parent && n == name),
            "{parent}/{name} unexpectedly has a files row: {rows:?}"
        );
        assert!(overlay.join(&parent[1..]).join(name).is_file());
    }

    let o = overlay.as_path();
    let p = Path::new;
    // Seals use exact normalization; also pin --normalize strict across seal.
    let exact = || expect(run(&[p("diff"), o, p("--hash")], &cache), 0);
    let strict = || {
        expect(
            run(
                &[p("diff"), o, p("--normalize"), p("strict"), p("--hash")],
                &cache,
            ),
            0,
        )
    };
    let hash = exact();
    let strict_hash = strict();
    assert!(hash.trim().starts_with("sha256:"), "{hash}");

    // diff sees every edit, including both row-less COW files.
    let manifest = expect(run(&[p("diff"), o, p("--manifest")], &cache), 0);
    for path in [
        "src/a.c",
        "src/b.c",
        "new.txt",
        "docs/gone.txt",
        "bin/tool",
        "gen/out.o",
        "gen/a.c",
    ] {
        assert!(
            manifest.contains(path),
            "manifest misses {path}:\n{manifest}"
        );
    }
    let link = manifest
        .lines()
        .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
        .find(|row| row["path"] == "gen/a.c")
        .unwrap();
    assert_eq!(link["type"], "symlink", "{link}");
    assert_eq!(link["target"], "../src/a.c", "{link}");
    assert!(link.get("mode").is_none(), "{link}");
    let patch = expect(run(&[p("diff"), o], &cache), 1);
    assert!(patch.contains("+int a(void) { return 10; }"), "{patch}");
    assert!(patch.contains("+int c(void) { return 3; }"), "{patch}");

    // fsck is clean, counts the row-less files as informational, and neither
    // a check nor a repair changes the hash.
    let report: serde_json::Value = serde_json::from_str(&expect(
        run(&[p("overlay"), p("fsck"), o, p("--json")], &cache),
        0,
    ))
    .unwrap();
    assert!(report["unrowed"].as_u64().unwrap() >= 2, "{report}");
    expect(run(&[p("overlay"), p("fsck"), o, p("--repair")], &cache), 0);
    assert_eq!(exact(), hash);
    assert_eq!(strict(), strict_hash);

    // Seal publishes the same digest and does not change what diff reports.
    let sealed = expect(run(&[p("overlay"), p("seal"), o], &cache), 0);
    assert_eq!(sealed.trim(), hash.trim());
    assert_eq!(exact(), hash, "diff --hash changed across seal");
    assert_eq!(
        strict(),
        strict_hash,
        "--normalize strict hash changed across seal"
    );
    assert_eq!(
        expect(run(&[p("diff"), o, p("--strict"), p("--hash")], &cache), 0),
        hash
    );
    assert_eq!(
        expect(run(&[p("diff"), o, p("--manifest")], &cache), 0),
        manifest,
        "manifest changed across seal"
    );
    assert_eq!(
        expect(run(&[p("overlay"), p("verify"), o], &cache), 0).trim(),
        hash.trim()
    );

    // pack -> unpack -> verify and diff keep the digest.
    let bundle = root.join("attempt.tar.zst");
    expect(run(&[p("overlay"), p("pack"), o, &bundle], &cache), 0);
    let restored = root.join("restored");
    assert_eq!(
        expect(
            run(&[p("overlay"), p("unpack"), &bundle, &restored], &cache),
            0
        )
        .trim(),
        hash.trim()
    );
    assert_eq!(
        expect(run(&[p("overlay"), p("verify"), &restored], &cache), 0).trim(),
        hash.trim()
    );
    assert_eq!(
        expect(
            run(&[p("diff"), &restored, p("--strict"), p("--hash")], &cache),
            0
        ),
        hash
    );
}
