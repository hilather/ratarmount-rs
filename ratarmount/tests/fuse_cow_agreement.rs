//! Regression: an overlay written through a real FUSE mount, where editing an
//! existing file leaves no `files` row, must give one canonical hash in diff,
//! fsck, seal, verify, pack and unpack, before and after sealing.
#![cfg(target_os = "linux")]

use std::fs;
use std::io::Write;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
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
        .env("HOME", cache)
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
        Self::start_with(base, Some(overlay), &[], &[], path, "Makefile")
    }

    /// Foreground mount; ready once `ready` is visible. `flags` go before the
    /// overlay/base/mountpoint, `env` is added to a private HOME/cache.
    fn start_with(
        base: &Path,
        overlay: Option<&Path>,
        flags: &[&std::ffi::OsStr],
        env: &[(&str, &Path)],
        path: &Path,
        ready: &str,
    ) -> Self {
        fs::create_dir(path).unwrap();
        let private = path.parent().unwrap().join("mount-home");
        fs::create_dir_all(&private).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
        cmd.env("HOME", &private)
            .env("XDG_CACHE_HOME", private.join("cache"));
        for (key, value) in env {
            cmd.env(key, value);
        }
        cmd.args(["-f", "--passthrough", "off", "--index-file", ":memory:"])
            .args(flags);
        if let Some(overlay) = overlay {
            cmd.arg("-w").arg(overlay);
        }
        let child = cmd
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
        while !path.join(ready).exists() {
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
            .is_ok_and(|status| status.success())
        {
            if Instant::now() >= deadline {
                // Detach and kill before the assertion unwinds into Drop.
                let _ = Command::new("fusermount3")
                    .arg("-uz")
                    .arg(&self.path)
                    .status();
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!("unmount stayed busy");
            }
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

/// Restore write access under `path` so `TempDir` can remove it. Runs from
/// destructors, so it never panics: errors are skipped, and a nested mount
/// point (different `st_dev` than the root) is not descended into.
fn make_writable(path: &Path) {
    let Ok(root) = fs::symlink_metadata(path) else {
        return;
    };
    make_writable_under(path, root.dev());
}

fn make_writable_under(path: &Path, dev: u64) {
    let Ok(meta) = fs::symlink_metadata(path) else {
        return;
    };
    if meta.file_type().is_symlink() || meta.dev() != dev {
        return;
    }
    let extra = if meta.is_dir() { 0o700 } else { 0o200 };
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(meta.mode() | extra));
    if meta.is_dir() {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                make_writable_under(&entry.path(), dev);
            }
        }
    }
}

/// Regression: a failed unmount left the mountpoint mounted, and the
/// `Writable` destructor `unwrap`ped while unwinding, aborting the test binary.
#[test]
fn regression_make_writable_never_panics_in_a_destructor() {
    let tmp = tempfile::tempdir().unwrap();
    make_writable(&tmp.path().join("missing"));

    let dir = tmp.path().join("locked");
    fs::create_dir(&dir).unwrap();
    let file = dir.join("f");
    fs::write(&file, b"x").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o000)).unwrap();
    make_writable(&dir);
    assert_ne!(fs::metadata(&file).unwrap().permissions().mode() & 0o200, 0);
    assert_ne!(fs::metadata(&dir).unwrap().permissions().mode() & 0o700, 0);
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

// ---------------------------------------------------------------------------
// Real-mount agreement cases, one per overlay feature of this round. Each ends
// in `agree`: one canonical hash across diff, fsck, seal, verify, pack, unpack.
// ---------------------------------------------------------------------------

/// Restores write access under the temp root when dropped (sealed trees are
/// read-only), even while a failed assertion unwinds.
struct Writable<'a>(&'a Path);
impl Drop for Writable<'_> {
    fn drop(&mut self) {
        make_writable(self.0);
    }
}

/// A directory base with the members `base_tar` has, plus a `Makefile`.
fn base_dir(root: &Path) -> PathBuf {
    let base = root.join("base");
    for (name, body) in [
        ("src/a.c", "int a(void) { return 1; }\n"),
        ("src/b.c", "int b(void) { return 2; }\n"),
        ("docs/keep.txt", "keep\n"),
        ("docs/gone.txt", "gone\n"),
        ("Makefile", "all:\n"),
    ] {
        fs::create_dir_all(base.join(name).parent().unwrap()).unwrap();
        fs::write(base.join(name), body).unwrap();
    }
    base
}

/// The edits every case makes through the mount: a row-less COW rewrite, a
/// new file and a delete inside an untouched directory.
fn edit(mnt: &Path) {
    fs::write(mnt.join("src/a.c"), b"int a(void) { return 10; }\n").unwrap();
    fs::write(mnt.join("new.txt"), b"new\n").unwrap();
    fs::remove_file(mnt.join("docs/gone.txt")).unwrap();
}

/// diff, fsck (check and repair), seal, verify, pack, unpack + verify agree on
/// one digest, which is returned. `verify_args` is added to every `verify`.
fn agree(root: &Path, overlay: &Path, cache: &Path, verify_args: &[&str]) -> String {
    agree_with(root, overlay, cache, verify_args, &[])
}

/// `agree` with `base_args` (e.g. `--force-base-mismatch`) added to every
/// `diff`, `seal` and `pack` of the live overlay; the unpacked bundle is not given them.
fn agree_with(
    root: &Path,
    overlay: &Path,
    cache: &Path,
    verify_args: &[&str],
    base_args: &[&str],
) -> String {
    let (o, p) = (overlay, Path::new);
    let with = |head: &[&'static str], tail: &[&Path]| -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = head.iter().map(PathBuf::from).collect();
        v.push(o.to_path_buf());
        v.extend(tail.iter().map(|t| t.to_path_buf()));
        v.extend(base_args.iter().map(PathBuf::from));
        v
    };
    let run_with = |head: &[&'static str], tail: &[&Path]| {
        let v = with(head, tail);
        let refs: Vec<&Path> = v.iter().map(PathBuf::as_path).collect();
        expect(run(&refs, cache), 0)
    };
    let hash = run_with(&["diff"], &[p("--hash")]);
    assert!(hash.trim().starts_with("sha256:"), "{hash}");
    expect(run(&[p("overlay"), p("fsck"), o], cache), 0);
    expect(run(&[p("overlay"), p("fsck"), o, p("--repair")], cache), 0);
    assert_eq!(
        run_with(&["diff"], &[p("--hash")]),
        hash,
        "diff --hash changed across fsck --repair"
    );
    assert_eq!(run_with(&["overlay", "seal"], &[]).trim(), hash.trim());
    assert_eq!(
        run_with(&["diff"], &[p("--hash")]),
        hash,
        "diff --hash changed across seal"
    );
    let verify = |dir: &Path| {
        let mut args = vec![p("overlay"), p("verify"), dir];
        args.extend(verify_args.iter().map(|a| p(a)));
        expect(run(&args, cache), 0)
    };
    assert_eq!(verify(o).trim(), hash.trim());
    let bundle = root.join("agree.tar.zst");
    let restored = root.join("agree-restored");
    run_with(&["overlay", "pack"], &[&bundle]);
    assert_eq!(
        expect(
            run(&[p("overlay"), p("unpack"), &bundle, &restored], cache),
            0
        )
        .trim(),
        hash.trim()
    );
    assert_eq!(verify(&restored).trim(), hash.trim());
    assert_eq!(
        expect(run(&[p("diff"), &restored, p("--hash")], cache), 0),
        hash
    );
    hash.trim().to_string()
}

fn meta_get(overlay: &Path, key: &str) -> Option<String> {
    ratarmount_compositing::OverlayMeta::read(overlay)
        .unwrap()
        .unwrap()
        .get(key)
        .map(str::to_string)
}

/// `--no-mount -w OVERLAY [flags] BASE`: reopen without serving.
fn reopen(overlay: &Path, base: &Path, flags: &[&str], cache: &Path) -> Output {
    let mut args: Vec<&Path> = vec![
        Path::new("--no-mount"),
        Path::new("--index-file"),
        Path::new(":memory:"),
        Path::new("-w"),
        overlay,
    ];
    args.extend(flags.iter().map(Path::new));
    args.push(base);
    run(&args, cache)
}

/// Weak directory digest: remount works, a base size change is refused naming
/// `--force-base-mismatch`, the flag lets it through, and the hash agrees.
#[test]
fn weak_base_digest_reopen_refusal_and_force() {
    if !available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _writable = Writable(tmp.path());
    let root = tmp.path();
    let cache = root.join("cache");
    let base = base_dir(root);
    let overlay = root.join("overlay");

    Mount::start(&base, &overlay, &root.join("mnt1")).unmount();
    assert!(meta_get(&overlay, "base_digest")
        .unwrap()
        .starts_with("weak:"));
    let mount = Mount::start(&base, &overlay, &root.join("mnt2"));
    edit(&root.join("mnt2"));
    mount.unmount();

    fs::write(base.join("docs/keep.txt"), b"keep, but longer\n").unwrap();
    let refused = reopen(&overlay, &base, &[], &cache);
    assert_ne!(refused.status.code(), Some(0));
    assert!(
        String::from_utf8_lossy(&refused.stderr).contains("--force-base-mismatch"),
        "{}",
        String::from_utf8_lossy(&refused.stderr)
    );
    let mount = Mount::start_with(
        &base,
        Some(&overlay),
        &[std::ffi::OsStr::new("--force-base-mismatch")],
        &[],
        &root.join("mnt3"),
        "Makefile",
    );
    mount.unmount();
    // Regression: diff against the edited base is refused without the override
    // and reports a forced run (recorded and actual base) with it.
    let diff_json = |extra: &[&str]| {
        let mut args = vec![
            Path::new("diff"),
            &overlay,
            Path::new("--hash"),
            Path::new("--json"),
        ];
        args.extend(extra.iter().map(Path::new));
        run(&args, &cache)
    };
    assert_ne!(diff_json(&[]).status.code(), Some(0));
    let report = expect(diff_json(&["--force-base-mismatch"]), 0);
    assert!(report.contains("\"base_forced\":true"), "{report}");
    assert!(report.contains("\"base_identity\":\"forced\""), "{report}");
    // The weak digest cannot vouch for the edited base, so verify skips it;
    // the layer hash is what must agree.
    agree_with(
        root,
        &overlay,
        &cache,
        &["--no-base-check"],
        &["--force-base-mismatch"],
    );
}

/// A supplied strong digest (from `overlay digest-base`) is recorded without
/// the mount hashing, `overlay verify` checks the base against it, and a base
/// edit that keeps size and mtime fails that check.
#[test]
fn supplied_strong_base_digest_and_verify_base_check() {
    if !available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _writable = Writable(tmp.path());
    let root = tmp.path();
    let cache = root.join("cache");
    let base = base_dir(root);
    let overlay = root.join("overlay");
    let digest = expect(
        run(
            &[Path::new("overlay"), Path::new("digest-base"), &base],
            &cache,
        ),
        0,
    );
    let digest = digest.trim();
    assert!(digest.starts_with("sha256:"), "{digest}");

    let mount = Mount::start_with(
        &base,
        Some(&overlay),
        &[std::ffi::OsStr::new("--base-digest"), digest.as_ref()],
        &[],
        &root.join("mnt"),
        "Makefile",
    );
    edit(&root.join("mnt"));
    mount.unmount();
    assert_eq!(meta_get(&overlay, "base_digest").as_deref(), Some(digest));
    assert_eq!(
        meta_get(&overlay, "base_digest_kind").as_deref(),
        Some("strong")
    );
    agree(root, &overlay, &cache, &[]);

    // Same-size edit of an untouched base file, mtime restored.
    let file = base.join("docs/keep.txt");
    let mtime = fs::metadata(&file).unwrap().modified().unwrap();
    fs::write(&file, b"KEEP\n").unwrap();
    fs::File::options()
        .write(true)
        .open(&file)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    let bad = run(
        &[
            Path::new("overlay"),
            Path::new("verify"),
            &overlay,
            Path::new("--json"),
        ],
        &cache,
    );
    assert_eq!(bad.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&bad.stdout).unwrap();
    assert_eq!(json["base_ok"], false, "{json}");
}

/// G5b: a journal added on a later mount joins the recorded exclusions
/// without re-recording the digest; the hash agrees, and a journal-free
/// remount still passes.
#[test]
fn journal_added_on_later_mount() {
    if !available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _writable = Writable(tmp.path());
    let root = tmp.path();
    let cache = root.join("cache");
    let base = base_dir(root);
    // Overlay and journal live inside the base directory.
    let overlay = base.join(".ov");
    let journal = base.join("j.jsonl");

    let mount = Mount::start(&base, &overlay, &root.join("mnt1"));
    fs::write(root.join("mnt1/first.txt"), b"first\n").unwrap();
    mount.unmount();
    let recorded = meta_get(&overlay, "base_digest").unwrap();
    assert!(recorded.starts_with("weak:"), "{recorded}");

    let mount = Mount::start_with(
        &base,
        Some(&overlay),
        &[std::ffi::OsStr::new("--journal"), journal.as_os_str()],
        &[],
        &root.join("mnt2"),
        "Makefile",
    );
    edit(&root.join("mnt2"));
    mount.unmount();
    assert!(fs::metadata(&journal).unwrap().len() > 0, "journal empty");
    let excludes = meta_get(&overlay, "base_weak_excludes").unwrap();
    assert!(
        excludes.contains("j.jsonl") && excludes.contains(".ov"),
        "{excludes}"
    );
    assert_eq!(meta_get(&overlay, "base_digest").unwrap(), recorded);

    // A journal-free remount passes with the grown journal in the base.
    Mount::start(&base, &overlay, &root.join("mnt3")).unmount();
    agree(root, &overlay, &cache, &[]);
}

/// Item A: pack the sealed overlay, serve the bundle as a `--lower` on a real
/// mount, unpack + verify agree, and a tampered bundle is refused.
#[test]
fn bundle_verify_unpack_after_pack() {
    if !available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _writable = Writable(tmp.path());
    let root = tmp.path();
    let cache = root.join("cache");
    let base = root.join("base.tar");
    base_tar(&base);
    let overlay = root.join("overlay");
    let mount = Mount::start(&base, &overlay, &root.join("mnt"));
    edit(&root.join("mnt"));
    mount.unmount();
    let hash = agree(root, &overlay, &cache, &[]);

    let bundle = root.join("lower.tar.zst");
    expect(
        run(
            &[Path::new("overlay"), Path::new("pack"), &overlay, &bundle],
            &cache,
        ),
        0,
    );
    let lower = Mount::start_with(
        &base,
        None,
        &[std::ffi::OsStr::new("--lower"), bundle.as_os_str()],
        &[("XDG_CACHE_HOME", &cache)],
        &root.join("lower-mnt"),
        "new.txt",
    );
    assert_eq!(
        fs::read(root.join("lower-mnt/src/a.c")).unwrap(),
        b"int a(void) { return 10; }\n"
    );
    assert!(!root.join("lower-mnt/docs/gone.txt").exists());
    lower.unmount();
    let restored = root.join("restored");
    assert_eq!(
        expect(
            run(
                &[
                    Path::new("overlay"),
                    Path::new("unpack"),
                    &bundle,
                    &restored
                ],
                &cache
            ),
            0
        )
        .trim(),
        hash
    );
    assert_eq!(
        expect(
            run(
                &[Path::new("overlay"), Path::new("verify"), &restored],
                &cache
            ),
            0
        )
        .trim(),
        hash
    );

    // Tamper with a layer file and repack: the bundle no longer matches its seal.
    let victim = overlay.join("src/a.c");
    make_writable(&overlay);
    fs::write(&victim, b"int a(void) { return 666; }\n").unwrap();
    let evil = root.join("evil.tar.zst");
    expect(
        run(
            &[Path::new("overlay"), Path::new("pack"), &overlay, &evil],
            &cache,
        ),
        0,
    );
    expect(
        run(
            &[
                Path::new("overlay"),
                Path::new("unpack"),
                &evil,
                &root.join("evil-restored"),
            ],
            &cache,
        ),
        1,
    );
    let refused = run(
        &[Path::new("--no-mount"), Path::new("--lower"), &evil, &base],
        &cache,
    );
    assert_ne!(refused.status.code(), Some(0), "tampered lower accepted");
}

/// Item E: the control folder name is reserved at the mount root; nothing
/// lands in the overlay, `overlay import` refuses it, and the hash agrees.
#[test]
fn reserved_control_name_rejected() {
    if !available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _writable = Writable(tmp.path());
    let root = tmp.path();
    let cache = root.join("cache");
    let base = root.join("base.tar");
    base_tar(&base);
    let overlay = root.join("overlay");
    let mnt = root.join("mnt");
    let mount = Mount::start_with(
        &base,
        Some(&overlay),
        &[std::ffi::OsStr::new("--control-interface")],
        &[],
        &mnt,
        "Makefile",
    );
    let ctl = mnt.join(".ratarmount-control");
    for result in [
        fs::write(ctl.join("x"), b"x"),
        fs::create_dir(ctl.join("dir")),
        std::os::unix::fs::symlink("src", ctl.join("link")),
    ] {
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }
    edit(&mnt);
    mount.unmount();
    assert!(!overlay.join(".ratarmount-control").exists());
    assert!(
        files_rows(&overlay)
            .iter()
            .all(|(path, name, _)| !path.contains(".ratarmount-control")
                && name != ".ratarmount-control"),
        "{:?}",
        files_rows(&overlay)
    );

    let mut child = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .env("XDG_CACHE_HOME", &cache)
        .env("HOME", &cache)
        .args(["overlay", "import", "-"])
        .arg(root.join("imported"))
        .arg(&base)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"--- /dev/null\n+++ b/.ratarmount-control/x\n@@ -0,0 +1 @@\n+x\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(2), "{out:?}");
    assert!(!root.join("imported").exists());
    agree(root, &overlay, &cache, &[]);
}

/// C2: an archive base mounted with the hash gate shut leaves the digest
/// `pending`; `overlay seal` resolves it and every verb agrees.
#[test]
fn pending_archive_digest_then_seal() {
    if !available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _writable = Writable(tmp.path());
    let root = tmp.path();
    let cache = root.join("cache");
    let base = root.join("base.tar");
    base_tar(&base);
    let overlay = root.join("overlay");
    let gate = root.join("gate");
    let mount = Mount::start_with(
        &base,
        Some(&overlay),
        &[],
        &[("RATARMOUNT_TEST_HASH_GATE", &gate)],
        &root.join("mnt"),
        "Makefile",
    );
    edit(&root.join("mnt"));
    mount.unmount();
    assert_eq!(
        meta_get(&overlay, "base_digest_kind").as_deref(),
        Some("pending")
    );
    agree(root, &overlay, &cache, &[]);
    assert_eq!(
        meta_get(&overlay, "base_digest_kind").as_deref(),
        Some("strong")
    );
    let expected = format!(
        "sha256:{}",
        ratarmount_index::sha256_hex_stream(&mut fs::File::open(&base).unwrap()).unwrap()
    );
    assert_eq!(meta_get(&overlay, "base_digest"), Some(expected));
}
