//! Regression: an overlay written through a real FUSE mount, where editing an
//! existing file leaves no `files` row, must give one canonical hash in diff,
//! fsck, seal, verify, pack and unpack, before and after sealing.
#![cfg(target_os = "linux")]

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use ratarmount_compositing::HIDDEN_DB;
use serde_json::{json, Value};

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
        Self::start_umask(base, overlay, flags, env, path, ready, None)
    }

    /// `start_with`, with the daemon's umask set to `umask` when given.
    fn start_umask(
        base: &Path,
        overlay: Option<&Path>,
        flags: &[&std::ffi::OsStr],
        env: &[(&str, &Path)],
        path: &Path,
        ready: &str,
        umask: Option<libc::mode_t>,
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
        if let Some(mask) = umask {
            use std::os::unix::process::CommandExt;
            // SAFETY: umask(2) is async-signal-safe and touches no memory.
            unsafe {
                cmd.pre_exec(move || {
                    libc::umask(mask);
                    Ok(())
                });
            }
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

/// Regression (#326): under `--overlay-readonly 'bin/**' --overlay-allow 'bin/agent/**'`,
/// `rm -rf bin/agent` of the exception root the agent created succeeds, leaves
/// no `files` row, tombstone or manifest row, and every verb agrees.
#[test]
fn regression_rmdir_overlay_created_exception_root() {
    if !available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _writable = Writable(tmp.path());
    let root = tmp.path();
    let cache = root.join("cache");
    let base = root.join("base.tar");
    base_tar(&base);
    let rules = [
        std::ffi::OsStr::new("--overlay-readonly"),
        std::ffi::OsStr::new("bin/**"),
        std::ffi::OsStr::new("--overlay-allow"),
        std::ffi::OsStr::new("bin/agent/**"),
    ];
    let overlay = root.join("overlay");
    let mnt = root.join("mnt");
    let mount = Mount::start_with(&base, Some(&overlay), &rules, &[], &mnt, "Makefile");
    let agent = mnt.join("bin/agent");
    fs::create_dir(&agent).unwrap();
    fs::write(agent.join("x.t"), b"1\n").unwrap();
    assert_eq!(
        fs::remove_dir(&agent).unwrap_err().raw_os_error(),
        Some(libc::ENOTEMPTY)
    );
    assert_eq!(fs::read(agent.join("x.t")).unwrap(), b"1\n");
    let rm = Command::new("rm").arg("-rf").arg(&agent).status().unwrap();
    assert!(rm.success(), "rm -rf bin/agent: {rm}");
    assert!(!agent.exists());
    // The base-provided parent stays protected.
    assert_eq!(
        fs::remove_file(mnt.join("bin/tool"))
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EROFS)
    );
    edit(&mnt);
    mount.unmount();
    assert!(!overlay.join("bin/agent").exists());
    assert!(
        files_rows(&overlay)
            .iter()
            .all(|(path, name, _)| !path.starts_with("/bin/agent") && name != "agent"),
        "{:?}",
        files_rows(&overlay)
    );

    // No manifest row for the removed root (the issue's manifest difference).
    // The materialized parent `bin` carries the base's mode (#326 residual).
    let manifest = expect(
        run(
            &[Path::new("diff"), &overlay, Path::new("--manifest")],
            &cache,
        ),
        0,
    );
    for line in manifest.lines() {
        let row: Value = serde_json::from_str(line).unwrap();
        let path = row["path"].as_str().expect("UTF-8 fixture path");
        assert!(!path.starts_with("bin"), "{manifest}");
    }
    agree(root, &overlay, &cache, &[]);
}

/// Regression: #326 residual. With the daemon under umask 0002, creating and
/// removing `t/agent` (and a COW edit of `src/a.c`) materialized the base
/// parents `t` (0755) and `src` (0750) with the umask (0775), so
/// `diff --manifest` listed them as mode-only changes versus a re-import of
/// the attempt's patch. Restrictive parents and existing metadata overrides
/// retain their visible modes; diff, fsck, seal and pack agree.
#[test]
fn regression_326_materialized_parents_keep_base_modes_fuse() {
    if !available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _writable = Writable(tmp.path());
    let root = tmp.path();
    let cache = root.join("cache");
    let base = base_dir(root);
    fs::create_dir(base.join("t")).unwrap();
    fs::write(base.join("t/keep.t"), b"keep\n").unwrap();
    for dir in ["ro", "private"] {
        fs::create_dir(base.join(dir)).unwrap();
        fs::write(base.join(dir).join("f"), b"base\n").unwrap();
    }
    for (dir, mode) in [
        ("t", 0o755),
        ("src", 0o750),
        ("docs", 0o2755),
        ("ro", 0o555),
        ("private", 0o750),
    ] {
        fs::set_permissions(base.join(dir), fs::Permissions::from_mode(mode)).unwrap();
    }
    let rules = [
        std::ffi::OsStr::new("--overlay-readonly"),
        std::ffi::OsStr::new("t/**"),
        std::ffi::OsStr::new("--overlay-allow"),
        std::ffi::OsStr::new("t/agent/**"),
    ];
    let overlay = root.join("overlay");
    let mnt = root.join("mnt");
    let mount = Mount::start_umask(
        &base,
        Some(&overlay),
        &rules,
        &[],
        &mnt,
        "Makefile",
        Some(0o002),
    );
    let script = "mkdir -p t/agent && echo 1 > t/agent/x.t && rm -rf t/agent";
    let status = Command::new("sh")
        .args(["-c", script])
        .current_dir(&mnt)
        .status()
        .unwrap();
    assert!(status.success(), "{script}: {status}");
    mount.unmount();
    let manifest = |cache: &Path| {
        expect(
            run(
                &[Path::new("diff"), &overlay, Path::new("--manifest")],
                cache,
            ),
            0,
        )
    };
    // The #326 flow alone leaves no change at all.
    assert_eq!(manifest(&cache), "", "after the #326 flow");
    let mnt = root.join("mnt2");
    let mount = Mount::start_umask(
        &base,
        Some(&overlay),
        &rules,
        &[],
        &mnt,
        "Makefile",
        Some(0o002),
    );
    fs::write(mnt.join("src/a.c"), b"int a(void) { return 10; }\n").unwrap();
    fs::write(mnt.join("docs/new.txt"), b"new\n").unwrap();
    fs::set_permissions(mnt.join("private"), fs::Permissions::from_mode(0o500)).unwrap();
    fs::write(mnt.join("ro/f"), b"changed\n").unwrap();
    fs::write(mnt.join("private/f"), b"changed\n").unwrap();
    for (dir, mode) in [
        ("t", 0o755),
        ("src", 0o750),
        ("docs", 0o2755),
        ("ro", 0o555),
        ("private", 0o500),
    ] {
        let seen = fs::metadata(mnt.join(dir)).unwrap().permissions().mode() & 0o7777;
        assert_eq!(seen, mode, "{dir}: mode seen through the mount");
    }
    mount.unmount();
    for (dir, mode) in [
        ("t", 0o755),
        ("src", 0o750),
        ("docs", 0o2755),
        ("ro", 0o755),
        ("private", 0o700),
    ] {
        let host = fs::metadata(overlay.join(dir))
            .unwrap()
            .permissions()
            .mode()
            & 0o7777;
        assert_eq!(host, mode, "{dir}: materialized host mode");
    }
    let manifest = manifest(&cache);
    let paths: Vec<String> = manifest
        .lines()
        .map(|line| {
            let row: Value = serde_json::from_str(line).unwrap();
            row["path"].as_str().unwrap().to_string()
        })
        .collect();
    assert_eq!(
        paths,
        ["docs/new.txt", "private", "private/f", "ro/f", "src/a.c"],
        "{manifest}"
    );
    agree(root, &overlay, &cache, &[]);
}

/// Regression (#328): creates and unlinks of names the base lacks write no
/// `files` rows on a real mount. The files keep their modes in `diff`, a
/// rename and a create over a tombstoned base member still write rows, and
/// diff, fsck, seal, verify, pack and unpack agree.
#[test]
fn regression_overlay_only_names_write_no_rows() {
    use std::os::unix::fs::OpenOptionsExt;
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
    let mount = Mount::start(&base, &overlay, &mnt);
    edit(&mnt);
    churn(&mnt);
    let mut tool = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o700)
        .open(mnt.join("tool.sh"))
        .unwrap();
    tool.write_all(b"#!/bin/sh\n").unwrap();
    drop(tool);
    fs::rename(mnt.join("churn-1.txt"), mnt.join("renamed.txt")).unwrap();
    fs::remove_file(mnt.join("docs/keep.txt")).unwrap();
    fs::write(mnt.join("docs/keep.txt"), b"replaced\n").unwrap();
    assert_eq!(
        fs::metadata(mnt.join("tool.sh")).unwrap().mode() & 0o7777,
        0o700
    );
    mount.unmount();
    let rows = files_rows(&overlay);
    for (_, name, _) in &rows {
        assert!(
            !name.starts_with("churn-") && name != "tool.sh" && name != "new.txt",
            "{rows:?}"
        );
    }
    for row in [
        ("/docs", "gone.txt", true),
        ("/docs", "keep.txt", false),
        ("", "renamed.txt", false),
    ] {
        assert!(
            rows.contains(&(row.0.into(), row.1.into(), row.2)),
            "{row:?} in {rows:?}"
        );
    }
    // `diff` without `--hash` exits 1 when there are changes.
    let patch = expect(run(&[Path::new("diff"), &overlay], &cache), 1);
    assert!(
        patch.contains("new file mode 100700"),
        "tool.sh mode missing from: {patch}"
    );
    agree(root, &overlay, &cache, &[]);
}

/// Regression (#328): a sealed layer with row-less additions must work as a
/// read-only --lower, including modes, empty files, implicit parents and whiteouts.
#[test]
fn regression_overlay_only_sealed_lower_reads_modes_and_whiteouts() {
    use std::os::unix::fs::OpenOptionsExt;
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
    let mnt = root.join("writer");
    let writer = Mount::start(&base, &overlay, &mnt);
    for (path, mode, bytes) in [
        ("tool.sh", 0o751, b"#!/bin/sh\n".as_slice()),
        ("docs/empty", 0o640, b"".as_slice()),
        ("docs/added", 0o600, b"added\n".as_slice()),
    ] {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(mnt.join(path))
            .unwrap();
        file.write_all(bytes).unwrap();
    }
    fs::remove_file(mnt.join("docs/gone.txt")).unwrap();
    // Rename in both directions across the base/overlay-only boundary.
    fs::write(mnt.join("replacement"), b"replacement\n").unwrap();
    fs::rename(mnt.join("replacement"), mnt.join("src/a.c")).unwrap();
    fs::write(mnt.join("moved"), b"discarded\n").unwrap();
    fs::rename(mnt.join("src/b.c"), mnt.join("moved")).unwrap();
    writer.unmount();

    let rows = files_rows(&overlay);
    for (parent, name) in [
        ("", "tool.sh"),
        ("/docs", "empty"),
        ("/docs", "added"),
        ("", "docs"),
    ] {
        assert!(
            !rows.iter().any(|(p, n, _)| p == parent && n == name),
            "{rows:?}"
        );
    }
    assert!(rows.contains(&("/docs".into(), "gone.txt".into(), true)));
    assert!(rows.contains(&("/src".into(), "a.c".into(), false)));
    assert!(rows.contains(&("/src".into(), "b.c".into(), true)));
    assert!(rows.contains(&("".into(), "moved".into(), false)));
    // This also exercises fsck --repair, seal/verify and bundle round-trip.
    agree(root, &overlay, &cache, &[]);
    assert_eq!(
        files_rows(&overlay),
        rows,
        "seal must not invent files rows"
    );
    assert_eq!(
        fs::metadata(overlay.join("tool.sh")).unwrap().mode() & 0o222,
        0
    );

    let path = root.join("reader");
    let reader = Mount::start_with(
        &base,
        None,
        &[std::ffi::OsStr::new("--lower"), overlay.as_os_str()],
        &[],
        &path,
        "Makefile",
    );
    for (name, mode, bytes) in [
        ("tool.sh", 0o751, b"#!/bin/sh\n".as_slice()),
        ("docs/empty", 0o640, b"".as_slice()),
        ("docs/added", 0o600, b"added\n".as_slice()),
    ] {
        assert_eq!(fs::read(path.join(name)).unwrap(), bytes, "{name}");
        let metadata = fs::metadata(path.join(name)).unwrap();
        assert!(metadata.is_file(), "{name}");
        assert_eq!(metadata.mode() & 0o7777, mode, "{name}");
        assert_eq!(metadata.len(), bytes.len() as u64, "{name}");
    }
    let mut docs: Vec<_> = fs::read_dir(path.join("docs"))
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    docs.sort();
    assert_eq!(docs, ["added", "empty", "keep.txt"]);
    for absent in ["docs/gone.txt", "src/b.c", "replacement"] {
        assert_eq!(
            fs::metadata(path.join(absent)).unwrap_err().kind(),
            std::io::ErrorKind::NotFound
        );
    }
    assert_eq!(fs::read(path.join("src/a.c")).unwrap(), b"replacement\n");
    assert_eq!(
        fs::read(path.join("moved")).unwrap(),
        b"int b(void) { return 2; }\n"
    );
    assert_eq!(
        fs::write(path.join("tool.sh"), b"denied")
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EROFS)
    );
    assert_eq!(
        fs::remove_file(path.join("tool.sh"))
            .unwrap_err()
            .raw_os_error(),
        Some(libc::EROFS)
    );
    reader.unmount();
    assert_eq!(files_rows(&overlay), rows);
    expect(
        run(
            &[Path::new("overlay"), Path::new("verify"), &overlay],
            &cache,
        ),
        0,
    );
}

/// Regression (#328): a mount SIGKILLed during a create/unlink loop of
/// overlay-only names leaves a consistent overlay. Before, a kill between the
/// host unlink and its row transaction left a `files` row without content
/// (`overlay fsck` exit 1); now such names have no rows to get out of step.
#[test]
fn regression_overlay_only_churn_sigkill_leaves_consistent_overlay() {
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
    for round in 0..3 {
        let mnt = root.join(format!("mnt-{round}"));
        let mut mount = Mount::start(&base, &overlay, &mnt);
        let worker = {
            let mnt = mnt.clone();
            std::thread::spawn(move || {
                for i in 0..100_000 {
                    if fs::write(mnt.join(format!("k{round}-{i}")), b"x\n").is_err() {
                        return i;
                    }
                    if i > 0 && fs::remove_file(mnt.join(format!("k{round}-{}", i - 1))).is_err() {
                        return i;
                    }
                }
                100_000
            })
        };
        std::thread::sleep(Duration::from_millis(300 + 100 * round));
        mount.child.kill().unwrap();
        mount.child.wait().unwrap();
        drop(mount);
        let done = worker.join().unwrap();
        assert!(done > 0 && done < 100_000, "round {round}: {done} ops");
        let report = expect(
            run(
                &[
                    Path::new("overlay"),
                    Path::new("fsck"),
                    &overlay,
                    Path::new("--json"),
                ],
                &cache,
            ),
            0,
        );
        let report: Value = serde_json::from_str(&report).unwrap();
        assert_eq!(report["result"], "ok", "round {round}: {report}");
    }
    let mnt = root.join("mnt-final");
    let mount = Mount::start(&base, &overlay, &mnt);
    for entry in fs::read_dir(&mnt).unwrap() {
        let path = entry.unwrap().path();
        if path.is_file() {
            fs::read(&path).unwrap();
        }
    }
    mount.unmount();
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

fn run_env(args: &[&Path], cache: &Path, env: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
    cmd.env("XDG_CACHE_HOME", cache).env("HOME", cache);
    for (key, value) in env {
        cmd.env(key, value);
    }
    cmd.args(args).output().unwrap()
}

/// Many creates and unlinks, the workload relaxed durability is for.
fn churn(mnt: &Path) {
    for i in 0..40 {
        fs::write(mnt.join(format!("churn-{i}.txt")), b"x\n").unwrap();
    }
    for i in (0..40).step_by(2) {
        fs::remove_file(mnt.join(format!("churn-{i}.txt"))).unwrap();
    }
}

/// Regression (#328): `--overlay-durability=relaxed` on a real `-w` mount.
/// A clean unmount leaves no marker and the same canonical hash as a `full`
/// mount with the same edits (diff, fsck, seal, verify, pack, unpack agree).
/// A SIGKILLed relaxed mount leaves this boot's marker, which a remount
/// accepts and clears. The same marker seen from another boot (the
/// `RATARMOUNT_TEST_BOOT_ID` seam) is refused by the remount, `diff`, `seal`
/// and `fsck` until `fsck --repair` passes its integrity check.
#[test]
fn regression_relaxed_durability_clean_killed_and_rebooted() {
    if !available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _writable = Writable(tmp.path());
    let root = tmp.path();
    let cache = root.join("cache");
    let base = root.join("base.tar");
    base_tar(&base);
    let relaxed = [std::ffi::OsStr::new("--overlay-durability=relaxed")];

    // Clean unmount: no marker, same hash as full durability.
    let full = root.join("full");
    let mount = Mount::start(&base, &full, &root.join("mnt-full"));
    edit(&root.join("mnt-full"));
    churn(&root.join("mnt-full"));
    mount.unmount();
    let overlay = root.join("relaxed");
    let mount = Mount::start_with(
        &base,
        Some(&overlay),
        &relaxed,
        &[],
        &root.join("mnt-relaxed"),
        "Makefile",
    );
    edit(&root.join("mnt-relaxed"));
    churn(&root.join("mnt-relaxed"));
    mount.unmount();
    assert_eq!(meta_get(&overlay, "relaxed_durability"), None);
    assert_eq!(meta_get(&full, "relaxed_durability"), None);
    let full_hash = expect(
        run(&[Path::new("diff"), &full, Path::new("--hash")], &cache),
        0,
    );
    let relaxed_hash = expect(
        run(&[Path::new("diff"), &overlay, Path::new("--hash")], &cache),
        0,
    );
    assert_eq!(relaxed_hash, full_hash);
    assert_eq!(agree(root, &overlay, &cache, &[]), full_hash.trim());

    // SIGKILL (same boot): the marker stays, the remount accepts and clears it.
    let killed = root.join("killed");
    let mnt = root.join("mnt-killed");
    let mut mount = Mount::start_with(&base, Some(&killed), &relaxed, &[], &mnt, "Makefile");
    edit(&mnt);
    churn(&mnt);
    mount.child.kill().unwrap();
    mount.child.wait().unwrap();
    drop(mount);
    let marker = meta_get(&killed, "relaxed_durability").expect("marker left by SIGKILL");
    let (boot, _pid) = marker.rsplit_once(':').unwrap();
    expect(
        run(&[Path::new("overlay"), Path::new("fsck"), &killed], &cache),
        0,
    );
    let mnt = root.join("mnt-killed-2");
    let mount = Mount::start(&base, &killed, &mnt);
    assert_eq!(fs::read(mnt.join("new.txt")).unwrap(), b"new\n");
    assert!(!mnt.join("docs/gone.txt").exists());
    assert!(mnt.join("churn-1.txt").exists() && !mnt.join("churn-0.txt").exists());
    mount.unmount();
    assert_eq!(meta_get(&killed, "relaxed_durability"), None);
    assert_eq!(
        expect(
            run(&[Path::new("diff"), &killed, Path::new("--hash")], &cache),
            0
        ),
        full_hash
    );

    // The same SIGKILL seen after a reboot: refused until fsck --repair.
    let crashed = root.join("crashed");
    let mnt = root.join("mnt-crashed");
    let mut mount = Mount::start_with(&base, Some(&crashed), &relaxed, &[], &mnt, "Makefile");
    edit(&mnt);
    mount.child.kill().unwrap();
    mount.child.wait().unwrap();
    drop(mount);
    assert!(meta_get(&crashed, "relaxed_durability")
        .unwrap()
        .starts_with(&format!("{boot}:")));
    let rebooted = [("RATARMOUNT_TEST_BOOT_ID", "another-boot")];
    let refused = |args: &[&Path]| {
        let out = run_env(args, &cache, &rebooted);
        assert_ne!(out.status.code(), Some(0), "{args:?} accepted");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(
            stderr.contains("--overlay-durability=relaxed") && stderr.contains("fsck --repair"),
            "{args:?}: {stderr}"
        );
    };
    let p = Path::new;
    refused(&[p("overlay"), p("fsck"), &crashed]);
    assert_eq!(
        run_env(&[p("overlay"), p("fsck"), &crashed], &cache, &rebooted)
            .status
            .code(),
        Some(2),
        "an unclean relaxed marker is an operational error"
    );
    refused(&[p("diff"), &crashed, p("--hash")]);
    refused(&[p("overlay"), p("seal"), &crashed]);
    refused(&[
        p("--no-mount"),
        p("--index-file"),
        p(":memory:"),
        p("-w"),
        &crashed,
        &base,
    ]);
    assert!(meta_get(&crashed, "relaxed_durability").is_some());
    expect(
        run_env(
            &[p("overlay"), p("fsck"), &crashed, p("--repair")],
            &cache,
            &rebooted,
        ),
        0,
    );
    assert_eq!(meta_get(&crashed, "relaxed_durability"), None);
    expect(
        run_env(&[p("overlay"), p("fsck"), &crashed], &cache, &rebooted),
        0,
    );
    let mount = Mount::start(&base, &crashed, &root.join("mnt-crashed-2"));
    assert_eq!(
        fs::read(root.join("mnt-crashed-2/new.txt")).unwrap(),
        b"new\n"
    );
    mount.unmount();
}

/// The pids (of this uid, not this process) whose argv has `mnt` as one
/// exact argument: a daemonized mount's serving child.
fn serving_pids(mnt: &Path) -> Vec<u32> {
    let want = mnt.as_os_str().as_encoded_bytes();
    let me = unsafe { libc::getuid() };
    let own = std::process::id();
    let mut out = Vec::new();
    for entry in fs::read_dir("/proc").unwrap().flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.parse::<u32>().ok())
        else {
            continue;
        };
        if pid == own || entry.metadata().map(|m| m.uid()).ok() != Some(me) {
            continue;
        }
        let Ok(cmd) = fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        if cmd.split(|b| *b == 0).any(|arg| arg == want) {
            out.push(pid);
        }
    }
    out
}

/// `pid` has exited (no `/proc/PID`, a zombie, or a reused pid whose argv no
/// longer names `mnt`).
fn serving_child_gone(pid: u32, mnt: &Path) -> bool {
    let zombie = fs::read_to_string(format!("/proc/{pid}/stat")).map_or(true, |stat| {
        stat.rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().next())
            .is_some_and(|state| state == "Z")
    });
    zombie || !serving_pids(mnt).contains(&pid)
}

/// `meta_get` that never rolls back a hot `-journal` (a hot journal or a lock
/// is retried until `deadline`): safe while a daemonized mount, which holds no
/// kernel lock on its database (#183), may be writing.
fn meta_get_no_recovery(overlay: &Path, key: &str, deadline: Instant) -> Option<String> {
    loop {
        match ratarmount_compositing::OverlayMeta::read_no_recovery(overlay) {
            Ok(meta) => return meta.unwrap().get(key).map(str::to_string),
            Err(error) => assert!(
                Instant::now() < deadline,
                "overlay metadata stayed unreadable: {error}"
            ),
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// Regression (#328): the forked launcher's exit must keep the marker, while
/// the serving child's clean exit must flush and clear it before process::exit.
///
/// Regression (flaky under CPU load): the test polled `OverlayMeta::read`
/// right after `fusermount3 -u`, while the serving child was committing the
/// marker's deletion. A daemonized mount holds no kernel lock on its database
/// (#183), so the poll took the child's live `-journal` for a hot one and
/// rolled the deletion back; the child exited believing it had committed, and
/// the marker stayed. Nothing that may roll back a journal touches the
/// database until the serving child has exited.
#[test]
fn regression_relaxed_durability_daemon_clean_close() {
    if !available() {
        return;
    }
    struct Mounted(Option<PathBuf>);
    impl Drop for Mounted {
        fn drop(&mut self) {
            if let Some(path) = &self.0 {
                let _ = Command::new("fusermount3").arg("-uz").arg(path).status();
            }
        }
    }
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("base.tar");
    base_tar(&base);
    let overlay = tmp.path().join("overlay");
    let mount = tmp.path().join("mnt");
    fs::create_dir(&mount).unwrap();
    let mut mounted = Mounted(Some(mount.clone()));
    let p = Path::new;
    expect(
        run(
            &[
                p("--passthrough"),
                p("off"),
                p("--index-file"),
                p(":memory:"),
                p("--overlay-durability=relaxed"),
                p("-w"),
                &overlay,
                &base,
                &mount,
            ],
            &tmp.path().join("cache"),
        ),
        0,
    );
    assert!(
        meta_get_no_recovery(
            &overlay,
            "relaxed_durability",
            Instant::now() + Duration::from_secs(10)
        )
        .is_some(),
        "launcher cleared the child's marker"
    );
    // The launcher has exited (`run` waited for it): only the child names `mount`.
    let child = match serving_pids(&mount)[..] {
        [pid] => pid,
        ref pids => panic!("expected one serving child for the mount, found {pids:?}"),
    };
    churn(&mount);
    let deadline = Instant::now() + Duration::from_secs(10);
    while !Command::new("fusermount3")
        .arg("-u")
        .arg(&mount)
        .status()
        .unwrap()
        .success()
    {
        assert!(Instant::now() < deadline, "unmount stayed busy");
        std::thread::sleep(Duration::from_millis(100));
    }
    mounted.0 = None;
    let deadline = Instant::now() + Duration::from_secs(10);
    while !serving_child_gone(child, &mount) {
        assert!(
            Instant::now() < deadline,
            "serving child {child} did not exit after the unmount"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    assert_eq!(
        meta_get(&overlay, "relaxed_durability"),
        None,
        "serving child did not clear the marker"
    );
    expect(
        run(
            &[p("overlay"), p("fsck"), &overlay],
            &tmp.path().join("cache"),
        ),
        0,
    );
}

/// `agree_with` for a layer that is sealed already, as a supervisor finalize
/// leaves it: `fsck` checks it read-only (`--repair` is refused on a sealed
/// overlay) and `seal` only reads the recorded digest back. `diff --hash`,
/// `verify --json`'s `computed` digest, and `pack`/`unpack` plus `verify`
/// of the restored layer must all give `expected`, which is returned.
/// `base_args` (the supervisor's `--index-folders`) go to every verb that
/// opens the base.
fn agree_sealed(
    root: &Path,
    overlay: &Path,
    cache: &Path,
    base_args: &[&str],
    expected: &str,
    sealed_at: &str,
) -> String {
    let (o, p) = (overlay, Path::new);
    let with_base = |args: &[&Path]| {
        let mut all = args.to_vec();
        all.extend(base_args.iter().map(|arg| Path::new(*arg)));
        run(&all, cache)
    };
    let hash = expect(with_base(&[p("diff"), o, p("--hash")]), 0);
    assert_eq!(hash.trim(), expected);
    let fsck: Value = serde_json::from_str(&expect(
        run(&[p("overlay"), p("fsck"), o, p("--json")], cache),
        0,
    ))
    .unwrap();
    assert_eq!(fsck["result"], "ok", "{fsck}");
    let repair = run(&[p("overlay"), p("fsck"), o, p("--repair")], cache);
    assert_eq!(repair.status.code(), Some(2), "{repair:?}");
    assert!(
        String::from_utf8_lossy(&repair.stderr).contains("sealed"),
        "{repair:?}"
    );
    assert_eq!(
        expect(with_base(&[p("diff"), o, p("--hash")]), 0),
        hash,
        "diff --hash changed across fsck"
    );
    let resealed: Value = serde_json::from_str(&expect(
        with_base(&[p("overlay"), p("seal"), o, p("--json")]),
        0,
    ))
    .unwrap();
    assert_eq!(
        resealed,
        json!({"layer_digest": expected, "sealed_at": sealed_at})
    );
    assert_eq!(
        expect(with_base(&[p("diff"), o, p("--hash")]), 0),
        hash,
        "diff --hash changed across seal"
    );
    let verify = |dir: &Path| {
        let report: Value = serde_json::from_str(&expect(
            with_base(&[p("overlay"), p("verify"), dir, p("--json")]),
            0,
        ))
        .unwrap();
        assert_eq!(report["ok"], true, "{report}");
        assert_eq!(report["recorded"], expected, "{report}");
        report["computed"].as_str().unwrap().to_owned()
    };
    assert_eq!(verify(o), expected);
    let (bundle, restored) = (root.join("agree.tar.zst"), root.join("agree-restored"));
    let (bundle, restored) = (bundle.as_path(), restored.as_path());
    expect(with_base(&[p("overlay"), p("pack"), o, bundle]), 0);
    assert_eq!(
        expect(with_base(&[p("overlay"), p("unpack"), bundle, restored]), 0).trim(),
        expected
    );
    assert_eq!(verify(restored), expected);
    assert_eq!(
        expect(with_base(&[p("diff"), restored, p("--hash")]), 0),
        hash
    );
    hash.trim().to_string()
}

/// A `ratarmount sandbox daemon` over `ROOT/state`, shut down when dropped
/// (its shutdown destroys the attempts it still holds).
struct SandboxDaemon {
    child: Child,
    socket: PathBuf,
}

impl SandboxDaemon {
    fn start(root: &Path) -> Self {
        let socket = root.join("api.sock");
        let log = root.join("daemon.log");
        let child = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
            .args(["sandbox", "daemon", "--socket"])
            .arg(&socket)
            .arg("--state-dir")
            .arg(root.join("state"))
            .args(["--max-attempts", "4", "--timeout", "30"])
            .env("XDG_CACHE_HOME", root.join("daemon-cache"))
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log).unwrap())
            .spawn()
            .unwrap();
        let mut daemon = Self { child, socket };
        let deadline = Instant::now() + Duration::from_secs(10);
        while UnixStream::connect(&daemon.socket).is_err() {
            assert!(
                daemon.child.try_wait().unwrap().is_none(),
                "{}",
                fs::read_to_string(&log).unwrap()
            );
            assert!(Instant::now() < deadline, "daemon socket timeout");
            std::thread::sleep(Duration::from_millis(20));
        }
        daemon
    }

    /// One request line, and the daemon's answer.
    fn send(&self, request: &Value) -> Value {
        let mut stream = UnixStream::connect(&self.socket).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(120)))
            .unwrap();
        writeln!(stream, "{request}").unwrap();
        let mut reply = String::new();
        BufReader::new(stream).read_line(&mut reply).unwrap();
        serde_json::from_str(&reply).unwrap()
    }

    fn call(&self, request: Value) -> Value {
        let response = self.send(&request);
        assert_eq!(response["ok"], true, "{response}");
        response["result"].clone()
    }

    /// `finalize` until it answers; `writers_active` (a desktop prober such
    /// as `gvfsd-trash` briefly holding the new mount) is retried with the
    /// same request for a bounded time, as the docs tell clients to.
    fn finalize(&self, request: &Value) -> Value {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let response = self.send(request);
            if response["ok"] == true {
                return response["result"].clone();
            }
            assert_eq!(response["error"]["code"], "writers_active", "{response}");
            assert!(Instant::now() < deadline, "attempt stayed busy: {response}");
            eprintln!("finalize answered writers_active; retrying: {response}");
            std::thread::sleep(Duration::from_secs(1));
        }
    }
}

impl Drop for SandboxDaemon {
    fn drop(&mut self) {
        if let Ok(mut stream) = UnixStream::connect(&self.socket) {
            let _ = stream.write_all(b"{\"version\":1,\"op\":\"shutdown\"}\n");
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        while matches!(self.child.try_wait(), Ok(None)) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Regression (R1c-1 F4): a layer the real supervisor finalized (its own
/// stop, fsck, seal and pack over a prepared TAR base, after an agent's
/// copy-on-write edits through the attempt's mount) must give the report's
/// `layer_digest` in `diff --hash`, `fsck`, `seal`, `verify`, `pack` and
/// `unpack`, and so must the bundle the supervisor packed.
#[test]
fn supervisor_finalized_layer() {
    if !available() {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let _writable = Writable(tmp.path());
    let root = tmp.path();
    let cache = root.join("cache");
    let base = root.join("base.tar");
    base_tar(&base);
    // Declared after `_writable`, so it shuts down before the tree is made
    // writable and removed.
    let daemon = SandboxDaemon::start(root);
    daemon.call(json!({"version": 1, "op": "create_base", "name": "task", "source": base}));
    let attempts = daemon.call(json!({"version": 1, "op": "new", "base": "task"}));
    let mnt = PathBuf::from(attempts[0]["path"].as_str().unwrap());
    edit(&mnt);
    let report = daemon.finalize(&json!({
        "version": 2, "op": "finalize", "id": attempts[0]["id"], "pack": true,
        "request_id": "f"
    }));
    assert_eq!(report["status"], "finalized", "{report}");
    let overlay = PathBuf::from(report["attempt"]["overlay_dir"].as_str().unwrap());
    let digest = report["layer_digest"].as_str().unwrap();
    let sealed_at = report["sealed_at"].as_str().unwrap();
    // The copy-on-write rewrite, the new file and the delete.
    assert_eq!(report["patch_hash"]["files"], 3, "{report}");
    let indexes = serde_json::to_string(&[root.join("state/indexes/task")]).unwrap();
    let index_folders = ["--index-folders", indexes.as_str()];
    let hash = agree_sealed(root, &overlay, &cache, &index_folders, digest, sealed_at);
    assert_eq!(hash, digest);
    // The bundle the supervisor packed restores the same layer.
    let bundle = PathBuf::from(report["bundle"].as_str().unwrap());
    let restored = root.join("supervisor-restored");
    let with_folders = |args: &[&Path]| {
        let mut all = args.to_vec();
        all.extend(index_folders.iter().map(|arg| Path::new(*arg)));
        expect(run(&all, &cache), 0)
    };
    let p = Path::new;
    assert_eq!(
        with_folders(&[p("overlay"), p("unpack"), &bundle, &restored]).trim(),
        digest
    );
    assert_eq!(
        with_folders(&[p("overlay"), p("verify"), &restored]).trim(),
        digest
    );
}
