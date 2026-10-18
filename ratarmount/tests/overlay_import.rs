//! Import CLI contracts, stdin, lower metadata and exit codes without FUSE.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::Arc;

use ratarmount_compositing::{FolderMountSource, OverlayCreateInfo, OverlayMeta, WriteOverlay};

#[path = "diff/cow.rs"]
mod cow;

fn import(base: &Path, dest: &Path, patch: &[u8], flags: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["overlay", "import", "--json"])
        .args(flags)
        .arg("-")
        .arg(dest)
        .arg(base)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(patch).unwrap();
    child.wait_with_output().unwrap()
}

/// Regression: COW edits of base files and prepared build outputs must survive diff/import/hash.
#[test]
fn regression_cow_git_import_hash_roundtrip_base_and_lower() {
    use ratarmount_compositing::{compose_stack, Immutability};
    use ratarmount_core::MountSource;
    for layered in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let base = root.path().join("base");
        fs::create_dir_all(base.join("lib")).unwrap();
        fs::write(base.join("lib/Foo.pm"), b"source\n").unwrap();
        let source: Arc<dyn MountSource> = Arc::new(FolderMountSource::new(&base).unwrap());
        let prepared = root.path().join("prepared");
        let lower = if layered {
            let ov = WriteOverlay::new(source.clone(), &prepared).unwrap();
            ov.mkdir("/blib", 0o755).unwrap();
            use std::os::fd::FromRawFd;
            let mut file =
                unsafe { fs::File::from_raw_fd(ov.create_file("/blib/x", 0o644).unwrap()) };
            file.write_all(b"built\n").unwrap();
            ov.finish_owned_write_fd(file);
            drop(ov);
            ratarmount_compositing::overlay_seal::seal(&prepared, source.clone()).unwrap();
            compose_stack(
                source.clone(),
                &[(prepared.clone(), Immutability::Immutable)],
            )
            .unwrap()
        } else {
            source
        };
        let attempt = root.path().join("attempt");
        let ov = WriteOverlay::new(lower, &attempt).unwrap();
        cow::cow_write(&ov, "/lib/Foo.pm", b"edited\n");
        if layered {
            cow::cow_write(&ov, "/blib/x", b"rebuilt\n");
        }
        drop(ov);
        let conn =
            rusqlite::Connection::open(attempt.join(ratarmount_compositing::HIDDEN_DB)).unwrap();
        assert_eq!(
            conn.query_row("SELECT count(*) FROM files", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            0
        );
        drop(conn);
        let flags = if layered {
            vec!["--lower", prepared.to_str().unwrap()]
        } else {
            vec![]
        };
        let diff = |dir: &Path, mode: &str| {
            Command::new(env!("CARGO_BIN_EXE_ratarmount"))
                .arg("diff")
                .arg(dir)
                .arg(&base)
                .arg(mode)
                .args(&flags)
                .output()
                .unwrap()
        };
        let names = diff(&attempt, "--name-status");
        assert_eq!(
            names.status.code(),
            Some(1),
            "{}",
            String::from_utf8_lossy(&names.stderr)
        );
        assert_eq!(
            names.stdout,
            if layered {
                b"M\tblib/x\nM\tlib/Foo.pm\n".as_slice()
            } else {
                b"M\tlib/Foo.pm\n"
            }
        );
        let patch = diff(&attempt, "--git");
        assert_eq!(patch.status.code(), Some(1));
        let dest = root.path().join("imported");
        let result = import(&base, &dest, &patch.stdout, &flags);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let original = diff(&attempt, "--hash");
        let imported = diff(&dest, "--hash");
        assert!(original.status.success() && imported.status.success());
        assert_eq!(original.stdout, imported.stdout);
        assert_ne!(
            String::from_utf8_lossy(&original.stdout).trim(),
            ratarmount_compositing::overlay_changes::EMPTY_SHA256
        );
        ratarmount_compositing::overlay_seal::unseal(&dest).unwrap();
        if layered {
            ratarmount_compositing::overlay_seal::unseal(&prepared).unwrap();
        }
    }
}

/// Regression: stdin must remain byte-oriented and JSON must be the only stdout.
#[test]
fn regression_import_stdin_seal_json_and_exit_codes() {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().join("base");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("a"), b"caf\xe9\n").unwrap();
    let dest = root.path().join("overlay");
    let patch = b"--- a/a\n+++ b/a\n@@ -1 +1 @@\n-caf\xe9\n+d\xe9j\xe0\n";
    let output = import(&base, &dest, patch, &["--mtime", "42"]);
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["files"], 1);
    assert_eq!(json["rejected"], 0);
    assert!(json["layer_digest"].is_string());
    assert!(OverlayMeta::read(&dest).unwrap().unwrap().layer_sealed());
    assert_eq!(fs::read(dest.join("a")).unwrap(), b"d\xe9j\xe0\n");
    let verify = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["overlay", "verify", "--json"])
        .arg(&dest)
        .arg(&base)
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );
    let error = import(&base, &dest, patch, &[]);
    assert_eq!(error.status.code(), Some(2));
    assert_eq!(fs::read(dest.join("a")).unwrap(), b"d\xe9j\xe0\n");
    ratarmount_compositing::overlay_seal::unseal(&dest).unwrap();

    let patch_file = root.path().join("edit.patch");
    fs::write(&patch_file, patch).unwrap();
    let file_dest = root.path().join("from-file");
    let result = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["overlay", "import", "--no-seal", "--json"])
        .arg(&patch_file)
        .arg(&file_dest)
        .arg(&base)
        .output()
        .unwrap();
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(file_dest.join("a")).unwrap(), b"d\xe9j\xe0\n");

    let reject = root.path().join("reject");
    let bad = b"--- a/a\n+++ b/a\n@@ -1 +1 @@\n-missing\n+changed\n";
    let result = import(&base, &reject, bad, &["--reject", "--no-seal"]);
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(json["rejected"], 1);
    assert!(json["layer_digest"].is_null());
    assert_eq!(fs::read(reject.join("a")).unwrap(), b"caf\xe9\n");
    assert!(reject.join("a.rej").is_file());
    let abort = root.path().join("abort");
    assert_eq!(import(&base, &abort, bad, &[]).status.code(), Some(2));
    assert!(!abort.exists());
}

/// Regression: import must apply against sealed lowers and record the mount's stack identity.
#[test]
fn regression_import_lower_stack_identity_and_unsealed_opt_in() {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().join("base");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("a"), b"base\n").unwrap();
    let source = Arc::new(FolderMountSource::new(&base).unwrap());
    let lower = root.path().join("lower");
    let ov = WriteOverlay::new_with_create_info(
        source.clone(),
        &lower,
        &OverlayCreateInfo {
            base_url: base.to_str().unwrap().into(),
            ..Default::default()
        },
    )
    .unwrap();
    cow::cow_write(&ov, "/a", b"prepared\n");
    drop(ov);
    let patch = b"--- a/a\n+++ b/a\n@@ -1 +1 @@\n-prepared\n+attempt\n";
    let fail = root.path().join("fail");
    assert_eq!(
        import(&base, &fail, patch, &["--lower", lower.to_str().unwrap()])
            .status
            .code(),
        Some(2)
    );
    assert!(!fail.exists());
    let shared = root.path().join("shared");
    let result = import(
        &base,
        &shared,
        patch,
        &[
            "--lower",
            lower.to_str().unwrap(),
            "--allow-unsealed-lower",
            "--no-seal",
        ],
    );
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let seal = ratarmount_compositing::overlay_seal::seal(&lower, source).unwrap();
    let dest = root.path().join("sealed-lower");
    let result = import(&base, &dest, patch, &["--lower", lower.to_str().unwrap()]);
    assert_eq!(
        result.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(fs::read(dest.join("a")).unwrap(), b"attempt\n");
    let meta = OverlayMeta::read(&dest).unwrap().unwrap();
    let records = meta.lower_layers().unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].path, lower.canonicalize().unwrap());
    assert_eq!(records[0].layer_digest, seal.layer_digest);
    assert_eq!(
        meta.stack_digest(),
        Some(
            ratarmount_compositing::stack_digest(
                meta.base_digest().unwrap(),
                &[&seal.layer_digest]
            )
            .as_str()
        )
    );
    ratarmount_compositing::overlay_seal::unseal(&dest).unwrap();
    ratarmount_compositing::overlay_seal::unseal(&lower).unwrap();
}

/// Spawn `overlay import` with the journal-hold seam and SIGKILL it while its
/// write transaction is open. Returns the overlay directory; the rollback
/// `-journal` is asserted to exist (a real hot journal, not a fabricated file).
#[cfg(unix)]
fn kill_import_mid_transaction(root: &Path, base: &Path) -> std::path::PathBuf {
    let dest = root.join("overlay");
    let ready = root.join("ready");
    let patch = b"--- /dev/null\n+++ b/new\n@@ -0,0 +1 @@\n+hello\n";
    let mut child = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .env("HOME", root)
        .env("XDG_CACHE_HOME", root.join("cache"))
        .env("RATARMOUNT_TEST_JOURNAL_HOLD", &ready)
        .args(["overlay", "import", "--no-seal", "-"])
        .arg(&dest)
        .arg(base)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(patch).unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !ready.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "import never reached the transaction hold"
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    child.kill().unwrap(); // SIGKILL
    child.wait().unwrap();
    let journal = dest.join(".ratarmount.overlay.sqlite-journal");
    assert!(journal.exists(), "no hot journal after SIGKILL");
    dest
}

#[cfg(unix)]
fn overlay_cli(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .env("HOME", root)
        .env("XDG_CACHE_HOME", root.join("cache"))
        .arg("overlay")
        .args(args)
        .output()
        .unwrap()
}

/// Regression: a killed `overlay import --no-seal` left an overlay that fsck
/// called clean and seal sealed, and (I1) its hot `-journal` made info, fsck
/// and seal fail with the misleading "attempt to write a readonly database".
/// A real SIGKILL mid-transaction: fsck must report `import_incomplete`.
#[cfg(unix)]
#[test]
fn regression_seal_refuses_incomplete_import() {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().join("base");
    fs::create_dir(&base).unwrap();
    let dest = kill_import_mid_transaction(root.path(), &base);
    let d = dest.to_str().unwrap();
    let info = overlay_cli(root.path(), &["info", "--json", d]);
    assert_eq!(info.status.code(), Some(0), "{info:?}");
    // The read rolled the journal back.
    assert!(!dest.join(".ratarmount.overlay.sqlite-journal").exists());
    let fsck = overlay_cli(root.path(), &["fsck", "--json", d]);
    assert_eq!(fsck.status.code(), Some(1), "{fsck:?}");
    let out = String::from_utf8_lossy(&fsck.stdout);
    assert!(out.contains("\"import_incomplete\":1"), "{out}");
    let seal = overlay_cli(root.path(), &["seal", d, base.to_str().unwrap()]);
    assert_eq!(seal.status.code(), Some(2), "{seal:?}");
    let err = String::from_utf8_lossy(&seal.stderr);
    assert!(err.contains("import"), "{err}");
    assert!(!err.contains("readonly"), "{err}");
    assert!(!OverlayMeta::read(&dest).unwrap().unwrap().layer_sealed());
}

/// Regression (I1): a hot journal in a read-only directory, or on a sealed
/// overlay, is not rolled back; the error names the interrupted write.
#[cfg(unix)]
#[test]
fn regression_hot_journal_unrecoverable_names_interrupted_write() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let base = root.path().join("base");
    fs::create_dir(&base).unwrap();
    let dest = kill_import_mid_transaction(root.path(), &base);
    let journal = dest.join(".ratarmount.overlay.sqlite-journal");
    let before = fs::read(&journal).unwrap();
    let check = |label: &str| {
        for args in [["info", "--json"], ["fsck", "--json"]] {
            let out = overlay_cli(root.path(), &[args[0], args[1], dest.to_str().unwrap()]);
            assert_ne!(out.status.code(), Some(0), "{label}: {out:?}");
            let err = String::from_utf8_lossy(&out.stderr);
            assert!(
                err.contains("interrupted write") && err.contains("-journal"),
                "{label}: {err}"
            );
            assert!(
                !err.contains("attempt to write a readonly"),
                "{label}: {err}"
            );
        }
        assert_eq!(
            fs::read(&journal).unwrap(),
            before,
            "{label}: journal changed"
        );
    };
    // Read-only directory (running as root would ignore the mode; skip then).
    fs::set_permissions(&dest, fs::Permissions::from_mode(0o555)).unwrap();
    if fs::File::create(dest.join("probe")).is_ok() {
        fs::set_permissions(&dest, fs::Permissions::from_mode(0o755)).unwrap();
        let _ = fs::remove_file(dest.join("probe"));
        eprintln!("skip: directory permissions are not enforced (root)");
        return;
    }
    check("read-only directory");
    fs::set_permissions(&dest, fs::Permissions::from_mode(0o755)).unwrap();
    // A sealed overlay (sentinel present) is never rolled back silently.
    fs::write(dest.join(".ratarmount-sealed"), b"sha256:0\n").unwrap();
    check("sealed sentinel");
}

/// Regression: N6, `overlay import` accepted `.ratarmount-control/` paths. The
/// mount's virtual control folder would hide them while diff/hash/seal still
/// covered the bytes. Refused like a traversal path (exit 2, no overlay).
#[test]
fn regression_import_refuses_control_dir_paths() {
    let root = tempfile::tempdir().unwrap();
    let base = root.path().join("base");
    fs::create_dir(&base).unwrap();
    let traversal = import(
        &base,
        &root.path().join("traversal"),
        b"--- /dev/null\n+++ b/../x\n@@ -0,0 +1 @@\n+x\n",
        &[],
    );
    assert_eq!(traversal.status.code(), Some(2));
    for (n, path) in [".ratarmount-control/x", ".ratarmount-control"]
        .into_iter()
        .enumerate()
    {
        let dest = root.path().join(format!("ctl{n}"));
        let patch = format!("--- /dev/null\n+++ b/{path}\n@@ -0,0 +1 @@\n+x\n");
        let output = import(&base, &dest, patch.as_bytes(), &[]);
        assert_eq!(
            output.status.code(),
            traversal.status.code(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!dest.exists(), "overlay created for {path}");
    }
    let dest = root.path().join("sub");
    let output = import(
        &base,
        &dest,
        b"--- /dev/null\n+++ b/sub/.ratarmount-control/x\n@@ -0,0 +1 @@\n+x\n",
        &["--no-seal"],
    );
    assert_eq!(
        output.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(dest.join("sub/.ratarmount-control/x").is_file());
}
