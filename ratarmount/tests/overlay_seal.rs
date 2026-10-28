//! Regression: real sealed overlays through the offline CLI, without /dev/fuse.

#[path = "support/token.rs"]
mod token;

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;

use ratarmount_compositing::{FolderMountSource, WriteOverlay, HIDDEN_DB};
use ratarmount_core::MountSource;

#[path = "diff/cow.rs"]
mod cow;

fn command(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ratarmount"))
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
fn fixture(root: &Path) -> (String, String) {
    let base = root.join("base");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("file"), b"base\n").unwrap();
    let dir = root.join("overlay");
    let writer = token::overlay_over(
        Arc::new(FolderMountSource::new(&base).unwrap()),
        &dir,
        base.to_str().unwrap(),
        Vec::new(),
    )
    .unwrap();
    cow::cow_write(&writer, "/file", b"change\n");
    drop(writer);
    (base.to_str().unwrap().into(), dir.to_str().unwrap().into())
}

/// Regression: sealing must work through strict diff and the existing -w/--lower mount checks.
#[test]
fn regression_cow_seal_cli_strict_diff_and_real_lower() {
    let tmp = tempfile::tempdir().unwrap();
    let (base, dir) = fixture(tmp.path());
    let text = expect(command(&["overlay", "seal", &dir, "--json"]), 0);
    let meta: serde_json::Value = serde_json::from_str(&text).unwrap();
    let digest = meta["layer_digest"].as_str().unwrap();
    assert!(digest.starts_with("sha256:"));
    assert!(meta["sealed_at"].as_str().unwrap().contains('T'));
    assert_eq!(
        expect(command(&["overlay", "seal", &dir]), 0).trim(),
        digest
    );
    assert_eq!(
        expect(command(&["overlay", "verify", &dir]), 0).trim(),
        digest
    );
    assert_eq!(
        expect(command(&["diff", &dir, "--strict", "--hash"]), 0).trim(),
        digest
    );
    let top = tmp.path().join("top");
    let top = top.to_str().unwrap();
    expect(
        command(&["--no-mount", "--lower", &dir, "-w", top, &base]),
        0,
    );
    expect(command(&["--no-mount", "--lower", &dir, &base]), 0);
    let refused = command(&["--no-mount", "-w", &dir, &base]);
    assert!(String::from_utf8_lossy(&refused.stderr).contains("sealed"));
    assert!(!refused.status.success());
    expect(command(&["overlay", "unseal", &dir]), 2);
    expect(command(&["overlay", "unseal", &dir, "--i-know"]), 0);
    expect(command(&["overlay", "verify", &dir]), 2);
    expect(command(&["--no-mount", "-w", &dir, &base]), 0);
    assert!(!Path::new(&dir).join(".ratarmount-sealed").exists());
    assert_ne!(fs::metadata(&dir).unwrap().permissions().mode() & 0o200, 0);
}

/// Regression: verify must exit 1 naming altered content or the sentinel, without DB writes.
#[test]
fn regression_cow_seal_cli_tamper_exit_one_names_path() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, dir) = fixture(tmp.path());
    expect(command(&["overlay", "seal", &dir]), 0);
    let db = fs::read(Path::new(&dir).join(HIDDEN_DB)).unwrap();
    let file = Path::new(&dir).join("file");
    fs::set_permissions(&file, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&file, b"tamper\n").unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(expect(command(&["overlay", "verify", &dir]), 1)
        .lines()
        .any(|l| l == "file"));
    assert_eq!(fs::read(Path::new(&dir).join(HIDDEN_DB)).unwrap(), db);
    let sentinel = Path::new(&dir).join(".ratarmount-sealed");
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&sentinel, b"bad digest").unwrap();
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o400)).unwrap();
    assert!(expect(command(&["overlay", "verify", &dir]), 1).contains("sentinel mismatch"));
    expect(command(&["overlay", "unseal", &dir, "--i-know"]), 0);
}

/// Regression: BASE/--lower positionals and recorded lower defaults must compose the same view.
#[test]
fn regression_seal_cli_recorded_lowers_and_legacy_explicit_base() {
    let tmp = tempfile::tempdir().unwrap();
    let (base, lower) = fixture(tmp.path());
    expect(command(&["overlay", "seal", &lower]), 0);
    let top = tmp.path().join("top");
    let top = top.to_str().unwrap();
    expect(
        command(&["--no-mount", "-w", top, "--lower", &lower, &base]),
        0,
    );
    expect(
        command(&["overlay", "seal", top, "--lower", &lower, &base]),
        0,
    );
    expect(command(&["overlay", "verify", top]), 0);
    expect(command(&["overlay", "unseal", top, "--i-know"]), 0);
    expect(command(&["overlay", "unseal", &lower, "--i-know"]), 0);
    rusqlite::Connection::open(Path::new(&lower).join(HIDDEN_DB))
        .unwrap()
        .execute_batch("DROP TABLE meta")
        .unwrap();
    let missing = command(&["overlay", "seal", &lower]);
    assert!(String::from_utf8_lossy(&missing.stderr).contains("pass BASE"));
    expect(missing, 2);
    expect(command(&["overlay", "seal", &lower, &base]), 0);
    expect(command(&["overlay", "verify", &lower, &base]), 0);
    expect(command(&["overlay", "unseal", &lower, "--i-know"]), 0);
}

/// Regression: SQLITE_OPEN_NOFOLLOW rejects a symlink in any path component, so
/// fsck, seal, verify and pack failed with "unable to open database file" when
/// the overlay sat below a symlinked directory (every macOS temp dir: /var).
#[test]
fn regression_symlinked_parent_dir_fsck_seal_verify_pack() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    fs::create_dir(&real).unwrap();
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let (_, dir) = fixture(&link);
    assert!(dir.contains("/link/"));
    expect(command(&["overlay", "fsck", &dir]), 0);
    let digest = expect(command(&["overlay", "seal", &dir]), 0);
    assert_eq!(expect(command(&["overlay", "verify", &dir]), 0), digest);
    let bundle = link.join("bundle.tar.zst");
    expect(
        command(&["overlay", "pack", &dir, bundle.to_str().unwrap()]),
        0,
    );
    expect(command(&["overlay", "unseal", &dir, "--i-know"]), 0);
}

/// Regression: an archive base hashed lazily is `pending` until something
/// resolves it; sealing must hash, record and only then seal, so a sealed
/// layer never carries `pending`, and `verify` agrees.
#[test]
fn regression_seal_of_pending_overlay_computes_and_records_digest() {
    use sha2::{Digest, Sha256};
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("base");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("file"), b"base\n").unwrap();
    let archive = tmp.path().join("base.tar");
    assert!(Command::new("tar")
        .arg("cf")
        .arg(&archive)
        .arg("-C")
        .arg(&base)
        .arg("file")
        .status()
        .unwrap()
        .success());
    let dir = tmp.path().join("overlay");
    let writer = token::overlay_over(
        Arc::new(FolderMountSource::new(&base).unwrap()),
        &dir,
        archive.to_str().unwrap(),
        Vec::new(),
    )
    .unwrap();
    cow::cow_write(&writer, "/file", b"change\n");
    drop(writer);
    let meta = ratarmount_compositing::OverlayMeta::read(&dir)
        .unwrap()
        .unwrap();
    assert_eq!(meta.base_digest_kind(), Some("pending"));
    assert_eq!(meta.stack_digest(), None);
    let dir = dir.to_str().unwrap();
    expect(command(&["overlay", "seal", dir]), 0);
    let meta = ratarmount_compositing::OverlayMeta::read(Path::new(dir))
        .unwrap()
        .unwrap();
    assert_eq!(meta.base_digest_kind(), Some("strong"));
    let expected = format!("sha256:{:x}", Sha256::digest(fs::read(&archive).unwrap()));
    assert_eq!(meta.base_digest(), Some(expected.as_str()));
    assert_eq!(
        meta.stack_digest(),
        Some(ratarmount_compositing::stack_digest(&expected, &[]).as_str())
    );
    assert!(meta.layer_sealed());
    expect(command(&["overlay", "verify", dir]), 0);
}

/// Regression: split archives must give an actionable refusal and leave the overlay unsealed.
#[test]
fn regression_seal_cli_split_archive_refused_and_overlay_unsealed() {
    for symlinked in [false, true] {
        for file_url in [false, true] {
            assert_split_seal_refused(symlinked, file_url);
        }
    }
}

fn assert_split_seal_refused(symlinked: bool, file_url: bool) {
    let tmp = tempfile::tempdir().unwrap();
    let payload = [b'x'; 2048];
    let mut archive = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_ustar();
    header.set_size(payload.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive
        .append_data(&mut header, "file", payload.as_slice())
        .unwrap();
    let bytes = archive.into_inner().unwrap();
    let first = tmp.path().join("base.tar.001");
    let second = tmp.path().join("base.tar.002");
    if symlinked {
        let first_target = tmp.path().join("part-one");
        let second_target = tmp.path().join("part-two");
        fs::write(&first_target, &bytes[..1024]).unwrap();
        fs::write(&second_target, &bytes[1024..]).unwrap();
        std::os::unix::fs::symlink(first_target, &first).unwrap();
        std::os::unix::fs::symlink(second_target, &second).unwrap();
    } else {
        fs::write(&first, &bytes[..1024]).unwrap();
        fs::write(&second, &bytes[1024..]).unwrap();
    }
    let dir = tmp.path().join("overlay");
    let base = if file_url {
        format!("file://{}", first.display())
    } else {
        first.to_str().unwrap().to_owned()
    };
    let (dir_s, first_s) = (dir.to_str().unwrap(), base.as_str());
    expect(
        env_command(
            tmp.path(),
            &[
                "--no-mount",
                "--index-file",
                ":memory:",
                "-w",
                dir_s,
                first_s,
            ],
        ),
        0,
    );
    fs::write(dir.join("file"), b"change\n").unwrap();

    for args in [
        vec!["overlay", "seal", dir_s, first_s],
        vec!["overlay", "seal", dir_s],
    ] {
        let out = env_command(tmp.path(), &args);
        let error = String::from_utf8_lossy(&out.stderr);
        assert!(
            error.contains("sealing over a split archive is not supported"),
            "{error}"
        );
        assert!(
            error.contains("join the parts into one archive file and seal that"),
            "{error}"
        );
        expect(out, 2);
        let meta = ratarmount_compositing::OverlayMeta::read(&dir)
            .unwrap()
            .unwrap();
        assert!(!meta.layer_sealed());
        assert_eq!(meta.get("layer_digest"), None);
        assert!(!dir.join(".ratarmount-sealed").exists());
        assert_ne!(fs::metadata(&dir).unwrap().permissions().mode() & 0o200, 0);
        assert_eq!(fs::read(dir.join("file")).unwrap(), b"change\n");
    }
    assert_eq!(fs::read(first).unwrap(), bytes[..1024]);
    assert_eq!(fs::read(second).unwrap(), bytes[1024..]);
}

// ---- overlay verify compares the base (section D) ----

fn env_command(home: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .env("HOME", home)
        .env("XDG_CACHE_HOME", home.join(".cache"))
        .args(args)
        .output()
        .unwrap()
}

/// A sealed overlay over a directory base holding `file` (modified by the
/// layer), `other` (untouched) and `link -> aaaa`. `strong` records a supplied
/// strong digest of the base; otherwise the default weak digest.
fn dir_base_fixture(root: &Path, strong: bool) -> (std::path::PathBuf, String, String) {
    let base = root.join("base");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("file"), b"base\n").unwrap();
    fs::write(base.join("other"), b"other\n").unwrap();
    std::os::unix::fs::symlink("aaaa", base.join("link")).unwrap();
    let dir = root.join("overlay");
    let base_digest = if strong {
        ratarmount_compositing::BaseDigestRequest::Supplied(
            ratarmount_compositing::directory_digest(&base).unwrap(),
        )
    } else {
        Default::default()
    };
    let source: Arc<dyn MountSource> = Arc::new(FolderMountSource::new(&base).unwrap());
    let token = token::ClassifiedBaseOver::folder(source.clone(), &base);
    let writer = WriteOverlay::open(
        &token,
        source,
        &dir,
        &ratarmount_compositing::CreateOptions {
            base_digest,
            ..Default::default()
        },
    )
    .unwrap();
    cow::cow_write(&writer, "/file", b"change\n");
    drop(writer);
    let dir = dir.to_str().unwrap().to_owned();
    expect(env_command(root, &["overlay", "seal", &dir]), 0);
    (base.clone(), base.to_str().unwrap().into(), dir)
}

/// Same-size edit of `path` with its mtime restored.
fn edit_keeping_mtime(path: &Path, bytes: &[u8]) {
    let mtime = fs::metadata(path).unwrap().modified().unwrap();
    fs::write(path, bytes).unwrap();
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
}

fn verify_json(root: &Path, dir: &str, extra: &[&str], code: i32) -> serde_json::Value {
    let mut args = vec!["overlay", "verify", dir, "--json"];
    args.extend_from_slice(extra);
    serde_json::from_str(&expect(env_command(root, &args), code)).unwrap()
}

/// Regression: `overlay verify` hashed only the layer's paths, so an archive
/// base edited with the same size and a restored mtime verified clean.
#[test]
fn regression_verify_base_archive_same_size_mtime_restored() {
    let tmp = tempfile::tempdir().unwrap();
    let archive = tmp.path().join("base.tar");
    fs::write(&archive, [0u8; 2048]).unwrap();
    let dir = tmp.path().join("overlay");
    let (dir, archive_s) = (dir.to_str().unwrap(), archive.to_str().unwrap());
    expect(
        env_command(
            tmp.path(),
            &[
                "--no-mount",
                "--index-file",
                ":memory:",
                "-w",
                dir,
                archive_s,
            ],
        ),
        0,
    );
    expect(env_command(tmp.path(), &["overlay", "seal", dir]), 0);
    let ok = verify_json(tmp.path(), dir, &[], 0);
    assert_eq!(ok["base_ok"], true, "{ok}");
    assert_eq!(ok["base_check"], "strong", "{ok}");
    let mut bytes = vec![0u8; 2048];
    bytes[1500] = 1;
    edit_keeping_mtime(&archive, &bytes);
    let bad = verify_json(tmp.path(), dir, &[], 1);
    assert_eq!(bad["base_ok"], false, "{bad}");
    assert_eq!(bad["base_check"], "strong", "{bad}");
    let text =
        String::from_utf8(env_command(tmp.path(), &["overlay", "verify", dir]).stdout).unwrap();
    assert!(text.contains("base mismatch: recorded sha256:"), "{text}");
    assert!(text.contains(", current sha256:"), "{text}");
    // The opt-out never opens the base.
    let skipped = verify_json(tmp.path(), dir, &["--no-base-check"], 0);
    assert_eq!(skipped["base_check"], "skipped", "{skipped}");
    assert!(skipped["base_ok"].is_null(), "{skipped}");
}

/// Regression: a directory base with a supplied strong digest was never
/// compared at verify; an untouched file edited with its mtime restored passed.
#[test]
fn regression_verify_base_directory_untouched_file_with_supplied_strong_digest() {
    let tmp = tempfile::tempdir().unwrap();
    let (base, _, dir) = dir_base_fixture(tmp.path(), true);
    let ok = verify_json(tmp.path(), &dir, &[], 0);
    assert_eq!(
        (ok["base_ok"].clone(), ok["base_check"].clone()),
        (true.into(), "strong".into())
    );
    edit_keeping_mtime(&base.join("other"), b"OTHER\n");
    let bad = verify_json(tmp.path(), &dir, &[], 1);
    assert_eq!(bad["base_ok"], false, "{bad}");
    assert_eq!(bad["base_check"], "strong", "{bad}");
}

/// Regression: same for a file the layer replaced (its base counterpart changed).
#[test]
fn regression_verify_base_directory_replaced_file_with_supplied_strong_digest() {
    let tmp = tempfile::tempdir().unwrap();
    let (base, _, dir) = dir_base_fixture(tmp.path(), true);
    edit_keeping_mtime(&base.join("file"), b"BASE\n");
    let bad = verify_json(tmp.path(), &dir, &[], 1);
    assert_eq!(bad["base_ok"], false, "{bad}");
}

fn retarget_same_length(base: &Path) {
    use std::os::unix::ffi::OsStrExt;
    let link = base.join("link");
    let before = fs::symlink_metadata(&link).unwrap();
    fs::remove_file(&link).unwrap();
    std::os::unix::fs::symlink("bbbb", &link).unwrap();
    // Restore the symlink's own mtime so only its target differs.
    let times = [
        libc::timespec {
            tv_sec: std::os::unix::fs::MetadataExt::atime(&before),
            tv_nsec: std::os::unix::fs::MetadataExt::atime_nsec(&before),
        },
        libc::timespec {
            tv_sec: std::os::unix::fs::MetadataExt::mtime(&before),
            tv_nsec: std::os::unix::fs::MetadataExt::mtime_nsec(&before),
        },
    ];
    let c = std::ffi::CString::new(link.as_os_str().as_bytes()).unwrap();
    let rc = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            c.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    assert_eq!(rc, 0);
}

/// Regression: a symlink retargeted to a same-length name verified clean, under
/// the default weak digest and under a supplied strong one.
#[test]
fn regression_verify_base_symlink_retargeted_same_length() {
    for strong in [false, true] {
        let tmp = tempfile::tempdir().unwrap();
        let (base, _, dir) = dir_base_fixture(tmp.path(), strong);
        let ok = verify_json(tmp.path(), &dir, &[], 0);
        assert_eq!(ok["base_ok"], true, "{ok}");
        retarget_same_length(&base);
        let bad = verify_json(tmp.path(), &dir, &[], 1);
        assert_eq!(bad["base_ok"], false, "{bad}");
        assert_eq!(
            bad["base_check"],
            if strong { "strong" } else { "weak" },
            "{bad}"
        );
    }
}

/// Documents the limit of the default weak digest: a same-size content edit
/// with a restored mtime is invisible to it (docs/sandbox.md, verify section).
#[test]
fn regression_verify_weak_directory_cannot_see_restored_mtime_edit() {
    let tmp = tempfile::tempdir().unwrap();
    let (base, _, dir) = dir_base_fixture(tmp.path(), false);
    edit_keeping_mtime(&base.join("other"), b"OTHER\n");
    let out = verify_json(tmp.path(), &dir, &[], 0);
    assert_eq!(out["base_check"], "weak", "{out}");
    assert_eq!(out["base_ok"], true, "{out}");
}

/// Regression: a size change of an untouched base file under the weak digest.
#[test]
fn regression_verify_weak_directory_catches_size_change() {
    let tmp = tempfile::tempdir().unwrap();
    let (base, _, dir) = dir_base_fixture(tmp.path(), false);
    fs::write(base.join("other"), b"much longer content\n").unwrap();
    let bad = verify_json(tmp.path(), &dir, &[], 1);
    assert_eq!(bad["base_ok"], false, "{bad}");
    assert_eq!(bad["base_check"], "weak", "{bad}");
    let text =
        String::from_utf8(env_command(tmp.path(), &["overlay", "verify", &dir]).stdout).unwrap();
    assert!(text.contains("base mismatch: recorded weak:"), "{text}");
    assert!(
        text.contains("(weak digest: size/mtime manifest)"),
        "{text}"
    );
}

/// Regression: verify of an unsealed overlay stays refused.
#[test]
fn regression_verify_unsealed_still_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let (_, _, dir) = dir_base_fixture(tmp.path(), false);
    expect(
        env_command(tmp.path(), &["overlay", "unseal", &dir, "--i-know"]),
        0,
    );
    let out = env_command(tmp.path(), &["overlay", "verify", &dir]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("not sealed"));
    expect(out, 2);
}

/// A base with no comparable digest is skipped, not an error.
#[test]
fn regression_verify_base_without_digest_is_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("base");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("file"), b"x\n").unwrap();
    let dir = tmp.path().join("overlay");
    let (dir, base) = (dir.to_str().unwrap(), base.to_str().unwrap());
    expect(
        env_command(
            tmp.path(),
            &["--no-mount", "-w", dir, "--base-digest", "none", base],
        ),
        0,
    );
    expect(env_command(tmp.path(), &["overlay", "seal", dir]), 0);
    let out = verify_json(tmp.path(), dir, &[], 0);
    assert_eq!(out["base_check"], "skipped", "{out}");
    assert!(out["base_ok"].is_null(), "{out}");
}

// ---- an interrupted seal is finished by re-running seal (N3) ----

/// Regression: a seal killed after its commit left no sentinel (verify failed
/// forever) and writable entries (verify passed on a writable tree); re-running
/// `overlay seal` was a silent no-op.
#[test]
fn regression_seal_rerun_cli_finishes_interrupted_seal() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir(&home).unwrap();
    let (_, dir) = fixture(tmp.path());
    let digest = expect(env_command(&home, &["overlay", "seal", &dir]), 0);
    // Simulate the kill: no sentinel, and the payload plus root writable again.
    let dirp = Path::new(&dir);
    let file = dirp.join("file");
    fs::set_permissions(dirp, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&file, fs::Permissions::from_mode(0o644)).unwrap();
    fs::remove_file(dirp.join(".ratarmount-sealed")).unwrap();
    expect(env_command(&home, &["overlay", "verify", &dir]), 1);
    assert_eq!(
        expect(env_command(&home, &["overlay", "seal", &dir]), 0),
        digest
    );
    assert!(dirp.join(".ratarmount-sealed").exists());
    assert_eq!(fs::metadata(&file).unwrap().permissions().mode() & 0o222, 0);
    assert_eq!(fs::metadata(dirp).unwrap().permissions().mode() & 0o222, 0);
    assert_eq!(
        expect(env_command(&home, &["overlay", "verify", &dir]), 0),
        digest
    );
    expect(
        env_command(&home, &["overlay", "unseal", &dir, "--i-know"]),
        0,
    );
}

/// Regression: no reader checked `format_version`, so an overlay written by a
/// newer ratarmount was sealed, verified, packed and listed as format 2.
#[test]
fn regression_format_version_3_refused_by_overlay_verbs() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("home");
    fs::create_dir(&home).unwrap();
    let (_, dir) = fixture(tmp.path());
    expect(env_command(&home, &["overlay", "seal", &dir]), 0);
    let db = Path::new(&dir).join(HIDDEN_DB);
    // A sealed layer is read-only (database and directory): open it up to
    // stand in for an overlay written by a newer build, then close it again.
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&db, fs::Permissions::from_mode(0o644)).unwrap();
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute("UPDATE meta SET value='3' WHERE key='format_version'", [])
        .unwrap();
    fs::set_permissions(&db, fs::Permissions::from_mode(0o444)).unwrap();
    let bundle = tmp.path().join("b.tar.zst");
    for args in [
        vec!["overlay", "info", &dir],
        vec!["overlay", "verify", &dir],
        vec!["overlay", "fsck", &dir],
        vec!["overlay", "seal", &dir],
        vec!["overlay", "pack", &dir, bundle.to_str().unwrap()],
    ] {
        let out = env_command(&home, &args);
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_ne!(out.status.code(), Some(0), "{args:?}: {stderr}");
        assert!(
            stderr.contains("is newer than this ratarmount supports"),
            "{args:?}: {stderr}"
        );
    }
    assert!(!bundle.exists());
}
