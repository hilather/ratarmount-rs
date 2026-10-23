//! Regression: layered mount startup and offline fsck, without /dev/fuse.

#[path = "support/token.rs"]
mod token;

use ratarmount_compositing::{stack_digest, FolderMountSource, OverlayMeta, HIDDEN_DB};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;

#[path = "diff/cow.rs"]
mod cow;

fn open(base: &Path, top: Option<&Path>, lowers: &[&Path], flags: &[&str]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
    cmd.args(["--no-mount", "--index-file", ":memory:"]);
    if let Some(top) = top {
        cmd.arg("-w").arg(top);
    }
    for lower in lowers {
        cmd.arg("--lower").arg(lower);
    }
    cmd.args(flags).arg(base).output().unwrap()
}

fn success(out: Output) {
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

fn seal(dir: &Path, digest: &str) {
    let conn = rusqlite::Connection::open(dir.join(HIDDEN_DB)).unwrap();
    OverlayMeta::set_many(
        &conn,
        &[
            ("sealed_at", "2026-10-17T00:00:00Z"),
            ("layer_digest", digest),
        ],
    )
    .unwrap();
}

/// Regression: top creation lost ordered lower digests, and remount accepted another stack.
#[test]
fn regression_lower_cli_records_stack_and_refuses_mismatch_unless_forced() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("base");
    fs::create_dir(&base).unwrap();
    let first = tmp.path().join("first");
    let second = tmp.path().join("second");
    for (dir, digest) in [(&first, "sha256:first"), (&second, "sha256:second")] {
        success(open(&base, Some(dir), &[], &[]));
        seal(dir, digest);
    }
    let top = tmp.path().join("top");
    success(open(&base, Some(&top), &[&first, &second], &[]));
    let meta = OverlayMeta::read(&top).unwrap().unwrap();
    let lowers = meta.lower_layers().unwrap();
    assert_eq!(lowers[0].path, first.canonicalize().unwrap());
    assert_eq!(lowers[1].path, second.canonicalize().unwrap());
    assert_eq!(lowers[0].layer_digest, "sha256:first");
    assert_eq!(lowers[0].sealed_at, "2026-10-17T00:00:00Z");
    assert_eq!(
        meta.stack_digest(),
        Some(
            stack_digest(
                meta.base_digest().unwrap(),
                &["sha256:first", "sha256:second"]
            )
            .as_str()
        )
    );
    success(open(&base, Some(&top), &[&first, &second], &[]));
    for given in [
        vec![first.as_path()],
        vec![second.as_path(), first.as_path()],
        vec![],
    ] {
        let refused = open(&base, Some(&top), &given, &[]);
        assert_eq!(refused.status.code(), Some(1));
        let error = String::from_utf8_lossy(&refused.stderr);
        assert!(
            error.contains("recorded lower_layers") && error.contains("given --lower"),
            "{error}"
        );
        assert!(
            error.contains(first.to_str().unwrap()) && error.contains(second.to_str().unwrap())
        );
    }
    seal(&first, "sha256:changed");
    assert!(!open(&base, Some(&top), &[&first, &second], &[])
        .status
        .success());
    success(open(
        &base,
        Some(&top),
        &[&first, &second],
        &["--force-stack-mismatch"],
    ));
    assert!(OverlayMeta::read(&top)
        .unwrap()
        .unwrap()
        .get("stack_mismatch_forced_at")
        .is_some());
    // Forcing does not rewrite the original stack identity.
    assert_eq!(
        OverlayMeta::read(&top)
            .unwrap()
            .unwrap()
            .lower_layers()
            .unwrap(),
        lowers
    );
    success(open(&base, None, &[&first, &second], &[]));
}

/// Regression: sealed tops could be written using -w or the sandbox preset.
#[test]
fn regression_lower_cli_sealed_top_and_unsealed_lower_checks() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("base");
    fs::create_dir(&base).unwrap();
    let lower = tmp.path().join("lower");
    success(open(&base, Some(&lower), &[], &[]));
    let refused = open(&base, None, &[&lower], &[]);
    assert!(String::from_utf8_lossy(&refused.stderr).contains("unsealed"));
    success(open(&base, None, &[&lower], &["--allow-unsealed-lower"]));
    let top = tmp.path().join("top");
    success(open(
        &base,
        Some(&top),
        &[&lower],
        &["--allow-unsealed-lower"],
    ));
    let record = OverlayMeta::read(&top)
        .unwrap()
        .unwrap()
        .lower_layers()
        .unwrap()
        .remove(0);
    assert!(record.layer_digest.is_empty() && record.sealed_at.is_empty());
    seal(&lower, "sha256:sealed");
    let before = fs::read(lower.join(HIDDEN_DB)).unwrap();
    for flags in [vec![], vec!["--sandbox"], vec!["--force-stack-mismatch"]] {
        let refused = open(&base, Some(&lower), &[], &flags);
        assert_eq!(refused.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&refused.stderr)
            .contains("sealed; mount it with --lower, or `overlay unseal`"));
    }
    assert_eq!(fs::read(lower.join(HIDDEN_DB)).unwrap(), before);
    success(open(&base, None, &[&lower], &[]));
}

fn fsck(dir: &Path, repair: bool) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
    cmd.args(["overlay", "fsck"]).arg(dir).arg("--json");
    if repair {
        cmd.arg("--repair");
    }
    cmd.output().unwrap()
}

/// Regression: fsck exit codes distinguish inconsistencies, successful repair, and errors.
#[test]
fn regression_cow_lower_fsck_cli_json_exit_codes_and_lock() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("base");
    fs::create_dir(&base).unwrap();
    let dir = tmp.path().join("overlay");
    assert_eq!(fsck(&dir, false).status.code(), Some(2));
    success(open(&base, Some(&dir), &[], &[]));
    fs::write(base.join("cow"), b"base").unwrap();
    let ov = token::new_overlay(Arc::new(FolderMountSource::new(&base).unwrap()), &dir).unwrap();
    cow::cow_write(&ov, "/cow", b"changed");
    drop(ov);
    let output = fsck(&dir, true);
    assert!(output.status.success());
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["unrowed"], 1);
    assert_eq!(json["orphan_content"], 0);
    assert_eq!(json["repaired"], 0);
    assert_eq!(json["result"], "ok");
    let conn = rusqlite::Connection::open(dir.join(HIDDEN_DB)).unwrap();
    assert_eq!(
        conn.query_row("SELECT count(*) FROM files", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        0
    );
    conn.execute(
        "INSERT INTO files(path,name,mode,deleted) VALUES ('','missing',33188,0)",
        [],
    )
    .unwrap();
    drop(conn);
    let output = fsck(&dir, false);
    assert_eq!(output.status.code(), Some(1));
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["missing_content"], 1);
    assert_eq!(json["result"], "errors:1");
    let human = Command::new(env!("CARGO_BIN_EXE_ratarmount"))
        .args(["overlay", "fsck"])
        .arg(&dir)
        .output()
        .unwrap();
    assert_eq!(human.status.code(), Some(1));
    let text = String::from_utf8_lossy(&human.stdout);
    assert!(text.contains("missing_content: 1") && text.contains("result: errors:1"));
    success(fsck(&dir, true));
    success(fsck(&dir, false));
    let mounted =
        token::new_overlay(Arc::new(FolderMountSource::new(base).unwrap()), &dir).unwrap();
    let busy = fsck(&dir, true);
    assert_eq!(busy.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&busy.stderr).contains("in use"));
    drop(mounted);
    seal(&dir, "sha256:sealed");
    assert_eq!(fsck(&dir, true).status.code(), Some(2));
    success(fsck(&dir, false));
}

/// Regression: a top over a sealed lower on a directory base records its own
/// weak measurement and a stack digest built from it, not the lower's value;
/// a supplied `--base-digest` is recorded as given. Two tops over the same
/// lower and base agree.
#[test]
fn regression_stack_top_over_lower_measures_own_base() {
    let tmp = tempfile::tempdir().unwrap();
    let base = tmp.path().join("base");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("f"), b"one").unwrap();
    let lower = tmp.path().join("lower");
    success(open(&base, Some(&lower), &[], &[]));
    seal(&lower, "sha256:lower");
    // Forge the lower's recorded identity: only the top's own measurement counts.
    let conn = rusqlite::Connection::open(lower.join(HIDDEN_DB)).unwrap();
    OverlayMeta::set(&conn, "base_digest", "sha256:forged").unwrap();
    drop(conn);
    let [a, b, c] = ["a", "b", "c"].map(|n| tmp.path().join(n));
    success(open(&base, Some(&a), &[&lower], &[]));
    success(open(&base, Some(&b), &[&lower], &[]));
    let supplied = format!("sha256:{}", "cd".repeat(32));
    success(open(
        &base,
        Some(&c),
        &[&lower],
        &["--base-digest", &supplied],
    ));
    let meta_a = OverlayMeta::read(&a).unwrap().unwrap();
    let own = meta_a.base_digest().unwrap();
    assert!(own.starts_with("weak:"), "{own}");
    assert_eq!(
        meta_a.stack_digest(),
        Some(stack_digest(own, &["sha256:lower"]).as_str())
    );
    let meta_b = OverlayMeta::read(&b).unwrap().unwrap();
    assert_eq!(meta_b.stack_digest(), meta_a.stack_digest());
    let meta_c = OverlayMeta::read(&c).unwrap().unwrap();
    assert_eq!(meta_c.base_digest(), Some(supplied.as_str()));
}

fn dir_base(root: &Path, name: &str, body: &[u8]) -> std::path::PathBuf {
    let base = root.join(name);
    fs::create_dir(&base).unwrap();
    fs::write(base.join("f"), body).unwrap();
    base
}

fn tar_base(path: &Path, body: &[u8]) {
    let mut tar = tar::Builder::new(fs::File::create(path).unwrap());
    let mut header = tar::Header::new_gnu();
    header.set_size(body.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar.append_data(&mut header, "f", body).unwrap();
    tar.finish().unwrap();
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

/// Regression: a lower sealed against one base mounted over another base was
/// accepted (read-only and as the lower of a `-w` top) and reported the lower's
/// own base identity.
#[test]
fn regression_lower_over_different_directory_base_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let x = dir_base(tmp.path(), "x", b"one");
    let y = dir_base(tmp.path(), "y", b"different length");
    let lower = tmp.path().join("lower");
    success(open(&x, Some(&lower), &[], &[]));
    seal(&lower, "sha256:lower");
    success(open(&x, None, &[&lower], &[]));
    for top in [None, Some(tmp.path().join("top"))] {
        let refused = open(&y, top.as_deref(), &[&lower], &[]);
        assert_eq!(refused.status.code(), Some(1), "{}", stderr(&refused));
        let error = stderr(&refused);
        assert!(
            error.contains("sealed against a different base")
                && error.contains("overlay verify")
                && error.contains("--force-stack-mismatch"),
            "{error}"
        );
        success(open(
            &y,
            top.as_deref(),
            &[&lower],
            &["--force-stack-mismatch"],
        ));
    }
}

/// Regression: a base edited after the lower was sealed was accepted; the
/// comparison is a metadata walk, so it must not read file content.
#[test]
fn regression_lower_directory_edit_is_refused_without_reading() {
    let tmp = tempfile::tempdir().unwrap();
    let base = dir_base(tmp.path(), "base", b"one");
    let lower = tmp.path().join("lower");
    success(open(&base, Some(&lower), &[], &[]));
    seal(&lower, "sha256:lower");
    success(open(&base, None, &[&lower], &[]));
    fs::write(base.join("g"), b"added after sealing").unwrap();
    let refused = open(&base, None, &[&lower], &[]);
    assert_eq!(refused.status.code(), Some(1), "{}", stderr(&refused));
    assert!(stderr(&refused).contains("sealed against a different base"));
}

/// Regression: a lower sealed against archive X mounted over archive Y.
#[test]
fn regression_lower_over_different_archive_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let x = tmp.path().join("x.tar");
    let y = tmp.path().join("y.tar");
    tar_base(&x, b"one");
    // Tar pads to 10 KiB blocks: a different size needs a bigger body.
    tar_base(&y, &[b'y'; 20_000]);
    let lower = tmp.path().join("lower");
    success(open(&x, Some(&lower), &[], &[]));
    seal(&lower, "sha256:lower");
    success(open(&x, None, &[&lower], &[]));
    for top in [None, Some(tmp.path().join("top"))] {
        let refused = open(&y, top.as_deref(), &[&lower], &[]);
        assert_eq!(refused.status.code(), Some(1), "{}", stderr(&refused));
        assert!(stderr(&refused).contains("sealed against a different base"));
        success(open(
            &y,
            top.as_deref(),
            &[&lower],
            &["--force-stack-mismatch"],
        ));
    }
}

/// A lower recorded with `--base-digest none` carries no identity: accepted.
#[test]
fn regression_lower_none_kind_lower_is_accepted_over_any_base() {
    let tmp = tempfile::tempdir().unwrap();
    let x = dir_base(tmp.path(), "x", b"one");
    let y = dir_base(tmp.path(), "y", b"different length");
    let lower = tmp.path().join("lower");
    success(open(&x, Some(&lower), &[], &["--base-digest", "none"]));
    seal(&lower, "sha256:lower");
    success(open(&y, None, &[&lower], &[]));
}

/// Regression: the lower's overlay inside the base (excluded from its weak
/// digest) that grows after sealing must not make the unchanged base differ.
#[test]
fn regression_a2_bottom_lower_with_own_exclusions_then_new_top() {
    let tmp = tempfile::tempdir().unwrap();
    let base = dir_base(tmp.path(), "base", b"one");
    let lower = base.join("lower-ov");
    success(open(&base, Some(&lower), &[], &[]));
    fs::write(lower.join("grown"), b"written after creation").unwrap();
    seal(&lower, "sha256:lower");
    success(open(&base, None, &[&lower], &[]));
    success(open(&base, Some(&tmp.path().join("top")), &[&lower], &[]));
    fs::write(base.join("g"), b"real change").unwrap();
    let refused = open(&base, None, &[&lower], &[]);
    assert_eq!(refused.status.code(), Some(1), "{}", stderr(&refused));
}
