#![allow(clippy::disallowed_methods)]

use super::*;
use crate::{FolderMountSource, WriteOverlay};
use ratarmount_core::{ArchiveRead, FileInfo, ListResult, MountSource};
use std::io;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

fn base(root: &Path) -> Arc<dyn MountSource> {
    Arc::new(FolderMountSource::new(root).unwrap())
}

fn info(path: &Path) -> OverlayCreateInfo {
    OverlayCreateInfo {
        base_url: path.to_str().unwrap().into(),
        ..Default::default()
    }
}

fn meta_with(rows: &[(&str, &str)]) -> OverlayMeta {
    OverlayMeta {
        values: rows
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    }
}

fn probe<'a>(
    path: Option<&'a Path>,
    git_tree: Option<&'a str>,
    supplied: Option<&'a str>,
    index: Option<&'a Path>,
) -> ContentProbe<'a> {
    ContentProbe {
        path,
        git_tree,
        supplied,
        index,
        extra_excludes: &[],
    }
}

/// Regression (Keystone mutant `recorded_tree != tree` -> `==`): the Git
/// branch of the `--lower` / seal / pack / diff base check refuses another
/// tree and accepts the recorded one.
#[test]
fn regression_compare_base_git_tree_mismatch_and_match() {
    let meta = meta_with(&[
        ("base_digest_kind", "git-tree"),
        ("base_digest", "git-tree:aaa"),
        ("base_git_tree", "aaa"),
    ]);
    let other = compare_content(Some(&meta), &probe(None, Some("bbb"), None, None)).unwrap();
    assert_eq!(other.mismatch.as_deref(), Some("git-tree:bbb"));
    assert_eq!(other.identity, "git-tree:bbb");
    let same = compare_content(Some(&meta), &probe(None, Some("aaa"), None, None)).unwrap();
    assert_eq!(same.mismatch, None);
    // Kind `none` recorded nothing to compare.
    let none = meta_with(&[("base_digest_kind", "none"), ("base_git_tree", "aaa")]);
    assert_eq!(
        compare_content(Some(&none), &probe(None, Some("bbb"), None, None))
            .unwrap()
            .mismatch,
        None
    );
}

/// Regression (R4-S3): a strong record with no stamp, manifest or tree (an
/// overlay made over an HTTP base) was accepted over any unrelated local
/// directory, archive or Git tree. Only the same strong digest, supplied or
/// cached, confirms it; a remote probe (no local path) keeps its behaviour.
#[test]
fn regression_compare_base_strong_without_local_rows_needs_confirmation() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("f"), b"unrelated").unwrap();
    let archive = dir.path().join("a.tar");
    fs::write(&archive, b"not the base").unwrap();
    let strong = format!("sha256:{}", "a".repeat(64));
    let other = format!("sha256:{}", "b".repeat(64));
    let record = meta_with(&[
        ("base_digest_kind", "strong"),
        ("base_digest", strong.as_str()),
        ("base_kind", "remote"),
    ]);
    // The same record taken over a directory / archive (kind row, no
    // manifest or stamp) needs the digest to confirm.
    for (path, kind) in [(dir.path(), "directory"), (archive.as_path(), "archive")] {
        let record = meta_with(&[
            ("base_digest_kind", "strong"),
            ("base_digest", strong.as_str()),
            ("base_kind", kind),
        ]);
        let bad = compare_content(Some(&record), &probe(Some(path), None, None, None)).unwrap();
        assert!(bad.mismatch.is_some(), "{path:?} accepted unconfirmed");
        let wrong =
            compare_content(Some(&record), &probe(Some(path), None, Some(&other), None)).unwrap();
        assert!(wrong.mismatch.is_some(), "{path:?} accepted a wrong digest");
        let ok =
            compare_content(Some(&record), &probe(Some(path), None, Some(&strong), None)).unwrap();
        assert_eq!(ok.mismatch, None, "{path:?}");
    }
    let git = compare_content(Some(&record), &probe(None, Some("abc"), None, None)).unwrap();
    assert!(git.mismatch.is_some(), "git tree accepted unconfirmed");
    let remote = compare_content(Some(&record), &probe(None, None, None, None)).unwrap();
    assert_eq!(remote.mismatch, None);
}

/// Regression (Keystone mutant on `need_walk`): a supplied digest skips the
/// walk only when there is no recorded manifest to compare; with one, the
/// walk runs and a strong record is confirmed by the supplied digest.
#[test]
fn regression_compare_base_need_walk_with_supplied_digest() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("f"), b"one").unwrap();
    let weak = directory_weak_digest(dir.path(), &BaseExcludes::default()).unwrap();
    let strong = format!("sha256:{}", "a".repeat(64));
    fs::write(dir.path().join("f"), b"edited").unwrap();
    let record = |extra: &[(&'static str, &str)]| {
        let mut rows = vec![
            ("base_digest_kind", "strong"),
            ("base_digest", strong.as_str()),
            ("base_kind", "directory"),
        ];
        rows.extend_from_slice(extra);
        meta_with(&rows)
    };
    // Recorded manifest + supplied digest: walked (the edit is seen), then
    // confirmed by the equal supplied digest.
    let with_weak = record(&[("base_weak_digest", weak.as_str())]);
    let walks = directory_weak_walks_this_thread();
    let ok = compare_content(
        Some(&with_weak),
        &probe(Some(dir.path()), None, Some(&strong), None),
    )
    .unwrap();
    assert_eq!(directory_weak_walks_this_thread() - walks, 1);
    assert!(ok.weak.as_ref().is_some_and(|w| *w != weak));
    assert_eq!(ok.mismatch, None);
    assert_eq!(ok.identity, strong);
    // A different supplied digest, or none, is a mismatch.
    let other = format!("sha256:{}", "b".repeat(64));
    for supplied in [Some(other.as_str()), None] {
        let bad = compare_content(
            Some(&with_weak),
            &probe(Some(dir.path()), None, supplied, None),
        )
        .unwrap();
        assert!(bad.mismatch.is_some(), "{supplied:?}");
    }
    // No recorded manifest and a supplied digest: nothing to walk.
    let without = record(&[]);
    let walks = directory_weak_walks_this_thread();
    let ok = compare_content(
        Some(&without),
        &probe(Some(dir.path()), None, Some(&strong), None),
    )
    .unwrap();
    assert_eq!(directory_weak_walks_this_thread(), walks);
    assert_eq!((ok.weak, ok.mismatch), (None, None));
    // Kind `none` with a recorded manifest: undecidable, so no walk either.
    let none = meta_with(&[
        ("base_digest_kind", "none"),
        ("base_weak_digest", weak.as_str()),
    ]);
    let walks = directory_weak_walks_this_thread();
    let ok = compare_content(
        Some(&none),
        &probe(Some(dir.path()), None, Some(&strong), None),
    )
    .unwrap();
    assert_eq!(directory_weak_walks_this_thread(), walks);
    assert_eq!(ok.mismatch, None);
}

/// An archive whose stamp differs is confirmed by the digest already
/// cached in its index (never hashed here), or by a supplied one.
#[test]
fn regression_compare_base_archive_confirmed_by_cached_or_supplied_digest() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("copy.tar");
    fs::write(&archive, b"bytes").unwrap();
    let index = dir.path().join("copy.tar.index.sqlite");
    let digest = format!("sha256:{}", "c".repeat(64));
    let record = meta_with(&[
        ("base_digest_kind", "strong"),
        ("base_digest", digest.as_str()),
        ("base_size", "999"),
        ("base_mtime_ns", "1"),
    ]);
    // Nothing cached: not confirmed.
    let miss = compare_content(
        Some(&record),
        &probe(Some(&archive), None, None, Some(&index)),
    )
    .unwrap();
    assert!(miss.mismatch.is_some());
    // Cache the (recorded) digest without hashing anything here.
    Connection::open(&index)
        .unwrap()
        .execute_batch("CREATE TABLE files (name TEXT);")
        .unwrap();
    ratarmount_index::cached_archive_digest_with(&archive, Some(&index), |_| Ok("c".repeat(64)))
        .unwrap();
    let hit = compare_content(
        Some(&record),
        &probe(Some(&archive), None, None, Some(&index)),
    )
    .unwrap();
    assert_eq!(
        (hit.mismatch, hit.identity.as_str()),
        (None, digest.as_str())
    );
    // A cached digest that is not the recorded one does not confirm.
    let other = meta_with(&[
        ("base_digest_kind", "strong"),
        ("base_digest", "sha256:dd"),
        ("base_size", "999"),
        ("base_mtime_ns", "1"),
    ]);
    assert!(compare_content(
        Some(&other),
        &probe(Some(&archive), None, None, Some(&index))
    )
    .unwrap()
    .mismatch
    .is_some());
    // Supplied equals recorded: confirmed even with no cache.
    let supplied = compare_content(
        Some(&record),
        &probe(Some(&archive), None, Some(&digest), None),
    )
    .unwrap();
    assert_eq!(supplied.mismatch, None);
    // A weak record is never rescued by a digest.
    let weak = meta_with(&[
        ("base_digest_kind", "weak"),
        ("base_digest", digest.as_str()),
        ("base_size", "999"),
        ("base_mtime_ns", "1"),
    ]);
    assert!(compare_content(
        Some(&weak),
        &probe(Some(&archive), None, Some(&digest), Some(&index))
    )
    .unwrap()
    .mismatch
    .is_some());
}

/// Regression: committing must preserve digest opt-out and legacy identities.
#[test]
fn regression_overlay_meta_commit_preserves_kind_and_legacy() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("base.tar");
    fs::write(&archive, b"after commit").unwrap();
    for kind in ["none", "weak"] {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(META_SCHEMA).unwrap();
        OverlayMeta::set_many(
            &conn,
            &[
                ("format_version", "2"),
                ("base_digest_kind", kind),
                ("base_digest", kind),
                ("lower_layers", "[]"),
            ],
        )
        .unwrap();
        refresh_committed_base(&conn, None, &archive).unwrap();
        let meta = OverlayMeta::from_connection(&conn).unwrap().unwrap();
        assert_eq!(meta.base_digest_kind(), Some(kind));
        assert_eq!(meta.get("base_size"), Some("12"));
        assert!(meta.get("base_committed_at").is_some());
        if kind == "none" {
            assert_eq!(meta.base_digest(), Some("none"));
        } else {
            assert!(meta.base_digest().unwrap().starts_with("weak:size=12,"));
        }
    }
    let conn = Connection::open_in_memory().unwrap();
    refresh_committed_base(&conn, None, &archive).unwrap();
    assert!(OverlayMeta::from_connection(&conn).unwrap().is_none());
    conn.execute_batch(META_SCHEMA).unwrap();
    OverlayMeta::set(&conn, "format_version", "1").unwrap();
    refresh_committed_base(&conn, None, &archive).unwrap();
    let meta = OverlayMeta::from_connection(&conn).unwrap().unwrap();
    assert_eq!(meta.values().len(), 1);
    assert!(meta.legacy());
}

/// Regression: new overlays lacked creation identity and stack ordering.
#[test]
fn regression_overlay_meta_creation_keys_and_stack_vector() {
    assert_eq!(
        stack_digest("sha256:base", &["sha256:first", "sha256:second"]),
        "sha256:4e3fef1cc62d99d7f6cb7fd49747c58d4f5f72e513cb7f3ed443c7fc44c31a6c"
    );
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("base.tar");
    fs::write(&archive, b"abc").unwrap();
    let overlay = root.path().join("overlay");
    let mut info = info(&archive);
    info.lower_layers.push(LowerLayerRecord {
        path: "prepared".into(),
        layer_digest: "sha256:first".into(),
        sealed_at: "2026-10-17T00:00:00Z".into(),
    });
    drop(WriteOverlay::new_with_create_info_for_tests(base(root.path()), &overlay, &info).unwrap());
    // An uncached archive is `pending` until something resolves it.
    assert_eq!(meta_of(&overlay).base_digest_kind(), Some("pending"));
    let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
    assert!(resolve_pending_base_digest(&conn).unwrap());
    drop(conn);
    let meta = OverlayMeta::read(&overlay).unwrap().unwrap();
    for key in [
        "format_version",
        "ratarmount_version",
        "created_at",
        "base_url",
        "base_digest",
        "base_digest_kind",
        "lower_layers",
        "stack_digest",
        "base_size",
        "base_mtime_ns",
    ] {
        assert!(meta.get(key).is_some(), "missing {key}");
    }
    chrono::DateTime::parse_from_rfc3339(meta.get("created_at").unwrap()).unwrap();
    assert_eq!(meta.format_version().unwrap(), Some(2));
    assert!(!meta.legacy());
    assert!(!meta.layer_sealed());
    assert_eq!(meta.base_digest_kind(), Some("strong"));
    assert_eq!(meta.base_url(), Some(info.base_url.as_str()));
    assert_eq!(
        meta.base_digest(),
        Some("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    assert_eq!(meta.lower_layers().unwrap(), info.lower_layers);
    assert_eq!(
        meta.stack_digest(),
        Some(stack_digest(meta.base_digest().unwrap(), &["sha256:first"]).as_str())
    );
}

/// Regression: `--base-digest none` on REOPEN of a weak directory overlay
/// suppressed the exclusion plan, skipped the recorded weak comparison and
/// accepted a changed base without `--force-base-mismatch`. The flag only
/// applies at creation; a reopen always compares the recorded identity.
#[test]
fn regression_reopen_with_base_digest_none_still_compares_recorded_weak() {
    let root = tempfile::tempdir().unwrap();
    let basedir = root.path().join("base");
    fs::create_dir(&basedir).unwrap();
    fs::write(basedir.join("f"), b"abc").unwrap();
    let overlay = root.path().join("overlay");
    drop(open_dir_base(&basedir, &overlay, &info(&basedir)).unwrap());
    assert!(OverlayMeta::read(&overlay)
        .unwrap()
        .unwrap()
        .get("base_weak_digest")
        .is_some());
    fs::write(basedir.join("f"), b"abcdef").unwrap();
    let mut request = info(&basedir);
    request.base_digest = BaseDigestRequest::None;
    request.force_base_mismatch = false;
    let err = open_dir_base(&basedir, &overlay, &request)
        .err()
        .expect("changed base must be refused")
        .to_string();
    assert!(err.contains("base mismatch"), "{err}");
    assert!(err.contains("--force-base-mismatch"), "{err}");
    // Forced: accepted, and the override is recorded.
    request.force_base_mismatch = true;
    drop(open_dir_base(&basedir, &overlay, &request).unwrap());
    assert!(OverlayMeta::read(&overlay)
        .unwrap()
        .unwrap()
        .get("base_mismatch_forced_at")
        .is_some());
    // A new overlay created with `none` still records no walk.
    let fresh = root.path().join("fresh");
    drop(open_dir_base(&basedir, &fresh, &request).unwrap());
    let meta = OverlayMeta::read(&fresh).unwrap().unwrap();
    assert_eq!(meta.base_digest_kind(), Some("none"));
    assert!(meta.get("base_weak_digest").is_none());
}

/// Regression: legacy overlays must keep tombstones and remain digest-free after migration.
#[test]
fn regression_overlay_meta_legacy_migration_preserves_deletions() {
    let root = tempfile::tempdir().unwrap();
    fs::write(root.path().join("deleted"), b"base").unwrap();
    let overlay = root.path().join("overlay");
    fs::create_dir(&overlay).unwrap();
    let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
    conn.execute_batch("CREATE TABLE files (path TEXT, name TEXT, mtime REAL, mode INTEGER, uid INTEGER, gid INTEGER, deleted BOOL, PRIMARY KEY(path,name)); INSERT INTO files VALUES ('','deleted',0,33188,0,0,1);").unwrap();
    drop(conn);
    assert!(OverlayMeta::read(&overlay).unwrap().is_none());
    let mut context = info(Path::new("missing base that must never be hashed"));
    context.force_base_mismatch = false;
    let ov = WriteOverlay::new_with_create_info_for_tests(base(root.path()), &overlay, &context)
        .unwrap();
    assert!(ov.lookup("/deleted", 0).is_none());
    drop(ov);
    let meta = OverlayMeta::read(&overlay).unwrap().unwrap();
    assert!(meta.legacy());
    assert_eq!(
        meta.values(),
        &BTreeMap::from([("format_version".into(), "1".into())])
    );
}

struct CountingBase(AtomicUsize);
impl MountSource for CountingBase {
    fn is_immutable(&self) -> bool {
        true
    }
    fn list(&self, _: &str) -> Option<ListResult> {
        None
    }
    fn lookup(&self, _: &str, _: i32) -> Option<FileInfo> {
        None
    }
    fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ArchiveRead>> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(io::Error::other("base payload must not be read"))
    }
}

/// Regression: a caller-supplied digest must never hash or open base payloads.
#[test]
fn regression_overlay_meta_supplied_digest_reads_no_base_bytes() {
    let root = tempfile::tempdir().unwrap();
    let source = Arc::new(CountingBase(AtomicUsize::new(0)));
    // A nonexistent local file would make the real file hasher fail.
    let mut context = info(&root.path().join("unreadable-base"));
    context.base_digest = BaseDigestRequest::Supplied(format!("sha256:{}", "a".repeat(64)));
    let overlay = root.path().join("overlay");
    drop(WriteOverlay::new_with_create_info_for_tests(source.clone(), &overlay, &context).unwrap());
    assert_eq!(source.0.load(Ordering::SeqCst), 0);
    assert_eq!(
        OverlayMeta::read(&overlay).unwrap().unwrap().base_digest(),
        Some(format!("sha256:{}", "a".repeat(64)).as_str())
    );
}

/// Regression: unchanged remounts rehashed bytes; changed bases were silently accepted.
#[test]
fn regression_overlay_meta_remount_mismatch_and_force() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("a.tar");
    fs::write(&archive, b"abc").unwrap();
    let overlay = root.path().join("overlay");
    let mut context = info(&archive);
    drop(
        WriteOverlay::new_with_create_info_for_tests(base(root.path()), &overlay, &context)
            .unwrap(),
    );
    resolve_pending_base_digest(&Connection::open(overlay.join(HIDDEN_DB)).unwrap()).unwrap();
    let old = OverlayMeta::read(&overlay)
        .unwrap()
        .unwrap()
        .base_digest()
        .unwrap()
        .to_owned();
    // Deliberately preserving size and mtime demonstrates the documented
    // cheap check: a remount must not compare newly hashed contents.
    let modified = fs::metadata(&archive).unwrap().modified().unwrap();
    fs::write(&archive, b"xyz").unwrap();
    fs::File::options()
        .write(true)
        .open(&archive)
        .unwrap()
        .set_modified(modified)
        .unwrap();
    context.index_path = Some(root.path().join("missing-index"));
    drop(
        WriteOverlay::new_with_create_info_for_tests(base(root.path()), &overlay, &context)
            .unwrap(),
    );
    assert!(!context.index_path.as_ref().unwrap().exists());
    fs::write(&archive, b"changed").unwrap();
    let error = WriteOverlay::new_with_create_info_for_tests(base(root.path()), &overlay, &context)
        .err()
        .unwrap()
        .to_string();
    assert!(
        error.contains(&old) && error.contains("current digest weak:size=7"),
        "{error}"
    );
    assert!(OverlayMeta::read(&overlay)
        .unwrap()
        .unwrap()
        .get("base_mismatch_forced_at")
        .is_none());
    context.force_base_mismatch = true;
    drop(
        WriteOverlay::new_with_create_info_for_tests(base(root.path()), &overlay, &context)
            .unwrap(),
    );
    let meta = OverlayMeta::read(&overlay).unwrap().unwrap();
    assert!(meta.get("base_mismatch_forced_at").is_some());
    assert_eq!(meta.base_digest(), Some(old.as_str()));
}

/// Regression: Git refs need a tree identity, while unavailable remote metadata stays weak.
#[test]
fn regression_overlay_meta_git_remote_and_none_kinds() {
    let root = tempfile::tempdir().unwrap();
    let mut context = OverlayCreateInfo {
        base_url: "repo@main".into(),
        git_tree: Some("a".repeat(40)),
        ..Default::default()
    };
    let overlay = root.path().join("git");
    drop(
        WriteOverlay::new_with_create_info_for_tests(base(root.path()), &overlay, &context)
            .unwrap(),
    );
    assert_eq!(
        OverlayMeta::read(&overlay)
            .unwrap()
            .unwrap()
            .base_digest_kind(),
        Some("git-tree")
    );
    context.git_tree = Some("b".repeat(40));
    let error = WriteOverlay::new_with_create_info_for_tests(base(root.path()), &overlay, &context)
        .err()
        .unwrap()
        .to_string();
    assert!(
        error.contains(&format!("git-tree:{}", "a".repeat(40)))
            && error.contains(&format!("git-tree:{}", "b".repeat(40)))
    );
    let remote = OverlayCreateInfo {
        base_url: "hf://datasets/a/b@main/snapshot.tar".into(),
        ..Default::default()
    };
    assert_eq!(remote.digest(None).unwrap().1, "weak");
    assert_eq!(remote.digest(None).unwrap(), remote.digest(None).unwrap());
    let with_token = OverlayCreateInfo {
        remote_token: Some("etag:123".into()),
        ..remote.clone()
    };
    assert_ne!(
        remote.digest(None).unwrap().0,
        with_token.digest(None).unwrap().0
    );
    let overlay = root.path().join("no-context");
    drop(WriteOverlay::new_for_tests(base(root.path()), &overlay).unwrap());
    let meta = OverlayMeta::read(&overlay).unwrap().unwrap();
    assert_eq!(meta.base_digest_kind(), Some("none"));
    assert_eq!(meta.format_version().unwrap(), Some(2));
}

/// Regression: a directory digest depended on creation order or followed symlinks.
#[test]
fn regression_overlay_meta_directory_digest_deterministic() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    for (root, names) in [(a.path(), ["one", "two"]), (b.path(), ["two", "one"])] {
        for name in names {
            fs::write(root.join(name), name).unwrap();
        }
        fs::create_dir(root.join("empty")).unwrap();
    }
    assert_eq!(
        directory_digest(a.path()).unwrap(),
        directory_digest(b.path()).unwrap()
    );
    fs::write(b.path().join("one"), "changed").unwrap();
    assert_ne!(
        directory_digest(a.path()).unwrap(),
        directory_digest(b.path()).unwrap()
    );
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("/absent-target", a.path().join("link")).unwrap();
        assert!(directory_digest(a.path()).is_ok());
        use std::os::unix::fs::PermissionsExt;
        let before = directory_digest(a.path()).unwrap();
        fs::set_permissions(a.path().join("one"), fs::Permissions::from_mode(0o755)).unwrap();
        assert_ne!(directory_digest(a.path()).unwrap(), before);
    }
}

fn meta_of(overlay: &Path) -> OverlayMeta {
    OverlayMeta::read(overlay).unwrap().unwrap()
}

fn open_dir_base(
    base_dir: &Path,
    overlay: &Path,
    context: &OverlayCreateInfo,
) -> Result<WriteOverlay> {
    WriteOverlay::new_with_create_info_for_tests(base(base_dir), overlay, context)
}

fn set_mtime(path: &Path, secs: u64) {
    fs::File::options()
        .write(true)
        .open(path)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs))
        .unwrap();
}

/// Regression: a directory base was hashed (every file read) at overlay
/// creation; it now records the cheap weak manifest and reads no content.
#[test]
fn regression_mount_without_base_digest_hashes_no_directory_content() {
    let root = tempfile::tempdir().unwrap();
    let basedir = root.path().join("base");
    fs::create_dir_all(basedir.join("sub")).unwrap();
    fs::write(basedir.join("sub/a"), b"a").unwrap();
    let (dirs, streams, walks) = (
        directory_digest_calls_this_thread(),
        ratarmount_index::sha256_stream_calls_this_thread(),
        directory_weak_walks_this_thread(),
    );
    let overlay = root.path().join("overlay");
    drop(open_dir_base(&basedir, &overlay, &info(&basedir)).unwrap());
    // Reopen, and an overlay inside the base.
    drop(open_dir_base(&basedir, &overlay, &info(&basedir)).unwrap());
    drop(open_dir_base(&basedir, &basedir.join(".ov"), &info(&basedir)).unwrap());
    assert_eq!(directory_digest_calls_this_thread(), dirs);
    assert_eq!(ratarmount_index::sha256_stream_calls_this_thread(), streams);
    assert_eq!(directory_weak_walks_this_thread(), walks + 3);
    let meta = meta_of(&overlay);
    assert_eq!(meta.base_digest_kind(), Some("weak"));
    assert!(meta.base_digest().unwrap().starts_with("weak:"));
    assert_eq!(meta.get("base_weak_digest"), meta.base_digest());
    assert_eq!(meta.get("base_digest_source"), Some("computed"));
    // Positive controls: the counters are wired.
    let archive = root.path().join("a.tar");
    fs::write(&archive, b"abc").unwrap();
    let ov2 = root.path().join("ov2");
    drop(open_dir_base(root.path(), &ov2, &info(&archive)).unwrap());
    resolve_pending_base_digest(&Connection::open(ov2.join(HIDDEN_DB)).unwrap()).unwrap();
    assert!(ratarmount_index::sha256_stream_calls_this_thread() > streams);
    directory_digest(root.path().join("base").join("sub").as_path()).unwrap();
    assert_eq!(directory_digest_calls_this_thread(), dirs + 1);
}

/// Regression: a base holding a FIFO or an unreadable file failed creation
/// ("cannot digest special file"); the weak walk never opens anything.
#[cfg(unix)]
#[test]
fn regression_directory_base_with_fifo_creates_weak() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let basedir = root.path().join("base");
    fs::create_dir_all(basedir.join("locked")).unwrap();
    fs::write(basedir.join("secret"), b"x").unwrap();
    fs::set_permissions(basedir.join("secret"), fs::Permissions::from_mode(0o0)).unwrap();
    fs::write(basedir.join("locked/in"), b"x").unwrap();
    fs::set_permissions(basedir.join("locked"), fs::Permissions::from_mode(0o0)).unwrap();
    assert!(std::process::Command::new("mkfifo")
        .arg(basedir.join("pipe"))
        .status()
        .unwrap()
        .success());
    let (tx, rx) = std::sync::mpsc::channel();
    let (b, o) = (basedir.clone(), root.path().join("overlay"));
    std::thread::spawn(move || {
        let result = open_dir_base(&b, &o, &info(&b)).map(drop);
        let _ = tx.send(result.map_err(|e| e.to_string()));
    });
    let result = rx.recv_timeout(std::time::Duration::from_secs(20));
    fs::set_permissions(basedir.join("locked"), fs::Permissions::from_mode(0o755)).unwrap();
    result.expect("creation blocked on the FIFO").unwrap();
    assert_eq!(
        meta_of(&root.path().join("overlay")).base_digest_kind(),
        Some("weak")
    );
}

/// `verify_base` table: recorded kind and base type decide strength; a
/// FIFO under a strong directory digest, `none` and a missing digest are
/// `Skipped`, never an error.
#[cfg(unix)]
#[test]
fn verify_base_strong_weak_skipped_table() {
    let root = tempfile::tempdir().unwrap();
    let basedir = root.path().join("base");
    fs::create_dir(&basedir).unwrap();
    fs::write(basedir.join("f"), b"abc").unwrap();
    // Weak (default) directory digest.
    let overlay = root.path().join("weak");
    open_dir_base(&basedir, &overlay, &info(&basedir)).unwrap();
    assert!(matches!(
        verify_base_path(&overlay, &basedir),
        BaseCheck::Matches {
            strength: BaseStrength::Weak,
            ..
        }
    ));
    fs::write(basedir.join("f"), b"abcd").unwrap();
    assert!(matches!(
        verify_base_path(&overlay, &basedir),
        BaseCheck::Mismatch {
            strength: BaseStrength::Weak,
            ..
        }
    ));
    fs::write(basedir.join("f"), b"abc").unwrap();
    // Strong (supplied) directory digest; a FIFO added later cannot be hashed.
    let strong = root.path().join("strong");
    let mut request = info(&basedir);
    request.base_digest = BaseDigestRequest::Supplied(directory_digest(&basedir).unwrap());
    open_dir_base(&basedir, &strong, &request).unwrap();
    assert!(matches!(
        verify_base_path(&strong, &basedir),
        BaseCheck::Matches {
            strength: BaseStrength::Strong,
            ..
        }
    ));
    assert!(std::process::Command::new("mkfifo")
        .arg(basedir.join("pipe"))
        .status()
        .unwrap()
        .success());
    assert!(matches!(
        verify_base_path(&strong, &basedir),
        BaseCheck::Skipped { .. }
    ));
    fs::remove_file(basedir.join("pipe")).unwrap();
    // `none` and a missing base are skipped.
    let none = root.path().join("none");
    let mut request = info(&basedir);
    request.base_digest = BaseDigestRequest::None;
    open_dir_base(&basedir, &none, &request).unwrap();
    assert!(matches!(
        verify_base_path(&none, &basedir),
        BaseCheck::Skipped { .. }
    ));
    assert!(matches!(
        verify_base_path(&overlay, &root.path().join("missing")),
        BaseCheck::Skipped { .. }
    ));
    // A git-tree base is skipped.
    let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
    OverlayMeta::set(&conn, "base_git_tree", "abc").unwrap();
    drop(conn);
    assert!(matches!(
        verify_base_path(&overlay, &basedir),
        BaseCheck::Skipped { .. }
    ));
}

/// Regression: `verify` through a symlink to the base classified the root
/// by `symlink_metadata`, so it was neither file nor directory and the
/// base check was skipped; an edited base verified (exit 0).
#[cfg(unix)]
#[test]
fn regression_verify_base_follows_a_root_symlink() {
    let root = tempfile::tempdir().unwrap();
    let basedir = root.path().join("base");
    fs::create_dir(&basedir).unwrap();
    fs::write(basedir.join("f"), b"abc").unwrap();
    let overlay = root.path().join("ov");
    open_dir_base(&basedir, &overlay, &info(&basedir)).unwrap();
    let link = root.path().join("link");
    std::os::unix::fs::symlink(&basedir, &link).unwrap();
    assert!(matches!(
        verify_base_path(&overlay, &link),
        BaseCheck::Matches {
            strength: BaseStrength::Weak,
            ..
        }
    ));
    fs::write(basedir.join("f"), b"abcd").unwrap();
    assert!(matches!(
        verify_base_path(&overlay, &link),
        BaseCheck::Mismatch { .. }
    ));
    // An archive base reached through a symlink is hashed too.
    let archive = root.path().join("a.tar");
    fs::write(&archive, b"abc").unwrap();
    let (strong, _) = pending_overlay(root.path(), &archive, "strong");
    let conn = Connection::open(strong.join(HIDDEN_DB)).unwrap();
    assert!(resolve_pending_base_digest(&conn).unwrap());
    drop(conn);
    let alink = root.path().join("alink");
    std::os::unix::fs::symlink(&archive, &alink).unwrap();
    fs::write(&archive, b"abX").unwrap();
    assert!(matches!(
        verify_base_path(&strong, &alink),
        BaseCheck::Mismatch { .. }
    ));
}

/// Regression: the weak digest is order independent and sees exactly
/// path, type, size, mtime and symlink targets.
#[test]
fn regression_directory_weak_digest_deterministic_and_sensitive() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    for (root, names) in [(a.path(), ["one", "two"]), (b.path(), ["two", "one"])] {
        for name in names {
            fs::write(root.join(name), name).unwrap();
            set_mtime(&root.join(name), 1_000_000);
        }
        fs::create_dir(root.join("empty")).unwrap();
    }
    let none = BaseExcludes::default();
    let digest = |p: &Path| directory_weak_digest(p, &none).unwrap();
    assert_eq!(digest(a.path()), digest(b.path()));
    assert!(digest(a.path()).starts_with("weak:"));
    let before = digest(a.path());
    // Same size, restored mtime: invisible (documented limitation).
    fs::write(a.path().join("one"), "ONE").unwrap();
    set_mtime(&a.path().join("one"), 1_000_000);
    assert_eq!(digest(a.path()), before);
    // Size, mtime, new/removed entries: visible.
    fs::write(a.path().join("one"), "longer").unwrap();
    set_mtime(&a.path().join("one"), 1_000_000);
    assert_ne!(digest(a.path()), before);
    fs::write(a.path().join("one"), "ONE").unwrap();
    set_mtime(&a.path().join("one"), 1_000_001);
    assert_ne!(digest(a.path()), before);
    set_mtime(&a.path().join("one"), 1_000_000);
    assert_eq!(digest(a.path()), before);
    fs::write(a.path().join("new"), "").unwrap();
    assert_ne!(digest(a.path()), before);
    fs::remove_file(a.path().join("new")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::os::unix::fs::symlink("/aaa", a.path().join("link")).unwrap();
        let linked = digest(a.path());
        fs::remove_file(a.path().join("link")).unwrap();
        std::os::unix::fs::symlink("/bbb", a.path().join("link")).unwrap();
        assert_ne!(digest(a.path()), linked, "same-length retarget must show");
        // Directory mode never counts.
        let now = digest(a.path());
        fs::set_permissions(a.path().join("empty"), fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(digest(a.path()), now);
    }
    // Sidecars written by ratarmount are invisible; look-alikes are not.
    let now = digest(a.path());
    fs::write(a.path().join("a.tar"), "x").unwrap();
    let with_tar = digest(a.path());
    for name in [
        "a.tar.index.sqlite",
        "a.tar.index.ptr",
        "a.tar.rgzi",
        "a.tar.ratarmount-commit-journal",
    ] {
        fs::write(a.path().join(name), "x").unwrap();
    }
    assert_eq!(digest(a.path()), with_tar);
    assert_ne!(with_tar, now);
    fs::write(a.path().join("x.index.txt"), "x").unwrap();
    assert_ne!(digest(a.path()), with_tar);
}

/// Regression: reopening an overlay over an edited directory base was never
/// checked; it now refuses naming `--force-base-mismatch`.
#[test]
fn regression_overlay_meta_directory_reopen_refuses_after_edit_naming_force_flag() {
    let root = tempfile::tempdir().unwrap();
    let basedir = root.path().join("base");
    fs::create_dir(&basedir).unwrap();
    fs::write(basedir.join("f"), b"one").unwrap();
    let overlay = root.path().join("overlay");
    let mut context = info(&basedir);
    drop(open_dir_base(&basedir, &overlay, &context).unwrap());
    // A sidecar written into the base does not count.
    fs::write(basedir.join("f.index.sqlite"), b"idx").unwrap();
    fs::write(basedir.join("f.ratarmount-commit-journal"), b"j").unwrap();
    drop(open_dir_base(&basedir, &overlay, &context).unwrap());
    fs::write(basedir.join("f"), b"edited!").unwrap();
    let error = open_dir_base(&basedir, &overlay, &context)
        .err()
        .unwrap()
        .to_string();
    assert!(
        error.contains("--force-base-mismatch") && error.contains("weak:"),
        "{error}"
    );
    assert!(meta_of(&overlay).get("base_mismatch_forced_at").is_none());
    context.force_base_mismatch = true;
    drop(open_dir_base(&basedir, &overlay, &context).unwrap());
    assert!(meta_of(&overlay).get("base_mismatch_forced_at").is_some());
}

/// Regression: `Compute` refused an overlay inside a directory base. It is
/// now excluded from the digest, so writing through it never changes it.
#[test]
fn regression_overlay_inside_directory_base_excluded_from_weak_digest() {
    let root = tempfile::tempdir().unwrap();
    let basedir = root.path().join("base");
    fs::create_dir(&basedir).unwrap();
    fs::write(basedir.join("f"), b"one").unwrap();
    let outside = directory_weak_digest(&basedir, &BaseExcludes::default()).unwrap();
    let overlay = basedir.join(".ov");
    let context = info(&basedir);
    let ov = open_dir_base(&basedir, &overlay, &context).unwrap();
    ov.create_file("/new.txt", 0o644).unwrap();
    drop(ov);
    let meta = meta_of(&overlay);
    assert_eq!(meta.base_digest(), Some(outside.as_str()));
    assert_eq!(meta.get("base_weak_excludes"), Some(r#"[".ov"]"#));
    drop(open_dir_base(&basedir, &overlay, &context).unwrap());
    fs::write(basedir.join("f"), b"changed").unwrap();
    let error = open_dir_base(&basedir, &overlay, &context)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("--force-base-mismatch"), "{error}");
    // The overlay may never be the base itself.
    let error = open_dir_base(&basedir, &basedir, &context)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("base directory itself"), "{error}");
    // A supplied digest still records the weak companion.
    let supplied = OverlayCreateInfo {
        base_digest: BaseDigestRequest::Supplied(format!("sha256:{}", "a".repeat(64))),
        ..info(&basedir)
    };
    let overlay = basedir.join(".ov2");
    drop(open_dir_base(&basedir, &overlay, &supplied).unwrap());
    let meta = meta_of(&overlay);
    assert_eq!(meta.base_digest_kind(), Some("strong"));
    assert_eq!(meta.get("base_digest_source"), Some("supplied"));
    assert!(meta.get("base_weak_digest").unwrap().starts_with("weak:"));
    fs::write(basedir.join("f"), b"changed again").unwrap();
    assert!(open_dir_base(&basedir, &overlay, &supplied).is_err());
}

/// Regression: an overlay in a not-yet-existing parent (`B/new/ov`) must
/// record `new` (topmost-new), since creating the overlay adds `B/new`.
#[test]
fn regression_overlay_in_new_parent_remount_and_verify_pass() {
    let root = tempfile::tempdir().unwrap();
    let basedir = root.path().join("base");
    fs::create_dir(&basedir).unwrap();
    fs::write(basedir.join("f"), b"one").unwrap();
    let expected = directory_weak_digest(&basedir, &BaseExcludes::default()).unwrap();
    let overlay = basedir.join("new/ov");
    let context = info(&basedir);
    drop(open_dir_base(&basedir, &overlay, &context).unwrap());
    let meta = meta_of(&overlay);
    assert_eq!(meta.get("base_weak_excludes"), Some(r#"["new"]"#));
    assert_eq!(meta.base_digest(), Some(expected.as_str()));
    drop(open_dir_base(&basedir, &overlay, &context).unwrap());
}

/// Regression: the recorded exclusion set only ever grows, and a journal
/// added on a later mount is appended (absent) or refused (base content).
#[test]
fn regression_journal_added_later_is_appended_and_recorded_excludes_are_append_only() {
    let a = BaseExcludes::new(["a".into(), "c".into()]);
    assert_eq!(a.to_json().unwrap(), r#"["a","c"]"#);
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(META_SCHEMA).unwrap();
    OverlayMeta::set(&conn, "base_weak_excludes", r#"["a","c"]"#).unwrap();
    append_base_excludes(&conn, &["b".into()]).unwrap();
    append_base_excludes(&conn, &["a".into()]).unwrap();
    let meta = OverlayMeta::from_connection(&conn).unwrap().unwrap();
    assert_eq!(meta.get("base_weak_excludes"), Some(r#"["a","b","c"]"#));

    let root = tempfile::tempdir().unwrap();
    let basedir = root.path().join("base");
    fs::create_dir(&basedir).unwrap();
    fs::write(basedir.join("existing.txt"), b"x").unwrap();
    let overlay = basedir.join(".ov");
    let mut context = info(&basedir);
    drop(open_dir_base(&basedir, &overlay, &context).unwrap());
    context.weak_exclude = vec![basedir.join("j.jsonl")];
    drop(open_dir_base(&basedir, &overlay, &context).unwrap());
    assert_eq!(
        meta_of(&overlay).get("base_weak_excludes"),
        Some(r#"[".ov","j.jsonl"]"#)
    );
    // The journal grows; a journal-free remount still passes.
    fs::write(basedir.join("j.jsonl"), b"lots of lines").unwrap();
    context.weak_exclude.clear();
    drop(open_dir_base(&basedir, &overlay, &context).unwrap());
    // A journal path that is base content is refused and appends nothing.
    context.weak_exclude = vec![basedir.join("existing.txt")];
    context.force_base_mismatch = true;
    let error = open_dir_base(&basedir, &overlay, &context)
        .err()
        .unwrap()
        .to_string();
    assert!(
        error.contains("already exists, so it is base content"),
        "{error}"
    );
    assert_eq!(
        meta_of(&overlay).get("base_weak_excludes"),
        Some(r#"[".ov","j.jsonl"]"#)
    );
}

/// Regression: exclusion paths that do not exist yet, symlinks and `..`.
#[cfg(unix)]
#[test]
fn regression_resolve_base_excludes_cases() {
    let root = tempfile::tempdir().unwrap();
    let basedir = root.path().join("base");
    fs::create_dir_all(basedir.join("real")).unwrap();
    fs::create_dir(basedir.join("new_parent")).unwrap();
    std::os::unix::fs::symlink(basedir.join("real"), basedir.join("link")).unwrap();
    let rel = |paths: &[PathBuf]| -> Vec<PathBuf> {
        resolve_base_excludes(&basedir, paths)
            .unwrap()
            .1
            .paths()
            .to_vec()
    };
    assert_eq!(
        rel(&[basedir.join("new_parent/ov")]),
        [PathBuf::from("new_parent/ov")]
    );
    assert_eq!(rel(&[basedir.join("a/b/c")]), [PathBuf::from("a")]);
    assert_eq!(rel(&[basedir.join("link/ov")]), [PathBuf::from("real/ov")]);
    assert_eq!(rel(&[basedir.join("link/x/ov")]), [PathBuf::from("real/x")]);
    assert_eq!(rel(&[basedir.join("real")]), [PathBuf::from("real")]);
    assert!(rel(&[root.path().join("outside/ov")]).is_empty());
    let error = resolve_base_excludes(&basedir, &[basedir.join("a/../b")])
        .err()
        .unwrap();
    assert!(error.to_string().contains("'..'"), "{error}");
    // A symlink loop and a dangling link never get followed by the walk.
    std::os::unix::fs::symlink("/absent-target", basedir.join("dangling")).unwrap();
    std::os::unix::fs::symlink("b", basedir.join("loop_a")).unwrap();
    std::os::unix::fs::symlink("loop_a", basedir.join("b")).unwrap();
    directory_weak_digest(&basedir, &BaseExcludes::default()).unwrap();
}

/// Regression: read-only metadata inspection created files or hid SQLITE_BUSY.
#[test]
fn regression_overlay_meta_read_only_missing_and_in_use() {
    let root = tempfile::tempdir().unwrap();
    let overlay = root.path().join("overlay");
    assert!(OverlayMeta::read(&overlay).is_err());
    assert!(!overlay.exists());
    let ov = WriteOverlay::new_for_tests(base(root.path()), &overlay).unwrap();
    let error = OverlayMeta::read(&overlay).unwrap_err().to_string();
    assert!(error.contains("in use"), "{error}");
    drop(ov);
    let db = overlay.join(HIDDEN_DB);
    let before = fs::read(&db).unwrap();
    assert!(OverlayMeta::read(&overlay).unwrap().is_some());
    assert_eq!(before, fs::read(&db).unwrap());
}

/// Regression: metadata batches must roll back together and respect caller transactions.
#[test]
fn regression_overlay_meta_set_many_atomic_in_transaction() {
    let mut conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(META_SCHEMA).unwrap();
    conn.execute_batch("CREATE TRIGGER reject_bad BEFORE INSERT ON meta WHEN NEW.key='bad' BEGIN SELECT RAISE(ABORT, 'bad key'); END;").unwrap();
    let tx = conn.transaction().unwrap();
    OverlayMeta::set(&tx, "kept", "yes").unwrap();
    assert!(OverlayMeta::set_many(&tx, &[("rolled_back", "yes"), ("bad", "no")]).is_err());
    let meta = OverlayMeta::from_connection(&tx).unwrap().unwrap();
    assert_eq!(meta.get("kept"), Some("yes"));
    assert_eq!(meta.get("rolled_back"), None);
    tx.rollback().unwrap();
    assert!(OverlayMeta::from_connection(&conn)
        .unwrap()
        .unwrap()
        .values()
        .is_empty());
}

/// The `base_digest_state` mapping: pending, none, and present for every
/// recorded digest (strong, weak, git-tree); legacy overlays map by digest.
#[test]
fn base_digest_state_mapping() {
    assert_eq!(base_digest_state(Some("pending"), ""), "pending");
    assert_eq!(base_digest_state(Some("none"), "none"), "none");
    for kind in ["strong", "weak", "git-tree"] {
        assert_eq!(base_digest_state(Some(kind), "sha256:x"), "present");
    }
    assert_eq!(base_digest_state(None, ""), "none");
    assert_eq!(base_digest_state(None, "sha256:x"), "present");
}

fn pending_overlay(root: &Path, archive: &Path, name: &str) -> (PathBuf, PendingBase) {
    let overlay = root.join(name);
    drop(
        WriteOverlay::new_with_create_info_for_tests(base(root), &overlay, &info(archive)).unwrap(),
    );
    let meta = meta_of(&overlay);
    let pending = PendingBase::from_meta(&meta).unwrap().expect("pending");
    (overlay, pending)
}

/// Regression: an uncached archive base was hashed on the mount's critical
/// path; it is now `pending` with no digest and no stack digest.
#[test]
fn regression_pending_archive_base_records_no_digest_until_resolved() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("a.tar");
    fs::write(&archive, b"abc").unwrap();
    let before = ratarmount_index::sha256_stream_calls_this_thread();
    let (overlay, _) = pending_overlay(root.path(), &archive, "overlay");
    assert_eq!(ratarmount_index::sha256_stream_calls_this_thread(), before);
    let meta = meta_of(&overlay);
    assert_eq!(meta.base_digest_kind(), Some("pending"));
    assert_eq!(meta.base_digest(), Some(""));
    assert_eq!(meta.stack_digest(), None);
    assert_eq!(meta.get("base_digest_source"), Some("computed"));
    let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
    assert!(resolve_pending_base_digest(&conn).unwrap());
    assert!(!resolve_pending_base_digest(&conn).unwrap());
    drop(conn);
    let meta = meta_of(&overlay);
    assert_eq!(meta.base_digest_kind(), Some("strong"));
    assert_eq!(
        meta.base_digest(),
        Some(format!("sha256:{:x}", Sha256::digest(b"abc")).as_str())
    );
    assert_eq!(
        meta.stack_digest(),
        Some(stack_digest(meta.base_digest().unwrap(), &[]).as_str())
    );
    assert!(ratarmount_index::sha256_stream_calls_this_thread() > before);
}

/// Regression: `record_base_digest` must be a compare-and-set on `pending`
/// for the recorded stamp, so a supplied digest or a moved archive wins.
#[test]
fn regression_pending_cas_loses_to_supplied_digest_and_changed_stamp() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("a.tar");
    fs::write(&archive, b"abc").unwrap();
    let (overlay, pending) = pending_overlay(root.path(), &archive, "overlay");
    let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
    let digest = format!("sha256:{}", "b".repeat(64));
    // A changed stamp (a commit moved the archive) records nothing.
    let moved = PendingBase {
        size: pending.size + 1,
        ..pending.clone()
    };
    assert!(!record_base_digest(&conn, &moved, &digest).unwrap());
    assert_eq!(meta_of(&overlay).base_digest_kind(), Some("pending"));
    // A digest recorded by someone else first wins.
    OverlayMeta::set_many(
        &conn,
        &[
            ("base_digest", "sha256:supplied"),
            ("base_digest_kind", "strong"),
        ],
    )
    .unwrap();
    assert!(!record_base_digest(&conn, &pending, &digest).unwrap());
    assert_eq!(meta_of(&overlay).base_digest(), Some("sha256:supplied"));
}

/// Regression: a pending reopen must still run the size/mtime check
/// before anything is hashed, naming `--force-base-mismatch`.
#[test]
fn regression_pending_reopen_size_mtime_check_still_refuses() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("a.tar");
    fs::write(&archive, b"abc").unwrap();
    let (overlay, _) = pending_overlay(root.path(), &archive, "overlay");
    drop(
        WriteOverlay::new_with_create_info_for_tests(base(root.path()), &overlay, &info(&archive))
            .unwrap(),
    );
    fs::write(&archive, b"changed").unwrap();
    let before = ratarmount_index::sha256_stream_calls_this_thread();
    let error =
        WriteOverlay::new_with_create_info_for_tests(base(root.path()), &overlay, &info(&archive))
            .err()
            .unwrap()
            .to_string();
    assert!(
        error.contains("base mismatch") && error.contains("recorded digest pending"),
        "{error}"
    );
    assert!(error.contains("--force-base-mismatch"), "{error}");
    assert_eq!(ratarmount_index::sha256_stream_calls_this_thread(), before);
    // The stale record cannot be resolved against the changed archive.
    let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
    let error = resolve_pending_base_digest(&conn).unwrap_err().to_string();
    assert!(
        error.contains("changed since the overlay was created"),
        "{error}"
    );
    assert_eq!(meta_of(&overlay).base_digest_kind(), Some("pending"));
}

/// Regression: a digest resolved once is cached in the index, so a second
/// overlay on the same archive records `strong` at creation (no pending).
#[test]
fn regression_pending_reopen_after_exit_resolves_via_cache() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("a.tar");
    fs::write(&archive, b"abc").unwrap();
    let index = root.path().join("a.tar.index.sqlite");
    Connection::open(&index)
        .unwrap()
        .execute_batch("CREATE TABLE files (name TEXT);")
        .unwrap();
    let mut context = info(&archive);
    context.index_path = Some(index);
    let first = root.path().join("first");
    drop(
        WriteOverlay::new_with_create_info_for_tests(base(root.path()), &first, &context).unwrap(),
    );
    assert_eq!(meta_of(&first).base_digest_kind(), Some("pending"));
    let conn = Connection::open(first.join(HIDDEN_DB)).unwrap();
    assert!(resolve_pending_base_digest(&conn).unwrap());
    drop(conn);
    let second = root.path().join("second");
    let before = ratarmount_index::sha256_stream_calls_this_thread();
    drop(
        WriteOverlay::new_with_create_info_for_tests(base(root.path()), &second, &context).unwrap(),
    );
    assert_eq!(ratarmount_index::sha256_stream_calls_this_thread(), before);
    assert_eq!(meta_of(&second).base_digest_kind(), Some("strong"));
    assert_eq!(
        meta_of(&second).base_digest(),
        meta_of(&first).base_digest()
    );
}

/// Regression (archive half of "with --base-digest no base file is
/// opened for hashing"): a supplied digest hashes nothing, and without it
/// creation hashes nothing either but resolving does (positive control).
#[test]
fn regression_base_digest_flag_opens_no_base_file_for_hashing() {
    let root = tempfile::tempdir().unwrap();
    let archive = root.path().join("a.tar");
    fs::write(&archive, b"abc").unwrap();
    let mut context = info(&archive);
    context.base_digest = BaseDigestRequest::Supplied(format!("sha256:{}", "c".repeat(64)));
    let before = ratarmount_index::sha256_stream_calls_this_thread();
    let overlay = root.path().join("supplied");
    drop(
        WriteOverlay::new_with_create_info_for_tests(base(root.path()), &overlay, &context)
            .unwrap(),
    );
    assert_eq!(ratarmount_index::sha256_stream_calls_this_thread(), before);
    assert_eq!(meta_of(&overlay).base_digest_kind(), Some("strong"));
    let (overlay, _) = pending_overlay(root.path(), &archive, "computed");
    assert_eq!(ratarmount_index::sha256_stream_calls_this_thread(), before);
    let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
    resolve_pending_base_digest(&conn).unwrap();
    assert!(ratarmount_index::sha256_stream_calls_this_thread() > before);
}

fn dir_names(dir: &Path) -> std::collections::BTreeSet<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect()
}

/// Everything new or left over since `before`, except `declared`, must be
/// invisible to the digest according to the shared predicate.
fn assert_new_names_are_sidecars(
    dir: &Path,
    before: &std::collections::BTreeSet<String>,
    declared: &[&str],
    what: &str,
) {
    for name in dir_names(dir).difference(before) {
        if declared.contains(&name.as_str()) {
            continue;
        }
        assert!(
            crate::base_sidecars::is_ratarmount_sidecar_name(name, &|stem| dir.join(stem).exists()),
            "{what}: {name} is written by ratarmount but the predicate does not hide it"
        );
    }
}

/// A directory base with an archive `a.tar`, a gzip `a.gz` and a plain file.
fn writer_base(root: &Path) -> PathBuf {
    use std::io::Write;
    let base = root.join("base");
    fs::create_dir(&base).unwrap();
    fs::write(base.join("a.tar"), vec![0u8; 2048]).unwrap();
    fs::write(base.join("plain.txt"), b"plain").unwrap();
    let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gz.write_all(&b"hello world\n".repeat(4096)).unwrap();
    fs::write(base.join("a.gz"), gz.finish().unwrap()).unwrap();
    base
}

/// Run the real index writers inside `base` (publish, pointer, rotate and a
/// cold build observed mid-way), calling `check(label)` after each step.
fn run_index_writers(base: &Path, outside: &Path, check: &mut dyn FnMut(&str)) {
    let archive = base.join("a.tar");
    let dest = base.join("a.tar.index.sqlite");
    let mut index = ratarmount_index::SqliteIndex::create_writable(Some(&dest)).unwrap();
    check("cold build staging (mid-build)");
    index.publish_tmp().unwrap();
    drop(index);
    check("index published");
    for round in 0..3 {
        let blob = outside.join(format!("blob{round}.sqlite"));
        fs::copy(&dest, &blob).unwrap();
        fs::write(
            &blob,
            [fs::read(&dest).unwrap(), vec![round as u8; 16]].concat(),
        )
        .unwrap();
        ratarmount_index::publish_index_pointer(&archive, &blob, None).unwrap();
        check(&format!("pointer publish/rotate {round}"));
    }
}

/// Regression: every file a ratarmount writer leaves beside a base archive
/// (index, pointer, rotated snapshot, staging, commit journal, manifest,
/// every repack mode) must satisfy the predicate the digest walks use.
#[test]
fn regression_sidecar_predicate_covers_every_writer_output() {
    let root = tempfile::tempdir().unwrap();
    let base = writer_base(root.path());
    let outside = root.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let mut before = dir_names(&base);
    {
        let b = base.clone();
        run_index_writers(&base, &outside, &mut |what| {
            assert_new_names_are_sidecars(&b, &before, &[], what);
            before = dir_names(&b);
        });
    }
    // Provenance manifest beside the archive.
    let mut manifest = base.join("a.tar").into_os_string();
    manifest.push(crate::base_sidecars::MANIFEST_SIDECAR_SUFFIX);
    fs::write(&manifest, b"{}\n").unwrap();
    assert_new_names_are_sidecars(&base, &before, &[], "manifest");
    // The commit journal exists while a suffix replacement is in flight.
    fs::copy(base.join("a.tar"), base.join("c.tar")).unwrap();
    before = dir_names(&base);
    let mut suffix = tempfile::tempfile().unwrap();
    std::io::Write::write_all(&mut suffix, &[1u8; 512]).unwrap();
    std::io::Seek::rewind(&mut suffix).unwrap();
    let mut seen_journal = false;
    let replaced = ratarmount_compress::commit_journal::replace_suffix_with_hook(
        &base.join("c.tar"),
        512,
        &mut suffix,
        &mut |_phase| {
            seen_journal |= dir_names(&base)
                .iter()
                .any(|n| n.ends_with(ratarmount_compress::commit_journal::COMMIT_JOURNAL_SUFFIX));
            assert_new_names_are_sidecars(&base, &before, &[], "commit journal");
            Ok(())
        },
    );
    match replaced {
        Ok(()) => assert!(seen_journal, "the hook never saw the commit journal"),
        Err(error) => eprintln!("skip: commit journal needs inode xattrs: {error}"),
    }
    assert_new_names_are_sidecars(&base, &before, &[], "after commit");
    // Every repack mode: only the declared output may be new content.
    use ratarmount_compress::{repack_seekable, GzipSidecar, RepackOptions};
    let runs: [(&str, GzipSidecar, bool); 5] = [
        ("o_rgzi.gz", GzipSidecar::Rgzi, false),
        ("o_gzidx.gz", GzipSidecar::Gzidx, false),
        ("o_both.gz", GzipSidecar::Both, false),
        ("o_rgzi.gz", GzipSidecar::Both, true),
        ("o_zstd.zst", GzipSidecar::Rgzi, false),
    ];
    for (out, sidecar, overwrite) in runs {
        before = dir_names(&base);
        let opts = RepackOptions {
            gzip_sidecar: sidecar,
            overwrite,
            ..Default::default()
        };
        repack_seekable(&base.join("a.gz"), &base.join(out), &opts).unwrap();
        assert_new_names_are_sidecars(&base, &before, &[out], &format!("repack {out}"));
    }
}

/// Regression: index publish/rotate/staging inside a directory base moved
/// its digest (the plan's `.rgzi` gap). Part 1: sidecar-only writers leave
/// weak and strong digests unchanged and reopen passes. Part 2 (documented
/// behaviour, G6): a legitimate repack writes an archive, which IS base
/// content, so reopen is refused naming `--force-base-mismatch`, while the
/// sidecars it leaves stay invisible.
#[test]
fn regression_index_publish_and_rotate_inside_directory_base_keeps_reopen() {
    use ratarmount_compress::{repack_seekable, GzipSidecar, RepackOptions};
    let root = tempfile::tempdir().unwrap();
    let base = writer_base(root.path());
    let outside = root.path().join("outside");
    fs::create_dir(&outside).unwrap();
    let none = BaseExcludes::default();
    let weak = directory_weak_digest(&base, &none).unwrap();
    let strong = directory_digest(&base).unwrap();
    let ov_weak = root.path().join("ov_weak");
    let ov_strong = root.path().join("ov_strong");
    let strong_info = OverlayCreateInfo {
        base_digest: BaseDigestRequest::Supplied(strong.clone()),
        ..info(&base)
    };
    drop(open_dir_base(&base, &ov_weak, &info(&base)).unwrap());
    drop(open_dir_base(&base, &ov_strong, &strong_info).unwrap());
    let b = base.clone();
    run_index_writers(&base, &outside, &mut |what| {
        assert_eq!(directory_weak_digest(&b, &none).unwrap(), weak, "{what}");
        assert_eq!(directory_digest(&b).unwrap(), strong, "{what}");
    });
    drop(open_dir_base(&base, &ov_weak, &info(&base)).unwrap());
    drop(open_dir_base(&base, &ov_strong, &strong_info).unwrap());

    // Part 2: baseline files the repack does not touch.
    let stamp = |name: &str| {
        let meta = fs::metadata(base.join(name)).unwrap();
        (fs::read(base.join(name)).unwrap(), meta.modified().unwrap())
    };
    let baseline: Vec<_> = ["a.tar", "plain.txt", "a.gz"]
        .iter()
        .map(|n| (*n, stamp(n)))
        .collect();
    let runs: [(&str, GzipSidecar, bool); 4] = [
        ("o_rgzi.gz", GzipSidecar::Rgzi, false),
        ("o_gzidx.gz", GzipSidecar::Gzidx, false),
        ("o_both.gz", GzipSidecar::Both, false),
        ("o_rgzi.gz", GzipSidecar::Both, true),
    ];
    for (n, (out, sidecar, overwrite)) in runs.into_iter().enumerate() {
        let overlay = root.path().join(format!("ov_repack{n}"));
        let context = info(&base);
        drop(open_dir_base(&base, &overlay, &context).unwrap());
        let recorded = meta_of(&overlay).base_digest().unwrap().to_string();
        let before = dir_names(&base);
        let with_output = BaseExcludes::new([PathBuf::from(out)]);
        let digest_before = directory_weak_digest(&base, &with_output).unwrap();
        let opts = RepackOptions {
            gzip_sidecar: sidecar,
            overwrite,
            ..Default::default()
        };
        repack_seekable(&base.join("a.gz"), &base.join(out), &opts).unwrap();
        // (ii) every other new name is a sidecar and invisible to the digest.
        assert_new_names_are_sidecars(&base, &before, &[out], out);
        // (i) only the output body counts: the digest moved, the reopen refuses.
        assert_ne!(
            directory_weak_digest(&base, &none).unwrap(),
            recorded,
            "{out}"
        );
        let error = open_dir_base(&base, &overlay, &context)
            .err()
            .unwrap_or_else(|| panic!("repack {out} did not change the digest"))
            .to_string();
        assert!(error.contains("--force-base-mismatch"), "{error}");
        let mut forced = context.clone();
        forced.force_base_mismatch = true;
        drop(open_dir_base(&base, &overlay, &forced).unwrap());
        // Excluding just the output makes the walk identical to before the repack
        // for a fresh output; an overwrite already counted the old body.
        if !overwrite {
            assert_eq!(
                directory_weak_digest(&base, &with_output).unwrap(),
                digest_before,
                "{out}: sidecars/staging names must not count"
            );
        }
    }
    // (iii) untouched baseline files are byte- and mtime-identical.
    for (name, before) in baseline {
        assert_eq!(stamp(name), before, "{name} was collateral damage");
    }
}

/// Regression: a mount point created inside the base after the digest was
/// taken (or mounted over later) changed the weak digest on remount. The
/// caller passes it in `weak_exclude`; topmost-new records it.
#[test]
fn regression_mountpoint_inside_base_is_in_the_recorded_excluded_set() {
    let root = tempfile::tempdir().unwrap();
    let basedir = root.path().join("base");
    fs::create_dir(&basedir).unwrap();
    fs::write(basedir.join("f"), b"one").unwrap();
    let expected = directory_weak_digest(&basedir, &BaseExcludes::default()).unwrap();
    // Overlay beside the base, mount point inside it, not created yet.
    let overlay = root.path().join("overlay");
    let context = OverlayCreateInfo {
        weak_exclude: vec![basedir.join("mnt")],
        ..info(&basedir)
    };
    drop(open_dir_base(&basedir, &overlay, &context).unwrap());
    assert_eq!(
        meta_of(&overlay).get("base_weak_excludes"),
        Some(r#"["mnt"]"#)
    );
    // The mount creates the directory afterwards and writes through it.
    fs::create_dir(basedir.join("mnt")).unwrap();
    drop(open_dir_base(&basedir, &overlay, &context).unwrap());
    assert_eq!(meta_of(&overlay).base_digest(), Some(expected.as_str()));
    // Overlay inside the base as well, mount point in a not-yet-existing parent.
    let overlay = basedir.join(".ov");
    let context = OverlayCreateInfo {
        weak_exclude: vec![basedir.join("mounts/m1")],
        ..info(&basedir)
    };
    drop(open_dir_base(&basedir, &overlay, &context).unwrap());
    assert_eq!(
        meta_of(&overlay).get("base_weak_excludes"),
        Some(r#"[".ov","mounts"]"#)
    );
    fs::create_dir_all(basedir.join("mounts/m1")).unwrap();
    drop(open_dir_base(&basedir, &overlay, &context).unwrap());
    // A journal-free, mount-point-free remount still passes (recorded set).
    drop(open_dir_base(&basedir, &overlay, &info(&basedir)).unwrap());
}

fn bump_format_version(overlay: &Path, version: &str) {
    let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
    OverlayMeta::set(&conn, "format_version", version).unwrap();
}

/// Regression: a `format_version` newer than this build read as valid and
/// was served and sealed as if it were format 2.
#[test]
fn regression_format_version_3_is_refused_by_every_reader() {
    let root = tempfile::tempdir().unwrap();
    let basedir = root.path().join("base");
    fs::create_dir(&basedir).unwrap();
    fs::write(basedir.join("f"), b"x").unwrap();
    let overlay = root.path().join("overlay");
    drop(open_dir_base(&basedir, &overlay, &info(&basedir)).unwrap());
    bump_format_version(&overlay, "3");
    let newer = |error: String| {
        assert!(
            error.contains("format_version 3 is newer") && error.contains("upgrade"),
            "{error}"
        )
    };
    newer(OverlayMeta::read(&overlay).unwrap_err().to_string());
    newer(
        open_dir_base(&basedir, &overlay, &info(&basedir))
            .err()
            .expect("WriteOverlay::new must refuse")
            .to_string(),
    );
    newer(
        crate::overlay_seal::verify(&overlay, base(&basedir))
            .unwrap_err()
            .to_string(),
    );
    let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
    newer(OverlayMeta::from_connection(&conn).unwrap_err().to_string());
    // Version 2 and an unparsable value keep their messages.
    bump_format_version(&overlay, "2");
    assert!(OverlayMeta::read(&overlay).unwrap().is_some());
    bump_format_version(&overlay, "two");
    assert!(OverlayMeta::read(&overlay)
        .unwrap_err()
        .to_string()
        .contains("invalid overlay format_version"));
}

/// Regression: the version gate must accept the additive format-2 keys.
#[test]
fn regression_format_version_2_accepts_additive_keys() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(META_SCHEMA).unwrap();
    OverlayMeta::set_many(
        &conn,
        &[
            ("format_version", "2"),
            ("base_digest_kind", "weak"),
            ("base_weak_digest", "weak:size=1,x"),
            ("base_weak_excludes", "[]"),
            ("base_digest_source", "computed"),
            ("import_in_progress", "1:2"),
        ],
    )
    .unwrap();
    let meta = OverlayMeta::from_connection(&conn).unwrap().unwrap();
    assert_eq!(meta.format_version().unwrap(), Some(2));
    assert_eq!(meta.get("import_in_progress"), Some("1:2"));
}

/// Build `dir/HIDDEN_DB` with a hot rollback journal: a table-less
/// database (no `files`) copied together with its `-journal` while a
/// writer's spilled transaction is open.
fn table_less_db_with_hot_journal(dir: &Path) {
    let scratch = tempfile::tempdir().unwrap();
    let src = scratch.path().join("src.sqlite");
    let conn = Connection::open(&src).unwrap();
    conn.execute_batch(
        "PRAGMA journal_mode=DELETE; CREATE TABLE t(x BLOB); \
             WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 64) \
             INSERT INTO t SELECT zeroblob(4096) FROM n;",
    )
    .unwrap();
    // A tiny cache spills the open transaction: journal synced, pages
    // written into the database file.
    conn.execute_batch(
        "PRAGMA cache_size=1; BEGIN; UPDATE t SET x = zeroblob(4000); \
             INSERT INTO t SELECT x FROM t;",
    )
    .unwrap();
    let journal = PathBuf::from(format!("{}-journal", src.display()));
    assert!(fs::metadata(&journal).unwrap().len() > 0, "spilled journal");
    let db = dir.join(HIDDEN_DB);
    fs::copy(&src, &db).unwrap();
    fs::copy(&journal, format!("{}-journal", db.display())).unwrap();
    drop(conn);
}

/// Regression (S3 skeptic #2): the required-record latch is kept across
/// the hot-journal recovery and the retry. A marker present when the
/// first read's open classified the database (after the caller's own
/// marker check) and removed after the acquisition made that attempt
/// required; the read hit `SQLITE_READONLY_ROLLBACK`, recovery rolled
/// the journal back, and the retry used the caller's original `false`,
/// so a table-less record read as "unrecorded" (`Ok(None)`).
#[test]
fn regression_required_latch_survives_hot_journal_retry() {
    let dir = tempfile::tempdir().unwrap();
    table_less_db_with_hot_journal(dir.path());
    let marker = dir.path().join(crate::write_overlay::OVERLAY_MARKER);
    fs::write(&marker, b"").unwrap();
    let journal = PathBuf::from(format!("{}-journal", dir.path().join(HIDDEN_DB).display()));

    let opens = std::rc::Rc::new(std::cell::Cell::new(0u32));
    let counted = opens.clone();
    let removed = marker.clone();
    crate::overlay_db::AFTER_ACQUIRE.with(|hook| {
        *hook.borrow_mut() = Some(Box::new(move |_| {
            counted.set(counted.get() + 1);
            if counted.get() == 1 {
                fs::remove_file(&removed).unwrap();
            }
        }))
    });
    // The caller's own marker check ran before the marker appeared.
    let result = OverlayMeta::read_with_required(dir.path(), true, false, false);
    crate::overlay_db::AFTER_ACQUIRE.with(|hook| *hook.borrow_mut() = None);

    assert_eq!(opens.get(), 3, "read, recovery, retry");
    assert!(!journal.exists(), "the hot journal was rolled back");
    match result {
        Err(OverlayError::Msg(msg)) => assert_eq!(msg, NO_FILES_TABLE),
        other => panic!("a required table-less record must refuse: {other:?}"),
    }
}

// ---------------------------------------------------------------------
// R11-S7 (#151): base hashing reads through managed readers.
// ---------------------------------------------------------------------

#[cfg(unix)]
use ratarmount_index::managed_read::lock_probe::other_process_sees_lock;

/// An SQLite database (an SQLAR or an index) at `path`; its bytes.
#[cfg(unix)]
fn s7_database(path: &Path) -> Vec<u8> {
    let c = Connection::open(path).unwrap();
    c.execute_batch(
        "CREATE TABLE sqlar(name TEXT PRIMARY KEY, mode INT, mtime INT, sz INT, data BLOB);
             INSERT INTO sqlar VALUES ('a', 33188, 0, 3, randomblob(150000));",
    )
    .unwrap();
    drop(c);
    fs::read(path).unwrap()
}

/// A connection of this process holding SHARED on `path`.
#[cfg(unix)]
fn s7_holder(path: &Path) -> Connection {
    let c = Connection::open(path).unwrap();
    c.execute_batch("BEGIN").unwrap();
    let _: i64 = c
        .query_row("SELECT count(*) FROM sqlite_master", [], |r| r.get(0))
        .unwrap();
    assert!(other_process_sees_lock(path));
    c
}

/// A file base with a supplied strong digest of `bytes`.
#[cfg(unix)]
fn s7_strong_overlay(root: &Path, archive: &Path, bytes: &[u8]) -> PathBuf {
    let overlay = root.join("strong-overlay");
    let mut request = info(archive);
    request.base_digest =
        BaseDigestRequest::Supplied(format!("sha256:{:x}", Sha256::digest(bytes)));
    drop(WriteOverlay::new_with_create_info_for_tests(base(root), &overlay, &request).unwrap());
    overlay
}

/// Regression: the strong directory digest hashed every file with a raw
/// `File`, releasing the lock of a connection of this process on an SQLAR
/// inside the base directory.
#[cfg(unix)]
#[test]
fn regression_directory_strong_digest_keeps_sqlar_lock() {
    let root = tempfile::tempdir().unwrap();
    let basedir = root.path().canonicalize().unwrap().join("base");
    fs::create_dir(&basedir).unwrap();
    let db = basedir.join("a.sqlar");
    s7_database(&db);
    let h = s7_holder(&db);
    directory_digest(&basedir).unwrap();
    assert!(other_process_sees_lock(&db), "lock kept");
    drop(fs::File::open(&db).unwrap());
    assert!(!other_process_sees_lock(&db), "oracle check");
    drop(h);
}

/// Regression: resolving a pending archive digest (the mount's background
/// hasher and `resolve_pending_base_digest`) hashed the archive raw while
/// a connection of this process had it open (the archive here is an
/// ordinary index with a `files` table).
#[cfg(unix)]
#[test]
fn regression_pending_base_hash_keeps_index_lock() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path().canonicalize().unwrap();
    let archive = root.join("a.tar");
    {
        let mut idx = ratarmount_index::SqliteIndex::create_writable(Some(&archive)).unwrap();
        idx.publish_tmp().unwrap();
    }
    let (overlay, pending) = pending_overlay(&root, &archive, "overlay");
    let h = {
        let c = Connection::open(&archive).unwrap();
        c.execute_batch("BEGIN").unwrap();
        let _: i64 = c
            .query_row("SELECT count(*) FROM files", [], |r| r.get(0))
            .unwrap();
        c
    };
    assert!(other_process_sees_lock(&archive));
    let digest = pending.hash(&|| Ok(())).unwrap();
    assert!(digest.starts_with("sha256:"));
    assert!(
        other_process_sees_lock(&archive),
        "PendingBase::hash kept it"
    );
    let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
    resolve_pending_base_digest(&conn).unwrap();
    assert!(other_process_sees_lock(&archive), "resolution kept it");
    drop(h);
}

/// Regression: `overlay verify`'s strong base check hashed the base raw
/// (an SQLAR another connection of this process has open).
#[cfg(unix)]
#[test]
fn regression_strong_base_verification_keeps_sqlar_lock() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path().canonicalize().unwrap();
    let archive = root.join("a.sqlar");
    let bytes = s7_database(&archive);
    let overlay = s7_strong_overlay(&root, &archive, &bytes);
    let h = s7_holder(&archive);
    assert!(matches!(
        verify_base_path(&overlay, &archive),
        BaseCheck::Matches {
            strength: BaseStrength::Strong,
            ..
        }
    ));
    assert!(other_process_sees_lock(&archive), "lock kept");
    drop(h);
}

/// Regression: a failed strong base hash must stay `Skipped` (the CLI
/// keeps its exit status and reports `base_ok: null`), never `Matches`.
#[cfg(unix)]
#[test]
fn regression_verify_base_hash_failure_stays_skipped() {
    use ratarmount_index::managed_read::{seams, Seam};
    let root = tempfile::tempdir().unwrap();
    let root = root.path().canonicalize().unwrap();
    let archive = root.join("a.sqlar");
    let bytes = s7_database(&archive);
    let overlay = s7_strong_overlay(&root, &archive, &bytes);
    for seam in [Seam::AfterOpen, Seam::BeforeRead] {
        let got = seams::with(
            move |s| {
                if s == seam {
                    Err(io::Error::other("injected"))
                } else {
                    Ok(())
                }
            },
            || verify_base_path(&overlay, &archive),
        );
        match got {
            BaseCheck::Skipped { reason } => assert!(reason.contains("injected"), "{reason}"),
            other => panic!("{seam:?}: {other:?}"),
        }
    }
}

/// Regression (live caller of the digest refresh, `refresh_archive_digest`
/// through `refresh_committed_base`): refreshing the committed base's
/// digest hashed an archive that is an SQLAR open in this process raw.
#[cfg(unix)]
#[test]
fn regression_archive_digest_and_refresh_keep_sqlar_lock_live_caller() {
    let root = tempfile::tempdir().unwrap();
    let root = root.path().canonicalize().unwrap();
    let archive = root.join("a.sqlar");
    let bytes = s7_database(&archive);
    let overlay = s7_strong_overlay(&root, &archive, &bytes);
    let h = s7_holder(&archive);
    let conn = Connection::open(overlay.join(HIDDEN_DB)).unwrap();
    refresh_committed_base(&conn, None, &archive).unwrap();
    assert!(other_process_sees_lock(&archive), "refresh kept the lock");
    drop(h);
}

/// Set by the creation-mode test for its child.
#[cfg(unix)]
const S7_MODE_CHILD_ENV: &str = "RATARMOUNT_TEST_S7_MODE_CHILD";

/// The child half of the creation-mode test (a no-op unless spawned):
/// under the given umask, a real overlay creation and an index build and
/// publication; reports every mode.
#[cfg(unix)]
#[test]
fn s7_mode_child() {
    use std::os::unix::fs::PermissionsExt;
    let Some(arg) = std::env::var_os(S7_MODE_CHILD_ENV) else {
        return;
    };
    let arg = arg.to_string_lossy().into_owned();
    let (umask, dir) = arg.split_once(':').unwrap();
    let umask = u32::from_str_radix(umask, 8).unwrap();
    // SAFETY: a single-threaded child.
    unsafe { libc::umask(umask as libc::mode_t) };
    let dir = PathBuf::from(dir);
    let mode_of = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o7777;
    let want = 0o644 & !umask;
    let mut report = Vec::new();
    // Overlay creation (SQLite creates the database).
    let archive = dir.join("a.tar");
    fs::write(&archive, b"abc").unwrap();
    let overlay = dir.join("overlay");
    let ov = WriteOverlay::new_with_create_info_for_tests(base(&dir), &overlay, &info(&archive))
        .unwrap();
    let db = overlay.join(HIDDEN_DB);
    assert_eq!(mode_of(&db), want, "overlay database");
    for side in ["-wal", "-shm", "-journal"] {
        let p = PathBuf::from(format!("{}{side}", db.display()));
        if p.exists() {
            assert_eq!(mode_of(&p), mode_of(&db), "overlay {side}");
            report.push(side.to_owned());
        }
    }
    drop(ov);
    // Cold index: temporary database, publication, companions.
    let dest = dir.join("idx").join("a.tar.index.sqlite");
    fs::create_dir_all(dest.parent().unwrap()).unwrap();
    let mut idx = ratarmount_index::SqliteIndex::create_writable(Some(&dest)).unwrap();
    let tmp = fs::read_dir(dest.parent().unwrap())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| p != &dest && p.is_file() && !p.to_string_lossy().ends_with("-journal"))
        .expect("temporary index");
    assert_eq!(mode_of(&tmp), want, "temporary index");
    idx.publish_tmp().unwrap();
    assert_eq!(
        mode_of(&dest),
        want,
        "published index (rename keeps the mode)"
    );
    for side in ["-wal", "-shm"] {
        let p = PathBuf::from(format!("{}{side}", dest.display()));
        if p.exists() {
            assert_eq!(mode_of(&p), want, "index {side}");
            report.push(format!("index{side}"));
        }
    }
    drop(idx);
    fs::write(dir.join("result"), format!("ok {}", report.join(","))).unwrap();
}

/// Regression (R11-S7 §7): the overlay database and the cold index keep
/// SQLite's `0644 & !umask` creation mode; publication's rename keeps the
/// temporary database's mode; companions take the database's mode.
/// Umasks 002, 022, 077, each in a fresh child.
#[cfg(unix)]
#[test]
fn regression_exclusive_create_preserves_overlay_and_published_index_modes() {
    for umask in ["002", "022", "077"] {
        let root = tempfile::tempdir().unwrap();
        let dir = root.path().canonicalize().unwrap();
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "overlay_meta::tests::s7_mode_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(S7_MODE_CHILD_ENV, format!("{umask}:{}", dir.display()))
            .output()
            .unwrap();
        let got = fs::read_to_string(dir.join("result")).unwrap_or_default();
        assert!(
            out.status.success() && got.starts_with("ok"),
            "umask {umask}: {got:?}\n{}\n{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
    }
}
