use super::*;

/// Regression: #238 a commit between the factory's source acquisition and
/// token minting paired an old TAR index/descriptor with the new path stamp.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[allow(clippy::disallowed_methods)]
fn regression_238_v3_commit_during_open_cannot_certify_old_source() {
    use ratarmount_compositing::{BaseDigestRequest, CreateOptions, OverlayMetadata, WriteOverlay};
    use ratarmount_compress::commit_journal;
    use std::io::{Read, Seek, SeekFrom};

    struct CommitDuringOpen<'a> {
        factory: FactoryOpener<'a>,
        archive: PathBuf,
        staged: PathBuf,
        replace: bool,
    }
    impl OpenBase for CommitDuringOpen<'_> {
        fn open_base(&mut self) -> Result<Opened, String> {
            let opened = self.factory.open_base()?;
            let original = std::fs::metadata(&self.archive).unwrap();
            if self.replace {
                let _guard = commit_journal::guard_copy(&self.archive, &original).unwrap();
                std::fs::rename(&self.staged, &self.archive).unwrap();
            } else {
                let mut suffix = std::fs::File::open(&self.staged).unwrap();
                commit_journal::replace_suffix_if_unchanged_with(
                    &self.archive,
                    0,
                    &mut suffix,
                    &original,
                    &mut || Ok(()),
                    &mut |_| Ok(()),
                )
                .unwrap();
            }
            Ok(opened)
        }
    }

    for replace in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("base.tar");
        let staged = dir.path().join("new.tar");
        write_tar_file(&archive);
        write_tar_file(&staged);
        // Keep the same layout; changing the inherited payload exposes a
        // stale digest even when an in-place source keeps the same offsets.
        let mut newer = std::fs::OpenOptions::new()
            .write(true)
            .open(&staged)
            .unwrap();
        newer.seek(SeekFrom::Start(512)).unwrap();
        std::io::Write::write_all(&mut newer, b"y").unwrap();
        drop(newer);
        let initial = fixtures::classify(&archive);
        let overlay_dir = dir.path().join("overlay");
        let overlay = WriteOverlay::open(
            &initial,
            initial.source(),
            &overlay_dir,
            &CreateOptions {
                base_digest: BaseDigestRequest::None,
                ..Default::default()
            },
        )
        .unwrap();
        overlay
            .set_metadata(
                "/f",
                &OverlayMetadata {
                    mode: Some(0o600),
                    ..Default::default()
                },
            )
            .unwrap();
        drop(overlay);
        drop(initial);
        let mut options = OpenOptions {
            index_in_memory: true,
            write_index: false,
            ..Default::default()
        };
        let factory = FactoryOpener::new(
            vec![archive.to_string_lossy().into_owned()],
            vec![archive.clone()],
            &mut options,
            false,
            Default::default(),
            Default::default(),
            false,
        );
        let token = ClassifiedBase::open(&mut CommitDuringOpen {
            factory,
            archive: archive.clone(),
            staged,
            replace,
        })
        .unwrap();
        if replace {
            let source = token.source();
            let info = source.lookup("/f", 0).unwrap();
            let mut bytes = Vec::new();
            source
                .open(&info, 0)
                .unwrap()
                .read_to_end(&mut bytes)
                .unwrap();
            assert_eq!(
                bytes, b"x",
                "the fixture must retain the old TAR descriptor"
            );
        }
        let result =
            ratarmount_compositing::overlay_seal::seal(&overlay_dir, &token, token.source());
        // Keep a failing red control removable even if it published a seal.
        if result.is_ok() {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&overlay_dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let error = result.expect_err("commit during open must not certify an obsolete source");
        assert!(
            error.to_string().contains("base view was opened"),
            "{error}"
        );
        assert!(!OverlayMeta::read(&overlay_dir)
            .unwrap()
            .unwrap()
            .layer_sealed());
        assert!(!overlay_dir.join(".ratarmount-sealed").exists());
    }
}

/// Regression: classification is the factory open a verb already needs and
/// nothing else: no directory walk, no digest, and (for an archive) no
/// hashing or stamp comparison. A big directory and a plain archive are
/// classified without any content work.
#[test]
fn regression_classifier_does_no_content_work() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let folder = root.join("folder");
    std::fs::create_dir(&folder).unwrap();
    for i in 0..50 {
        std::fs::write(folder.join(format!("f{i}")), vec![b'x'; 1024]).unwrap();
    }
    let archive = root.join("a.tar");
    let members = [ratarmount_formats_tar::UstarMember {
        path: "f",
        payload: ratarmount_formats_tar::UstarPayload::File { bytes: b"x" },
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: 0,
        xattrs: &[],
    }];
    let mut file = std::fs::File::create(&archive).unwrap();
    ratarmount_formats_tar::write_ustar_members(&mut file, &members).unwrap();
    ratarmount_formats_tar::write_tar_eof(&mut file).unwrap();
    drop(file);
    let walks = ratarmount_compositing::directory_weak_walks_this_thread();
    let digests = ratarmount_compositing::directory_digest_calls_this_thread();
    for base in [&folder, &archive] {
        classify_offline(base, GitIntent::Replay(None), &OverlayRunContext::default()).unwrap();
    }
    assert_eq!(
        ratarmount_compositing::directory_weak_walks_this_thread(),
        walks
    );
    assert_eq!(
        ratarmount_compositing::directory_digest_calls_this_thread(),
        digests
    );
    // No sidecar was created next to the archive, either.
    assert!(!root.join("a.tar.index.sqlite").exists());
}

/// Regression (R6-G4, offline-commit cost): offline `--commit-overlay`
/// classified the archive with an in-memory index (R6 review), then by
/// loading its sidecar (R6-F7), so a multi-GB archive paid an index
/// build or load just to learn it is an archive. The commit's classifier
/// opens nothing: the token's source holds no member of the archive, no
/// file appears beside it and its sidecar is untouched; the sidecar is
/// still the peek target for a cached digest.
#[test]
fn regression_offline_commit_classification_builds_no_index() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let archive = root.join("a.tar");
    let members = [ratarmount_formats_tar::UstarMember {
        path: "f",
        payload: ratarmount_formats_tar::UstarPayload::File { bytes: b"x" },
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: 0,
        xattrs: &[],
    }];
    let mut file = std::fs::File::create(&archive).unwrap();
    ratarmount_formats_tar::write_ustar_members(&mut file, &members).unwrap();
    ratarmount_formats_tar::write_tar_eof(&mut file).unwrap();
    drop(file);
    let sidecar = root.join("a.tar.index.sqlite");
    drop(
        ratarmount_formats_tar::SqliteIndexedTar::create_index(
            &archive,
            &archive,
            Some(&sidecar),
            &ratarmount_core::OpenOptions::default(),
            "test",
            &mut None,
        )
        .unwrap(),
    );
    let names = |dir: &Path| {
        let mut all: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        all.sort();
        all
    };
    let (listing, before) = (names(&root), std::fs::read(&sidecar).unwrap());
    let context = OverlayRunContext::default();
    let token = classify_offline_commit(&archive, &context).unwrap();
    assert_eq!(token.actual().kind(), BaseKind::Archive);
    assert!(
        token.source().lookup("/f", 0).is_none(),
        "no index of the archive may be built or loaded"
    );
    assert_eq!(token.actual().index_for_peek(), Some(sidecar.as_path()));
    assert_eq!(names(&root), listing, "nothing created beside the archive");
    assert!(
        std::fs::read(&sidecar).unwrap() == before,
        "sidecar written"
    );
    // The other offline verbs keep the factory's in-memory open.
    let fresh = classify_offline(&archive, GitIntent::Replay(None), &context).unwrap();
    assert!(fresh.source().lookup("/f", 0).is_some());
}

fn write_tar_file(path: &Path) {
    let members = [ratarmount_formats_tar::UstarMember {
        path: "f",
        payload: ratarmount_formats_tar::UstarPayload::File { bytes: b"x" },
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: 0,
        xattrs: &[],
    }];
    let mut file = std::fs::File::create(path).unwrap();
    ratarmount_formats_tar::write_ustar_members(&mut file, &members).unwrap();
    ratarmount_formats_tar::write_tar_eof(&mut file).unwrap();
}

/// Leave `archive` mid-commit the way a crash does: `step` names the hook
/// the attempt dies at (`archive truncate`: torn, marker `A`; `locator
/// complete`: rolled forward on recovery, marker `C`; `journal unlink`:
/// finished, marker `D`, journal already gone).
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(clippy::disallowed_methods)]
fn crash_commit(archive: &Path, step: &'static str) {
    use std::io::Write;
    let len = std::fs::metadata(archive).unwrap().len();
    let mut suffix = tempfile::tempfile().unwrap();
    suffix.write_all(&[0u8; 1536]).unwrap();
    let crashed = ratarmount_compress::commit_journal::replace_suffix_with_hook(
        archive,
        len - 1024,
        &mut suffix,
        &mut |s| {
            if s == step {
                Err(std::io::Error::other("crash"))
            } else {
                Ok(())
            }
        },
    );
    assert!(crashed.is_err());
}

/// Regression (#174): offline classification opened the base through the
/// factory with `recover_journals` on, so a pending commit journal was
/// rolled back or forward under `Owner::Inode` before any identity gate —
/// a write a mount or an offline commit would refuse for a foreign journal
/// (B renamed over A; the journal's inode matches the renamed file). The
/// classify open now refuses a pending journal started for the file and
/// never recovers: archive and journal stay byte-identical.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regression_offline_classify_refuses_pending_commit_journal() {
    use ratarmount_compress::commit_journal::{journal_path, pending};
    for complete in [false, true] {
        for renamed in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().join("base.tar");
            write_tar_file(&base);
            let (crashed, journal) = if renamed {
                let foreign = dir.path().join("foreign.tar");
                write_tar_file(&foreign);
                crash_commit(
                    &foreign,
                    if complete {
                        "locator complete"
                    } else {
                        "archive truncate"
                    },
                );
                let journal = journal_path(&foreign);
                let bytes = std::fs::read(&foreign).unwrap();
                std::fs::rename(&foreign, &base).unwrap();
                (bytes, journal)
            } else {
                crash_commit(
                    &base,
                    if complete {
                        "locator complete"
                    } else {
                        "archive truncate"
                    },
                );
                (std::fs::read(&base).unwrap(), journal_path(&base))
            };
            let journal_bytes = std::fs::read(&journal).unwrap();
            let context = OverlayRunContext::default();
            let error = match classify_offline(&base, GitIntent::Replay(None), &context) {
                Err(error) => error,
                Ok(_) => panic!("a pending commit journal must refuse classification"),
            };
            assert!(
                error.contains("commit journal"),
                "complete={complete} renamed={renamed}: {error}"
            );
            assert_eq!(
                std::fs::read(&base).unwrap(),
                crashed,
                "complete={complete} renamed={renamed}: archive"
            );
            assert_eq!(
                std::fs::read(&journal).unwrap(),
                journal_bytes,
                "complete={complete} renamed={renamed}: journal"
            );
            assert!(
                pending(&base).unwrap().is_some(),
                "complete={complete} renamed={renamed}: journal still pending"
            );
        }
    }
}

/// The `user.ratarmount.commit-journal` locator bytes on `path`, if set.
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn commit_locator(path: &Path) -> Option<Vec<u8>> {
    use std::os::unix::ffi::OsStrExt;
    let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    let name = c"user.ratarmount.commit-journal";
    let mut buf = vec![0u8; 8192];
    #[cfg(target_os = "linux")]
    let n = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    #[cfg(target_os = "macos")]
    let n = unsafe {
        libc::getxattr(
            path.as_ptr(),
            name.as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
            0,
            libc::XATTR_NOFOLLOW,
        )
    };
    if n < 0 {
        return None;
    }
    buf.truncate(n as usize);
    Some(buf)
}

/// Regression (#174): a locator whose journal is missing refuses the way
/// recovery would — an `A` or `C` phase means the archive sits mid-crash
/// (a torn TAR that ends on a header boundary parses, so the factory open
/// alone is no guard). A `D` locator with its journal already unlinked is
/// what a finished commit leaves: classification proceeds. Either way the
/// locator itself is left for a mount or `--no-mount` to act on.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regression_offline_classify_missing_commit_journal() {
    use ratarmount_compress::commit_journal::journal_path;
    for step in ["archive truncate", "locator complete"] {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base.tar");
        write_tar_file(&base);
        crash_commit(&base, step);
        let bytes = std::fs::read(&base).unwrap();
        let locator = commit_locator(&base);
        assert!(locator.is_some(), "{step}: the crash left a locator");
        let journal = journal_path(&base);
        std::fs::remove_file(&journal).unwrap();
        let context = OverlayRunContext::default();
        let error = match classify_offline(&base, GitIntent::Replay(None), &context) {
            Err(error) => error,
            Ok(_) => panic!("a missing journal must refuse classification"),
        };
        assert!(error.contains("commit-journal locator"), "{step}: {error}");
        assert_eq!(std::fs::read(&base).unwrap(), bytes, "{step}: archive");
        assert!(!journal.exists(), "{step}: journal");
        assert_eq!(commit_locator(&base), locator, "{step}: locator");
    }
    // Finished commit (`D` locator, journal already unlinked): allowed.
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.tar");
    write_tar_file(&base);
    crash_commit(&base, "journal unlink");
    let locator = commit_locator(&base);
    let context = OverlayRunContext::default();
    classify_offline(&base, GitIntent::Replay(None), &context)
        .expect("a finished commit's stale locator does not refuse");
    assert!(!journal_path(&base).exists());
    assert_eq!(commit_locator(&base), locator, "stale D locator left alone");
}

/// Regression (#174): a sibling journal whose header names ANOTHER inode
/// (a copy of a crashed archive's journal left beside a fresh base) is not
/// this file's journal: the refusal does not fire, but
/// `recover_journals: false` is what keeps the factory from recovering it.
/// Under the old default the factory's `Owner::Inode` recovery refused the
/// inode mismatch and the open failed — this test fails if the flag is
/// dropped.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn regression_offline_classify_ignores_foreign_sibling_journal() {
    use ratarmount_compress::commit_journal::journal_path;
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("base.tar");
    write_tar_file(&base);
    let victim = dir.path().join("victim.tar");
    write_tar_file(&victim);
    crash_commit(&victim, "archive truncate");
    let bytes = std::fs::read(&base).unwrap();
    let journal = journal_path(&base);
    let journal_bytes = std::fs::read(journal_path(&victim)).unwrap();
    std::fs::copy(journal_path(&victim), &journal).unwrap();
    let context = OverlayRunContext::default();
    let token = classify_offline(&base, GitIntent::Replay(None), &context)
        .expect("a journal naming another inode does not refuse");
    assert!(token.source().lookup("/f", 0).is_some());
    assert_eq!(std::fs::read(&base).unwrap(), bytes, "archive");
    assert_eq!(std::fs::read(&journal).unwrap(), journal_bytes, "journal");
}
