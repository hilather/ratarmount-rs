//! R6-1: the factory reports what it ACTUALLY served for the base-identity
//! token (`MountBundle::served`), never a guess from a path or URL.

use super::*;
use ratarmount_formats_tar::{write_ustar_members, UstarMember, UstarPayload};

fn tar(path: &Path) {
    let members = [UstarMember {
        path: "f",
        payload: UstarPayload::File { bytes: b"x" },
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: 0,
        xattrs: &[],
    }];
    write_ustar_members(&mut std::fs::File::create(path).unwrap(), &members).unwrap();
}

fn options() -> OpenOptions {
    OpenOptions {
        index_in_memory: true,
        ..Default::default()
    }
}

fn served_of(inputs: &[PathBuf], options: &mut OpenOptions) -> Served {
    build_mount_source_ex(inputs, options, false, CompositingOptions::default())
        .unwrap()
        .served
        .expect("an opened input reports what it served")
}

fn commit_repo(path: &Path, bare: bool) -> (String, String) {
    let repo = if bare {
        git2::Repository::init_bare(path)
    } else {
        git2::Repository::init(path)
    }
    .unwrap();
    let signature = git2::Signature::now("Test", "test@example.com").unwrap();
    let mut builder = repo.treebuilder(None).unwrap();
    builder
        .insert("file", repo.blob(b"original").unwrap(), 0o100644)
        .unwrap();
    let tree = repo.find_tree(builder.write().unwrap()).unwrap();
    let commit = repo
        .commit(Some("HEAD"), &signature, &signature, "first", &tree, &[])
        .unwrap();
    (tree.id().to_string(), commit.to_string())
}

/// R6-1: every LOCAL arm of the factory names the kind and the path it opened.
/// Remote arms are in `remote_open::tests::regression_served_kind_table_remote`;
/// ssh/webdav/torrent rows are in `regression_served_kind_table_fetched_and_torrent`;
/// arms with no offline server (smb, ftp, ipfs, rclone, gs, az, oci,
/// restic, hf) are enforced by the type: `RemoteOpened` has no `Default`, so
/// every `return Ok` in `open_remote_input_with_nested` must name its kind.
#[test]
fn regression_served_kind_table() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();

    // Plain archive.
    let archive = root.join("a.tar");
    tar(&archive);
    let served = served_of(std::slice::from_ref(&archive), &mut options());
    assert_eq!(served.kind, ServedKind::Archive);
    assert_eq!(
        served.location,
        Some(ServedLocation::Local(archive.clone()))
    );
    assert!(!served.fetched);

    // Directory.
    let folder = root.join("folder");
    std::fs::create_dir(&folder).unwrap();
    let served = served_of(std::slice::from_ref(&folder), &mut options());
    assert_eq!(served.kind, ServedKind::Folder);
    assert_eq!(served.location, Some(ServedLocation::Local(folder.clone())));

    // Split set: a joined plain file is still one archive-like file.
    std::fs::write(root.join("foo.001"), b"foo").unwrap();
    std::fs::write(root.join("foo.002"), b"bar").unwrap();
    let served = served_of(&[root.join("foo.001")], &mut options());
    assert_eq!(served.kind, ServedKind::Archive);
    assert_eq!(
        served.location,
        Some(ServedLocation::Local(root.join("foo.001")))
    );

    // Declared sources: the caller names what it built; `inputs[0]` wins.
    let declared = |kind: ServedKind, location: Option<ServedLocation>| DeclaredSource {
        src: Arc::new(FolderMountSource::new(&folder).unwrap()),
        kind,
        location,
        label: "declared".into(),
    };
    let bundle = build_mount_source_with_bindings(
        &[],
        &mut options(),
        false,
        CompositingOptions::default(),
        SourceBindings {
            sources: vec![declared(ServedKind::Folder, None)],
            ..Default::default()
        },
    )
    .unwrap();
    let served = bundle.served.expect("declared source");
    assert_eq!((served.kind, served.location), (ServedKind::Folder, None));
    let bundle = build_mount_source_with_bindings(
        &[],
        &mut options(),
        false,
        CompositingOptions::default(),
        SourceBindings {
            sources: vec![declared(
                ServedKind::Archive,
                Some(ServedLocation::Local(archive.clone())),
            )],
            ..Default::default()
        },
    )
    .unwrap();
    let served = bundle.served.expect("declared rolling source");
    assert_eq!(served.kind, ServedKind::Archive);
    assert_eq!(
        served.location,
        Some(ServedLocation::Local(archive.clone()))
    );
    let bundle = build_mount_source_with_bindings(
        std::slice::from_ref(&folder),
        &mut options(),
        false,
        CompositingOptions::default(),
        SourceBindings {
            sources: vec![declared(ServedKind::Archive, None)],
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(bundle.served.expect("input wins").kind, ServedKind::Folder);

    // Composite: the first element in factory order is what is reported.
    let served = served_of(&[archive.clone(), folder.clone()], &mut options());
    assert_eq!(served.kind, ServedKind::Archive);
    let served = served_of(&[folder.clone(), archive.clone()], &mut options());
    assert_eq!(served.kind, ServedKind::Folder);

    // Bind-only: the bind source is the first (only) element.
    let bundle = build_mount_source_with_bindings(
        &[],
        &mut options(),
        false,
        CompositingOptions::default(),
        SourceBindings {
            binds: vec![SourceBind {
                mount_path: "/b".into(),
                source: archive.to_string_lossy().into(),
            }],
            ..Default::default()
        },
    )
    .unwrap();
    let served = bundle.served.clone().expect("bind-only");
    assert_eq!(served.kind, ServedKind::Archive);
    assert_eq!(
        served.location,
        Some(ServedLocation::Local(archive.clone()))
    );
    // The fetched-file keep-alive is handed out without the bundle.
    let _keep_alive: Box<dyn std::any::Any + Send + Sync> = bundle.into_keep_alive();

    // `file://` is a local path: the resolved path, never the typed URI.
    let url = |p: &Path| PathBuf::from(url::Url::from_file_path(p).unwrap().as_str());
    let served = served_of(&[url(&archive)], &mut options());
    assert_eq!(served.kind, ServedKind::Archive);
    assert_eq!(
        served.location,
        Some(ServedLocation::Local(archive.clone()))
    );
    assert!(!served.fetched, "file:// is not a fetched copy");
    let served = served_of(&[url(&folder)], &mut options());
    assert_eq!(served.kind, ServedKind::Folder);
    assert_eq!(served.location, Some(ServedLocation::Local(folder.clone())));
}

/// R6-1: Git rows. The tree is the one actually served (after any subtree
/// selection) and the location is the repository path that was opened, not
/// the typed selector.
#[cfg(feature = "git")]
#[test]
fn regression_served_kind_table_git() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let work = root.join("work");
    let bare = root.join("bare.git");
    let (work_tree, work_commit) = commit_repo(&work, false);
    let (bare_tree, _) = commit_repo(&bare, true);

    // `--git` on a working tree.
    let mut opts = options();
    opts.git = true;
    let served = served_of(std::slice::from_ref(&work), &mut opts);
    assert_eq!(
        served.kind,
        ServedKind::Git {
            tree: work_tree.clone()
        }
    );
    assert_eq!(served.location, Some(ServedLocation::Local(work.clone())));

    // A bare repository is Git without any flag.
    let served = served_of(std::slice::from_ref(&bare), &mut options());
    assert_eq!(served.kind, ServedKind::Git { tree: bare_tree });
    assert_eq!(served.location, Some(ServedLocation::Local(bare.clone())));

    // `repo@rev`: the location is the repository, not the typed selector.
    let typed = PathBuf::from(format!("{}@{work_commit}", work.display()));
    let served = served_of(&[typed], &mut options());
    assert_eq!(served.kind, ServedKind::Git { tree: work_tree });
    assert_eq!(served.location, Some(ServedLocation::Local(work.clone())));

    // Composite and bind selectors report the resolved repository too.
    let archive = root.join("a.tar");
    tar(&archive);
    let typed = PathBuf::from(format!("{}@{work_commit}", work.display()));
    let served = served_of(&[typed.clone(), archive.clone()], &mut options());
    assert_eq!(served.location, Some(ServedLocation::Local(work.clone())));
    assert!(matches!(served.kind, ServedKind::Git { .. }), "{served:?}");
    let bundle = build_mount_source_with_bindings(
        &[],
        &mut options(),
        false,
        CompositingOptions::default(),
        SourceBindings {
            binds: vec![SourceBind {
                mount_path: "/repo".into(),
                source: typed.to_string_lossy().into_owned(),
            }],
            ..Default::default()
        },
    )
    .unwrap();
    let served = bundle.served.expect("bind-only git");
    assert_eq!(served.location, Some(ServedLocation::Local(work.clone())));
    assert!(matches!(served.kind, ServedKind::Git { .. }), "{served:?}");

    // A working tree without a flag is a plain folder.
    let served = served_of(std::slice::from_ref(&work), &mut options());
    assert_eq!(served.kind, ServedKind::Folder);

    // `file://` bare repository: Git, and the resolved path.
    let url = PathBuf::from(url::Url::from_file_path(&bare).unwrap().as_str());
    let served = served_of(&[url], &mut options());
    assert!(matches!(served.kind, ServedKind::Git { .. }), "{served:?}");
    assert_eq!(served.location, Some(ServedLocation::Local(bare)));
}

/// R6-6: an in-memory open (every offline verb) selects no index, so the
/// token would have nothing to peek a cached digest in. The factory names the
/// sidecar the open WOULD have used (sibling, a custom `--index-folders`
/// entry, or an explicit `--index-file`), as a pure path computation: nothing
/// is created, fetched or written, and a name with no existing file is none.
#[test]
fn regression_served_sidecar_candidate() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let archive = root.join("a.tar");
    tar(&archive);
    let in_memory = || OpenOptions {
        index_in_memory: true,
        write_index: false,
        ..Default::default()
    };
    // No sidecar anywhere: no candidate, and the open created none.
    let served = served_of(std::slice::from_ref(&archive), &mut in_memory());
    assert_eq!(served.sidecar_candidate, None);
    assert!(!root.join("a.tar.index.sqlite").exists());
    // The sibling sidecar.
    let sibling = root.join("a.tar.index.sqlite");
    drop(
        build_mount_source_ex(
            std::slice::from_ref(&archive),
            &mut OpenOptions {
                write_index: true,
                index_minimum_file_count: 0,
                ..Default::default()
            },
            true,
            CompositingOptions::default(),
        )
        .unwrap(),
    );
    assert!(
        sibling.is_file(),
        "the writing open made the sibling sidecar"
    );
    let served = served_of(std::slice::from_ref(&archive), &mut in_memory());
    assert_eq!(served.sidecar_candidate, Some(sibling.clone()));
    assert_eq!(
        served.index,
        IndexProvenance::None,
        "the index itself stays in memory"
    );
    // A custom folder wins over a missing sibling (named like the index).
    std::fs::remove_file(&sibling).unwrap();
    let folder = root.join("idx");
    std::fs::create_dir(&folder).unwrap();
    let named = folder.join(format!("{}.index.sqlite", archive.display()).replace('/', "_"));
    std::fs::write(&named, b"not empty").unwrap();
    let mut options = in_memory();
    options.index_folders = vec![folder.clone()];
    assert_eq!(
        served_of(std::slice::from_ref(&archive), &mut options).sidecar_candidate,
        Some(named.clone())
    );
    // An explicit existing `--index-file` is the candidate; `:memory:` is none.
    let mut options = in_memory();
    options.index_file_path = Some(named.clone());
    assert_eq!(
        served_of(std::slice::from_ref(&archive), &mut options).sidecar_candidate,
        Some(named)
    );
    let mut options = in_memory();
    options.index_file_path = Some(PathBuf::from(ratarmount_index::MEMORY_INDEX));
    assert_eq!(
        served_of(std::slice::from_ref(&archive), &mut options).sidecar_candidate,
        None
    );
}

/// R6-1 (guardrail 4): the arms with no offline server still get a row. A
/// body fetched over ssh/scp/sftp or webdav(s), and a torrent (whose "path" is
/// `torrent:<infohash>`), are `Remote` at the TYPED location - never the
/// temporary copy or the torrent pseudo-path; only a `file://` body is Local.
#[test]
fn regression_served_kind_table_fetched_and_torrent() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    let source: Arc<dyn MountSource> = Arc::new(FolderMountSource::new(&root).unwrap());
    let opened =
        |path: &str, kind: ServedKind, local: bool, fetched: bool| remote_open::RemoteOpened {
            path: PathBuf::from(path),
            source: source.clone(),
            kind,
            local,
            fetched,
            index: IndexUsed::none(),
        };
    let rows = [
        // (typed input, what the arm returned, expected location is remote)
        (
            "ssh://user@host.example/data/a.tar",
            opened("/tmp/fetched-ssh.tar", ServedKind::Archive, false, true),
            true,
        ),
        (
            "sftp://host.example/data/a.tar",
            opened("/tmp/fetched-sftp.tar", ServedKind::Archive, false, true),
            true,
        ),
        (
            "scp://host.example/data/a.tar",
            opened("/tmp/fetched-scp.tar", ServedKind::Archive, false, true),
            true,
        ),
        (
            "webdav://host.example/files/a.tar",
            opened("/tmp/fetched-dav.tar", ServedKind::Archive, false, true),
            true,
        ),
        (
            "webdavs://host.example/files/a.tar",
            opened("/tmp/fetched-davs.tar", ServedKind::Archive, false, true),
            true,
        ),
        (
            "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567",
            opened(
                "torrent:0123456789abcdef0123456789abcdef01234567",
                ServedKind::Folder,
                false,
                false,
            ),
            true,
        ),
        (
            "file:///data/a.tar",
            opened("/data/a.tar", ServedKind::Archive, true, false),
            false,
        ),
    ];
    for (input, opened, remote) in rows {
        let served = served_from_remote(input, &opened);
        assert_eq!(served.kind, opened.kind, "{input}");
        assert_eq!(served.fetched, opened.fetched, "{input}");
        let expected = if remote {
            ServedLocation::Remote(input.to_owned())
        } else {
            ServedLocation::Local(opened.path.clone())
        };
        assert_eq!(served.location, Some(expected), "{input}");
    }
}

/// Regression (R6-H5, B5): the offline `--commit-overlay` classifier took its
/// kind from `stat` alone, so a bare repository was a Folder although the
/// factory serves Git. `served_without_indexing` sniffs what the factory would
/// serve: a bare repository is Git (with its tree id), a file is an Archive, a
/// directory a Folder, and nothing is created beside any of them (no index,
/// sidecar or journal).
#[test]
fn regression_served_without_indexing_sniffs_git_and_builds_no_index() {
    fn listing(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = walkdir_names(dir);
        names.sort();
        names
    }
    fn walkdir_names(dir: &Path) -> Vec<String> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            out.push(entry.path().to_string_lossy().into_owned());
            if entry.file_type().unwrap().is_dir() {
                out.extend(walkdir_names(&entry.path()));
            }
        }
        out
    }
    let dir = tempfile::tempdir().unwrap();
    let bare = dir.path().join("repo.git");
    let (tree, _) = commit_repo(&bare, true);
    let archive = dir.path().join("a.tar");
    tar(&archive);
    let folder = dir.path().join("plain");
    std::fs::create_dir(&folder).unwrap();
    let before = listing(dir.path());

    let served = served_without_indexing(&bare, &[]).unwrap();
    assert_eq!(served.kind, ServedKind::Git { tree }, "bare repo is Git");
    assert!(matches!(served.index, IndexProvenance::None));
    let served = served_without_indexing(&archive, &[]).unwrap();
    assert_eq!(served.kind, ServedKind::Archive);
    assert!(matches!(served.index, IndexProvenance::None));
    let served = served_without_indexing(&folder, &[]).unwrap();
    assert_eq!(served.kind, ServedKind::Folder);
    assert_eq!(listing(dir.path()), before, "something was created");
}
