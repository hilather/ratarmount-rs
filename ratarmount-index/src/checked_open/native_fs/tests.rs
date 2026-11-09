use super::*;
use std::fs;

fn raw(id: Option<u64>, object: u32) -> Lookup {
    Lookup::Existing(ExistingObject {
        identity: id.map_or(
            Capability::Unavailable(CapabilityUnavailable::FullIdentityUnavailable(None)),
            |file_id| {
                Capability::Known(NativeIdentity::MacOs {
                    volume: [1, 2],
                    file_id,
                })
            },
        ),
        kind: ObjectKind::File,
        mac_objid: Some(MacObjIdObservation {
            object,
            generation: 0,
        }),
    })
}

fn undecided(a: Lookup, b: Lookup) {
    for (a, b) in [(a.clone(), b.clone()), (b, a)] {
        assert!(matches!(
            compare(a, b),
            ExistingNameComparison::Undecided {
                reason: UndecidedReason::FullIdentityUnavailable,
                ..
            }
        ));
    }
}

/// Regression: link-specific OBJID differences cannot decide different objects.
#[test]
fn regression_235_part2_a1_macos_objid_link_ids() {
    undecided(raw(None, 41), raw(None, 42));
    undecided(raw(Some(7), 41), raw(None, 42));
    assert!(matches!(
        compare(raw(Some(7), 41), raw(Some(7), 42)),
        ExistingNameComparison::SameObject { .. }
    ));
}

/// Regression: matching low32 OBJIDs cannot hide distinct full FILEIDs.
#[test]
fn regression_235_part2_a1_macos_objid_low32_collision() {
    undecided(raw(None, 42), raw(None, 42));
    undecided(raw(Some(0x1_0000_002a), 42), raw(None, 42));
    assert!(matches!(
        compare(raw(Some(0x1_0000_002a), 42), raw(Some(0x2_0000_002a), 42)),
        ExistingNameComparison::DifferentObjects { .. }
    ));
    let linux = Lookup::Existing(ExistingObject {
        identity: Capability::Known(NativeIdentity::Linux {
            device: 1,
            inode: 7,
        }),
        kind: ObjectKind::File,
        mac_objid: None,
    });
    assert!(matches!(
        compare(raw(Some(7), 42), linux),
        ExistingNameComparison::Undecided {
            reason: UndecidedReason::IncomparableDomains,
            ..
        }
    ));
}

/// Regression: components are untouched native names, never paths or NUL strings.
#[test]
fn regression_235_part2_a1_component_validation() {
    for s in ["", ".", "..", "/", "a/b", "a\0b"] {
        assert!(validate(OsStr::new(s)).is_err(), "{s:?}");
    }
    for s in ["main-wal", "é", "e\u{301}"] {
        validate(OsStr::new(s)).unwrap();
    }
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        validate(OsStr::from_bytes(b"\xff")).unwrap();
    }
}

/// Regression: only existing full IDs decide equivalence, including hard links.
#[test]
fn regression_235_part2_a1_existing_and_missing() {
    let t = tempfile::tempdir().unwrap();
    fs::write(t.path().join("main"), b"identical bytes").unwrap();
    fs::write(t.path().join("main-wal"), b"identical bytes").unwrap();
    fs::hard_link(t.path().join("main"), t.path().join("alias")).unwrap();
    let d = NativeDirectory::open_parent(t.path()).unwrap();
    assert!(matches!(
        d.compare_existing(OsStr::new("main"), OsStr::new("alias"))
            .unwrap(),
        ExistingNameComparison::SameObject { .. }
    ));
    assert!(matches!(
        d.compare_existing(OsStr::new("main"), OsStr::new("main-wal"))
            .unwrap(),
        ExistingNameComparison::DifferentObjects { .. }
    ));
    for (a, b) in [
        ("main", "absent"),
        ("absent", "main"),
        ("absent", "absent2"),
    ] {
        assert!(matches!(
            d.compare_existing(OsStr::new(a), OsStr::new(b)).unwrap(),
            ExistingNameComparison::Undecided {
                reason: UndecidedReason::AbsentName(AbsentNameDecision::Adr1),
                ..
            }
        ));
    }
    assert_eq!(fs::read_dir(t.path()).unwrap().count(), 3);
}

/// Regression: parent aliases work while leaf/companion links never attest targets.
#[cfg(unix)]
#[test]
fn regression_235_part2_a1_parent_and_leaf_links() {
    use std::os::unix::fs::symlink;
    let t = tempfile::tempdir().unwrap();
    fs::create_dir(t.path().join("dir")).unwrap();
    symlink("dir", t.path().join("parent")).unwrap();
    let d = NativeDirectory::open_parent(&t.path().join("parent")).unwrap();
    fs::write(t.path().join("dir/main"), b"unchanged").unwrap();
    for (name, target) in [
        ("link", "main"),
        ("dangling", "missing"),
        ("main-journal", "main"),
        ("main-wal", "main"),
        ("main-shm", "main"),
    ] {
        symlink(target, t.path().join("dir").join(name)).unwrap();
        assert_eq!(
            d.lookup_existing(OsStr::new(name)).unwrap_err().kind,
            NativeFsErrorKind::LeafLinkOrReparse
        );
    }
    let fifo = t.path().join("dir/fifo");
    use std::os::unix::ffi::OsStrExt;
    let fifo = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
    // SAFETY: special-object fixture in an owned disposable directory.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert_eq!(
        d.lookup_existing(OsStr::new("fifo")).unwrap_err().kind,
        NativeFsErrorKind::WrongKind
    );
    assert_eq!(fs::read(t.path().join("dir/main")).unwrap(), b"unchanged");
}

/// Regression: bounded drift retries and unavailable parent IDs never certify stability.
#[test]
fn regression_235_part2_a1_query_drift() {
    let t = tempfile::tempdir().unwrap();
    let d = NativeDirectory::open_parent(t.path()).unwrap();
    let mut caps = d.capabilities().unwrap();
    let mut count = 0;
    let result = stable(
        || {
            count += 1;
            caps.case_sensitive = Capability::Known(if count % 2 == 0 {
                CaseMode::Sensitive
            } else {
                CaseMode::Insensitive
            });
            Ok(caps.clone())
        },
        || Ok(()),
    );
    assert_eq!(
        result.unwrap_err().kind,
        NativeFsErrorKind::ChangedDuringQuery
    );
    assert_eq!(count, 6);
    caps.identity = Capability::Unavailable(CapabilityUnavailable::FullIdentityUnavailable(None));
    let mut actions = 0;
    assert_eq!(
        stable(
            || Ok(caps.clone()),
            || {
                actions += 1;
                Ok(())
            }
        )
        .unwrap_err()
        .kind,
        NativeFsErrorKind::FullIdentityUnavailable
    );
    assert_eq!(actions, 0);
}

/// Regression: metadata queries/drop preserve SQLite POSIX locks on hard-linked files.
#[cfg(unix)]
#[test]
fn regression_235_part2_a1_unix_queries_preserve_locks() {
    use std::os::fd::AsRawFd;
    if let Some(path) = std::env::var_os("RRS_A1_LOCK_CHILD") {
        let f = File::open(&path).unwrap();
        // SAFETY: initialized flock output and a borrowed regular-file descriptor.
        let locked = unsafe {
            let mut lock: libc::flock = std::mem::zeroed();
            lock.l_type = libc::F_WRLCK as _;
            lock.l_whence = libc::SEEK_SET as _;
            assert_eq!(libc::fcntl(f.as_raw_fd(), libc::F_GETLK, &mut lock), 0);
            lock.l_type != libc::F_UNLCK as libc::c_short
        };
        let c = rusqlite::Connection::open(&path).unwrap();
        c.busy_timeout(std::time::Duration::ZERO).unwrap();
        let busy = c.execute_batch("BEGIN IMMEDIATE").is_err();
        let expected = std::env::var("RRS_A1_EXPECT_LOCK").unwrap() == "1";
        assert_eq!((locked, busy), (expected, expected));
        return;
    }
    let _guard = crate::test_process::exclusive(); // No nested spawning guard.
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("main");
    let c = rusqlite::Connection::open(&path).unwrap();
    c.execute_batch("CREATE TABLE t(x); BEGIN IMMEDIATE;")
        .unwrap();
    fs::hard_link(&path, t.path().join("alias")).unwrap();
    let borrowed = File::open(&path).unwrap();
    let engine: String = c
        .query_row(
            "SELECT sqlite_version() || ' ' || sqlite_source_id()",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let cipher: Result<String, _> = c.query_row("PRAGMA cipher_version", [], |r| r.get(0));
    eprintln!("engine: {engine}; cipher_version: {cipher:?}");
    let probe = |expected: bool| {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "checked_open::native_fs::tests::regression_235_part2_a1_unix_queries_preserve_locks", "--nocapture"])
            .env("RRS_A1_LOCK_CHILD", &path).env("RRS_A1_EXPECT_LOCK", if expected { "1" } else { "0" }).spawn().unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if std::time::Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("lock child timeout");
            }
            std::thread::sleep(std::time::Duration::from_millis(5)); // Completion polling, not race synchronization.
        }
    };
    probe(true);
    let names = || {
        let mut n: Vec<_> = fs::read_dir(t.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        n.sort();
        n
    };
    let before = names();
    {
        let d = NativeDirectory::open_parent(t.path()).unwrap();
        identity_from_file(&borrowed).unwrap();
        d.capabilities().unwrap();
        for name in ["main", "alias", "main-journal", "main-wal", "main-shm"] {
            d.lookup_existing(OsStr::new(name)).unwrap();
        }
        d.compare_existing(OsStr::new("main"), OsStr::new("alias"))
            .unwrap();
        d.existing_short_names(OsStr::new("main")).unwrap();
        probe(true);
    }
    probe(true);
    assert_eq!(before, names());
    c.execute_batch("ROLLBACK").unwrap();
    probe(false);
    c.execute_batch("BEGIN IMMEDIATE").unwrap();
    probe(true);
    drop(File::open(t.path().join("alias")).unwrap()); // Test-only POSIX negative control.
    probe(false);
    c.execute_batch("ROLLBACK").unwrap();
}

#[cfg(target_os = "linux")]
mod linux_tests {
    use super::super::linux::*;
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn exercise(root: &Path, expected: LinuxFilesystem) {
        let t = match tempfile::tempdir_in(root) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("skip: {root:?} disposable filesystem fixture unavailable: {e}");
                return;
            }
        };
        let d = NativeDirectory::open_parent(t.path()).unwrap();
        let c = d.capabilities().unwrap();
        eprintln!("fixture {root:?}: {c:?}");
        assert!(matches!(c.filesystem, FilesystemKind::Linux { kind, .. } if kind == expected));
        let metadata = fs::metadata(t.path()).unwrap();
        assert_eq!(
            c.identity,
            Capability::Known(NativeIdentity::Linux {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        );
        assert_eq!(
            c.case_sensitive,
            if expected == LinuxFilesystem::Tmpfs {
                Capability::Unavailable(CapabilityUnavailable::UnreviewedFilesystem)
            } else {
                Capability::Known(CaseMode::Sensitive)
            }
        );
        for (a, b) in [("Name", "name"), ("é", "e\u{301}")] {
            fs::write(t.path().join(a), b"same").unwrap();
            fs::write(t.path().join(b), b"same").unwrap();
            assert!(matches!(
                d.compare_existing(OsStr::new(a), OsStr::new(b)).unwrap(),
                ExistingNameComparison::DifferentObjects { .. }
            ));
        }
    }

    fn mount_path(field: &str) -> std::path::PathBuf {
        field
            .replace("\\040", " ")
            .replace("\\011", "\t")
            .replace("\\012", "\n")
            .replace("\\134", "\\")
            .into()
    }

    fn mounted_fs<'a>(mounts: &'a str, root: &Path) -> Option<&'a str> {
        let entries: Vec<_> = mounts
            .lines()
            .filter_map(|l| {
                let (a, b) = l.split_once(" - ")?;
                let mount = mount_path(a.split_whitespace().nth(4)?);
                root.starts_with(&mount)
                    .then_some((mount.as_os_str().len(), b.split_whitespace().next()?))
            })
            .collect();
        let longest = entries.iter().map(|(len, _)| *len).max()?;
        let mut deepest = entries.iter().filter(|(len, _)| *len == longest);
        let kind = deepest.next()?.1;
        deepest.next().is_none().then_some(kind)
    }

    fn ext4_root() -> Option<std::path::PathBuf> {
        let mounts = fs::read_to_string("/proc/self/mountinfo").unwrap();
        let roots = std::env::var_os("RRS_A1_EXT4_ROOT").map_or_else(
            || {
                mounts
                    .lines()
                    .filter_map(|l| {
                        let (a, b) = l.split_once(" - ")?;
                        (b.split_whitespace().next()? == "ext4")
                            .then(|| mount_path(a.split_whitespace().nth(4).unwrap()))
                    })
                    .collect()
            },
            |p| vec![std::path::PathBuf::from(p)],
        );
        let found = roots
            .into_iter()
            .filter_map(|p| fs::canonicalize(p).ok())
            .find(|p| p.is_dir() && mounted_fs(&mounts, p) == Some("ext4"));
        if found.is_none() {
            eprintln!("skip: no ext4 fixture root corroborated by /proc/self/mountinfo (ext-family magic alone is insufficient)");
        }
        found
    }

    /// Regression: native tmpfs IDs/modes and distinct NFC/NFD spellings.
    #[test]
    fn regression_235_part2_a1_linux_tmpfs() {
        for root in [
            std::env::var_os("RRS_A1_TMPFS_ROOT").unwrap_or_else(|| "/tmp".into()),
            "/dev/shm".into(),
        ] {
            let root = Path::new(&root);
            if NativeDirectory::open_parent(root)
                .and_then(|d| d.capabilities())
                .is_ok_and(|c| {
                    matches!(
                        c.filesystem,
                        FilesystemKind::Linux {
                            kind: LinuxFilesystem::Tmpfs,
                            ..
                        }
                    )
                })
                && tempfile::tempdir_in(root).is_ok()
            {
                exercise(root, LinuxFilesystem::Tmpfs);
                return;
            }
        }
        eprintln!("skip: no verified writable tmpfs fixture at configured/default roots");
    }

    /// Regression: ext4 sensitivity must be based on flags, not shared magic alone.
    #[test]
    fn regression_235_part2_a1_linux_ext4() {
        if let Some(root) = ext4_root() {
            exercise(&root, LinuxFilesystem::ExtFamily);
        }
    }

    /// Regression: FS_CASEFOLD_FL is queried on a disposable ext4 directory only.
    #[test]
    fn regression_235_part2_a1_linux_ext4_casefold() {
        use std::os::fd::AsRawFd;
        let Some(root) = ext4_root() else {
            return;
        };
        let t = match tempfile::tempdir_in(&root) {
            Ok(t) => t,
            Err(e) => {
                eprintln!("skip: {root:?} disposable casefold fixture unavailable: {e}");
                return;
            }
        };
        let d = NativeDirectory::open_parent(t.path()).unwrap();
        let Capability::Known(flags) = d.capabilities().unwrap().linux_flags else {
            eprintln!("skip: ext4 GETFLAGS unavailable");
            return;
        };
        let flags = (flags | CASEFOLD) as libc::c_int;
        // SAFETY: changes flags only on an owned empty disposable child directory.
        if unsafe { libc::ioctl(d.file.as_raw_fd(), libc::FS_IOC_SETFLAGS, &flags) } != 0 {
            eprintln!(
                "skip: ext4 casefold fixture unavailable: {}",
                std::io::Error::last_os_error()
            );
            return;
        }
        assert_eq!(
            d.capabilities().unwrap().case_sensitive,
            Capability::Known(CaseMode::Insensitive)
        );
        for (a, b) in [("Name", "name"), ("é", "e\u{301}")] {
            fs::write(t.path().join(a), b"fixture").unwrap();
            assert!(matches!(
                d.compare_existing(OsStr::new(a), OsStr::new(b)).unwrap(),
                ExistingNameComparison::SameObject { .. }
            ));
        }
        assert_eq!(
            d.capabilities().unwrap().absent_names,
            AbsentNameCapability::default()
        );
    }

    /// Regression: unsupported ABI makes zero ioctls; access/I/O aren't case facts.
    #[test]
    fn regression_235_part2_a1_linux_classification_errors() {
        // Regression: ext4 ancestors must not corroborate nested ext2/tmpfs.
        let mounts = "1 0 8:1 / / rw - ext4 /dev/a rw\n2 1 8:2 / /nested rw - ext2 /dev/b rw\n3 1 0:3 / /with\\040space rw - tmpfs tmpfs rw\n";
        assert_eq!(mounted_fs(mounts, Path::new("/other")), Some("ext4"));
        assert_eq!(mounted_fs(mounts, Path::new("/nested/child")), Some("ext2"));
        assert_eq!(
            mounted_fs(mounts, Path::new("/with space/child")),
            Some("tmpfs")
        );
        assert_eq!(
            mounted_fs(&format!("{mounts}{mounts}"), Path::new("/nested")),
            None
        );
        assert_eq!(classify(0xffff_ffff), LinuxFilesystem::Unknown);
        assert_eq!(classify(0xef53), LinuxFilesystem::ExtFamily);
        assert_eq!(case_mode(0), CaseMode::Sensitive);
        assert_eq!(case_mode(CASEFOLD), CaseMode::Insensitive);
        assert_eq!(
            flags_with(true, || Ok(CASEFOLD)).unwrap(),
            Capability::Known(CASEFOLD)
        );
        assert_eq!(classify(0x9123_683e), LinuxFilesystem::RecognizedUnreviewed);
        let mut calls = 0;
        assert_eq!(
            flags_with(false, || {
                calls += 1;
                Ok(0)
            })
            .unwrap(),
            Capability::Unavailable(CapabilityUnavailable::UnsupportedAbi)
        );
        assert_eq!(calls, 0);
        for e in [libc::ENOTTY, libc::EOPNOTSUPP] {
            assert!(
                matches!(flags_with(true, || Err(e)).unwrap(), Capability::Unavailable(CapabilityUnavailable::UnsupportedApi(Some(NativeCode::Errno(n)))) if n == e)
            );
        }
        for (e, kind) in [
            (libc::EACCES, NativeFsErrorKind::Access),
            (libc::EIO, NativeFsErrorKind::Io),
        ] {
            let error = flags_with(true, || Err(e)).unwrap_err();
            assert_eq!((error.kind, error.code), (kind, Some(NativeCode::Errno(e))));
        }
    }

    /// Regression: disposable sentinel observations never upgrade the absent API.
    #[test]
    fn regression_235_part2_a1_linux_pending_after_experiment() {
        for (a, b) in [
            ("Case", "case"),
            ("case", "Case"),
            ("é", "e\u{301}"),
            ("e\u{301}", "é"),
        ] {
            let t = tempfile::tempdir().unwrap();
            fs::write(t.path().join(a), b"test-only sentinel").unwrap();
            let d = NativeDirectory::open_parent(t.path()).unwrap();
            eprintln!(
                "disposable {a:?} -> {b:?}: {:?}",
                d.lookup_existing(OsStr::new(b)).unwrap()
            );
            assert_eq!(
                d.capabilities().unwrap().absent_names,
                AbsentNameCapability::default()
            );
        }
    }
}
