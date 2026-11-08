use super::*;
use std::fs;

// Test-only fixture policy. Never discover a host mount or create a missing root.
pub(super) fn unavailable<T>(
    variable: &str,
    group: &str,
    cause: impl std::fmt::Display,
) -> Option<T> {
    let root = std::env::var_os(variable);
    match std::env::var("RRS_A1_REQUIRE_FIXTURES").as_deref() {
        Ok("1") => {
            panic!("A1_REQUIRED_FIXTURE_FAILURE {group} {variable} root={root:?} cause={cause}")
        }
        Err(std::env::VarError::NotPresent) | Ok("0") => {
            eprintln!("A1_OPTIONAL_FIXTURE_SKIP {group} {variable} root={root:?} cause={cause}");
            None
        }
        other => panic!(
            "A1_REQUIRED_FIXTURE_FAILURE {group} {variable} root={root:?} cause=invalid RRS_A1_REQUIRE_FIXTURES: {other:?}"
        ),
    }
}

pub(super) fn complete(name: &str, groups: &[&str]) {
    for group in groups {
        eprintln!("A1_GROUP_COMPLETE {group}");
    }
    eprintln!("A1_TEST_COMPLETE {name}");
}

fn owned_root(root: &Path) -> Result<(), String> {
    if !root.is_absolute() || root.parent().is_none() {
        return Err("root must be an explicit absolute owned child directory".into());
    }
    let metadata = fs::symlink_metadata(root).map_err(|e| format!("root metadata: {e}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("root is not a directory or is a link".into());
    }
    let canonical = fs::canonicalize(root).map_err(|e| format!("root canonicalize: {e}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if canonical != root {
            return Err("root must be its exact canonical path (no aliased ancestors)".into());
        }
        // SAFETY: geteuid has no preconditions or side effects.
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err("root must be owned by this uid and private (mode 0700)".into());
        }
    }
    Ok(())
}

pub(super) struct Fixture {
    temp: tempfile::TempDir,
    root: std::path::PathBuf,
    directory: NativeDirectory,
    snapshot: DirectoryCapabilities,
    variable: &'static str,
    group: &'static str,
    required: bool,
}

impl Fixture {
    pub(super) fn path(&self) -> &Path {
        self.temp.path()
    }

    #[cfg(target_os = "linux")]
    pub(super) fn root(&self) -> &Path {
        &self.root
    }

    pub(super) fn verify(&self) {
        let result = (|| -> Result<(), String> {
            owned_root(&self.root)?;
            let current = NativeDirectory::open_parent(&self.root)
                .and_then(|d| d.capabilities())
                .map_err(|e| format!("root recheck: {e}"))?;
            if current != self.snapshot
                || self.directory.capabilities().map_err(|e| e.to_string())? != self.snapshot
            {
                return Err("configured root identity/type/mode changed".into());
            }
            Ok(())
        })();
        assert!(
            result.is_ok(),
            "A1_REQUIRED_FIXTURE_FAILURE {} {} root={:?} cause={result:?}",
            self.group,
            self.variable,
            self.root
        );
    }
}

pub(super) fn fixture(
    variable: &'static str,
    group: &'static str,
    check: impl Fn(&Path, &DirectoryCapabilities) -> Result<(), String>,
) -> Option<Fixture> {
    let result = (|| -> Result<Fixture, String> {
        let required = match std::env::var("RRS_A1_REQUIRE_FIXTURES").as_deref() {
            Ok("1") => true,
            Err(std::env::VarError::NotPresent) | Ok("0") => false,
            other => return Err(format!("invalid required-fixtures flag: {other:?}")),
        };
        let root = std::path::PathBuf::from(
            std::env::var_os(variable).ok_or_else(|| "root is unset".to_string())?,
        );
        owned_root(&root)?;
        let directory = NativeDirectory::open_parent(&root).map_err(|e| e.to_string())?;
        let snapshot = directory.capabilities().map_err(|e| e.to_string())?;
        if !matches!(snapshot.identity, Capability::Known(_)) {
            return Err("root full identity unavailable".into());
        }
        check(&root, &snapshot)?;
        let temp = tempfile::tempdir_in(&root).map_err(|e| format!("root not writable: {e}"))?;
        let child = NativeDirectory::open_parent(temp.path())
            .and_then(|d| d.capabilities())
            .map_err(|e| format!("child capabilities: {e}"))?;
        if child.filesystem != snapshot.filesystem {
            return Err("child filesystem differs from configured root".into());
        }
        check(temp.path(), &child)?;
        let fixture = Fixture {
            temp,
            root,
            directory,
            snapshot,
            variable,
            group,
            required,
        };
        fixture.verify();
        eprintln!(
            "A1_FIXTURE_ROOT {group} {variable} mode={} root={:?} snapshot={:?}",
            if fixture.required {
                "required"
            } else {
                "optional"
            },
            fixture.root,
            fixture.snapshot
        );
        Ok(fixture)
    })();
    match result {
        Ok(fixture) => Some(fixture),
        Err(cause) => unavailable(variable, group, cause),
    }
}

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
    complete(
        "checked_open::native_fs::tests::regression_235_part2_a1_macos_objid_link_ids",
        &["seam.macos_objid_link_ids"],
    );
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
    complete(
        "checked_open::native_fs::tests::regression_235_part2_a1_macos_objid_low32_collision",
        &["seam.macos_objid_low32_collision"],
    );
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
    complete(
        "checked_open::native_fs::tests::regression_235_part2_a1_component_validation",
        &["shared.component_validation"],
    );
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
    complete(
        "checked_open::native_fs::tests::regression_235_part2_a1_existing_and_missing",
        &["shared.existing_and_missing"],
    );
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
    complete(
        "checked_open::native_fs::tests::regression_235_part2_a1_parent_and_leaf_links",
        &["unix.parent_and_leaf_links"],
    );
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
    complete(
        "checked_open::native_fs::tests::regression_235_part2_a1_query_drift",
        &["seam.query_drift"],
    );
}

// Test-only observations from the live connection, including every lock child.
// Ordinary workspace tests still run the complete lock proof without qualification.
#[cfg(unix)]
fn observe_engine(connection: &rusqlite::Connection, role: &str) {
    use rusqlite::OptionalExtension;
    use sha2::{Digest, Sha256};
    let strict = match std::env::var("RRS_A1_STRICT_ENGINE").as_deref() {
        Ok("1") => true,
        Err(std::env::VarError::NotPresent) | Ok("0") => false,
        _ => panic!("invalid RRS_A1_STRICT_ENGINE"),
    };
    let expected = match std::env::var("RATARMOUNT_TEST_SQLITE_BACKEND") {
        Ok(value) if value == "stock" || value == "sqlcipher" => Some(value),
        Err(std::env::VarError::NotPresent) if !strict => None,
        Err(std::env::VarError::NotPresent) => {
            panic!("strict engine requires RATARMOUNT_TEST_SQLITE_BACKEND")
        }
        _ => panic!("invalid RATARMOUNT_TEST_SQLITE_BACKEND"),
    };
    let version: String = connection
        .query_row("SELECT sqlite_version()", [], |row| row.get(0))
        .unwrap();
    let source_id: String = connection
        .query_row("SELECT sqlite_source_id()", [], |row| row.get(0))
        .unwrap();
    let cipher: Option<String> = connection
        .query_row("PRAGMA cipher_version", [], |row| row.get(0))
        .optional()
        .unwrap();
    assert!(!version.trim().is_empty() && !source_id.trim().is_empty());
    assert!(cipher.as_ref().is_none_or(|value| !value.trim().is_empty()));
    let actual = if cipher.is_some() {
        "sqlcipher"
    } else {
        "stock"
    };
    if let Some(expected) = &expected {
        assert_eq!(
            expected, actual,
            "SQLite engine differs from requested backend"
        );
    }
    let executable = fs::canonicalize(std::env::current_exe().unwrap()).unwrap();
    if strict {
        assert_eq!(
            executable,
            std::path::PathBuf::from(std::env::var_os("RRS_A1_ENGINE_EXE").unwrap()),
            "engine executable binding differs"
        );
    }
    let digest = format!("{:x}", Sha256::digest(fs::read(&executable).unwrap()));
    eprintln!(
        "ENGINE_OBSERVATION {}",
        serde_json::json!({"role": role, "version": version, "source_id": source_id,
            "cipher_version": cipher, "engine": actual, "strict": strict,
            "expected": expected, "executable": executable, "sha256": digest,
            "pid": std::process::id()})
    );
}

/// Regression: metadata queries/drop preserve SQLite POSIX locks on hard-linked files.
#[cfg(unix)]
#[test]
fn regression_235_part2_a1_unix_queries_preserve_locks() {
    use std::os::fd::AsRawFd;
    if let Some(path) = std::env::var_os("RRS_A1_LOCK_CHILD") {
        let role = std::env::var("RRS_A1_LOCK_ROLE").unwrap();
        let expected = match role.as_str() {
            "initial_locked"
            | "during_queries_locked"
            | "after_drop_locked"
            | "restarted_locked" => true,
            "after_rollback_released" | "raw_alias_close_released" => false,
            _ => panic!("unknown lock child role {role:?}"),
        };
        eprintln!("A1_LOCK_CHILD_BEGIN {role}");
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
        observe_engine(&c, &role);
        c.busy_timeout(std::time::Duration::ZERO).unwrap();
        let busy = match c.execute_batch("BEGIN IMMEDIATE") {
            Ok(()) => false,
            Err(error) => {
                assert_eq!(
                    error.sqlite_error_code(),
                    Some(rusqlite::ErrorCode::DatabaseBusy)
                );
                true
            }
        };
        assert_eq!((locked, busy), (expected, expected));
        eprintln!("A1_LOCK_CHILD_COMPLETE {role}");
        return;
    }
    eprintln!("A1_LOCK_PARENT_BEGIN");
    let _guard = crate::test_process::exclusive(); // No nested spawning guard.
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("main");
    let c = rusqlite::Connection::open(&path).unwrap();
    observe_engine(&c, "parent");
    c.execute_batch("CREATE TABLE t(x); BEGIN IMMEDIATE;")
        .unwrap();
    fs::hard_link(&path, t.path().join("alias")).unwrap();
    let borrowed = File::open(&path).unwrap();
    let probe = |role: &str| {
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "checked_open::native_fs::tests::regression_235_part2_a1_unix_queries_preserve_locks", "--nocapture", "--test-threads=1"])
            .env("RRS_A1_LOCK_CHILD", &path).env("RRS_A1_LOCK_ROLE", role).spawn().unwrap();
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
    probe("initial_locked");
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
        probe("during_queries_locked");
    }
    probe("after_drop_locked");
    assert_eq!(before, names());
    c.execute_batch("ROLLBACK").unwrap();
    probe("after_rollback_released");
    c.execute_batch("BEGIN IMMEDIATE").unwrap();
    probe("restarted_locked");
    drop(File::open(t.path().join("alias")).unwrap()); // Test-only POSIX negative control.
    probe("raw_alias_close_released");
    c.execute_batch("ROLLBACK").unwrap();
    complete(
        "checked_open::native_fs::tests::regression_235_part2_a1_unix_queries_preserve_locks",
        &["unix.lock_parent"],
    );
}

#[cfg(target_os = "linux")]
mod linux_tests {
    use super::super::linux::*;
    use super::*;
    use std::os::unix::fs::MetadataExt;

    fn assert_identity(path: &Path, c: &DirectoryCapabilities) {
        let metadata = fs::metadata(path).unwrap();
        assert_eq!(
            c.identity,
            Capability::Known(NativeIdentity::Linux {
                device: metadata.dev(),
                inode: metadata.ino(),
            })
        );
    }

    fn linux_fixture(
        variable: &'static str,
        group: &'static str,
        expected: LinuxFilesystem,
    ) -> Option<Fixture> {
        fixture(variable, group, |root, caps| {
            corroborate(root, expected)?;
            if !matches!(caps.filesystem, FilesystemKind::Linux { kind, .. } if kind == expected) {
                return Err(format!("wrong native filesystem: {:?}", caps.filesystem));
            }
            if expected == LinuxFilesystem::ExtFamily
                && !matches!(caps.linux_flags, Capability::Known(flags) if flags & CASEFOLD == 0)
            {
                return Err(format!(
                    "ext4 sensitive root GETFLAGS required: {:?}",
                    caps.linux_flags
                ));
            }
            assert_identity(root, caps);
            Ok(())
        })
    }

    fn exercise(variable: &'static str, group: &'static str, expected: LinuxFilesystem) -> bool {
        let Some(t) = linux_fixture(variable, group, expected) else {
            return false;
        };
        let d = NativeDirectory::open_parent(t.path()).unwrap();
        let c = d.capabilities().unwrap();
        assert!(matches!(c.filesystem, FilesystemKind::Linux { kind, .. } if kind == expected));
        assert_identity(t.path(), &c);
        assert_eq!(
            c.case_sensitive,
            if expected == LinuxFilesystem::Tmpfs {
                Capability::Unavailable(CapabilityUnavailable::UnreviewedFilesystem)
            } else {
                Capability::Known(CaseMode::Sensitive)
            }
        );
        if expected == LinuxFilesystem::ExtFamily {
            assert!(matches!(c.linux_flags, Capability::Known(flags) if flags & CASEFOLD == 0));
        }
        for (a, b) in [("Name", "name"), ("é", "e\u{301}")] {
            fs::write(t.path().join(a), b"same").unwrap();
            fs::write(t.path().join(b), b"same").unwrap();
            assert!(matches!(
                d.compare_existing(OsStr::new(a), OsStr::new(b)).unwrap(),
                ExistingNameComparison::DifferentObjects { .. }
            ));
        }
        corroborate(t.root(), expected).unwrap();
        t.verify();
        true
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

    fn corroborate(root: &Path, expected: LinuxFilesystem) -> Result<(), String> {
        let mounts = fs::read_to_string("/proc/self/mountinfo")
            .map_err(|e| format!("mountinfo unavailable: {e}"))?;
        let kind = if expected == LinuxFilesystem::Tmpfs {
            "tmpfs"
        } else {
            "ext4"
        };
        if mounted_fs(&mounts, root) != Some(kind) {
            return Err(format!(
                "wrong filesystem: mountinfo does not corroborate {kind} for {root:?}"
            ));
        }
        let metadata = fs::metadata(root).map_err(|e| e.to_string())?;
        let device = format!(
            "{}:{}",
            libc::major(metadata.dev()),
            libc::minor(metadata.dev())
        );
        let deepest = mounts
            .lines()
            .filter_map(|line| {
                let (a, _) = line.split_once(" - ")?;
                let fields: Vec<_> = a.split_whitespace().collect();
                let mount = mount_path(fields.get(4)?);
                root.starts_with(&mount)
                    .then_some((mount.as_os_str().len(), *fields.get(2)?))
            })
            .max_by_key(|(len, _)| *len);
        if deepest.map(|(_, dev)| dev) != Some(device.as_str()) {
            return Err("mountinfo device differs from root metadata".into());
        }
        Ok(())
    }

    /// Regression: native tmpfs IDs/modes and distinct NFC/NFD spellings.
    #[test]
    fn regression_235_part2_a1_linux_tmpfs() {
        if exercise("RRS_A1_TMPFS_ROOT", "linux.tmpfs", LinuxFilesystem::Tmpfs) {
            complete(
                "checked_open::native_fs::tests::linux_tests::regression_235_part2_a1_linux_tmpfs",
                &["linux.tmpfs_identity", "linux.tmpfs_names"],
            );
        }
    }

    /// Regression: ext4 sensitivity must be based on flags, not shared magic alone.
    #[test]
    fn regression_235_part2_a1_linux_ext4() {
        if exercise(
            "RRS_A1_EXT4_ROOT",
            "linux.ext4_sensitive",
            LinuxFilesystem::ExtFamily,
        ) {
            complete(
                "checked_open::native_fs::tests::linux_tests::regression_235_part2_a1_linux_ext4",
                &[
                    "linux.ext4_sensitive_identity",
                    "linux.ext4_sensitive_flags",
                ],
            );
        }
    }

    /// Regression: FS_CASEFOLD_FL is queried on a disposable ext4 directory only.
    #[test]
    fn regression_235_part2_a1_linux_ext4_casefold() {
        use std::os::fd::AsRawFd;
        let Some(t) = linux_fixture(
            "RRS_A1_EXT4_ROOT",
            "linux.ext4_casefold",
            LinuxFilesystem::ExtFamily,
        ) else {
            return;
        };
        let d = NativeDirectory::open_parent(t.path()).unwrap();
        let Capability::Known(flags) = d.capabilities().unwrap().linux_flags else {
            let _ = unavailable::<()>(
                "RRS_A1_EXT4_ROOT",
                "linux.ext4_casefold",
                "child GETFLAGS unavailable",
            );
            return;
        };
        let flags = (flags | CASEFOLD) as libc::c_int;
        // SAFETY: changes flags only on an owned empty disposable child directory.
        if unsafe { libc::ioctl(d.file.as_raw_fd(), libc::FS_IOC_SETFLAGS, &flags) } != 0 {
            let _ = unavailable::<()>(
                "RRS_A1_EXT4_ROOT",
                "linux.ext4_casefold",
                format!(
                    "SETFLAGS casefold unavailable: {}",
                    std::io::Error::last_os_error()
                ),
            );
            return;
        }
        let caps = d.capabilities().unwrap();
        assert_identity(t.path(), &caps);
        assert!(matches!(caps.linux_flags, Capability::Known(flags) if flags & CASEFOLD != 0));
        assert_eq!(
            caps.case_sensitive,
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
        corroborate(t.root(), LinuxFilesystem::ExtFamily).unwrap();
        t.verify();
        complete(
            "checked_open::native_fs::tests::linux_tests::regression_235_part2_a1_linux_ext4_casefold",
            &[
                "linux.ext4_casefold_identity",
                "linux.ext4_casefold_flags",
                "linux.ext4_casefold_names",
            ],
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
        complete(
            "checked_open::native_fs::tests::linux_tests::regression_235_part2_a1_linux_classification_errors",
            &["linux.classification_errors"],
        );
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
            let Some(t) = linux_fixture(
                "RRS_A1_TMPFS_ROOT",
                "linux.pending_experiments",
                LinuxFilesystem::Tmpfs,
            ) else {
                return;
            };
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
            corroborate(t.root(), LinuxFilesystem::Tmpfs).unwrap();
            t.verify();
        }
        complete(
            "checked_open::native_fs::tests::linux_tests::regression_235_part2_a1_linux_pending_after_experiment",
            &["linux.pending_experiments"],
        );
    }
}
