use super::*;
use std::fs;
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::Storage::FileSystem::*;

fn fixture(variable: &str) -> Option<tempfile::TempDir> {
    let root = std::env::var_os(variable)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let t = tempfile::tempdir_in(root).unwrap();
    let c = NativeDirectory::open_parent(t.path())
        .unwrap()
        .capabilities()
        .unwrap();
    if !matches!(c.filesystem, FilesystemKind::Windows { ref name } if name == &"NTFS".encode_utf16().collect::<Vec<_>>())
    {
        eprintln!("skip: {variable} isn't NTFS: {c:?}");
        return None;
    }
    eprintln!("NTFS fixture: {c:?}");
    Some(t)
}

/// Regression: full W1 IDs preserve hard links and nofollow refuses leaf reparse points.
#[test]
fn regression_235_part2_a1_windows_identity_and_reparse() {
    let Some(t) = fixture("RRS_A1_NTFS_ROOT") else {
        return;
    };
    fs::write(t.path().join("main"), b"payload").unwrap();
    fs::hard_link(t.path().join("main"), t.path().join("alias")).unwrap();
    let d = NativeDirectory::open_parent(t.path()).unwrap();
    assert!(matches!(
        d.compare_existing(OsStr::new("main"), OsStr::new("alias"))
            .unwrap(),
        ExistingNameComparison::SameObject { .. }
    ));
    match std::os::windows::fs::symlink_file("main", t.path().join("leaf")) {
        Ok(()) => {
            assert_eq!(
                d.lookup_existing(OsStr::new("leaf")).unwrap_err().kind,
                NativeFsErrorKind::LeafLinkOrReparse
            );
            assert!(matches!(
                d.existing_short_names(OsStr::new("main")).unwrap(),
                Capability::Known(_)
            ));
        }
        Err(e) => eprintln!("skip: symlink privilege unavailable: {e}"),
    }
    let junction = t.path().join("parent");
    let status = std::process::Command::new("cmd")
        .args(["/c", "mklink", "/J"])
        .arg(&junction)
        .arg(t.path())
        .status()
        .unwrap();
    assert!(status.success());
    assert!(NativeDirectory::open_parent(&junction).is_ok());
    fs::remove_dir(junction).unwrap();
}

/// Regression: exact OBJ_CASE_INSENSITIVE relative options must agree with ordinary CreateFileW.
#[test]
fn regression_235_part2_a1_windows_case_modes() {
    for sensitive in [false, true] {
        let Some(t) = fixture("RRS_A1_NTFS_ROOT") else {
            return;
        };
        if sensitive {
            use std::os::windows::fs::OpenOptionsExt;
            let f = fs::OpenOptions::new()
                .access_mode(FILE_WRITE_ATTRIBUTES)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
                .open(t.path())
                .unwrap();
            let flags = FILE_CASE_SENSITIVE_INFO { Flags: 1 };
            // SAFETY: enable mode only in an owned empty disposable directory.
            if unsafe {
                SetFileInformationByHandle(
                    f.as_raw_handle(),
                    FileCaseSensitiveInfo,
                    (&flags as *const FILE_CASE_SENSITIVE_INFO).cast(),
                    std::mem::size_of_val(&flags) as u32,
                )
            } == 0
            {
                eprintln!(
                    "skip: NTFS sensitive fixture unavailable: {}",
                    std::io::Error::last_os_error()
                );
                continue;
            }
        }
        fs::write(t.path().join("Case"), b"upper").unwrap();
        if sensitive {
            fs::write(t.path().join("case"), b"lower").unwrap();
        }
        let d = NativeDirectory::open_parent(t.path()).unwrap();
        assert_eq!(
            d.capabilities().unwrap().case_sensitive,
            Capability::Known(if sensitive {
                CaseMode::Sensitive
            } else {
                CaseMode::Insensitive
            })
        );
        let comparison = d
            .compare_existing(OsStr::new("Case"), OsStr::new("case"))
            .unwrap();
        assert!(if sensitive {
            matches!(comparison, ExistingNameComparison::DifferentObjects { .. })
        } else {
            matches!(comparison, ExistingNameComparison::SameObject { .. })
        });
        for name in ["Case", "case", "CASE", "missing"] {
            let relative = d.lookup_existing(OsStr::new(name)).unwrap();
            let ordinary = match windows::ordinary_open(&t.path().join(name), true) {
                Ok(f) => Lookup::Existing(identity_from_file(&f).unwrap()),
                Err(e)
                    if e.code
                        == Some(NativeCode::Win32(
                            windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND,
                        )) =>
                {
                    Lookup::Missing
                }
                Err(e) => panic!("{e}"),
            };
            assert_eq!(
                relative, ordinary,
                "ordinary/relative mismatch: {sensitive}/{name}"
            );
        }
    }
}

/// Regression: real existing 8.3 aliases are confirmed with full W1 IDs, never synthesized.
#[test]
fn regression_235_part2_a1_windows_existing_short_aliases() {
    let Some(t) = fixture("RRS_A1_NTFS_ROOT") else {
        return;
    };
    let name = OsStr::new("a sufficiently long existing filename.txt");
    fs::write(t.path().join(name), b"fixture").unwrap();
    let d = NativeDirectory::open_parent(t.path()).unwrap();
    let Capability::Known(aliases) = d.existing_short_names(name).unwrap() else {
        panic!("alias API unavailable");
    };
    fs::write(t.path().join("PLAIN.TXT"), b"short spelling").unwrap();
    assert!(
        matches!(d.existing_short_names(OsStr::new("PLAIN.TXT")).unwrap(), Capability::Known(v) if !v.is_empty() && v.iter().all(|n| n.short.is_none()))
    );
    if !aliases.iter().any(|v| v.short.is_some()) {
        eprintln!("skip: NTFS fixture reports no real 8.3 alias; empty-alternate control executed");
    }
    for a in aliases {
        if let Some(short) = a.short {
            assert!(matches!(
                d.compare_existing(&a.long, &short).unwrap(),
                ExistingNameComparison::SameObject { .. }
            ));
        }
    }
}

/// Regression: trailing-dot siblings cannot break main capabilities or companion/alias queries.
#[test]
fn regression_235_part2_a1_windows_alias_companions() {
    let Some(t) = fixture("RRS_A1_NTFS_ROOT") else {
        return;
    };
    let d = NativeDirectory::open_parent(t.path()).unwrap();
    fs::write(t.path().join("main"), b"main").unwrap();
    let sibling = fs::canonicalize(t.path()).unwrap().join("other.");
    fs::write(&sibling, b"native spelling").unwrap();
    assert!(matches!(
        windows::lookup(&d.file, OsStr::new("other.")).unwrap(),
        Lookup::Existing(_)
    ));
    assert!(d.capabilities().is_ok());
    assert!(matches!(
        d.existing_short_names(OsStr::new("main")).unwrap(),
        Capability::Known(v) if v.iter().any(|a| a.long == "main")
    ));
    for name in ["main-journal", "main-wal", "main-shm"] {
        fs::write(t.path().join(name), b"companion").unwrap();
        assert!(matches!(
            d.compare_existing(OsStr::new("main"), OsStr::new(name))
                .unwrap(),
            ExistingNameComparison::DifferentObjects { .. }
        ));
    }
    assert_eq!(fs::read_dir(t.path()).unwrap().count(), 5);
    fs::remove_file(sibling).unwrap();
}

/// Regression: signed short lengths, malformed records, sharing/access/API errors stay typed.
#[test]
fn regression_235_part2_a1_windows_native_errors() {
    for s in ["NUL", "COM¹.txt", "LPT9", "name.", "name ", "a:b", "C:\\x"] {
        assert!(validate(OsStr::new(s)).is_err());
    }
    for n in [-128, -1, 1, 25, 127] {
        assert_eq!(
            windows::short_length(n).unwrap_err().kind,
            NativeFsErrorKind::MalformedData
        );
    }
    assert_eq!(windows::short_length(24).unwrap(), 12);
    assert!(windows::parse_records(&[0; 12], &mut Vec::new()).is_err());
    use std::os::windows::ffi::OsStringExt;
    validate(&std::ffi::OsString::from_wide(&[0xd800])).unwrap();
    assert!(validate(&std::ffi::OsString::from_wide(&[78, 85, 76, 46, 0xd800])).is_err());
    for next in [4u32, 103, 4096] {
        let mut bytes = [0; 256];
        bytes[..4].copy_from_slice(&next.to_le_bytes());
        assert_eq!(
            windows::parse_records(&bytes, &mut Vec::new())
                .unwrap_err()
                .kind,
            NativeFsErrorKind::MalformedData
        );
    }
    use windows_sys::Win32::Foundation::*;
    for (code, kind) in [
        (ERROR_ACCESS_DENIED, NativeFsErrorKind::Access),
        (ERROR_SHARING_VIOLATION, NativeFsErrorKind::Busy),
        (ERROR_INVALID_PARAMETER, NativeFsErrorKind::UnsupportedApi),
    ] {
        assert_eq!(windows::win_error("fixture", code).kind, kind);
    }
    let Some(t) = fixture("RRS_A1_NTFS_ROOT") else {
        return;
    };
    let path = t.path().join("denied");
    fs::write(&path, b"fixture").unwrap();
    let d = NativeDirectory::open_parent(t.path()).unwrap();
    use std::os::windows::fs::OpenOptionsExt;
    let held = fs::OpenOptions::new()
        .read(true)
        .share_mode(0)
        .open(&path)
        .unwrap();
    // Attribute-only opens are not data-sharing conflicts (CreateFileW contract).
    assert_eq!(
        d.lookup_existing(OsStr::new("denied")).unwrap(),
        Lookup::Existing(identity_from_file(&held).unwrap())
    );
    drop(held);
    let user = format!(
        "{}\\{}",
        std::env::var("USERDOMAIN").unwrap(),
        std::env::var("USERNAME").unwrap()
    );
    let acl = |args: &[&str]| {
        std::process::Command::new("icacls")
            .arg(&path)
            .args(args)
            .status()
            .unwrap()
            .success()
    };
    if acl(&["/deny", &format!("{user}:(RA)")]) {
        let result = d.lookup_existing(OsStr::new("denied"));
        assert!(acl(&["/remove:d", &user]));
        assert_eq!(result.unwrap_err().kind, NativeFsErrorKind::Access);
    } else {
        eprintln!("skip: owned NTFS ACL denial fixture unavailable");
    }
    // Denied listing must not prevent attribute-only existing-name queries.
    let acl = |args: &[&str]| {
        std::process::Command::new("icacls")
            .arg(t.path())
            .args(args)
            .status()
            .unwrap()
            .success()
    };
    if acl(&["/deny", &format!("{user}:(RD)")]) {
        let lookup = d.lookup_existing(OsStr::new("denied"));
        let listing = d.capabilities();
        assert!(acl(&["/remove:d", &user]));
        assert!(matches!(lookup.unwrap(), Lookup::Existing(_)));
        assert_eq!(listing.unwrap_err().kind, NativeFsErrorKind::Access);
    } else {
        eprintln!("skip: owned NTFS list-denial fixture unavailable");
    }
}

/// Regression: owned case/non-ASCII/NFC experiments cannot answer absent-name prediction.
#[test]
fn regression_235_part2_a1_windows_pending_after_experiment() {
    for (a, b, equivalent) in [
        ("Case", "case", true),
        ("case", "Case", true),
        ("é", "e\u{301}", false),
        ("e\u{301}", "é", false),
        ("Δ", "δ", true),
    ] {
        let Some(t) = fixture("RRS_A1_NTFS_ROOT") else {
            return;
        };
        fs::write(t.path().join(a), b"test-only sentinel").unwrap();
        if !equivalent {
            fs::write(t.path().join(b), b"distinct normalization spelling").unwrap();
        }
        let d = NativeDirectory::open_parent(t.path()).unwrap();
        assert!(matches!(
            (
                equivalent,
                d.compare_existing(OsStr::new(a), OsStr::new(b)).unwrap()
            ),
            (true, ExistingNameComparison::SameObject { .. })
                | (false, ExistingNameComparison::DifferentObjects { .. })
        ));
        assert_eq!(
            d.capabilities().unwrap().absent_names,
            AbsentNameCapability::default()
        );
    }
}
