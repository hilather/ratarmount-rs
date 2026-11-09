use super::*;
use std::fs;
use std::os::unix::ffi::OsStrExt;

fn fixture(variable: &str) -> Option<tempfile::TempDir> {
    let root = std::env::var_os(variable).unwrap_or_else(|| "/var/tmp".into());
    let t = tempfile::tempdir_in(root).unwrap();
    let c = NativeDirectory::open_parent(t.path())
        .unwrap()
        .capabilities()
        .unwrap();
    if !matches!(c.filesystem, FilesystemKind::MacOs { ref name } if name == b"apfs") {
        eprintln!("skip: {variable} isn't native APFS: {c:?}");
        return None;
    }
    eprintln!("APFS fixture: {c:?}");
    Some(t)
}

/// Regression: APFS full FILEID distinguishes clones and preserves hard-link identity.
#[test]
fn regression_235_part2_a1_macos_apfs_identity() {
    let Some(t) = fixture("RRS_A1_APFS_ROOT") else {
        return;
    };
    let a = t.path().join("main");
    fs::write(&a, b"payload").unwrap();
    fs::hard_link(&a, t.path().join("alias")).unwrap();
    let cstr = |p: &Path| std::ffi::CString::new(p.as_os_str().as_bytes()).unwrap();
    // SAFETY: clone experiment creates only an owned disposable fixture entry.
    assert_eq!(
        unsafe { libc::clonefile(cstr(&a).as_ptr(), cstr(&t.path().join("clone")).as_ptr(), 0) },
        0
    );
    let d = NativeDirectory::open_parent(t.path()).unwrap();
    assert!(matches!(
        d.compare_existing(OsStr::new("main"), OsStr::new("alias"))
            .unwrap(),
        ExistingNameComparison::SameObject { .. }
    ));
    assert!(matches!(
        d.compare_existing(OsStr::new("main"), OsStr::new("clone"))
            .unwrap(),
        ExistingNameComparison::DifferentObjects { .. }
    ));
}

/// Regression: native APFS facts do not imply a normalization comparator.
#[test]
fn regression_235_part2_a1_macos_apfs_modes() {
    for (variable, mode) in [
        ("RRS_A1_APFS_ROOT", CaseMode::Insensitive),
        ("RRS_A1_APFS_SENSITIVE_ROOT", CaseMode::Sensitive),
    ] {
        if std::env::var_os(variable).is_none() {
            eprintln!("skip: {variable} must provision the requested APFS mode");
            continue;
        }
        let Some(t) = fixture(variable) else {
            continue;
        };
        let d = NativeDirectory::open_parent(t.path()).unwrap();
        assert_eq!(
            d.capabilities().unwrap().case_sensitive,
            Capability::Known(mode)
        );
        for (a, b) in [("Name", "name"), ("é", "e\u{301}"), ("Δ", "δ")] {
            fs::write(t.path().join(a), b"fixture").unwrap();
            let expected = d.lookup_existing(OsStr::new(a)).unwrap();
            assert!(matches!(expected, Lookup::Existing(_)));
            assert_eq!(
                d.lookup_existing(OsStr::new(b)).unwrap(),
                if a == "é" || mode == CaseMode::Insensitive {
                    expected
                } else {
                    Lookup::Missing
                }
            );
        }
    }
}

/// Regression: truncated/invalid attribute masks and access errors cannot become facts.
#[test]
fn regression_235_part2_a1_macos_attribute_errors() {
    let common = libc::ATTR_CMN_RETURNED_ATTRS;
    let mut truncated = [0u8; 128];
    truncated[..4].copy_from_slice(&24u32.to_ne_bytes());
    truncated[4..8]
        .copy_from_slice(&(common | libc::ATTR_CMN_FSID | libc::ATTR_CMN_OBJTYPE).to_ne_bytes());
    assert_eq!(
        macos::Attributes::checked(
            truncated,
            common | libc::ATTR_CMN_FSID | libc::ATTR_CMN_OBJTYPE | libc::ATTR_CMN_FILEID,
            0
        )
        .err()
        .unwrap()
        .kind,
        NativeFsErrorKind::MalformedData
    );
    let volume = libc::ATTR_VOL_CAPABILITIES;
    let mut valid = [0u8; 128];
    for (i, word) in [
        56u32, common, volume, 0, 0, 0, 0x300, 0, 0, 0, 0x300, 0, 0, 0,
    ]
    .into_iter()
    .enumerate()
    {
        valid[i * 4..i * 4 + 4].copy_from_slice(&word.to_ne_bytes());
    }
    assert_eq!(
        macos::Attributes::checked(valid, common, volume | libc::ATTR_VOL_INFO)
            .unwrap()
            .word()
            .unwrap(),
        0x300
    );
    for (offset, word) in [(4, common | libc::ATTR_CMN_OBJID), (8, 0), (12, 1)] {
        let mut bytes = valid;
        bytes[offset..offset + 4].copy_from_slice(&word.to_ne_bytes());
        assert_eq!(
            macos::Attributes::checked(bytes, common, volume)
                .err()
                .unwrap()
                .kind,
            NativeFsErrorKind::MalformedData
        );
    }
    for length in [0u32, 20, 25, 132] {
        let mut bytes = [0; 128];
        bytes[..4].copy_from_slice(&length.to_ne_bytes());
        assert!(macos::Attributes::checked(bytes, libc::ATTR_CMN_FILEID, 0).is_err());
    }
    assert!(matches!(
        macos::volume_bit(0, 0, libc::VOL_CAP_FMT_CASE_SENSITIVE),
        Capability::Unavailable(_)
    ));
    assert_eq!(
        errno("fixture", libc::EACCES).kind,
        NativeFsErrorKind::Access
    );
    let t = tempfile::tempdir().unwrap();
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir(t.path().join("denied")).unwrap();
    fs::set_permissions(t.path().join("denied"), fs::Permissions::from_mode(0o0)).unwrap();
    let result = NativeDirectory::open_parent(&t.path().join("denied"));
    fs::set_permissions(t.path().join("denied"), fs::Permissions::from_mode(0o700)).unwrap();
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skip: root bypasses permission-denial fixture");
    } else {
        assert_eq!(result.err().unwrap().kind, NativeFsErrorKind::Access);
    }
}

/// Regression: real hard links under forced OBJID fallback retain no equality authority.
#[test]
fn regression_235_part2_a1_macos_forced_objid_fallback() {
    let Some(t) = fixture("RRS_A1_APFS_ROOT") else {
        return;
    };
    fs::write(t.path().join("main"), b"payload").unwrap();
    fs::hard_link(t.path().join("main"), t.path().join("alias")).unwrap();
    let f = File::open(t.path().join("main")).unwrap();
    let full = identity_from_file(&f).unwrap();
    let d = NativeDirectory::open_parent(t.path()).unwrap();
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            macos::FORCE_OBJID.set(false);
        }
    }
    let _reset = Reset;
    macos::FORCE_OBJID.set(true);
    let fallback = identity_from_file(&f).unwrap();
    let alias = macos::lookup(&d.file, OsStr::new("alias")).unwrap();
    assert!(matches!(
        compare(Lookup::Existing(fallback.clone()), alias),
        ExistingNameComparison::Undecided {
            reason: UndecidedReason::FullIdentityUnavailable,
            ..
        }
    ));
    for (a, b) in [(41, 42), (42, 42)] {
        let mut x = fallback.clone();
        let mut y = fallback.clone();
        x.mac_objid.as_mut().unwrap().object = a;
        y.mac_objid.as_mut().unwrap().object = b;
        assert!(matches!(
            compare(Lookup::Existing(x), Lookup::Existing(y)),
            ExistingNameComparison::Undecided { .. }
        ));
    }
    assert!(fallback.mac_objid.is_some());
    assert!(matches!(
        fallback.identity,
        Capability::Unavailable(CapabilityUnavailable::FullIdentityUnavailable(_))
    ));
    for (a, b) in [
        (full.clone(), fallback.clone()),
        (fallback.clone(), full),
        (fallback.clone(), fallback),
    ] {
        assert!(matches!(
            compare(Lookup::Existing(a), Lookup::Existing(b)),
            ExistingNameComparison::Undecided {
                reason: UndecidedReason::FullIdentityUnavailable,
                ..
            }
        ));
    }
    assert_eq!(
        d.lookup_existing(OsStr::new("main")).unwrap_err().kind,
        NativeFsErrorKind::FullIdentityUnavailable
    );
}

/// Regression: disposable case/NFC experiments leave all absent capability decisions pending.
#[test]
fn regression_235_part2_a1_macos_pending_after_experiment() {
    for (a, b) in [
        ("Case", "case"),
        ("case", "Case"),
        ("é", "e\u{301}"),
        ("e\u{301}", "é"),
    ] {
        let Some(t) = fixture("RRS_A1_APFS_ROOT") else {
            return;
        };
        fs::write(t.path().join(a), b"test-only sentinel").unwrap();
        let d = NativeDirectory::open_parent(t.path()).unwrap();
        assert!(matches!(
            d.compare_existing(OsStr::new(a), OsStr::new(b)).unwrap(),
            ExistingNameComparison::SameObject { .. }
        ));
        assert_eq!(
            d.capabilities().unwrap().absent_names,
            AbsentNameCapability::default()
        );
    }
}
