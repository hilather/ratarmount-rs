use super::*;
use std::io::Cursor;

const BLOCK: usize = 2048;

fn both(value: u32) -> Vec<u8> {
    [value.to_le_bytes(), value.to_be_bytes()].concat()
}

fn entry(signature: &[u8; 2], payload: &[u8]) -> Vec<u8> {
    [
        signature.as_slice(),
        &[u8::try_from(4 + payload.len()).unwrap(), 1],
        payload,
    ]
    .concat()
}

fn nm(flags: u8, name: &str) -> Vec<u8> {
    entry(b"NM", &[&[flags], name.as_bytes()].concat())
}

fn px(mode: u32, serial: bool) -> Vec<u8> {
    let mut payload = [both(mode), both(3), both(123), both(456)].concat();
    if serial {
        payload.extend(both(42));
    }
    entry(b"PX", &payload)
}

fn ce(block: u32, offset: u32, length: u32) -> Vec<u8> {
    entry(b"CE", &[both(block), both(offset), both(length)].concat())
}

fn record(extent: u32, dir: bool, name: &[u8], su: &[u8]) -> Vec<u8> {
    let start = 33 + name.len() + usize::from(name.len().is_multiple_of(2));
    let mut rec = vec![0; start];
    rec[2..10].copy_from_slice(&both(extent));
    rec[10..18].copy_from_slice(&both(if dir { BLOCK as u32 } else { 4 }));
    rec[18..25].copy_from_slice(&[124, 1, 2, 3, 4, 5, 0]);
    rec[25] = if dir { 2 } else { 0 };
    rec[28..32].copy_from_slice(&[1, 0, 0, 1]);
    rec[32] = name.len() as u8;
    rec[33..33 + name.len()].copy_from_slice(name);
    rec.extend(su);
    rec[0] = u8::try_from(rec.len()).unwrap();
    rec
}

fn directory(image: &mut [u8], block: usize, root_su: &[u8], records: &[Vec<u8>]) {
    let start = block * BLOCK;
    image[start..start + BLOCK].fill(0);
    let mut offset = start;
    for rec in [
        record(block as u32, true, &[0], root_su),
        record(20, true, &[1], &[]),
    ]
    .iter()
    .chain(records)
    {
        image[offset..offset + rec.len()].copy_from_slice(rec);
        offset += rec.len();
    }
    assert!(offset <= start + BLOCK);
}

fn joliet(name: &str) -> Vec<u8> {
    name.encode_utf16().flat_map(u16::to_be_bytes).collect()
}

fn image(sp: bool, primary: &[Vec<u8>], supplementary: Option<&[Vec<u8>]>) -> Vec<u8> {
    let mut image = vec![0; 100 * BLOCK];
    for (sector, kind, root) in [(16, 1, 20), (17, 2, 21), (18, 255, 0)] {
        let offset = sector * BLOCK;
        image[offset] = if sector == 17 && supplementary.is_none() {
            255
        } else {
            kind
        };
        image[offset + 1..offset + 6].copy_from_slice(b"CD001");
        image[offset + 6] = 1;
        image[offset + 88..offset + 91].copy_from_slice(b"%/E");
        let root = record(root, true, &[0], &[]);
        image[offset + 156..offset + 156 + root.len()].copy_from_slice(&root);
    }
    directory(
        &mut image,
        20,
        &if sp {
            entry(b"SP", &[0xbe, 0xef, 0])
        } else {
            vec![]
        },
        primary,
    );
    if let Some(records) = supplementary {
        directory(&mut image, 21, &[], records);
    }
    image[30 * BLOCK..30 * BLOCK + 4].copy_from_slice(b"data");
    image
}

// Exercise reader, cold path and durable warm path against identical expectations.
fn check_sources(bytes: Vec<u8>, check: impl Fn(&Iso9660MountSource)) {
    let opts = OpenOptions {
        index_in_memory: true,
        ..OpenOptions::default()
    };
    let reader = Iso9660MountSource::open_from_reader(
        Cursor::new(bytes.clone()),
        "test.iso",
        None,
        &opts,
        "test",
    )
    .unwrap();
    check(&reader);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test.iso");
    std::fs::write(&path, bytes).unwrap();
    let opts = OpenOptions::default();
    let cold = Iso9660MountSource::open(&path, None, &opts, "test", true).unwrap();
    check(&cold);
    drop(cold);
    let warm = Iso9660MountSource::open(&path, None, &opts, "test", false).unwrap();
    check(&warm);
}

fn names(src: &Iso9660MountSource, path: &str) -> Vec<String> {
    let mut names: Vec<_> = src
        .list_dirents(path)
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    names.sort();
    names
}

fn assert_file(src: &Iso9660MountSource, path: &str) -> FileInfo {
    let fi = src
        .lookup(path, 0)
        .unwrap_or_else(|| panic!("missing {path}"));
    let mut bytes = Vec::new();
    src.open(&fi, 0).unwrap().read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"data");
    fi
}

/// Regression: uppercase/truncated ISO identifiers replace the actual RR names.
#[test]
fn regression_rock_ridge_names_replace_8_3_names() {
    let long = "LongMixedCaseFilenameWithMoreThan31Characters.bin";
    let records = vec![
        record(30, false, b"BLOB.BIN;1", &nm(0, "blob.bin")),
        record(
            30,
            false,
            b"LONG.BIN;1",
            &[nm(1, &long[..25]), nm(0, &long[25..])].concat(),
        ),
        record(30, false, b"README.;1", &nm(0, "ReadMe")),
        record(30, false, b"SPACE.;1", &nm(0, "name with spaces")),
        record(
            22,
            true,
            b"D00",
            &[nm(0, "d00"), px(ratarmount_core::S_IFDIR | 0o750, false)].concat(),
        ),
    ];
    let mut bytes = image(true, &records, None);
    directory(
        &mut bytes,
        22,
        &[],
        &[record(30, false, b"F0001.BIN;1", &nm(0, "f0001.bin"))],
    );
    check_sources(bytes, |src| {
        let mut expected = vec!["blob.bin", long, "ReadMe", "name with spaces", "d00"];
        expected.sort();
        assert_eq!(names(src, "/"), expected);
        for name in [
            "blob.bin",
            long,
            "ReadMe",
            "name with spaces",
            "d00/f0001.bin",
        ] {
            assert_file(src, &format!("/{name}"));
        }
        assert!(src.lookup("/BLOB.BIN", 0).is_none());
        assert_eq!(
            src.lookup("/d00", 0).unwrap().mode,
            ratarmount_core::S_IFDIR | 0o750
        );
    });
}

/// Regression: CE and SP len_skp must apply to SUSP, not to continuation bytes.
#[test]
fn regression_rock_ridge_continuation_and_skip() {
    let continuation = nm(0, "Continued Name");
    let rec = record(
        30,
        false,
        b"SHORT.;1",
        &[vec![0xaa; 2], ce(40, 7, continuation.len() as u32)].concat(),
    );
    let mut bytes = image(true, &[], None);
    directory(&mut bytes, 20, &entry(b"SP", &[0xbe, 0xef, 2]), &[rec]);
    bytes[40 * BLOCK + 7..40 * BLOCK + 7 + continuation.len()].copy_from_slice(&continuation);
    check_sources(bytes, |src| {
        assert_file(src, "/Continued Name");
    });
}

/// Regression: PX short/long forms preserve executable bits and ownership.
#[test]
fn regression_rock_ridge_posix_modes() {
    for serial in [false, true] {
        let rec = record(
            30,
            false,
            b"RUN.;1",
            &px(ratarmount_core::S_IFREG | 0o751, serial),
        );
        check_sources(image(true, &[rec], None), |src| {
            let fi = assert_file(src, "/RUN");
            assert_eq!(fi.mode, ratarmount_core::S_IFREG | 0o751);
            assert_eq!((fi.uid, fi.gid), (123, 456));
            assert_eq!(src.list_dirents("/").unwrap()[0].mode, fi.mode);
        });
    }
}

/// Regression: SL entry and component continuations describe a symlink, not file data.
#[test]
fn regression_rock_ridge_symlink_target() {
    let sl1 = entry(
        b"SL",
        &[1, 4, 0, 0, 3, b'd', b'i', b'r', 1, 3, b'l', b'o', b'n'],
    );
    let sl2 = entry(b"SL", &[0, 0, 1, b'g', 2, 0, 0, 4, b'f', b'i', b'l', b'e']);
    let rec = record(30, false, b"LINK.;1", &[sl1, sl2].concat());
    let abs = record(
        30,
        false,
        b"ABS.;1",
        &entry(b"SL", &[0, 8, 0, 0, 3, b'e', b't', b'c']),
    );
    check_sources(image(true, &[rec, abs], None), |src| {
        for (name, target) in [("LINK", "../dir/long/./file"), ("ABS", "/etc")] {
            let fi = src.lookup(&format!("/{name}"), 0).unwrap();
            assert_eq!(fi.mode & ratarmount_core::S_IFMT, ratarmount_core::S_IFLNK);
            assert_eq!(fi.linkname, target);
            assert_eq!(fi.size, target.len() as u64);
            assert!(
                src.open(&fi, 0).is_err(),
                "symlink must not expose extent bytes"
            );
            assert_eq!(
                src.list_dirents("/")
                    .unwrap()
                    .into_iter()
                    .find(|e| e.name == name)
                    .unwrap()
                    .mode,
                fi.mode
            );
        }
    });
}

/// Regression: TF MODIFY selects the correct short/long timestamp and timezone.
#[test]
fn regression_rock_ridge_modification_times() {
    let short = entry(b"TF", &[3, 100, 1, 1, 0, 0, 0, 0, 124, 1, 2, 4, 4, 5, 4]);
    let long = entry(b"TF", &[&[0x82][..], b"2024010204040525", &[4]].concat());
    let creation_only = entry(b"TF", &[1, 100, 1, 1, 0, 0, 0, 0]);
    let recs = [
        record(30, false, b"SHORT;1", &short),
        record(30, false, b"LONG;1", &long),
        record(30, false, b"FALLBACK;1", &creation_only),
    ];
    check_sources(image(true, &recs, None), |src| {
        assert_eq!(src.lookup("/SHORT", 0).unwrap().mtime, 1704164645.0);
        assert_eq!(src.lookup("/LONG", 0).unwrap().mtime, 1704164645.25);
        assert_eq!(src.lookup("/FALLBACK", 0).unwrap().mtime, 1704164645.0);
    });
}

/// Regression: Joliet Unicode names and subdirectories are used without any NM.
#[test]
fn regression_joliet_names_used_without_rock_ridge() {
    for sp in [false, true] {
        for escape in [b"%/@", b"%/C", b"%/E"] {
            let primary = [
                record(30, false, b"CAFE.TXT;1", &[]),
                record(22, true, b"SUBDIR", &[]),
            ];
            let supplementary = [
                record(30, false, &joliet("Café Long Name.txt;1"), &[]),
                record(23, true, &joliet("SubDirectory"), &[]),
            ];
            let mut bytes = image(sp, &primary, Some(&supplementary));
            bytes[17 * BLOCK + 88..17 * BLOCK + 91].copy_from_slice(escape);
            directory(&mut bytes, 22, &[], &[record(30, false, b"CHILD;1", &[])]);
            directory(
                &mut bytes,
                23,
                &[],
                &[record(30, false, &joliet("Child.;1"), &[])],
            );
            check_sources(bytes, |src| {
                assert_eq!(names(src, "/"), ["Café Long Name.txt", "SubDirectory"]);
                assert_file(src, "/Café Long Name.txt");
                assert_file(src, "/SubDirectory/Child.");
            });
        }
    }
}

/// Regression: RR wins even when NM first appears below the root; missing NM uses Joliet.
#[test]
fn regression_rock_ridge_precedes_joliet() {
    let primary = [
        record(22, true, b"SUBDIR", &[]),
        record(31, false, b"FALLBACK;1", &[]),
        record(24, true, b"EMPTY", &[]),
    ];
    let supplementary = [
        record(23, true, &joliet("SubDirectory"), &[]),
        record(31, false, &joliet("Fallback Name;1"), &[]),
        record(25, true, &joliet("Empty Directory"), &[]),
    ];
    let mut bytes = image(true, &primary, Some(&supplementary));
    directory(&mut bytes, 24, &[], &[]);
    directory(&mut bytes, 25, &[], &[]);
    directory(
        &mut bytes,
        22,
        &[],
        &[record(30, false, b"CHILD;1", &nm(0, "Rock Ridge Child"))],
    );
    directory(
        &mut bytes,
        23,
        &[],
        &[record(30, false, &joliet("Joliet Child;1"), &[])],
    );
    check_sources(bytes, |src| {
        assert_eq!(
            names(src, "/"),
            ["Empty Directory", "Fallback Name", "SubDirectory"]
        );
        assert_eq!(names(src, "/SubDirectory"), ["Rock Ridge Child"]);
        assert_file(src, "/SubDirectory/Rock Ridge Child");
    });
}

/// Regression: selecting Joliet for names must not discard PX/TF/SL when NM is absent.
#[test]
fn regression_joliet_names_preserve_rock_ridge_metadata_without_nm() {
    let primary = [
        record(
            30,
            false,
            b"RUN;1",
            &[
                px(ratarmount_core::S_IFREG | 0o751, true),
                entry(b"TF", &[2, 124, 1, 2, 4, 4, 5, 4]),
            ]
            .concat(),
        ),
        record(
            30,
            false,
            b"LINK;1",
            &entry(b"SL", &[0, 0, 3, b'r', b'u', b'n']),
        ),
    ];
    let supplementary = [record(30, false, &joliet("Run Program;1"), &[])];
    check_sources(image(true, &primary, Some(&supplementary)), |src| {
        assert_eq!(names(src, "/"), ["LINK", "Run Program"]);
        let fi = assert_file(src, "/Run Program");
        assert_eq!(fi.mode, ratarmount_core::S_IFREG | 0o751);
        assert_eq!((fi.uid, fi.gid), (123, 456));
        assert_eq!(fi.mtime, 1704164645.0);
        let link = src.lookup("/LINK", 0).unwrap();
        assert_eq!(
            link.mode & ratarmount_core::S_IFMT,
            ratarmount_core::S_IFLNK
        );
        assert_eq!(link.linkname, "run");
    });
}

/// Regression: images without extensions keep the exact previous ISO names/default modes.
#[test]
fn regression_plain_iso_names_unchanged() {
    check_sources(
        image(
            false,
            &[
                record(30, false, b"BLOB.BIN;1", &[]),
                record(30, false, b"README.;1", &nm(0, "Ignored Without SP")),
            ],
            None,
        ),
        |src| {
            assert_eq!(names(src, "/"), ["BLOB.BIN", "README"]);
            assert_eq!(
                assert_file(src, "/BLOB.BIN").mode,
                ratarmount_core::S_IFREG | 0o644
            );
        },
    );
}

/// Regression: malformed SUSP lengths, truncated names/links, and cyclic CE fall back safely.
#[test]
fn regression_malformed_rock_ridge_falls_back() {
    for su in [
        vec![b'N', b'M', 99, 1, 0, b'x'],
        nm(1, "unfinished"),
        entry(b"SL", &[0, 0, 9, b'x']),
        ce(40, 0, 28),
        ce(90, 0, u32::MAX),
        [nm(0, "Discard Partial"), vec![b'P', b'X', 40, 1]].concat(),
    ] {
        let mut bytes = image(true, &[record(30, false, b"PLAIN;1", &su)], None);
        bytes[40 * BLOCK..40 * BLOCK + 28].copy_from_slice(&ce(40, 0, 28));
        check_sources(bytes, |src| {
            assert_eq!(names(src, "/"), ["PLAIN"]);
            assert_file(src, "/PLAIN");
        });
    }
}

/// Regression: an overlong acyclic CE chain is bounded as well as a cycle.
#[test]
fn regression_rock_ridge_continuation_hop_limit() {
    let mut bytes = image(true, &[record(30, false, b"PLAIN;1", &ce(40, 0, 28))], None);
    for i in 0..65 {
        let offset = 40 * BLOCK + i * 28;
        bytes[offset..offset + 28].copy_from_slice(&ce(40, (i as u32 + 1) * 28, 28));
    }
    let name = nm(0, "too far");
    bytes[40 * BLOCK + 65 * 28..40 * BLOCK + 65 * 28 + name.len()].copy_from_slice(&name);
    check_sources(bytes, |src| assert_eq!(names(src, "/"), ["PLAIN"]));
}

/// Regression: odd UCS-2 identifiers are skipped; invalid surrogate units are replaced.
#[test]
fn regression_joliet_malformed_code_units() {
    let supplementary = [
        record(30, false, &[0, b'x', 0], &[]),
        record(30, false, &[0xd8, 0, 0, b'x'], &[]),
    ];
    check_sources(
        image(
            false,
            &[record(30, false, b"PLAIN;1", &[])],
            Some(&supplementary),
        ),
        |src| {
            assert_eq!(names(src, "/"), ["�x"]);
            assert_file(src, "/�x");
        },
    );
}

/// Regression: CL follows the relocated directory's own size; RE hides its stored alias.
#[test]
fn regression_rock_ridge_relocated_directory() {
    let primary = [
        record(
            0,
            false,
            b"DEEP",
            &[nm(0, "deep"), entry(b"CL", &both(22))].concat(),
        ),
        record(22, true, b"STORED", &entry(b"RE", &[])),
    ];
    let mut bytes = image(true, &primary, None);
    directory(
        &mut bytes,
        22,
        &entry(b"PL", &both(20)),
        &[record(30, false, b"CHILD;1", &nm(0, "child"))],
    );
    check_sources(bytes, |src| {
        assert_eq!(names(src, "/"), ["deep"]);
        assert_file(src, "/deep/child");
    });
}

/// Regression: cached plain-name sidecars must rebuild after extension support is added.
#[test]
fn regression_rock_ridge_rebuilds_legacy_index() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.iso");
    let index_path = default_index_path(&path);
    let bytes = image(
        true,
        &[record(30, false, b"PLAIN;1", &nm(0, "Resolved Name"))],
        None,
    );
    std::fs::write(&path, bytes).unwrap();
    let index =
        SqliteIndex::create_writable_for_open(Some(&index_path), &OpenOptions::default()).unwrap();
    index.begin_write().unwrap();
    index
        .insert_file(
            "",
            "PLAIN",
            30 * BLOCK as i64,
            30 * BLOCK as i64,
            4,
            0.0,
            i64::from(ratarmount_core::S_IFREG | 0o644),
            0,
            "",
            0,
            0,
            false,
            false,
            false,
            0,
        )
        .unwrap();
    index
        .store_metadata_key_value("backendName", BACKEND_NAME)
        .unwrap();
    index.store_tarstats_for_path(&path).unwrap();
    index.commit_write().unwrap();
    drop(index.into_read_only().unwrap());
    let src = Iso9660MountSource::open(
        &path,
        Some(&index_path),
        &OpenOptions::default(),
        "test",
        false,
    )
    .unwrap();
    assert_eq!(names(&src, "/"), ["Resolved Name"]);
    assert_file(&src, "/Resolved Name");
}

/// Regression: undersized directory records must not panic before SUSP validation.
#[test]
fn regression_short_directory_record_does_not_panic() {
    for len in [1, 2, 10, 25, 32, 33] {
        let mut bytes = image(false, &[], None);
        bytes[20 * BLOCK] = len;
        check_sources(bytes, |src| assert!(src.lookup("/bogus", 0).is_none()));
    }
}

/// Regression: resolving names must not introduce a second directory scan or payload reads.
#[test]
fn regression_directory_metadata_read_once() {
    struct Counted {
        bytes: Cursor<Vec<u8>>,
        reads: Arc<Mutex<std::collections::HashMap<u64, usize>>>,
    }
    impl Read for Counted {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            *self
                .reads
                .lock()
                .unwrap()
                .entry(self.bytes.position())
                .or_default() += 1;
            self.bytes.read(buf)
        }
    }
    impl Seek for Counted {
        fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
            self.bytes.seek(from)
        }
    }
    let primary = [record(22, true, b"DIR", &nm(0, "Directory"))];
    let supplementary = [record(23, true, &joliet("Directory"), &[])];
    let mut bytes = image(true, &primary, Some(&supplementary));
    directory(
        &mut bytes,
        22,
        &[],
        &[record(30, false, b"CHILD;1", &nm(0, "Child"))],
    );
    directory(
        &mut bytes,
        23,
        &[],
        &[record(30, false, &joliet("Child;1"), &[])],
    );
    let reads = Arc::new(Mutex::new(std::collections::HashMap::new()));
    let reader = Counted {
        bytes: Cursor::new(bytes),
        reads: Arc::clone(&reads),
    };
    let opts = OpenOptions {
        index_in_memory: true,
        ..OpenOptions::default()
    };
    let src =
        Iso9660MountSource::open_from_reader(reader, "counted.iso", None, &opts, "test").unwrap();
    assert_eq!(names(&src, "/Directory"), ["Child"]);
    let reads = reads.lock().unwrap();
    for block in [20, 21, 22, 23] {
        assert_eq!(reads.get(&(block * SECTOR)), Some(&1));
    }
    assert!(!reads.contains_key(&(30 * SECTOR)));
}

/// Regression: real mkisofs -R -J output keeps mixed case, executable modes and symlinks.
#[cfg(unix)]
#[test]
fn regression_xorriso_rock_ridge_joliet() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::process::Command;
    match Command::new("xorriso").arg("-version").output() {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            eprintln!("skip: xorriso not on PATH");
            return;
        }
        result => assert!(result.unwrap().status.success()),
    }
    let dir = tempfile::tempdir().unwrap();
    let tree = dir.path().join("tree");
    std::fs::create_dir_all(tree.join("MixedCaseDirectory")).unwrap();
    std::fs::set_permissions(
        tree.join("MixedCaseDirectory"),
        std::fs::Permissions::from_mode(0o750),
    )
    .unwrap();
    let long = "LongMixedCaseFilenameWithMoreThan31Characters.bin";
    std::fs::write(tree.join(long), b"data").unwrap();
    std::fs::set_permissions(tree.join(long), std::fs::Permissions::from_mode(0o751)).unwrap();
    std::fs::write(tree.join("MixedCaseDirectory/Child Name.txt"), b"data").unwrap();
    symlink(format!("../{long}"), tree.join("MixedCaseDirectory/Link")).unwrap();
    let iso = dir.path().join("real.iso");
    let output = Command::new("xorriso")
        .args(["-as", "mkisofs", "-R", "-J", "-o"])
        .arg(&iso)
        .arg(&tree)
        .output()
        .unwrap();
    eprintln!(
        "xorriso -as mkisofs -R -J: {}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success());
    check_sources(std::fs::read(iso).unwrap(), |src| {
        assert_eq!(names(src, "/"), [long, "MixedCaseDirectory"]);
        assert_eq!(
            assert_file(src, &format!("/{long}")).mode,
            ratarmount_core::S_IFREG | 0o751
        );
        assert_file(src, "/MixedCaseDirectory/Child Name.txt");
        assert_eq!(
            src.lookup("/MixedCaseDirectory", 0).unwrap().mode,
            ratarmount_core::S_IFDIR | 0o750
        );
        let link = src.lookup("/MixedCaseDirectory/Link", 0).unwrap();
        assert_eq!(link.linkname, format!("../{long}"));
        assert_eq!(
            link.mode & ratarmount_core::S_IFMT,
            ratarmount_core::S_IFLNK
        );
    });
    eprintln!(
        "xorriso check: names, executable mode, nested file and symlink OK (reader/cold/warm)"
    );
}
