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

fn sl(target: &str) -> Vec<u8> {
    let mut payload = vec![0, 0, u8::try_from(target.len()).unwrap()];
    payload.extend(target.as_bytes());
    entry(b"SL", &payload)
}

fn listed_mode(src: &Iso9660MountSource, dir: &str, name: &str) -> u32 {
    src.list_dirents(dir)
        .unwrap_or_else(|| panic!("missing dir {dir}"))
        .into_iter()
        .find(|e| e.name == name)
        .unwrap_or_else(|| panic!("missing {dir}/{name}"))
        .mode
}

fn open_mem(bytes: Vec<u8>) -> Result<Iso9660MountSource> {
    let opts = OpenOptions {
        index_in_memory: true,
        ..OpenOptions::default()
    };
    Iso9660MountSource::open_from_reader(Cursor::new(bytes), "test.iso", None, &opts, "test")
}

fn assert_is_directory(src: &Iso9660MountSource, fi: &FileInfo) {
    match src.open(fi, 0) {
        Err(err) => assert_eq!(err.kind(), io::ErrorKind::IsADirectory),
        Ok(_) => panic!("directory opened as a file"),
    }
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

/// Regression: PX type bits retype a directory record (file as directory, directory as file, SL directory drops its child).
#[test]
fn regression_rock_ridge_type_follows_directory_flag() {
    check_sources(
        image(
            true,
            &[record(
                30,
                false,
                b"FILE.;1",
                &px(ratarmount_core::S_IFDIR | 0o4755, false),
            )],
            None,
        ),
        |src| {
            let fi = assert_file(src, "/FILE");
            assert_eq!(fi.mode, ratarmount_core::S_IFREG | 0o4755);
            assert_eq!(fi.linkname, "");
            assert!(src.list_dirents("/FILE").is_none());
            assert_eq!(listed_mode(src, "/", "FILE"), fi.mode);
        },
    );

    let mut dir_as_file = image(
        true,
        &[record(
            22,
            true,
            b"D00",
            &[nm(0, "dir"), px(ratarmount_core::S_IFREG | 0o2755, false)].concat(),
        )],
        None,
    );
    directory(
        &mut dir_as_file,
        22,
        &[],
        &[record(30, false, b"CHILD.;1", &nm(0, "child"))],
    );
    check_sources(dir_as_file, |src| {
        let fi = src.lookup("/dir", 0).unwrap();
        assert_eq!(fi.mode, ratarmount_core::S_IFDIR | 0o2755);
        assert_eq!(fi.linkname, "");
        assert_eq!(fi.size, 0);
        assert_is_directory(src, &fi);
        assert_eq!(listed_mode(src, "/", "dir"), fi.mode);
        assert_eq!(names(src, "/dir"), ["child"]);
        assert_file(src, "/dir/child");
    });

    let mut sl_dir = image(
        true,
        &[record(
            22,
            true,
            b"DIR",
            &[
                nm(0, "dir"),
                px(ratarmount_core::S_IFLNK | 0o750, false),
                sl("link"),
            ]
            .concat(),
        )],
        None,
    );
    directory(
        &mut sl_dir,
        22,
        &[],
        &[record(30, false, b"CHILD.;1", &nm(0, "child"))],
    );
    check_sources(sl_dir, |src| {
        let fi = src.lookup("/dir", 0).unwrap();
        assert_eq!(fi.mode, ratarmount_core::S_IFDIR | 0o750);
        assert_eq!(fi.linkname, "");
        assert_eq!(fi.size, 0);
        assert_is_directory(src, &fi);
        assert_eq!(names(src, "/dir"), ["child"]);
        assert_file(src, "/dir/child");
    });

    check_sources(
        image(
            true,
            &[record(
                30,
                false,
                b"FILE.;1",
                &px(ratarmount_core::S_IFLNK | 0o700, false),
            )],
            None,
        ),
        |src| {
            let fi = assert_file(src, "/FILE");
            assert_eq!(fi.mode, ratarmount_core::S_IFREG | 0o700);
            assert_eq!(fi.linkname, "");
            assert_eq!(listed_mode(src, "/", "FILE"), fi.mode);
        },
    );
}

/// Regression: Rock Ridge character/block devices, FIFOs and sockets are shown as device nodes.
#[test]
fn regression_rock_ridge_device_fifo_socket_are_regular_files() {
    let pn = entry(b"PN", &[both(1), both(3)].concat());
    let cases = [
        ("CHR.;1", "CHR", ratarmount_core::S_IFCHR | 0o620),
        ("BLK.;1", "BLK", ratarmount_core::S_IFBLK | 0o660),
        ("FIFO.;1", "FIFO", ratarmount_core::S_IFIFO | 0o640),
        ("SOCK.;1", "SOCK", ratarmount_core::S_IFSOCK | 0o600),
    ];
    let records: Vec<_> = cases
        .iter()
        .map(|(iso, _, mode)| {
            record(
                30,
                false,
                iso.as_bytes(),
                &[px(*mode, false), pn.clone()].concat(),
            )
        })
        .collect();
    check_sources(image(true, &records, None), |src| {
        for (_, name, mode) in cases {
            let fi = assert_file(src, &format!("/{name}"));
            let expect = ratarmount_core::S_IFREG | (mode & 0o7777);
            assert_eq!(fi.mode, expect, "{name}");
            assert_eq!(fi.linkname, "");
            assert_eq!(listed_mode(src, "/", name), fi.mode);
        }
    });
}

/// Regression: a Joliet-selected SL directory missing from Joliet is dropped with its children.
#[test]
fn regression_joliet_selected_sl_directory_grafts_children() {
    let primary = [record(
        22,
        true,
        b"D",
        &[px(ratarmount_core::S_IFLNK | 0o750, false), sl("elsewhere")].concat(),
    )];
    let supplementary = [record(31, false, &joliet("Joliet Only;1"), &[])];
    let mut bytes = image(true, &primary, Some(&supplementary));
    directory(&mut bytes, 22, &[], &[record(30, false, b"F.;1", &[])]);
    check_sources(bytes, |src| {
        assert_eq!(names(src, "/"), ["D", "Joliet Only"]);
        let d = src.lookup("/D", 0).unwrap();
        assert_eq!(d.mode, ratarmount_core::S_IFDIR | 0o750);
        assert_eq!(d.linkname, "");
        assert_eq!(d.size, 0);
        assert_is_directory(src, &d);
        assert_eq!(listed_mode(src, "/", "D"), d.mode);
        assert_eq!(names(src, "/D"), ["F"]);
        assert_file(src, "/D/F");
    });
}

/// Regression: one-to-one unmatched-directory pairing binds an SL directory to the only other Joliet directory and drops its children.
#[test]
fn regression_joliet_unmatched_directory_pairing_skips_sl_directories() {
    let primary = [record(
        22,
        true,
        b"D",
        &[px(ratarmount_core::S_IFDIR | 0o755, false), sl("elsewhere")].concat(),
    )];
    let supplementary = [record(23, true, &joliet("Other"), &[])];
    let mut bytes = image(true, &primary, Some(&supplementary));
    directory(&mut bytes, 22, &[], &[record(30, false, b"F.;1", &[])]);
    check_sources(bytes, |src| {
        assert_eq!(names(src, "/"), ["D", "Other"]);
        let d = src.lookup("/D", 0).unwrap();
        assert_eq!(d.mode, ratarmount_core::S_IFDIR | 0o755);
        assert_eq!(d.linkname, "");
        assert_eq!(d.size, 0);
        assert_eq!(names(src, "/D"), ["F"]);
        assert_file(src, "/D/F");
        assert_eq!(
            src.lookup("/Other", 0).unwrap().mode & ratarmount_core::S_IFMT,
            ratarmount_core::S_IFDIR
        );
    });
}

/// Regression: nested SL directories keep the inner directory, its file, and its symlink.
#[test]
fn regression_joliet_nested_sl_directories() {
    let primary = [record(
        22,
        true,
        b"OUT",
        &[px(ratarmount_core::S_IFLNK | 0o750, false), sl("outer")].concat(),
    )];
    let supplementary = [record(31, false, &joliet("Joliet Only;1"), &[])];
    let mut bytes = image(true, &primary, Some(&supplementary));
    directory(
        &mut bytes,
        22,
        &[],
        &[record(
            23,
            true,
            b"IN",
            &[px(ratarmount_core::S_IFLNK | 0o755, false), sl("inner")].concat(),
        )],
    );
    directory(
        &mut bytes,
        23,
        &[],
        &[
            record(30, false, b"F.;1", &[]),
            record(30, false, b"L.;1", &sl("leaf")),
        ],
    );
    check_sources(bytes, |src| {
        assert_eq!(names(src, "/"), ["Joliet Only", "OUT"]);
        let out = src.lookup("/OUT", 0).unwrap();
        assert_eq!(out.mode, ratarmount_core::S_IFDIR | 0o750);
        assert_eq!(out.linkname, "");
        assert_eq!(out.size, 0);
        assert_is_directory(src, &out);
        assert_eq!(names(src, "/OUT"), ["IN"]);
        let inner = src.lookup("/OUT/IN", 0).unwrap();
        assert_eq!(inner.mode, ratarmount_core::S_IFDIR | 0o755);
        assert_eq!(inner.linkname, "");
        assert_eq!(inner.size, 0);
        let children = names(src, "/OUT/IN");
        assert_eq!(children, ["F", "L"]);
        assert_eq!(children.len(), 2);
        assert_file(src, "/OUT/IN/F");
        let link = src.lookup("/OUT/IN/L", 0).unwrap();
        assert_eq!(link.mode, ratarmount_core::S_IFLNK | 0o644);
        assert_eq!(link.linkname, "leaf");
        match src.open(&link, 0) {
            Err(err) => assert_eq!(err.kind(), io::ErrorKind::InvalidInput),
            Ok(_) => panic!("symlink opened as a file"),
        }
        assert!(src.lookup("/IN", 0).is_none());
        assert!(src.lookup("/L", 0).is_none());
        assert!(src.lookup("/OUT/L", 0).is_none());
    });
}

/// Regression: an extent-matched child must not bind its SL directory to the Joliet parent.
#[test]
fn regression_joliet_sl_directory_matched_descendant() {
    let primary = [record(
        22,
        true,
        b"D",
        &[px(ratarmount_core::S_IFLNK | 0o750, false), sl("elsewhere")].concat(),
    )];
    let supplementary = [record(23, true, &joliet("Other"), &[])];
    let mut bytes = image(true, &primary, Some(&supplementary));
    directory(
        &mut bytes,
        22,
        &[],
        &[
            record(30, false, b"KEEP.;1", &[]),
            record(32, false, b"ONLY.;1", &[]),
        ],
    );
    directory(
        &mut bytes,
        23,
        &[],
        &[record(30, false, &joliet("Kept Name;1"), &[])],
    );
    bytes[32 * BLOCK..32 * BLOCK + 4].copy_from_slice(b"data");
    check_sources(bytes, |src| {
        assert_eq!(names(src, "/"), ["D", "Other"]);
        assert_eq!(names(src, "/D"), ["ONLY"]);
        assert_eq!(names(src, "/Other"), ["Kept Name"]);
        assert_file(src, "/D/ONLY");
        assert_file(src, "/Other/Kept Name");
        let d = src.lookup("/D", 0).unwrap();
        assert_eq!(d.mode, ratarmount_core::S_IFDIR | 0o750);
        assert_eq!(d.linkname, "");
        assert_eq!(
            src.lookup("/Other", 0).unwrap().mode,
            ratarmount_core::S_IFDIR | 0o755
        );
        assert!(src.lookup("/D/KEEP", 0).is_none());
        assert!(src.lookup("/D/Kept Name", 0).is_none());
    });
}

/// Regression: a matched child binds an SL directory's non-unique parent without binding the SL directory.
#[test]
fn regression_joliet_sl_directory_under_non_unique_parent() {
    let primary = [
        record(22, true, b"P", &px(ratarmount_core::S_IFDIR | 0o700, false)),
        record(24, true, b"SIB", &[]),
    ];
    let supplementary = [
        record(23, true, &joliet("Parent"), &[]),
        record(26, true, &joliet("Sibling"), &[]),
    ];
    let mut bytes = image(true, &primary, Some(&supplementary));
    directory(
        &mut bytes,
        22,
        &[],
        &[record(
            25,
            true,
            b"D",
            &[px(ratarmount_core::S_IFLNK | 0o750, false), sl("elsewhere")].concat(),
        )],
    );
    directory(
        &mut bytes,
        25,
        &[],
        &[
            record(30, false, b"KEEP.;1", &[]),
            record(32, false, b"ONLY.;1", &[]),
        ],
    );
    directory(
        &mut bytes,
        23,
        &[],
        &[record(27, true, &joliet("Other"), &[])],
    );
    directory(
        &mut bytes,
        27,
        &[],
        &[record(30, false, &joliet("Kept Name;1"), &[])],
    );
    bytes[32 * BLOCK..32 * BLOCK + 4].copy_from_slice(b"data");
    check_sources(bytes, |src| {
        assert_eq!(names(src, "/"), ["Parent", "Sibling"]);
        assert_eq!(names(src, "/Parent"), ["D", "Other"]);
        assert_eq!(names(src, "/Parent/D"), ["ONLY"]);
        assert_eq!(names(src, "/Parent/Other"), ["Kept Name"]);
        assert_eq!(
            src.lookup("/Parent", 0).unwrap().mode,
            ratarmount_core::S_IFDIR | 0o700
        );
        assert_eq!(
            src.lookup("/Parent/Other", 0).unwrap().mode,
            ratarmount_core::S_IFDIR | 0o755
        );
        assert_eq!(
            src.lookup("/Sibling", 0).unwrap().mode,
            ratarmount_core::S_IFDIR | 0o755
        );
        let d = src.lookup("/Parent/D", 0).unwrap();
        assert_eq!(d.mode, ratarmount_core::S_IFDIR | 0o750);
        assert_eq!(d.linkname, "");
        assert_file(src, "/Parent/D/ONLY");
        assert_file(src, "/Parent/Other/Kept Name");
    });
}

/// Regression: nested SL dirs under a plain parent bind it one Joliet level too high.
#[test]
fn regression_joliet_nested_sl_under_plain_parent() {
    let primary = [record(
        22,
        true,
        b"P",
        &px(ratarmount_core::S_IFDIR | 0o700, false),
    )];
    let supplementary = [record(23, true, &joliet("Parent"), &[])];
    let mut bytes = image(true, &primary, Some(&supplementary));
    directory(
        &mut bytes,
        22,
        &[],
        &[record(
            24,
            true,
            b"OUT",
            &[px(ratarmount_core::S_IFLNK | 0o750, false), sl("outer")].concat(),
        )],
    );
    directory(
        &mut bytes,
        24,
        &[],
        &[record(
            25,
            true,
            b"IN",
            &[px(ratarmount_core::S_IFLNK | 0o711, false), sl("inner")].concat(),
        )],
    );
    directory(
        &mut bytes,
        25,
        &[],
        &[
            record(30, false, b"KEEP.;1", &[]),
            record(32, false, b"ONLY.;1", &[]),
        ],
    );
    directory(
        &mut bytes,
        23,
        &[],
        &[record(27, true, &joliet("Other"), &[])],
    );
    directory(
        &mut bytes,
        27,
        &[],
        &[record(30, false, &joliet("Kept Name;1"), &[])],
    );
    bytes[32 * BLOCK..32 * BLOCK + 4].copy_from_slice(b"data");
    check_sources(bytes, |src| {
        assert!(src.lookup("/OUT", 0).is_none(), "/OUT exists");
        assert!(src.lookup("/IN", 0).is_none());
        assert!(src.lookup("/Parent/IN", 0).is_none());
        assert_eq!(names(src, "/"), ["Parent"]);
        assert_eq!(names(src, "/Parent"), ["OUT", "Other"]);
        assert_eq!(names(src, "/Parent/OUT"), ["IN"]);
        assert_eq!(names(src, "/Parent/OUT/IN"), ["ONLY"]);
        assert_eq!(names(src, "/Parent/Other"), ["Kept Name"]);
        assert_eq!(
            src.lookup("/Parent", 0).unwrap().mode,
            ratarmount_core::S_IFDIR | 0o700
        );
        assert_ne!(
            src.lookup("/", 0).unwrap().mode,
            ratarmount_core::S_IFDIR | 0o700
        );
        let out = src.lookup("/Parent/OUT", 0).unwrap();
        assert_eq!(out.mode, ratarmount_core::S_IFDIR | 0o750);
        assert_eq!(out.linkname, "");
        assert_is_directory(src, &out);
        let inner = src.lookup("/Parent/OUT/IN", 0).unwrap();
        assert_eq!(inner.mode, ratarmount_core::S_IFDIR | 0o711);
        assert_eq!(inner.linkname, "");
        assert_is_directory(src, &inner);
        assert_file(src, "/Parent/OUT/IN/ONLY");
        assert_file(src, "/Parent/Other/Kept Name");
    });
}

/// Regression: a second Joliet hop through a plain directory under an SL run binds the plain parent to the root.
#[test]
fn regression_joliet_sl_then_plain_dir_under_plain_parent() {
    let primary = [record(
        22,
        true,
        b"P",
        &px(ratarmount_core::S_IFDIR | 0o700, false),
    )];
    let supplementary = [record(23, true, &joliet("Parent"), &[])];
    let mut bytes = image(true, &primary, Some(&supplementary));
    directory(
        &mut bytes,
        22,
        &[],
        &[record(
            24,
            true,
            b"OUT",
            &[px(ratarmount_core::S_IFLNK | 0o750, false), sl("outer")].concat(),
        )],
    );
    directory(
        &mut bytes,
        24,
        &[],
        &[record(
            25,
            true,
            b"MID",
            &px(ratarmount_core::S_IFDIR | 0o711, false),
        )],
    );
    directory(&mut bytes, 25, &[], &[record(30, false, b"KEEP.;1", &[])]);
    directory(
        &mut bytes,
        23,
        &[],
        &[record(26, true, &joliet("Other"), &[])],
    );
    directory(
        &mut bytes,
        26,
        &[],
        &[record(30, false, &joliet("Kept Name;1"), &[])],
    );
    check_sources(bytes, |src| {
        assert!(src.lookup("/OUT", 0).is_none(), "/OUT exists");
        assert_eq!(
            src.lookup("/Parent", 0).unwrap().mode,
            ratarmount_core::S_IFDIR | 0o700
        );
        assert_eq!(
            src.lookup("/Parent/Other", 0).unwrap().mode,
            ratarmount_core::S_IFDIR | 0o711
        );
        assert_ne!(
            src.lookup("/", 0).unwrap().mode,
            ratarmount_core::S_IFDIR | 0o700
        );
        let out = src.lookup("/Parent/OUT", 0).unwrap();
        assert_eq!(out.mode, ratarmount_core::S_IFDIR | 0o750);
        assert_eq!(out.linkname, "");
        assert_is_directory(src, &out);
        assert_eq!(names(src, "/Parent"), ["OUT", "Other"]);
        assert_eq!(names(src, "/Parent/Other"), ["Kept Name"]);
        assert_file(src, "/Parent/Other/Kept Name");
    });
}

/// Regression: a file hop and a directory hop through one SL run disagree, so the plain parent stays unbound and the SL directory is not grafted.
///
/// `/` is the synthetic index root (`S_IFDIR | 0o777`). Binding the plain parent onto the Joliet root does not change that mode; the failure is `/OUT` plus `/Parent` taking the sibling's mode.
#[test]
fn regression_joliet_sl_run_file_and_plain_dir_conflict() {
    let primary = [
        record(22, true, b"P", &px(ratarmount_core::S_IFDIR | 0o700, false)),
        record(
            28,
            true,
            b"SIB",
            &px(ratarmount_core::S_IFDIR | 0o751, false),
        ),
    ];
    let supplementary = [record(23, true, &joliet("Parent"), &[])];
    let mut bytes = image(true, &primary, Some(&supplementary));
    directory(
        &mut bytes,
        22,
        &[],
        &[record(
            24,
            true,
            b"OUT",
            &[px(ratarmount_core::S_IFLNK | 0o750, false), sl("elsewhere")].concat(),
        )],
    );
    // FILE before MID: the reverse walk applies MID first, then FILE.
    directory(
        &mut bytes,
        24,
        &[],
        &[
            record(32, false, b"FILE.;1", &[]),
            record(
                25,
                true,
                b"MID",
                &px(ratarmount_core::S_IFDIR | 0o711, false),
            ),
        ],
    );
    directory(&mut bytes, 25, &[], &[record(30, false, b"KEEP.;1", &[])]);
    directory(&mut bytes, 28, &[], &[]);
    directory(
        &mut bytes,
        23,
        &[],
        &[
            record(32, false, &joliet("Hoisted;1"), &[]),
            record(26, true, &joliet("Other"), &[]),
        ],
    );
    directory(
        &mut bytes,
        26,
        &[],
        &[record(30, false, &joliet("Kept;1"), &[])],
    );
    bytes[32 * BLOCK..32 * BLOCK + 4].copy_from_slice(b"data");
    check_sources(bytes, |src| {
        assert_eq!(
            src.lookup("/", 0).unwrap().mode,
            ratarmount_core::S_IFDIR | 0o777
        );
        assert_eq!(
            src.lookup("/Parent", 0).unwrap().mode,
            ratarmount_core::S_IFDIR | 0o755
        );
        assert!(src.lookup("/OUT", 0).is_none(), "/OUT exists");
        assert!(src.lookup("/Parent/OUT", 0).is_none(), "/Parent/OUT exists");
        assert_eq!(
            src.lookup("/Parent/Other", 0).unwrap().mode,
            ratarmount_core::S_IFDIR | 0o711
        );
        assert_file(src, "/Parent/Hoisted");
    });
}

/// Regression: an unmatched plain directory outside an SL subtree is not grafted.
#[test]
fn regression_joliet_unmatched_plain_dir_outside_sl_not_grafted() {
    // D then P: walk_tree's stack yields D=1, P=2, and OUT's id is above D.
    let primary = [
        record(
            22,
            true,
            b"D",
            &[px(ratarmount_core::S_IFLNK | 0o750, false), sl("elsewhere")].concat(),
        ),
        record(24, true, b"P", &px(ratarmount_core::S_IFDIR | 0o700, false)),
    ];
    let supplementary = [record(23, true, &joliet("Parent"), &[])];
    let mut bytes = image(true, &primary, Some(&supplementary));
    directory(&mut bytes, 22, &[], &[record(32, false, b"ONLY.;1", &[])]);
    directory(
        &mut bytes,
        24,
        &[],
        &[
            record(30, false, b"KEEP.;1", &[]),
            record(
                25,
                true,
                b"OUT",
                &px(ratarmount_core::S_IFDIR | 0o711, false),
            ),
        ],
    );
    directory(&mut bytes, 25, &[], &[]);
    directory(
        &mut bytes,
        23,
        &[],
        &[
            record(30, false, &joliet("Kept;1"), &[]),
            record(26, true, &joliet("Extra1"), &[]),
            record(27, true, &joliet("Extra2"), &[]),
        ],
    );
    directory(&mut bytes, 26, &[], &[]);
    directory(&mut bytes, 27, &[], &[]);
    bytes[32 * BLOCK..32 * BLOCK + 4].copy_from_slice(b"data");
    check_sources(bytes, |src| {
        assert_eq!(names(src, "/"), ["D", "Parent"]);
        assert_eq!(names(src, "/D"), ["ONLY"]);
        assert_eq!(
            src.lookup("/D", 0).unwrap().mode,
            ratarmount_core::S_IFDIR | 0o750
        );
        assert_file(src, "/D/ONLY");
        assert_eq!(
            src.lookup("/Parent", 0).unwrap().mode,
            ratarmount_core::S_IFDIR | 0o700
        );
        assert!(src.lookup("/Parent/OUT", 0).is_none(), "/Parent/OUT exists");
        assert_eq!(names(src, "/Parent"), ["Extra1", "Extra2", "Kept"]);
    });
}

/// Regression: a plain directory between an SL directory and a matched file must not mis-bind or drop either file.
#[test]
fn regression_joliet_sl_directory_with_plain_dir_before_match() {
    let primary = [record(
        22,
        true,
        b"D",
        &[px(ratarmount_core::S_IFLNK | 0o750, false), sl("elsewhere")].concat(),
    )];
    // Joliet omitted the SL directory and hoisted MID to the supplementary root.
    let supplementary = [record(24, true, &joliet("Other"), &[])];
    let mut bytes = image(true, &primary, Some(&supplementary));
    directory(
        &mut bytes,
        22,
        &[],
        &[
            record(
                23,
                true,
                b"MID",
                &px(ratarmount_core::S_IFDIR | 0o711, false),
            ),
            record(32, false, b"ONLY.;1", &[]),
        ],
    );
    directory(&mut bytes, 23, &[], &[record(30, false, b"KEEP.;1", &[])]);
    directory(
        &mut bytes,
        24,
        &[],
        &[record(30, false, &joliet("Kept Name;1"), &[])],
    );
    bytes[32 * BLOCK..32 * BLOCK + 4].copy_from_slice(b"data");
    check_sources(bytes, |src| {
        fn collect(
            src: &Iso9660MountSource,
            path: &str,
            dirs: &mut Vec<(String, u32)>,
            keeps: &mut Vec<String>,
        ) {
            let Some(entries) = src.list_dirents(path) else {
                return;
            };
            for ent in entries {
                let child = if path == "/" {
                    format!("/{}", ent.name)
                } else {
                    format!("{path}/{}", ent.name)
                };
                if ent.name == "KEEP" || ent.name == "Kept Name" {
                    keeps.push(child.clone());
                }
                let Some(fi) = src.lookup(&child, 0) else {
                    continue;
                };
                if fi.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR {
                    dirs.push((child.clone(), fi.mode));
                    collect(src, &child, dirs, keeps);
                }
            }
        }

        assert_file(src, "/D/ONLY");
        let d = src.lookup("/D", 0).unwrap_or_else(|| panic!("missing /D"));
        assert_eq!(d.mode, ratarmount_core::S_IFDIR | 0o750);
        assert_eq!(d.linkname, "");
        let root = src.lookup("/", 0).unwrap_or_else(|| panic!("missing /"));
        assert_ne!(root.mode, ratarmount_core::S_IFDIR | 0o750);
        let mut dirs = vec![("/".to_string(), root.mode)];
        let mut keeps = Vec::new();
        collect(src, "/", &mut dirs, &mut keeps);
        for (path, mode) in &dirs {
            if path != "/D" {
                assert_ne!(
                    *mode,
                    ratarmount_core::S_IFDIR | 0o750,
                    "{path} took the SL directory mode"
                );
            }
        }
        assert_eq!(
            keeps.len(),
            1,
            "Kept Name/KEEP data reachable {} times at {keeps:?}",
            keeps.len()
        );
        assert_file(src, &keeps[0]);
    });
}

/// Regression: nested SL directories with an extent-matched inner file stay grafted; the Joliet directory keeps mode 0o755.
#[test]
fn regression_joliet_nested_sl_with_matched_file() {
    let primary = [record(
        22,
        true,
        b"OUT",
        &[px(ratarmount_core::S_IFLNK | 0o750, false), sl("outer")].concat(),
    )];
    let supplementary = [record(24, true, &joliet("Other"), &[])];
    let mut bytes = image(true, &primary, Some(&supplementary));
    directory(
        &mut bytes,
        22,
        &[],
        &[record(
            23,
            true,
            b"IN",
            &[px(ratarmount_core::S_IFLNK | 0o700, false), sl("inner")].concat(),
        )],
    );
    directory(
        &mut bytes,
        23,
        &[],
        &[
            record(30, false, b"KEEP.;1", &[]),
            record(32, false, b"ONLY.;1", &[]),
        ],
    );
    directory(
        &mut bytes,
        24,
        &[],
        &[record(30, false, &joliet("Kept Name;1"), &[])],
    );
    bytes[32 * BLOCK..32 * BLOCK + 4].copy_from_slice(b"data");
    check_sources(bytes, |src| {
        assert_eq!(names(src, "/"), ["OUT", "Other"]);
        assert!(src.lookup("/IN", 0).is_none());
        let out = src.lookup("/OUT", 0).unwrap();
        assert_eq!(out.mode, ratarmount_core::S_IFDIR | 0o750);
        assert_eq!(out.linkname, "");
        assert_eq!(names(src, "/OUT"), ["IN"]);
        let inner = src.lookup("/OUT/IN", 0).unwrap();
        assert_eq!(inner.mode, ratarmount_core::S_IFDIR | 0o700);
        assert_eq!(inner.linkname, "");
        assert_eq!(names(src, "/OUT/IN"), ["ONLY"]);
        assert_eq!(
            src.lookup("/Other", 0).unwrap().mode,
            ratarmount_core::S_IFDIR | 0o755
        );
        assert_eq!(names(src, "/Other"), ["Kept Name"]);
        assert_file(src, "/OUT/IN/ONLY");
        assert_file(src, "/Other/Kept Name");
    });
}

/// Regression: a type-2 SVD whose escape is not Joliet is ignored while its tree stays valid.
#[test]
fn regression_non_joliet_supplementary_descriptor_ignored() {
    for escape in [b"%/A", b"%/D", b"   "] {
        let primary = [
            record(30, false, b"FILE.;1", &[]),
            record(22, true, b"SUBDIR", &[]),
        ];
        let supplementary = [record(31, false, &joliet("Supplementary Only;1"), &[])];
        let mut bytes = image(false, &primary, Some(&supplementary));
        bytes[17 * BLOCK + 88..17 * BLOCK + 91].copy_from_slice(escape);
        directory(&mut bytes, 22, &[], &[record(30, false, b"CHILD;1", &[])]);
        check_sources(bytes, |src| {
            assert_eq!(names(src, "/"), ["FILE", "SUBDIR"]);
            assert_eq!(names(src, "/SUBDIR"), ["CHILD"]);
            assert_file(src, "/FILE");
            assert_file(src, "/SUBDIR/CHILD");
            assert!(src.lookup("/Supplementary Only", 0).is_none());
        });
    }
}

/// Regression: a child directory past EOF is rejected; one that ends on the last byte is listed.
#[test]
fn regression_directory_extent_past_eof_and_exact_end() {
    let edge = 20 * BLOCK
        + record(20, true, &[0], &entry(b"SP", &[0xbe, 0xef, 0])).len()
        + record(20, true, &[1], &[]).len();
    let mut past_eof = image(true, &[record(99, true, b"EDGE", &[])], None);
    directory(&mut past_eof, 99, &[], &[record(30, false, b"F.;1", &[])]);
    past_eof[edge + 10..edge + 18].copy_from_slice(&both(4096));
    match open_mem(past_eof) {
        Err(err) => assert!(err.to_string().contains("extends beyond image"), "{err}"),
        Ok(_) => panic!("directory extent past the image was accepted"),
    }

    let mut exact = image(true, &[record(99, true, b"EDGE", &[])], None);
    directory(&mut exact, 99, &[], &[record(30, false, b"F.;1", &[])]);
    exact[edge + 10..edge + 18].copy_from_slice(&both(2048));
    check_sources(exact, |src| {
        assert_eq!(names(src, "/"), ["EDGE"]);
        assert_eq!(names(src, "/EDGE"), ["F"]);
        assert_file(src, "/EDGE/F");
    });
}

/// Regression: a damaged Joliet tree fails the image or replaces the ISO 9660 names.
#[test]
fn regression_damaged_joliet_falls_back_to_iso() {
    let mut past_eof = image(
        true,
        &[record(30, false, b"FILE.;1", &nm(0, "Real Name"))],
        Some(&[]),
    );
    past_eof[17 * BLOCK + 158..17 * BLOCK + 166].copy_from_slice(&both(1000));
    check_sources(past_eof, |src| {
        assert_eq!(names(src, "/"), ["Real Name"]);
        assert_file(src, "/Real Name");
    });

    let primary = [record(30, false, b"FILE.;1", &[])];
    let looped = [
        record(21, true, &joliet("LoopDir"), &[]),
        record(30, false, &joliet("Joliet Name;1"), &[]),
    ];
    check_sources(image(true, &primary, Some(&looped)), |src| {
        assert_eq!(names(src, "/"), ["FILE"]);
        assert_file(src, "/FILE");
    });

    let mut truncated = image(true, &primary, Some(&[]));
    truncated[21 * BLOCK] = 10;
    check_sources(truncated, |src| {
        assert_eq!(names(src, "/"), ["FILE"]);
        assert_file(src, "/FILE");
    });

    let mut primary_past_eof = image(true, &primary, Some(&[]));
    primary_past_eof[16 * BLOCK + 158..16 * BLOCK + 166].copy_from_slice(&both(1000));
    match open_mem(primary_past_eof) {
        Err(err) => assert!(err.to_string().contains("extends beyond image"), "{err}"),
        Ok(_) => panic!("primary extent past the image was accepted"),
    }
}

/// Regression: Joliet with no Rock Ridge and a damaged Joliet root drops the primary tree.
#[test]
fn regression_damaged_joliet_without_rock_ridge_falls_back_to_iso() {
    let mut bytes = image(false, &[record(30, false, b"FILE.;1", &[])], Some(&[]));
    bytes[17 * BLOCK + 158..17 * BLOCK + 166].copy_from_slice(&both(1000));
    check_sources(bytes, |src| {
        assert_eq!(names(src, "/"), ["FILE"]);
        assert_file(src, "/FILE");
    });
}

/// Regression: a rock-ridge-joliet-v1 through v3 sidecar keeps a PX directory type for a file.
#[test]
fn regression_iso_metadata_v1_rebuilds_after_type_split() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("v1.iso");
    let index_path = default_index_path(&path);
    let bytes = image(
        true,
        &[record(
            30,
            false,
            b"PLAIN;1",
            &[
                px(ratarmount_core::S_IFDIR | 0o750, false),
                nm(0, "Real Name"),
            ]
            .concat(),
        )],
        None,
    );
    std::fs::write(&path, bytes).unwrap();
    for version in [
        "rock-ridge-joliet-v1",
        "rock-ridge-joliet-v2",
        "rock-ridge-joliet-v3",
    ] {
        // A successful open rewrites isoMetadataVersion, so plant the stale
        // directory row and the old version again before every open.
        if index_path.exists() {
            std::fs::remove_file(&index_path).unwrap();
        }
        let index =
            SqliteIndex::create_writable_for_open(Some(&index_path), &OpenOptions::default())
                .unwrap();
        index.begin_write().unwrap();
        index
            .insert_file(
                "",
                "PLAIN",
                30 * BLOCK as i64,
                30 * BLOCK as i64,
                4,
                0.0,
                i64::from(ratarmount_core::S_IFDIR | 0o755),
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
            .store_metadata_key_value("isoMetadataVersion", version)
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
        assert_eq!(names(&src, "/"), ["Real Name"], "{version}");
        let looked = src
            .lookup("/Real Name", 0)
            .unwrap_or_else(|| panic!("missing /Real Name ({version})"));
        assert_eq!(
            looked.mode,
            ratarmount_core::S_IFREG | 0o750,
            "{version} sidecar kept the PX directory type"
        );
        let fi = assert_file(&src, "/Real Name");
        assert_eq!(fi.mode, ratarmount_core::S_IFREG | 0o750, "{version}");
        drop(src);
    }
}

/// Regression: real mkisofs -R -J output keeps mixed case, executable modes and symlinks.
#[cfg(unix)]
#[test]
fn regression_xorriso_rock_ridge_joliet() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::process::Command;
    let bin = std::env::var("RATARMOUNT_XORRISO").unwrap_or_else(|_| "xorriso".to_string());
    match Command::new(&bin).arg("-version").output() {
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if std::env::var("RATARMOUNT_REQUIRE_XORRISO").ok().as_deref() == Some("1") {
                panic!("xorriso not on PATH (RATARMOUNT_REQUIRE_XORRISO=1; binary {bin})");
            }
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
    let output = Command::new(&bin)
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
