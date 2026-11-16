//! Regression coverage for immutable prepared factory inputs, without FUSE.
use super::*;
use std::collections::BTreeMap;
use std::io::{Cursor, Read, Write};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Clone, Copy, Debug)]
enum Codec {
    Gzip,
    Zstd,
    Bzip2,
}
impl Codec {
    fn suffix(self) -> &'static str {
        match self {
            Self::Gzip => "gz",
            Self::Zstd => "zst",
            Self::Bzip2 => "bz2",
        }
    }
    fn encode(self, bytes: &[u8]) -> Vec<u8> {
        match self {
            Self::Gzip => {
                let mut out =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
                out.write_all(bytes).unwrap();
                out.finish().unwrap()
            }
            Self::Zstd => bytes
                .chunks(100_000)
                .flat_map(|chunk| zstd::stream::encode_all(chunk, 1).unwrap())
                .collect(),
            Self::Bzip2 => {
                let mut out = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::new(1));
                out.write_all(bytes).unwrap();
                out.finish().unwrap()
            }
        }
    }
}
const CODECS: [Codec; 3] = [Codec::Gzip, Codec::Zstd, Codec::Bzip2];
fn payload() -> Vec<u8> {
    (0..350_000u32).map(|i| ((i / 17) % 251) as u8).collect()
}
fn tar_bytes(name: &str, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    ratarmount_formats_tar::write_ustar_members(
        &mut out,
        &[ratarmount_formats_tar::UstarMember {
            path: name,
            payload: ratarmount_formats_tar::UstarPayload::File { bytes: data },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            xattrs: &[],
        }],
    )
    .unwrap();
    out
}
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    fn walk(dir: &Path, files: &mut BTreeMap<PathBuf, Vec<u8>>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, files)
            } else {
                files.insert(p.clone(), std::fs::read(p).unwrap());
            }
        }
    }
    let mut files = BTreeMap::new();
    walk(dir, &mut files);
    files
}
fn read_member(source: &dyn MountSource, name: &str) -> Vec<u8> {
    let info = source.lookup(name, 0).unwrap();
    let mut got = Vec::new();
    source
        .open(&info, 0)
        .unwrap()
        .read_to_end(&mut got)
        .unwrap();
    got
}

/// Regression: file URLs must retain each selected local index for preparation finalization.
#[test]
fn regression_prepared_index_file_urls_finalize_primary_and_bind() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("indexes");
    std::fs::create_dir(&cache).unwrap();
    let primary = dir.path().join("base.tar.zst");
    let bound = dir.path().join("bound.tar.zst");
    for (path, bytes) in [
        (&primary, b"primary payload".as_slice()),
        (&bound, b"bound payload".as_slice()),
    ] {
        std::fs::write(path, Codec::Zstd.encode(&tar_bytes("payload", bytes))).unwrap();
    }
    let paths = [PathBuf::from(format!("file://{}", primary.display()))];
    let bindings = || SourceBindings {
        binds: vec![format!("/bound=file://{}", bound.display())
            .parse()
            .unwrap()],
        ..Default::default()
    };
    let mut options = OpenOptions {
        index_folders: vec![cache],
        ..Default::default()
    };
    let bundle = build_mount_source_with_bindings(
        &paths,
        &mut options,
        false,
        Default::default(),
        bindings(),
    )
    .unwrap();
    let artifacts = bundle.prepared_artifacts.clone();
    drop(bundle);
    for artifact in &artifacts {
        SqliteIndex::finalize_prepared(artifact).unwrap();
    }
    let before = snapshot(dir.path());
    options.read_only_index = true;
    options.write_index = false;
    let bundle = build_mount_source_with_bindings(
        &paths,
        &mut options,
        false,
        Default::default(),
        bindings(),
    )
    .unwrap();
    assert_eq!(
        artifacts.len(),
        2,
        "preparer lost a selected local URL index"
    );
    assert_eq!(
        read_member(bundle.source.as_ref(), "/payload"),
        b"primary payload"
    );
    assert_eq!(
        read_member(bundle.source.as_ref(), "/bound/payload"),
        b"bound payload"
    );
    assert_eq!(snapshot(dir.path()), before);
    drop(bundle);
    assert_eq!(snapshot(dir.path()), before);
}

struct Fixture {
    dir: tempfile::TempDir,
    path: PathBuf,
    index: PathBuf,
    data: Vec<u8>,
    member: String,
    options: OpenOptions,
}
impl Fixture {
    fn new(codec: Codec, tar: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let data = payload();
        let name = if tar { "base.tar" } else { "base.txt" };
        let path = dir.path().join(format!("{name}.{}", codec.suffix()));
        let member = if tar { "/payload" } else { "/base.txt" }.to_string();
        let bytes = if tar {
            tar_bytes("payload", &data)
        } else {
            data.clone()
        };
        std::fs::write(&path, codec.encode(&bytes)).unwrap();
        let index = dir.path().join("prepared.sqlite");
        let options = OpenOptions {
            index_file_path: Some(index.clone()),
            gzip_seek_point_spacing: 64 * 1024,
            parallelization: ratarmount_core::ParallelizationSpec::new(1),
            ..Default::default()
        };
        drop(open_path(&path, &options, true).unwrap());
        SqliteIndex::finalize_prepared(&index).unwrap();
        Self {
            dir,
            path,
            index,
            data,
            member,
            options,
        }
    }
    fn strict(&self) -> OpenOptions {
        let mut options = self.options.clone();
        options.read_only_index = true;
        options.write_index = false;
        options
    }
    fn open(&self, reader: bool, options: &OpenOptions) -> Result<Arc<dyn MountSource>, String> {
        if reader {
            let bytes = std::fs::read(&self.path).unwrap();
            let len = bytes.len() as u64;
            open_from_live_range(
                Cursor::new(bytes),
                len,
                self.path.to_str().unwrap(),
                options,
                false,
                "prepared-test",
                || panic!("strict importer reopened to reconstruct seek state"),
            )?
            .map(|(_, src)| src)
            .ok_or_else(|| "unsupported fixture".into())
        } else {
            open_path(&self.path, options, false)
        }
    }
    fn valid(&self, reader: bool) {
        let before = snapshot(self.dir.path());
        let source = self.open(reader, &self.strict()).unwrap();
        assert_eq!(read_member(source.as_ref(), &self.member), self.data);
        assert_eq!(snapshot(self.dir.path()), before);
        drop(source);
        assert_eq!(snapshot(self.dir.path()), before);
    }
    fn refuses(&self, reader: bool, symptom: &str) {
        let before = snapshot(self.dir.path());
        let ticks = Arc::new(AtomicUsize::new(0));
        let record = ticks.clone();
        let mut options = self.strict();
        options.index_build.on_progress = Some(Arc::new(move |_| {
            record.fetch_add(1, Ordering::SeqCst);
        }));
        let error = self
            .open(reader, &options)
            .err()
            .expect("strict open must refuse");
        assert!(error.contains(symptom), "expected {symptom:?}: {error}");
        assert_eq!(ticks.load(Ordering::SeqCst), 0, "worker built a file table");
        assert_eq!(
            snapshot(self.dir.path()),
            before,
            "worker changed prepared artifacts"
        );
    }
    fn mutate_map(&self, codec: Codec, change: impl FnOnce(&mut Vec<(i64, i64)>)) {
        let idx = SqliteIndex::open_writable(&self.index).unwrap();
        let mut map = match codec {
            Codec::Zstd => idx.get_zstd_blocks().unwrap(),
            Codec::Bzip2 => idx.get_bzip2_blocks().unwrap(),
            Codec::Gzip => panic!("not a pair map"),
        };
        assert!(map.len() >= 3);
        change(&mut map);
        match codec {
            Codec::Zstd => idx.set_zstd_blocks(&map).unwrap(),
            Codec::Bzip2 => idx.set_bzip2_blocks(&map).unwrap(),
            Codec::Gzip => unreachable!(),
        };
        drop(idx);
        SqliteIndex::finalize_prepared(&self.index).unwrap();
    }
    fn mutate_gzip(
        &self,
        change: impl FnOnce(&mut ratarmount_compress::GzipSeekIndexBlob) -> Vec<u8>,
    ) {
        let idx = SqliteIndex::open_writable(&self.index).unwrap();
        let blob = idx.get_gzip_index_blobs().unwrap().remove(0);
        let mut parsed = ratarmount_compress::try_import_gzip_seek_blob(&blob).unwrap();
        let changed = change(&mut parsed);
        idx.set_gzip_index_blob(&changed).unwrap();
        drop(idx);
        SqliteIndex::finalize_prepared(&self.index).unwrap();
    }
}

/// Regression: compressed TAR workers must only import their immutable prepared seek state.
#[test]
fn regression_prepared_index_compression_lookup_never_writes() {
    for codec in CODECS {
        let fixture = Fixture::new(codec, true);
        fixture.valid(false);
        fixture.valid(true);
    }
}

/// Regression: missing, empty, wrong-codec and invalid seek data must never trigger a cold map.
#[test]
fn regression_prepared_index_compression_refuses_missing_or_bad_seek_state() {
    for codec in CODECS {
        for defect in ["missing", "empty", "corrupt", "wrong-codec", "import"] {
            let fixture = Fixture::new(codec, true);
            let conn = rusqlite::Connection::open(&fixture.index).unwrap();
            let table = match codec {
                Codec::Gzip => "gzipindexes",
                Codec::Zstd => "zstdblocks",
                Codec::Bzip2 => "bzip2blocks",
            };
            // Use public table APIs for malformed values; table names are queried for drops below.
            drop(conn);
            let idx = SqliteIndex::open_writable(&fixture.index).unwrap();
            match codec {
                Codec::Gzip => idx
                    .set_gzip_index_blob(if defect == "import" {
                        b"RGZI"
                    } else {
                        b"bad gzip state"
                    })
                    .unwrap(),
                Codec::Zstd => idx
                    .set_zstd_blocks(if defect == "empty" {
                        &[]
                    } else {
                        &[(0, 0), (i64::MAX, 100)]
                    })
                    .unwrap(),
                Codec::Bzip2 => idx
                    .set_bzip2_blocks(if defect == "empty" {
                        &[]
                    } else {
                        &[(32, 0), (i64::MAX, 100)]
                    })
                    .unwrap(),
            };
            drop(idx);
            if defect == "missing" || defect == "wrong-codec" {
                let conn = rusqlite::Connection::open(&fixture.index).unwrap();
                let actual = if matches!(codec, Codec::Gzip) {
                    let names:Vec<String>=conn.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'gzip%' ").unwrap().query_map([],|r|r.get(0)).unwrap().map(Result::unwrap).collect();
                    names
                } else {
                    vec![table.to_string()]
                };
                for name in actual {
                    conn.execute_batch(&format!("DROP TABLE {name}")).unwrap();
                }
            }
            SqliteIndex::finalize_prepared(&fixture.index).unwrap();
            fixture.refuses(false, "prepared");
            fixture.refuses(true, "prepared");
        }
    }
}

/// Regression: plain compression shells need matching tarstats and validated codec data, without backendName.
#[test]
fn regression_prepared_index_plain_compression_requires_valid_shell() {
    for codec in CODECS {
        let fixture = Fixture::new(codec, false);
        assert!(SqliteIndex::open_lookup(&fixture.index)
            .unwrap()
            .backend_name()
            .unwrap()
            .is_none());
        fixture.valid(false);
        fixture.valid(true);
        for sql in [
            "DELETE FROM metadata WHERE key='tarstats'",
            "DELETE FROM metadata",
        ] {
            let original = std::fs::read(&fixture.index).unwrap();
            {
                let conn = rusqlite::Connection::open(&fixture.index).unwrap();
                conn.execute_batch(sql).unwrap();
            }
            SqliteIndex::finalize_prepared(&fixture.index).unwrap();
            fixture.refuses(false, "prepared");
            fixture.refuses(true, "prepared");
            std::fs::write(&fixture.index, original).unwrap();
        }
        let original = std::fs::read(&fixture.index).unwrap();
        for defect in ["missing-table", "empty", "corrupt", "wrong-codec"] {
            if defect == "missing-table" {
                let conn = rusqlite::Connection::open(&fixture.index).unwrap();
                let table = match codec {
                    Codec::Gzip => conn.query_row("SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'gzip%' LIMIT 1", [], |r| r.get::<_, String>(0)).unwrap(),
                    Codec::Zstd => "zstdblocks".into(),
                    Codec::Bzip2 => "bzip2blocks".into(),
                };
                conn.execute_batch(&format!("DROP TABLE {table}")).unwrap();
            } else {
                let idx = SqliteIndex::open_writable(&fixture.index).unwrap();
                match codec {
                    Codec::Gzip => idx
                        .set_gzip_index_blob(match defect {
                            "empty" => b"",
                            "wrong-codec" => b"BZh9not-gzip",
                            _ => b"invalid gzip",
                        })
                        .unwrap(),
                    Codec::Zstd => idx
                        .set_zstd_blocks(match defect {
                            "empty" => &[],
                            "wrong-codec" => &[(32, 0), (128, 100)],
                            _ => &[(-1, 0), (100, 100)],
                        })
                        .unwrap(),
                    Codec::Bzip2 => idx
                        .set_bzip2_blocks(match defect {
                            "empty" => &[],
                            "wrong-codec" => &[(0, 0), (128, 100)],
                            _ => &[(-1, 0), (100, 100)],
                        })
                        .unwrap(),
                }
            }
            SqliteIndex::finalize_prepared(&fixture.index).unwrap();
            fixture.refuses(false, "prepared");
            fixture.refuses(true, "prepared");
            std::fs::write(&fixture.index, &original).unwrap();
        }
    }
}

/// Regression: consumed reader import failures must propagate before fresh-reader reconstruction.
#[test]
fn regression_prepared_index_reader_import_failure_does_not_rebuild() {
    for codec in CODECS {
        let fixture = Fixture::new(codec, true);
        match codec {
            Codec::Gzip => fixture.mutate_gzip(|p| {
                p.points[0].0 = u64::MAX;
                ratarmount_compress::encode_gzip_seek_index_blob(
                    p.spacing,
                    p.uncompressed_size,
                    &p.points,
                )
            }),
            _ => fixture.mutate_map(codec, |p| {
                p.last_mut().unwrap().0 = i64::MAX;
            }),
        };
        fixture.refuses(true, "prepared");
    }
}

#[cfg(feature = "gzip-rapidgzip")]
/// Regression: a rapidgzip import error must not reopen and fall through to cold G3.
#[test]
fn regression_prepared_index_reader_import_failure_does_not_rebuild_rapidgzip() {
    let fixture = Fixture::new(Codec::Gzip, true);
    let idx = SqliteIndex::open_writable(&fixture.index).unwrap();
    idx.set_gzip_index_blob(b"invalid rapidgzip index").unwrap();
    drop(idx);
    SqliteIndex::finalize_prepared(&fixture.index).unwrap();
    let mut options = fixture.strict();
    options.use_backends = vec!["rapidgzip".into()];
    let before = snapshot(fixture.dir.path());
    let error = fixture.open(true, &options).err().expect("must refuse");
    assert!(error.contains("prepared"), "{error}");
    assert_eq!(snapshot(fixture.dir.path()), before);
}

fn missing_g3_initial(reader: bool) {
    let fixture = Fixture::new(Codec::Gzip, true);
    fixture.valid(reader);
    fixture.mutate_gzip(|p| {
        assert!(p.points.len() > 1);
        p.points.remove(0);
        ratarmount_compress::encode_gzip_seek_index_blob(p.spacing, p.uncompressed_size, &p.points)
    });
    fixture.refuses(reader, "initial checkpoint");
}
/// Regression: a named TAR gzip catalog cannot conceal missing initial G3 checkpoint coverage.
#[test]
fn regression_prepared_index_g3_path_refuses_missing_initial_checkpoint() {
    missing_g3_initial(false);
}
/// Regression: reader G3 imports share the same required initial checkpoint predicate.
#[test]
fn regression_prepared_index_g3_reader_refuses_missing_initial_checkpoint() {
    missing_g3_initial(true);
}

/// Regression: zero-point RGZI and strict GZIDX must not reach internally repairing G3 imports.
#[test]
fn regression_prepared_index_g3_refuses_internal_repair() {
    for defect in [0, 1, 2] {
        let fixture = Fixture::new(Codec::Gzip, true);
        fixture.mutate_gzip(|p| {
            if defect == 0 {
                ratarmount_compress::encode_gzip_seek_index_blob(
                    p.spacing,
                    p.uncompressed_size,
                    &[],
                )
            } else {
                let point = if defect == 1 { 0 } else { u64::MAX };
                ratarmount_compress::encode_indexed_gzip_index_blob(
                    100,
                    p.uncompressed_size,
                    p.spacing as u32,
                    32768,
                    &[(point, 0, 0, None)],
                )
            }
        });
        fixture.refuses(
            false,
            if defect == 0 {
                "initial checkpoint"
            } else {
                "GZIDX"
            },
        );
        fixture.refuses(
            true,
            if defect == 0 {
                "initial checkpoint"
            } else {
                "GZIDX"
            },
        );
    }
}
fn missing_pair(codec: Codec, reader: bool, initial: bool) {
    for tar in [false, true] {
        let fixture = Fixture::new(codec, tar);
        fixture.valid(reader);
        fixture.mutate_map(codec, |map| {
            if initial {
                map.remove(0);
            } else {
                map.pop();
            }
        });
        fixture.refuses(reader, if initial { "initial" } else { "terminal" });
    }
}
/// Regression: zstd path import cannot use a genuine suffix lacking the initial frame.
#[test]
fn regression_prepared_index_zstd_path_refuses_missing_initial_frame() {
    missing_pair(Codec::Zstd, false, true);
}
/// Regression: zstd reader import cannot use a genuine suffix lacking the initial frame.
#[test]
fn regression_prepared_index_zstd_reader_refuses_missing_initial_frame() {
    missing_pair(Codec::Zstd, true, true);
}
/// Regression: zstd plain and named-TAR paths cannot silently omit the final genuine frame.
#[test]
fn regression_prepared_index_zstd_path_refuses_missing_terminal_sentinel() {
    missing_pair(Codec::Zstd, false, false);
}
/// Regression: zstd plain and named-TAR readers cannot silently omit the final genuine frame.
#[test]
fn regression_prepared_index_zstd_reader_refuses_missing_terminal_sentinel() {
    missing_pair(Codec::Zstd, true, false);
}
/// Regression: bzip2 path import cannot expose a genuine later block at offset zero.
#[test]
fn regression_prepared_index_bzip2_path_refuses_missing_initial_block() {
    missing_pair(Codec::Bzip2, false, true);
}
/// Regression: bzip2 reader import cannot expose a genuine later block at offset zero.
#[test]
fn regression_prepared_index_bzip2_reader_refuses_missing_initial_block() {
    missing_pair(Codec::Bzip2, true, true);
}
/// Regression: bzip2 plain and named-TAR paths need a genuine final EOS sentinel.
#[test]
fn regression_prepared_index_bzip2_path_refuses_missing_terminal_sentinel() {
    missing_pair(Codec::Bzip2, false, false);
}
/// Regression: bzip2 plain and named-TAR readers need a genuine final EOS sentinel.
#[test]
fn regression_prepared_index_bzip2_reader_refuses_missing_terminal_sentinel() {
    missing_pair(Codec::Bzip2, true, false);
}

/// Regression: preparation must explicitly refuse unpersistable single-block bzip2 before index writes.
#[test]
fn regression_prepared_index_single_block_bzip2_preparation_refuses() {
    for tar in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join(if tar { "base.tar.bz2" } else { "base.txt.bz2" });
        let data = if tar {
            tar_bytes("f", b"small")
        } else {
            b"small".to_vec()
        };
        std::fs::write(&path, Codec::Bzip2.encode(&data)).unwrap();
        let index = dir.path().join("prepared.sqlite");
        for existing in [false, true] {
            if existing {
                std::fs::write(&index, b"sentinel existing index").unwrap();
            }
            let before = snapshot(dir.path());
            let error = validate_worker_preparation(&path)
                .expect_err("single block preparation must refuse");
            assert!(
                error.contains("single-block bzip2 cannot be prepared for read-only workers"),
                "{error}"
            );
            assert_eq!(snapshot(dir.path()), before);
        }
    }
}

fn zip_bytes() -> Vec<u8> {
    let mut out = zip::ZipWriter::new(Cursor::new(Vec::new()));
    out.start_file(
        "hello.txt",
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored),
    )
    .unwrap();
    out.write_all(b"worker base").unwrap();
    out.finish().unwrap().into_inner()
}
/// Regression: compressed ZIP's always-building reader route must refuse prepared workers.
#[test]
fn regression_prepared_index_compressed_zip_refuses_rebuild() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("base.zip.gz");
    let index = dir.path().join("prepared.sqlite");
    std::fs::write(&path, Codec::Gzip.encode(&zip_bytes())).unwrap();
    let mut options = OpenOptions {
        index_file_path: Some(index.clone()),
        ..Default::default()
    };
    drop(open_path(&path, &options, true).unwrap());
    SqliteIndex::finalize_prepared(&index).unwrap();
    options.read_only_index = true;
    options.write_index = false;
    let ticks = Arc::new(AtomicUsize::new(0));
    let record = ticks.clone();
    options.index_build.on_progress = Some(Arc::new(move |_| {
        record.fetch_add(1, Ordering::SeqCst);
    }));
    let before = snapshot(dir.path());
    let error = open_path(&path, &options, false)
        .err()
        .expect("must refuse rebuilding reader");
    assert!(error.contains("--no-recreate-index"), "{error}");
    assert_eq!(ticks.load(Ordering::SeqCst), 0);
    assert_eq!(snapshot(dir.path()), before);
}

fn copy_7z() -> Vec<u8> {
    fn crc(bytes: &[u8]) -> u32 {
        let mut c = !0u32;
        for &b in bytes {
            c ^= u32::from(b);
            for _ in 0..8 {
                c = (c >> 1) ^ if c & 1 != 0 { 0xedb88320 } else { 0 };
            }
        }
        !c
    }
    let payload = b"worker base";
    let n = payload.len() as u8;
    let mut header = vec![
        1, 4, 6, 0, 1, 9, n, 0, 7, 11, 1, 0, 1, 1, 0, 12, n, 0, 0, 5, 1, 17, 21, 0,
    ];
    for u in "hello.txt\0".encode_utf16() {
        header.extend(u.to_le_bytes());
    }
    header.extend([0, 0]);
    let mut start = (payload.len() as u64).to_le_bytes().to_vec();
    start.extend((header.len() as u64).to_le_bytes());
    start.extend(crc(&header).to_le_bytes());
    let mut bytes = b"7z\xBC\xAF'\x1C".to_vec();
    bytes.extend([0, 4]);
    bytes.extend(crc(&start).to_le_bytes());
    bytes.extend(start);
    bytes.extend(payload);
    bytes.extend(header);
    bytes
}

/// Regression: detected missing, malformed, stale and mismatched native catalogs must never rebuild.
#[test]
fn regression_prepared_index_factory_refuses_missing_corrupt_and_mismatched() {
    #[allow(unused_mut)]
    let mut archives = vec![
        ("tar", tar_bytes("hello.txt", b"worker base")),
        ("zip", zip_bytes()),
        ("7z", copy_7z()),
    ];
    #[cfg(feature = "ar")]
    archives.push((
        "ar",
        super::tests::synthetic_ar("hello.txt", b"worker base"),
    ));
    #[cfg(feature = "cpio")]
    archives.push((
        "cpio",
        super::tests::build_newc_cpio("hello.txt", b"worker base", 0o100644),
    ));
    for (extension, bytes) in archives {
        for defect in ["missing", "corrupt", "stale", "backend"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(format!("base.{extension}"));
            let index = dir.path().join("prepared.sqlite");
            std::fs::write(&path, bytes.clone()).unwrap();
            let mut options = OpenOptions {
                index_file_path: Some(index.clone()),
                ..Default::default()
            };
            drop(open_path(&path, &options, true).unwrap());
            SqliteIndex::finalize_prepared(&index).unwrap();
            options.read_only_index = true;
            options.write_index = false;
            let source = open_path(&path, &options, false).unwrap();
            assert_eq!(read_member(source.as_ref(), "/hello.txt"), b"worker base");
            drop(source);
            match defect {
                "missing" => std::fs::remove_file(&index).unwrap(),
                "corrupt" => std::fs::write(&index, b"not a SQLite catalog").unwrap(),
                "stale" => {
                    let mut f = std::fs::OpenOptions::new()
                        .append(true)
                        .open(&path)
                        .unwrap();
                    f.write_all(&[0]).unwrap();
                }
                "backend" => {
                    let idx = SqliteIndex::open_writable(&index).unwrap();
                    idx.store_metadata_key_value("backendName", "not-the-selected-backend")
                        .unwrap();
                    drop(idx);
                    SqliteIndex::finalize_prepared(&index).unwrap();
                }
                _ => unreachable!(),
            };
            let ticks = Arc::new(AtomicUsize::new(0));
            let record = ticks.clone();
            options.index_build.on_progress = Some(Arc::new(move |_| {
                record.fetch_add(1, Ordering::SeqCst);
            }));
            let before = snapshot(dir.path());
            let error = open_path(&path, &options, false)
                .err()
                .expect("must refuse");
            assert!(
                error.contains("--no-recreate-index")
                    && error.contains("prepare")
                    && error.contains(index.to_str().unwrap()),
                "{error}"
            );
            assert_eq!(ticks.load(Ordering::SeqCst), 0);
            assert_eq!(snapshot(dir.path()), before, "{extension} {defect}");
        }
    }
}

/// Regression: strict nested reader and materialized private work must never write the outer catalog.
#[test]
fn regression_prepared_index_nested_private_work_keeps_outer_immutable() {
    let dir = tempfile::tempdir().unwrap();
    let inner = tar_bytes("hello.txt", b"private nested");
    let outer = dir.path().join("outer.tar");
    let index = dir.path().join("prepared.sqlite");
    std::fs::write(&outer, tar_bytes("inner.tar", &inner)).unwrap();
    let mut options = OpenOptions {
        index_file_path: Some(index.clone()),
        ..Default::default()
    };
    drop(open_path(&outer, &options, true).unwrap());
    SqliteIndex::finalize_prepared(&index).unwrap();
    options.read_only_index = true;
    options.write_index = false;
    let before = snapshot(dir.path());
    let opener = open_nested_reader_fn(options.clone());
    let source = opener(
        Box::new(Cursor::new(inner.clone())),
        Path::new("inner.tar"),
        NestedOpenContext {
            member_size: inner.len() as u64,
            member_path: "inner.tar".into(),
            outer_index_path: Some(index),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        read_member(source.as_ref(), "/hello.txt"),
        b"private nested"
    );
    assert_eq!(snapshot(dir.path()), before);
    drop(source);
    let private = tempfile::tempdir().unwrap();
    let path = private.path().join("inner.tar");
    std::fs::write(&path, &inner).unwrap();
    let private_before = snapshot(private.path());
    let source = open_nested_fn(options)(&path).unwrap();
    assert_eq!(
        read_member(source.as_ref(), "/hello.txt"),
        b"private nested"
    );
    assert_eq!(snapshot(private.path()), private_before);
    assert_eq!(snapshot(dir.path()), before);
    drop(source);
    assert_eq!(snapshot(dir.path()), before);
}

#[cfg(feature = "exfat")]
/// Regression: a pure image backend has no required external index candidate or finalizer target.
#[test]
fn regression_prepared_index_mixed_tar_and_unindexed_bind_image_control() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image.exfat");
    let index = dir.path().join("unused.sqlite");
    std::fs::write(&path, super::tests::synthetic_exfat_image()).unwrap();
    std::fs::write(&index, b"unrelated candidate").unwrap();
    let options = OpenOptions {
        read_only_index: true,
        write_index: false,
        index_file_path: Some(index),
        ..Default::default()
    };
    let before = snapshot(dir.path());
    let opened = open_path_impl(&path, &options, false, true, &mut false).unwrap();
    assert!(opened.actual_artifact.is_none());
    assert!(opened.index.location.is_memory());
    assert!(opened.index.sidecar_candidate.is_none());
    assert!(!opened.source.list_dirents("/").unwrap().is_empty());
    assert_eq!(snapshot(dir.path()), before);
    drop(opened);
    assert_eq!(snapshot(dir.path()), before);
}

/// Regression: plain xz needs no external catalog and must never finalize an ignored candidate.
#[test]
fn regression_prepared_index_plain_codec_ignores_unused_candidate() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("plain.txt.xz");
    // Fixed xz/LZMA2 fixture, independent of external producer tools.
    let bytes: &[u8] = &[
        253, 55, 122, 88, 90, 0, 0, 4, 230, 214, 180, 70, 2, 0, 33, 1, 22, 0, 0, 0, 116, 47, 229,
        163, 1, 0, 23, 111, 114, 100, 105, 110, 97, 114, 121, 32, 99, 111, 109, 112, 114, 101, 115,
        115, 101, 100, 32, 102, 105, 108, 101, 0, 107, 170, 232, 1, 222, 37, 12, 58, 0, 1, 48, 24,
        142, 27, 172, 236, 31, 182, 243, 125, 1, 0, 0, 0, 0, 4, 89, 90,
    ];
    std::fs::write(&path, bytes).unwrap();
    let index = dir.path().join("unused.sqlite");
    for existing in [false, true] {
        if existing {
            std::fs::write(&index, b"unrelated index candidate").unwrap();
        }
        let before = snapshot(dir.path());
        for strict in [false, true] {
            let mut options = OpenOptions {
                read_only_index: strict,
                write_index: !strict,
                index_file_path: Some(index.clone()),
                ..Default::default()
            };
            let bundle = build_mount_source_with_bindings(
                std::slice::from_ref(&path),
                &mut options,
                false,
                Default::default(),
                Default::default(),
            )
            .unwrap();
            assert!(bundle.prepared_artifacts.is_empty());
            assert_eq!(
                read_member(bundle.source.as_ref(), "/plain.txt"),
                b"ordinary compressed file"
            );
            if strict {
                let served = bundle.served.as_ref().unwrap();
                assert!(matches!(served.index, IndexProvenance::None));
                assert!(served.sidecar_candidate.is_none());
            }
            assert_eq!(snapshot(dir.path()), before);
            drop(bundle);
            assert_eq!(snapshot(dir.path()), before);
        }
    }
}

/// Regression: an index discarded by the configured minimum is not a preparer finalization target.
#[test]
fn regression_prepared_index_discarded_minimum_has_no_artifact() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("small.tar");
    let index = dir.path().join("discarded.sqlite");
    std::fs::write(&path, tar_bytes("member", b"payload")).unwrap();
    let mut options = OpenOptions {
        index_file_path: Some(index.clone()),
        index_minimum_file_count: 2,
        ..Default::default()
    };
    let bundle = build_mount_source_with_bindings(
        &[path],
        &mut options,
        true,
        Default::default(),
        Default::default(),
    )
    .unwrap();
    assert!(!index.exists());
    assert!(bundle.prepared_artifacts.is_empty());
    assert_eq!(read_member(bundle.source.as_ref(), "/member"), b"payload");
}

/// Inventory (#220/#221): the seekable-body materialization tempfile
/// (`materialize_seekable_body_for_path_backends_with_index`) is classified
/// `mode_policy: 0600`; pin the real mode `NamedTempFile::new()` creates.
#[cfg(unix)]
#[test]
fn regression_materialize_tempfile_is_created_0600() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let mode = std::fs::metadata(tmp.path()).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, 0o600, "{mode:o}");
}
