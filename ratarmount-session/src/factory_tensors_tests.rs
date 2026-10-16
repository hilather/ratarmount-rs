use super::*;
use crate::{IndexPolicy, OpenRequest, ReadRequest, Recreate, Session, SourceSpec};
use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};
use std::io::{Cursor, Read};
use std::sync::atomic::{AtomicUsize, Ordering};

const PAYLOAD: &[u8] = b"tensor-range-payload";
const TENSOR_PATH: &str = "/model/layers/0/weight";

fn safetensors_fixture() -> Vec<u8> {
    let header = format!(
        r#"{{"__metadata__":{{"name":"test model"}},"model.layers.0.weight":{{"dtype":"U8","shape":[{}],"data_offsets":[0,{}]}}}}"#,
        PAYLOAD.len(),
        PAYLOAD.len()
    );
    let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
    bytes.extend(header.as_bytes());
    bytes.extend(PAYLOAD);
    bytes
}

fn gguf_fixture() -> Vec<u8> {
    fn string(bytes: &mut Vec<u8>, value: &str) {
        bytes.extend((value.len() as u64).to_le_bytes());
        bytes.extend(value.as_bytes());
    }
    let mut bytes = b"GGUF".to_vec();
    bytes.extend(3u32.to_le_bytes());
    bytes.extend(1u64.to_le_bytes()); // tensor count
    bytes.extend(1u64.to_le_bytes()); // metadata count
    string(&mut bytes, "general.name");
    bytes.extend(8u32.to_le_bytes()); // string
    string(&mut bytes, "test model");
    string(&mut bytes, "model.layers.0.weight");
    bytes.extend(1u32.to_le_bytes()); // dimension count
    bytes.extend((PAYLOAD.len() as u64).to_le_bytes());
    bytes.extend(24u32.to_le_bytes()); // I8
    bytes.extend(0u64.to_le_bytes()); // relative offset
    bytes.resize(bytes.len().next_multiple_of(32), 0);
    bytes.extend(PAYLOAD);
    bytes
}

fn open_session(path: &Path, recursive: bool) -> Result<Session, crate::Error> {
    Session::open(OpenRequest {
        source: SourceSpec::Path(path.to_path_buf()),
        index: IndexPolicy::Memory,
        explicit_index: None,
        extra_dirs: Vec::new(),
        password: None,
        recursive,
        recursion_depth: Some(1),
        recreate: Recreate::IfInvalid,
    })
}

fn read_tensor(source: &dyn MountSource, path: &str) -> Vec<u8> {
    let info = source.lookup(path, 0).expect("tensor lookup");
    let mut reader = source.open(&info, 0).expect("tensor open");
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    bytes
}

fn write_outer_tar(path: &Path, files: &[(&str, &[u8])]) {
    let members: Vec<_> = files
        .iter()
        .map(|&(path, bytes)| UstarMember {
            path,
            payload: UstarPayload::File { bytes },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
        })
        .collect();
    let mut file = std::fs::File::create(path).unwrap();
    write_ustar_members(&mut file, &members).unwrap();
    write_tar_eof(&mut file).unwrap();
}

/// Regression: top-level checkpoint files must select Tensors rather than the single-file fallback.
#[test]
fn tensors_factory_safetensors_and_gguf_read_original_bytes() {
    let dir = tempfile::tempdir().unwrap();
    for (name, bytes) in [
        ("model.safetensors", safetensors_fixture()),
        ("model.gguf", gguf_fixture()),
    ] {
        let path = dir.path().join(name);
        std::fs::write(&path, bytes).unwrap();
        let session = open_session(&path, false).unwrap();
        assert_eq!(read_tensor(session.mount_source(), TENSOR_PATH), PAYLOAD);
        let mut range = session
            .read_range(ReadRequest {
                path: TENSOR_PATH.into(),
                offset: 3,
                max_len: 6,
            })
            .unwrap();
        let mut actual = Vec::new();
        range.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, &PAYLOAD[3..9]);
        let entries = session
            .mount_source()
            .list_dirents("/model/layers/0")
            .unwrap();
        assert!(entries
            .iter()
            .any(|entry| entry.name == "weight" && entry.size == PAYLOAD.len() as u64));
        assert!(entries
            .iter()
            .any(|entry| entry.name == "weight.json" && entry.size > 0));
    }
}

/// Regression: safetensors headers must be detected without a filename suffix.
#[test]
fn tensors_factory_extensionless_safetensors_detected() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("checkpoint");
    std::fs::write(&path, safetensors_fixture()).unwrap();
    let session = open_session(&path, false).unwrap();
    assert_eq!(read_tensor(session.mount_source(), TENSOR_PATH), PAYLOAD);
}

/// Regression: `recursive` must discover tensor suffixes in TAR without requiring a custom extension selection.
#[test]
fn nested_tensors_inside_tar_recursive_reads_original_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let outer = dir.path().join("outer.tar");
    for (name, bytes) in [
        ("model.safetensors", safetensors_fixture()),
        ("model.gguf", gguf_fixture()),
    ] {
        write_outer_tar(&outer, &[(name, &bytes)]);
        let session = open_session(&outer, true).unwrap();
        assert_eq!(
            read_tensor(session.mount_source(), &format!("/{name}{TENSOR_PATH}")),
            PAYLOAD
        );
    }
}

/// Regression: nested tensor mounts must use the real reader dispatcher; path spool is forbidden.
#[test]
fn nested_tensors_inside_tar_reader_opener_never_spools() {
    let dir = tempfile::tempdir().unwrap();
    let outer = dir.path().join("outer.tar");
    for (name, bytes) in [
        ("model.safetensors", safetensors_fixture()),
        ("model.gguf", gguf_fixture()),
    ] {
        write_outer_tar(&outer, &[(name, &bytes)]);
        let options = OpenOptions {
            index_in_memory: true,
            recursive: true,
            ..OpenOptions::default()
        };
        let source = open_path(&outer, &options, false).unwrap();
        let reader_opener = open_nested_reader_fn(options);
        let reader_calls = Arc::new(AtomicUsize::new(0));
        let calls = Arc::clone(&reader_calls);
        let checked_reader: OpenNestedReaderFn = Arc::new(move |reader, label, context| {
            let source = reader_opener(reader, label, context)?;
            calls.fetch_add(1, Ordering::SeqCst);
            Ok(source)
        });
        let forbidden_path: OpenNestedFn =
            Arc::new(|path| panic!("tensor archive spooled to {}", path.display()));
        let layer = AutoMountLayer::new_with_openers(
            source,
            1,
            forbidden_path,
            Some(checked_reader),
            AutoMountOptions {
                recursive_extensions: parse_recursive_extensions(".safetensors,.gguf"),
                ..AutoMountOptions::default()
            },
        );
        assert_eq!(
            read_tensor(&layer, &format!("/{name}{TENSOR_PATH}")),
            PAYLOAD
        );
        assert_eq!(reader_calls.load(Ordering::SeqCst), 1);
    }
}

fn assert_parallel_nested_members_never_spool(
    members: &[(String, Vec<u8>, Vec<u8>)],
    inner_path: &str,
) {
    let dir = tempfile::tempdir().unwrap();
    let outer = dir.path().join("outer.tar");
    let files: Vec<_> = members
        .iter()
        .map(|(name, bytes, _)| (name.as_str(), bytes.as_slice()))
        .collect();
    write_outer_tar(&outer, &files);
    for _ in 0..32 {
        // All four members use the real reader dispatcher through
        // AutoMount's eager parallel path.
        let options = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let source = open_path(&outer, &options, false).unwrap();
        let opener = open_nested_reader_fn(options);
        let calls = Arc::new(AtomicUsize::new(0));
        let reader_calls = Arc::clone(&calls);
        let barrier = std::sync::Barrier::new(members.len());
        let checked_reader: OpenNestedReaderFn = Arc::new(move |reader, label, context| {
            barrier.wait();
            let source = opener(reader, label, context)?;
            reader_calls.fetch_add(1, Ordering::SeqCst);
            Ok(source)
        });
        let forbidden_path: OpenNestedFn =
            Arc::new(|path| panic!("parallel nested open spooled to {}", path.display()));
        let layer = AutoMountLayer::new_with_openers(
            source,
            1,
            forbidden_path,
            Some(checked_reader),
            AutoMountOptions {
                recursive_extensions: parse_recursive_extensions(".safetensors,.gguf,.ar"),
                parallel_nested_threads: members.len() as u32,
                ..AutoMountOptions::default()
            },
        );
        assert_eq!(calls.load(Ordering::SeqCst), members.len());
        std::thread::scope(|scope| {
            for (name, _, expected) in members {
                let layer = &layer;
                scope.spawn(move || {
                    for _ in 0..32 {
                        assert_eq!(
                            read_tensor(layer, &format!("/{name}{inner_path}")),
                            *expected
                        );
                    }
                });
            }
        });
    }
}

/// Regression: parallel safetensors/GGUF opens in one TAR failed probes or read sibling bytes.
#[test]
fn regression_parallel_nested_tensors_correct_bytes_without_spool() {
    let members: Vec<_> = (0..4)
        .map(|i| {
            let (suffix, mut bytes) = if i % 2 == 0 {
                ("safetensors", safetensors_fixture())
            } else {
                ("gguf", gguf_fixture())
            };
            let payload = vec![b'A' + i; PAYLOAD.len()];
            let start = bytes.len() - payload.len();
            bytes[start..].copy_from_slice(&payload);
            (format!("model-{i}.{suffix}"), bytes, payload)
        })
        .collect();
    assert_parallel_nested_members_never_spool(&members, TENSOR_PATH);
}

/// Regression: shared parent seek interference also corrupted parallel nested AR opens.
#[cfg(feature = "ar")]
#[test]
fn regression_parallel_nested_ar_correct_bytes_without_spool() {
    let members: Vec<_> = (0..4)
        .map(|i| {
            let payload = vec![b'A' + i; 4096];
            let mut bytes = b"!<arch>\n".to_vec();
            bytes.extend_from_slice(
                format!(
                    "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                    "payload/",
                    0,
                    0,
                    0,
                    "100644",
                    payload.len()
                )
                .as_bytes(),
            );
            bytes.extend_from_slice(&payload);
            (format!("inner-{i}.ar"), bytes, payload)
        })
        .collect();
    assert_parallel_nested_members_never_spool(&members, "/payload");
}

/// Regression: reader dispatch must recognize extensionless tensors without requiring a host path.
#[test]
fn nested_tensors_extensionless_from_cursor_via_opener() {
    let opener = open_nested_reader_fn(OpenOptions::default());
    for bytes in [safetensors_fixture(), gguf_fixture()] {
        let source = opener(
            Box::new(Cursor::new(bytes)),
            Path::new("/missing-parent/checkpoint"),
            NestedOpenContext::default(),
        )
        .expect("nested tensors must open from their original reader");
        assert_eq!(read_tensor(source.as_ref(), TENSOR_PATH), PAYLOAD);
    }
}

/// Regression: adding tensor defaults must preserve explicit recursive suffix restrictions.
#[test]
fn nested_tensors_respect_explicit_recursive_extensions() {
    let dir = tempfile::tempdir().unwrap();
    let outer = dir.path().join("outer.tar");
    write_outer_tar(
        &outer,
        &[
            ("model.safetensors", &safetensors_fixture()),
            ("model.gguf", &gguf_fixture()),
        ],
    );
    for selection in [None, Some("/archive"), Some("/all"), Some(".tar")] {
        let mut options = OpenOptions {
            index_in_memory: true,
            recursive: true,
            ..OpenOptions::default()
        };
        let bundle = build_mount_source_ex(
            std::slice::from_ref(&outer),
            &mut options,
            false,
            CompositingOptions {
                recursive: true,
                recursive_extensions: selection.map(str::to_string),
                parallel_nested_threads: 1,
                ..CompositingOptions::default()
            },
        )
        .unwrap();
        for name in ["model.safetensors", "model.gguf"] {
            let tensor = bundle.source.lookup(&format!("/{name}{TENSOR_PATH}"), 0);
            assert_eq!(
                tensor.is_some(),
                selection != Some(".tar"),
                "selection {selection:?}"
            );
        }
    }
}

/// Regression: claimed tensor formats must return parser diagnostics for malformed headers, while unrelated data falls through.
#[test]
fn tensors_factory_malformed_headers_report_clear_errors() {
    let dir = tempfile::tempdir().unwrap();
    let options = OpenOptions {
        index_in_memory: true,
        ..OpenOptions::default()
    };
    for (name, bytes, expected) in [
        (
            "bad.safetensors",
            (ratarmount_formats_tensors::MAX_HEADER_SIZE + 1)
                .to_le_bytes()
                .to_vec(),
            "header too large",
        ),
        (
            "bad.gguf",
            [b"GGUF".as_slice(), &1u32.to_le_bytes(), &[0; 16]].concat(),
            "unsupported GGUF version",
        ),
    ] {
        let path = dir.path().join(name);
        std::fs::write(&path, &bytes).unwrap();
        let error = open_session(&path, false)
            .err()
            .expect("malformed tensor format must fail")
            .to_string();
        assert!(error.contains(expected), "{error}");
        let opener = open_nested_reader_fn(options.clone());
        let error = opener(
            Box::new(Cursor::new(bytes)),
            Path::new(name),
            NestedOpenContext::default(),
        )
        .err()
        .expect("malformed nested tensor format must fail")
        .to_string();
        assert!(error.contains(expected), "{error}");
    }
    let unrelated = dir.path().join("plain.txt");
    std::fs::write(&unrelated, b"ordinary data").unwrap();
    assert!(
        try_open_format_backend(&unrelated, FormatBackend::Tensors, None, &options, false)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        read_tensor(
            open_path(&unrelated, &options, false).unwrap().as_ref(),
            "/plain.txt"
        ),
        b"ordinary data"
    );
}

/// Regression: each --use-backend alias must prioritize Tensors once and still open either tensor format.
#[test]
fn tensors_ordered_format_backends_aliases_select_tensors_once() {
    let dir = tempfile::tempdir().unwrap();
    for alias in ["safetensors", "gguf", "tensors", "tensorsmountsource"] {
        assert_eq!(parse_format_backend(alias), Some(FormatBackend::Tensors));
        let order = ordered_format_backends(&[alias.into()]);
        assert_eq!(order[0], FormatBackend::Tensors);
        assert_eq!(
            order
                .iter()
                .filter(|&&b| b == FormatBackend::Tensors)
                .count(),
            1
        );
        for (name, bytes) in [
            ("model.safetensors", safetensors_fixture()),
            ("model.gguf", gguf_fixture()),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            let options = OpenOptions {
                index_in_memory: true,
                use_backends: vec![alias.into()],
                ..OpenOptions::default()
            };
            let source = open_path(&path, &options, false).unwrap();
            assert_eq!(read_tensor(source.as_ref(), TENSOR_PATH), PAYLOAD);
        }
    }
}
