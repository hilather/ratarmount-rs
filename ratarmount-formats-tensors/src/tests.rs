use super::*;
use std::io::Write;
use std::sync::atomic::{AtomicUsize, Ordering};

fn safetensors(header: Value, data: &[u8]) -> Vec<u8> {
    let header = serde_json::to_vec(&header).unwrap();
    let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
    bytes.extend(header);
    bytes.extend(data);
    bytes
}

fn tensor(dtype: &str, shape: &[u64], begin: u64, end: u64) -> Value {
    json!({"dtype":dtype,"shape":shape,"data_offsets":[begin,end]})
}

fn mount(bytes: Vec<u8>) -> Result<TensorsMountSource> {
    TensorsMountSource::open_from_reader(
        Cursor::new(bytes),
        "virtual/weights",
        None,
        &OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        },
        "test",
    )
}

fn read(src: &TensorsMountSource, path: &str) -> Vec<u8> {
    let info = src
        .lookup(path, 0)
        .unwrap_or_else(|| panic!("missing {path}"));
    let mut bytes = Vec::new();
    MountSource::open(src, &info, 0)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes.len() as u64, info.size);
    bytes
}

fn sidecar(src: &TensorsMountSource, path: &str) -> Value {
    serde_json::from_slice(&read(src, path)).unwrap()
}

fn assert_error(bytes: Vec<u8>, message: &str) {
    let err = mount(bytes).err().expect("must reject fixture").to_string();
    assert!(err.contains(message), "expected {message:?}: {err}");
}

/// Regression: tensors must expose their original bytes and correct absolute offsets.
#[test]
fn safetensors_list_read_sidecars_metadata() {
    let header = json!({"__metadata__":{"training":"finetune"},
        "model.layers.12.mlp.down_proj.weight":tensor("F32",&[2],0,8),
        "bias":tensor("U8",&[3],8,11), "empty":tensor("F32",&[0,u64::MAX],11,11),
        "scalar":tensor("I8",&[],11,12)});
    let bytes = safetensors(header.clone(), b"abcdefghijkl");
    let start = 8 + u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let src = mount(bytes).unwrap();
    assert_eq!(
        read(&src, "/model/layers/12/mlp/down_proj/weight"),
        b"abcdefgh"
    );
    assert_eq!(read(&src, "/bias"), b"ijk");
    assert_eq!(read(&src, "/empty"), b"");
    assert_eq!(read(&src, "/scalar"), b"l");
    assert_eq!(sidecar(&src, "/__metadata__.json"), header["__metadata__"]);
    assert_eq!(sidecar(&src, "/__header__.json"), header);
    let s = sidecar(&src, "/model/layers/12/mlp/down_proj/weight.json");
    assert_eq!(s["dtype"], "F32");
    assert_eq!(s["shape"], json!([2]));
    assert_eq!(s["data_offsets"], json!([0, 8]));
    assert_eq!(s["byte_length"], 8);
    assert_eq!(s["absolute_file_offset"], start);
    assert_eq!(s["size_check"], "validated");
    assert_eq!(s["overlapping"], false);
    assert!(
        matches!(src.list("/model/layers/12/mlp/down_proj"), Some(ListResult::Infos(m)) if m.len() == 2)
    );
}

/// Regression: a tensor leaf/prefix, sidecar-like name or escaped slash must not hide another tensor.
#[test]
fn collision_naming_preserves_every_tensor_and_sidecar() {
    let names = [
        "a.b",
        "a.b.c",
        "a.b.tensor",
        "a.b.json",
        "a/b",
        "a%2Fb",
        ".",
        "",
        "%EMPTY",
        "__metadata__.json",
        "__header__.json",
        "雪.\0",
    ];
    let mut header = serde_json::Map::new();
    for (i, name) in names.iter().enumerate() {
        header.insert(name.to_string(), tensor("U8", &[1], i as u64, i as u64 + 1));
    }
    let src = mount(safetensors(
        Value::Object(header),
        &(0..names.len() as u8).collect::<Vec<_>>(),
    ))
    .unwrap();
    let paths = [
        "a/b.tensor",
        "a/b/c",
        "a/b/tensor",
        "a/b/json",
        "a%2Fb",
        "a%252Fb",
        "%EMPTY/%EMPTY",
        "%EMPTY.tensor",
        "%25EMPTY",
        "%5F_metadata__/json",
        "%5F_header__/json",
        "%E9%9B%AA/%00",
    ];
    for (i, path) in paths.iter().enumerate() {
        assert_eq!(read(&src, &format!("/{path}")), vec![i as u8]);
        assert_eq!(sidecar(&src, &format!("/{path}.json"))["name"], names[i]);
    }
    assert_eq!(sidecar(&src, "/__metadata__.json"), json!({}));
}

/// Regression: malformed lengths, UTF-8, ranges and shape arithmetic must fail closed.
#[test]
fn safetensors_rejects_oversized_truncated_and_invalid_ranges() {
    assert_error(
        (MAX_HEADER_SIZE + 1).to_le_bytes().to_vec(),
        "header too large",
    );
    assert!(mount(vec![0; 3]).is_err());
    assert_error(
        [100u64.to_le_bytes().as_slice(), b"{}"].concat(),
        "truncated",
    );
    assert!(mount([2u64.to_le_bytes().as_slice(), &[b'{', 255]].concat()).is_err());
    assert!(mount([2u64.to_le_bytes().as_slice(), b"[]"].concat()).is_err());
    for (begin, end) in [(2, 1), (0, 3), (u64::MAX, u64::MAX)] {
        assert_error(
            safetensors(json!({"bad":tensor("U8",&[1],begin,end)}), b"ab"),
            "offsets out of range",
        );
    }
    assert_error(
        safetensors(json!({"bad":tensor("F32",&[2],0,4)}), b"abcd"),
        "size mismatch",
    );
    assert_error(
        safetensors(json!({"bad":tensor("F32",&[u64::MAX,2],0,0)}), b""),
        "overflow",
    );
    assert_error(
        safetensors(json!({"bad":tensor("F64",&[u64::MAX],0,0)}), b""),
        "overflow",
    );
    assert_error(
        safetensors(json!({"__metadata__":{"bad":7}}), b""),
        "expected a string",
    );
    let good = safetensors(json!({"a":tensor("U8",&[2],0,2)}), b"ab");
    for len in 0..good.len() {
        assert!(
            mount(good[..len].to_vec()).is_err(),
            "accepted truncated length {len}"
        );
    }
}

/// Regression: future dtypes and overlapping ranges remain readable and explicitly annotated.
#[test]
fn safetensors_unknown_dtype_and_overlap_noted() {
    let src = mount(safetensors(
        json!({"a":tensor("FUTURE",&[200],0,4),
        "b":tensor("U8",&[2],1,3),"c":tensor("U8",&[1],2,3),"empty":tensor("U8",&[0],2,2)}),
        b"abcd",
    ))
    .unwrap();
    assert_eq!(read(&src, "/a"), b"abcd");
    assert_eq!(
        sidecar(&src, "/a.json")["size_check"],
        "skipped_unknown_dtype"
    );
    for p in ["a", "b", "c"] {
        assert_eq!(sidecar(&src, &format!("/{p}.json"))["overlapping"], true);
    }
    assert_eq!(sidecar(&src, "/empty.json")["overlapping"], false);
}

/// Regression: packed and newly specified safetensors dtypes need bit-accurate sizes.
#[test]
fn safetensors_all_known_dtype_sizes() {
    let types = [
        ("BOOL", 8),
        ("F4", 4),
        ("F6_E2M3", 6),
        ("F6_E3M2", 6),
        ("U8", 8),
        ("I8", 8),
        ("F8_E5M2", 8),
        ("F8_E4M3", 8),
        ("F8_E8M0", 8),
        ("F8_E4M3FNUZ", 8),
        ("F8_E5M2FNUZ", 8),
        ("I16", 16),
        ("U16", 16),
        ("F16", 16),
        ("BF16", 16),
        ("I32", 32),
        ("U32", 32),
        ("F32", 32),
        ("I64", 64),
        ("U64", 64),
        ("F64", 64),
        ("C64", 64),
    ];
    for (dtype, bits) in types {
        assert_eq!(safetensors::dtype_bits(dtype), Some(bits));
        let data = vec![7; bits as usize];
        let src = mount(safetensors(json!({"a":tensor(dtype,&[8],0,bits)}), &data)).unwrap();
        assert_eq!(read(&src, "/a"), data);
    }
    assert_error(
        safetensors(json!({"a":tensor("F4",&[1],0,1)}), b"x"),
        "size mismatch",
    );
}

fn string(out: &mut Vec<u8>, value: &str) {
    out.extend((value.len() as u64).to_le_bytes());
    out.extend(value.as_bytes());
}
fn kv(name: &str, ty: u32, value: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    string(&mut out, name);
    out.extend(ty.to_le_bytes());
    out.extend(value);
    out
}
fn string_value(value: &str) -> Vec<u8> {
    let mut out = Vec::new();
    string(&mut out, value);
    out
}
fn array(ty: u32, count: u64, values: &[u8]) -> Vec<u8> {
    let mut out = ty.to_le_bytes().to_vec();
    out.extend(count.to_le_bytes());
    out.extend(values);
    out
}
struct GgTensor<'a> {
    name: &'a str,
    dims: &'a [u64],
    ty: u32,
    offset: u64,
    bytes: Vec<u8>,
}
fn gguf(
    version: u32,
    metadata: Vec<Vec<u8>>,
    alignment: usize,
    tensors: &[GgTensor<'_>],
) -> Vec<u8> {
    let mut out = b"GGUF".to_vec();
    out.extend(version.to_le_bytes());
    out.extend((tensors.len() as u64).to_le_bytes());
    out.extend((metadata.len() as u64).to_le_bytes());
    for kv in metadata {
        out.extend(kv);
    }
    for t in tensors {
        string(&mut out, t.name);
        out.extend((t.dims.len() as u32).to_le_bytes());
        for d in t.dims {
            out.extend(d.to_le_bytes());
        }
        out.extend(t.ty.to_le_bytes());
        out.extend(t.offset.to_le_bytes());
    }
    let start = out.len().next_multiple_of(alignment);
    out.resize(start, 0);
    for t in tensors {
        let begin = start + t.offset as usize;
        out.resize(out.len().max(begin + t.bytes.len()), 0);
        out[begin..begin + t.bytes.len()].copy_from_slice(&t.bytes);
    }
    out
}

/// Regression: every GGUF KV tag, arrays, alignment and both supported versions must round trip.
#[test]
fn gguf_v2_v3_kv_types_alignment_list_and_read() {
    let metadata = vec![
        kv("u8", 0, vec![255]),
        kv("i8", 1, vec![254]),
        kv("u16", 2, 65535u16.to_le_bytes().to_vec()),
        kv("i16", 3, (-300i16).to_le_bytes().to_vec()),
        kv("u32", 4, u32::MAX.to_le_bytes().to_vec()),
        kv("i32", 5, (-70000i32).to_le_bytes().to_vec()),
        kv("f32", 6, 1.5f32.to_le_bytes().to_vec()),
        kv("bool", 7, vec![1]),
        kv("string", 8, string_value("hello 雪")),
        kv(
            "array",
            9,
            array(8, 2, &[string_value("one"), string_value("two")].concat()),
        ),
        kv("u64", 10, u64::MAX.to_le_bytes().to_vec()),
        kv("i64", 11, i64::MIN.to_le_bytes().to_vec()),
        kv("f64", 12, (-2.5f64).to_le_bytes().to_vec()),
        kv("general.alignment", 4, 64u32.to_le_bytes().to_vec()),
    ];
    let tensors = [
        GgTensor {
            name: "blk.12.ffn_down.weight",
            dims: &[2, 2],
            ty: 0,
            offset: 64,
            bytes: (0..16).collect(),
        },
        GgTensor {
            name: "bias",
            dims: &[2],
            ty: 1,
            offset: 0,
            bytes: vec![50, 51, 52, 53],
        },
    ];
    for version in [2, 3] {
        let bytes = gguf(version, metadata.clone(), 64, &tensors);
        let src = mount(bytes.clone()).unwrap();
        assert_eq!(read(&src, "/blk/12/ffn_down/weight"), tensors[0].bytes);
        assert_eq!(read(&src, "/bias"), tensors[1].bytes);
        let s = sidecar(&src, "/blk/12/ffn_down/weight.json");
        let absolute = s["absolute_file_offset"].as_u64().unwrap() as usize;
        assert_eq!(absolute % 64, 0);
        assert_eq!(s["data_offset"], 64);
        assert_eq!(s["byte_length"], 16);
        assert_eq!(s["ggml_type_name"], "F32");
        assert_eq!(s["dims"], json!([2, 2]));
        assert_eq!(s["version"], version);
        assert_eq!(bytes[absolute..absolute + 16], tensors[0].bytes);
        let m = sidecar(&src, "/__metadata__.json");
        assert_eq!(
            m,
            json!({"u8":255,"i8":-2,"u16":65535,"i16":-300,"u32":u32::MAX,"i32":-70000,
            "f32":1.5,"bool":true,"string":"hello 雪","array":["one","two"],"u64":u64::MAX,
            "i64":i64::MIN,"f64":-2.5,"general.alignment":64})
        );
    }
}

/// Regression: all known GGML block layouts must exclude alignment padding from tensor files.
#[test]
fn gguf_quantized_block_sizes_and_unknown_extent() {
    let layouts = [
        (0, 1, 4),
        (1, 1, 2),
        (2, 32, 18),
        (3, 32, 20),
        (6, 32, 22),
        (7, 32, 24),
        (8, 32, 34),
        (9, 32, 36),
        (10, 256, 84),
        (11, 256, 110),
        (12, 256, 144),
        (13, 256, 176),
        (14, 256, 210),
        (15, 256, 292),
        (16, 256, 66),
        (17, 256, 74),
        (18, 256, 98),
        (19, 256, 50),
        (20, 32, 18),
        (21, 256, 110),
        (22, 256, 82),
        (23, 256, 136),
        (24, 1, 1),
        (25, 1, 2),
        (26, 1, 4),
        (27, 1, 8),
        (28, 1, 8),
        (29, 256, 56),
        (30, 1, 2),
        (34, 256, 54),
        (35, 256, 66),
        (39, 32, 17),
        (40, 64, 36),
        (41, 128, 18),
        (42, 64, 18),
    ];
    for (ty, block, size) in layouts {
        let bytes: Vec<u8> = (0..size * 4).map(|i| i as u8).collect();
        let dims = [block * 2, 2];
        let fixture = gguf(
            3,
            vec![],
            32,
            &[GgTensor {
                name: "quant",
                dims: &dims,
                ty,
                offset: 0,
                bytes: bytes.clone(),
            }],
        );
        let src = mount(fixture).unwrap();
        assert_eq!(read(&src, "/quant"), bytes, "type {ty}");
        assert_eq!(sidecar(&src, "/quant.json")["byte_length"], size * 4);
    }
    // Tensor infos deliberately out of offset order; unknown last tensor uses EOF.
    let fixture = gguf(
        3,
        vec![],
        32,
        &[
            GgTensor {
                name: "last",
                dims: &[1],
                ty: 999,
                offset: 64,
                bytes: vec![9; 5],
            },
            GgTensor {
                name: "first",
                dims: &[1],
                ty: 998,
                offset: 0,
                bytes: vec![7; 32],
            },
            GgTensor {
                name: "middle",
                dims: &[1],
                ty: 0,
                offset: 32,
                bytes: vec![8; 4],
            },
        ],
    );
    let src = mount(fixture).unwrap();
    assert_eq!(read(&src, "/first"), vec![7; 32]);
    assert_eq!(read(&src, "/last"), vec![9; 5]);
    assert_eq!(
        sidecar(&src, "/first.json")["size_source"],
        "next_offset_or_data_end"
    );
}

/// Regression: hostile GGUF versions, counts, strings, alignment and truncated tensors fail closed.
#[test]
fn gguf_rejects_big_endian_truncated_and_malformed_headers() {
    assert_error(
        [b"GGUF".as_slice(), &3u32.to_be_bytes(), &[0; 16]].concat(),
        "big-endian",
    );
    assert_error([b"FUGG".as_slice(), &[0; 20]].concat(), "big-endian");
    assert_error(gguf(1, vec![], 32, &[]), "unsupported GGUF version");
    let good = gguf(
        3,
        vec![kv("x", 8, string_value("text"))],
        32,
        &[GgTensor {
            name: "x",
            dims: &[2],
            ty: 0,
            offset: 0,
            bytes: vec![3; 8],
        }],
    );
    for len in 0..good.len() {
        assert!(
            mount(good[..len].to_vec()).is_err(),
            "accepted truncated length {len}"
        );
    }
    let mut huge = b"GGUF".to_vec();
    huge.extend(3u32.to_le_bytes());
    huge.extend(u64::MAX.to_le_bytes());
    huge.extend(0u64.to_le_bytes());
    assert_error(huge, "counts exceed");
    assert_error(
        gguf(
            3,
            vec![kv("x", 8, u64::MAX.to_le_bytes().to_vec())],
            32,
            &[],
        ),
        "overflow",
    );
    assert_error(gguf(3, vec![kv("x", 7, vec![2])], 32, &[]), "boolean");
    assert_error(
        gguf(3, vec![kv("x", 13, vec![])], 32, &[]),
        "unknown GGUF metadata",
    );
    assert_error(
        gguf(3, vec![kv("x", 9, array(99, 0, &[]))], 32, &[]),
        "unknown GGUF array",
    );
    assert_error(
        gguf(3, vec![kv("x", 9, array(0, u64::MAX, &[]))], 32, &[]),
        "array length",
    );
    for alignment in [0u32, 3, u32::MAX] {
        assert_error(
            gguf(
                3,
                vec![kv("general.alignment", 4, alignment.to_le_bytes().to_vec())],
                32,
                &[],
            ),
            "alignment",
        );
    }
    for (dims, ty, offset, msg) in [
        (&[31][..], 2, 0, "quantization block"),
        (&[1][..], 0, 1, "alignment"),
        (&[][..], 0, 0, "n_dims"),
        (&[0][..], 0, 0, "positive"),
        (&[u64::MAX, 2][..], 0, 0, "overflow"),
    ] {
        assert_error(
            gguf(
                3,
                vec![],
                32,
                &[GgTensor {
                    name: "x",
                    dims,
                    ty,
                    offset,
                    bytes: vec![0; 32],
                }],
            ),
            msg,
        );
    }
    let mut offset_oob = good.clone();
    // Last u64 of tensor-info is the relative offset, before alignment padding.
    let offset_pos = 24 + 8 + 1 + 4 + 8 + 4 + 8 + 1 + 4 + 8 + 4;
    offset_oob[offset_pos..offset_pos + 8].copy_from_slice(&4096u64.to_le_bytes());
    assert_error(offset_oob, "offset out of range");
    let duplicate = gguf(3, vec![kv("x", 0, vec![1]), kv("x", 0, vec![2])], 32, &[]);
    assert_error(duplicate, "duplicate GGUF metadata");
}

/// Regression: large tokenizer arrays remain bounded, but malformed discarded entries still fail.
#[test]
fn gguf_large_arrays_summary_and_nonfinite_values() {
    let count = gguf::ARRAY_SUMMARY_THRESHOLD + 1;
    let values: Vec<_> = (0..count).flat_map(|i| (i as u32).to_le_bytes()).collect();
    let src = mount(gguf(
        3,
        vec![
            kv("tokens", 9, array(4, count, &values)),
            kv("nan", 12, f64::NAN.to_le_bytes().to_vec()),
            kv("inf", 6, f32::INFINITY.to_le_bytes().to_vec()),
            kv("negative_inf", 12, f64::NEG_INFINITY.to_le_bytes().to_vec()),
        ],
        32,
        &[],
    ))
    .unwrap();
    let m = sidecar(&src, "/__metadata__.json");
    assert_eq!(m["tokens"]["length"], count);
    assert_eq!(m["tokens"]["element_type"], 4);
    assert_eq!(m["tokens"]["preview"], json!((0..16).collect::<Vec<_>>()));
    assert_eq!(m["nan"], "NaN");
    assert_eq!(m["inf"], "Infinity");
    assert_eq!(m["negative_inf"], "-Infinity");
    let mut bools = vec![0; count as usize];
    bools[count as usize - 1] = 2;
    assert_error(
        gguf(3, vec![kv("invalid", 9, array(7, count, &bools))], 32, &[]),
        "boolean",
    );
    let mut nested = array(0, 0, &[]);
    for _ in 0..18 {
        nested = array(9, 1, &nested);
    }
    assert_error(
        gguf(3, vec![kv("nested", 9, nested)], 32, &[]),
        "nesting too deep",
    );
}

/// Regression: cheap readdir must carry tensor and generated JSON sizes in SQLite and compact mode.
#[test]
fn list_dirents_sizes_match_lookup_without_fat_list() {
    for compact in [false, true] {
        let src = TensorsMountSource::open_from_reader(
            Cursor::new(safetensors(
                json!({"layer.w":tensor("U8",&[4],0,4)}),
                b"abcd",
            )),
            "nested",
            None,
            &OpenOptions {
                index_compact_only: compact,
                index_in_memory: !compact,
                ..OpenOptions::default()
            },
            "test",
        )
        .unwrap();
        for path in ["/", "/layer"] {
            for entry in src.list_dirents(path).unwrap() {
                let full = format!("{}/{}", path.trim_end_matches('/'), entry.name);
                assert_eq!(entry.size, src.lookup(&full, 0).unwrap().size);
            }
        }
        assert_eq!(read(&src, "/layer/w"), b"abcd");
        assert_eq!(sidecar(&src, "/layer/w.json")["dtype"], "U8");
        assert!(src.search_cheap("*").is_some());
        assert!(src.search_cheap("fts:weight").is_none());
    }
}

struct CountedReader {
    inner: Cursor<Vec<u8>>,
    bytes: Arc<AtomicUsize>,
}
impl Read for CountedReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes.fetch_add(n, Ordering::Relaxed);
        Ok(n)
    }
}
impl Seek for CountedReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

/// Regression: indexing reads headers only; independent concurrent range handles must never share a cursor.
#[test]
fn nested_open_reads_no_payload_and_concurrent_handles_are_independent() {
    let data: Vec<_> = (0..65536).map(|i| i as u8).collect();
    let fixture = safetensors(
        json!({"a":tensor("U8",&[32768],0,32768),"b":tensor("U8",&[32768],32768,65536)}),
        &data,
    );
    let header_len = fixture.len() - data.len();
    let bytes = Arc::new(AtomicUsize::new(0));
    let src = Arc::new(
        TensorsMountSource::open_from_reader(
            CountedReader {
                inner: Cursor::new(fixture),
                bytes: bytes.clone(),
            },
            "missing-parent/nested.safetensors",
            None,
            &OpenOptions::default(),
            "test",
        )
        .unwrap(),
    );
    assert!(bytes.load(Ordering::Relaxed) <= header_len + 4);
    let threads: Vec<_> = ["/a", "/b"]
        .into_iter()
        .map(|path| {
            let src = Arc::clone(&src);
            std::thread::spawn(move || {
                let fi = src.lookup(path, 0).unwrap();
                let mut reader = MountSource::open(&*src, &fi, 0).unwrap();
                for i in (0..32768).step_by(127) {
                    reader.seek(SeekFrom::Start(i)).unwrap();
                    let mut byte = [0];
                    reader.read_exact(&mut byte).unwrap();
                    assert_eq!(byte[0], i as u8);
                }
                assert_eq!(reader.seek(SeekFrom::End(-1)).unwrap(), 32767);
                let mut byte = [0];
                reader.read_exact(&mut byte).unwrap();
                assert_eq!(byte[0], 255);
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
}

/// Regression: a warm index must retain generated files, reject tarstats changes, and rebuild after replacement.
#[test]
fn warm_index_tarstats_rebuilds_replaced_archive() {
    for gg in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join(if gg { "test.gguf" } else { "test.safetensors" });
        let index = dir.path().join("index.sqlite");
        let fixture = |data: &[u8]| {
            if gg {
                gguf(
                    3,
                    vec![],
                    32,
                    &[GgTensor {
                        name: "a",
                        dims: &[data.len() as u64],
                        ty: 24,
                        offset: 0,
                        bytes: data.to_vec(),
                    }],
                )
            } else {
                safetensors(
                    json!({"a":tensor("U8",&[data.len() as u64],0,data.len() as u64)}),
                    data,
                )
            }
        };
        std::fs::write(&path, fixture(b"abc")).unwrap();
        let opts = OpenOptions::default();
        let src = TensorsMountSource::open(&path, Some(&index), &opts, "test", true).unwrap();
        assert_eq!(read(&src, "/a"), b"abc");
        drop(src);
        let metadata_before = std::fs::read(&index).unwrap();
        let src = TensorsMountSource::open(&path, Some(&index), &opts, "test", false).unwrap();
        assert_eq!(read(&src, "/a"), b"abc");
        assert_eq!(sidecar(&src, "/a.json")["byte_length"], 3);
        drop(src);
        assert_eq!(std::fs::read(&index).unwrap(), metadata_before);
        std::fs::write(&path, fixture(b"longer")).unwrap();
        assert!(TensorsMountSource::existing(&index)
            .unwrap()
            .check_tarstats_matches_archive(&path)
            .is_err());
        let src = TensorsMountSource::open(&path, Some(&index), &opts, "test", false).unwrap();
        assert_eq!(read(&src, "/a"), b"longer");
        assert_eq!(sidecar(&src, "/a.json")["byte_length"], 6);
    }
}

/// Regression: a virtual label must not be treated as a host path; explicit nested indexes must reuse and revalidate.
#[test]
fn nested_reader_index_path_reuses_and_rebuilds_after_replacement() {
    let dir = tempfile::tempdir().unwrap();
    let index = dir.path().join("nested.sqlite");
    let fixture = |data: &[u8]| {
        safetensors(
            json!({"a":tensor("U8",&[data.len() as u64],0,data.len() as u64)}),
            data,
        )
    };
    let open = |data: &[u8]| {
        TensorsMountSource::open_from_reader(
            Cursor::new(fixture(data)),
            "/not/a/host/path",
            Some(&index),
            &OpenOptions::default(),
            "test",
        )
        .unwrap()
    };
    let src = open(b"abc");
    assert_eq!(read(&src, "/a"), b"abc");
    drop(src);
    let before = std::fs::read(&index).unwrap();
    let src = open(b"abc");
    assert_eq!(read(&src, "/a"), b"abc");
    drop(src);
    assert_eq!(std::fs::read(&index).unwrap(), before);
    let src = open(b"xyz");
    assert_ne!(std::fs::read(&index).unwrap(), before);
    assert_eq!(read(&src, "/a"), b"xyz");
    assert_eq!(sidecar(&src, "/a.json")["byte_length"], 3);
}

/// Regression: magic probes must detect extensionless files and rewind nested readers.
#[test]
fn probes_detect_formats_and_rewind_reader() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    let bytes = safetensors(json!({"a":tensor("U8",&[1],0,1)}), b"x");
    file.write_all(&bytes).unwrap();
    assert!(looks_like_safetensors(file.path()));
    assert!(!looks_like_gguf(file.path()));
    let mut reader = Cursor::new(bytes);
    reader.set_position(13);
    assert!(looks_like_safetensors_reader(&mut reader));
    assert_eq!(reader.position(), 0);
    let mut bad = Cursor::new(vec![0; 8]);
    assert!(!looks_like_safetensors_reader(&mut bad));
    assert_eq!(bad.position(), 0);
    std::fs::write(file.path(), gguf(3, vec![], 32, &[])).unwrap();
    assert!(looks_like_gguf(file.path()));
    assert!(!looks_like_safetensors(file.path()));
}

/// Regression: duplicate safetensors names and descriptor fields must not be silently overwritten.
#[test]
fn safetensors_duplicate_names_and_descriptor_fields_rejected() {
    for header in [
        r#"{"a":{"dtype":"U8","shape":[1],"data_offsets":[0,1]},"a":{"dtype":"U8","shape":[1],"data_offsets":[0,1]}}"#,
        r#"{"a":{"dtype":"U8","dtype":"I8","shape":[1],"data_offsets":[0,1]}}"#,
        r#"{"__metadata__":{},"__metadata__":{}}"#,
    ] {
        let mut bytes = (header.len() as u64).to_le_bytes().to_vec();
        bytes.extend(header.as_bytes());
        bytes.push(7);
        assert_error(bytes, "duplicate");
    }
}

/// Regression: GGUF arrays of each scalar type, empty arrays and nested arrays must retain values.
#[test]
fn gguf_array_value_types_round_trip() {
    let entries = [
        (0, vec![9], json!(9)),
        (1, vec![255], json!(-1)),
        (2, 1234u16.to_le_bytes().to_vec(), json!(1234)),
        (3, (-1234i16).to_le_bytes().to_vec(), json!(-1234)),
        (4, 123456u32.to_le_bytes().to_vec(), json!(123456)),
        (5, (-123456i32).to_le_bytes().to_vec(), json!(-123456)),
        (6, 1.5f32.to_le_bytes().to_vec(), json!(1.5)),
        (7, vec![0], json!(false)),
        (8, string_value("value"), json!("value")),
        (10, u64::MAX.to_le_bytes().to_vec(), json!(u64::MAX)),
        (11, i64::MIN.to_le_bytes().to_vec(), json!(i64::MIN)),
        (12, (-1.5f64).to_le_bytes().to_vec(), json!(-1.5)),
        (9, array(0, 1, &[7]), json!([7])),
    ];
    for (ty, bytes, value) in entries {
        let src = mount(gguf(
            3,
            vec![
                kv("a", 9, array(ty, 1, &bytes)),
                kv("empty", 9, array(ty, 0, &[])),
            ],
            32,
            &[],
        ))
        .unwrap();
        let m = sidecar(&src, "/__metadata__.json");
        assert_eq!(m["a"], json!([value]));
        assert_eq!(m["empty"], json!([]));
    }
}

/// Regression: a declared GGUF string beyond the header budget must fail before allocating its bytes.
#[test]
fn gguf_oversized_header_rejected_before_string_allocation() {
    let mut file = tempfile::tempfile().unwrap();
    let mut prefix = b"GGUF".to_vec();
    prefix.extend(3u32.to_le_bytes());
    prefix.extend(0u64.to_le_bytes());
    prefix.extend(1u64.to_le_bytes());
    prefix.extend(MAX_HEADER_SIZE.to_le_bytes());
    file.write_all(&prefix).unwrap();
    file.set_len(MAX_HEADER_SIZE + 128).unwrap();
    let error = TensorsMountSource::open_from_reader(
        file,
        "large.gguf",
        None,
        &OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        },
        "test",
    )
    .err()
    .unwrap()
    .to_string();
    assert!(error.contains("oversized GGUF header"), "{error}");
}

/// Regression: GGUF reserved tensor names must not replace generated root metadata with their sidecars.
#[test]
fn gguf_reserved_root_names_preserve_tensor_bytes_and_metadata() {
    let src = mount(gguf(
        3,
        vec![kv("general.name", 8, string_value("reserved-name model"))],
        32,
        &[
            GgTensor {
                name: "__metadata__",
                dims: &[4],
                ty: 24,
                offset: 0,
                bytes: b"meta".to_vec(),
            },
            GgTensor {
                name: "__header__",
                dims: &[4],
                ty: 24,
                offset: 32,
                bytes: b"head".to_vec(),
            },
        ],
    ))
    .unwrap();
    let names: BTreeSet<_> = src
        .list_dirents("/")
        .unwrap()
        .into_iter()
        .map(|entry| entry.name)
        .collect();
    assert_eq!(
        names,
        [
            "%5F_metadata__",
            "%5F_metadata__.json",
            "%5F_header__",
            "%5F_header__.json",
            "__metadata__.json",
        ]
        .map(String::from)
        .into_iter()
        .collect()
    );
    for (path, name, bytes) in [
        ("%5F_metadata__", "__metadata__", b"meta"),
        ("%5F_header__", "__header__", b"head"),
    ] {
        assert_eq!(read(&src, &format!("/{path}")), bytes);
        assert_eq!(sidecar(&src, &format!("/{path}.json"))["name"], name);
    }
    assert_eq!(
        sidecar(&src, "/__metadata__.json"),
        json!({"general.name": "reserved-name model"})
    );
}
