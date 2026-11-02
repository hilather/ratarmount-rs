use super::*;
use crate::manifest::{build_manifest_with_limit, tensor_rows};
use crate::tests::{gguf, gguf_with_start, safetensors, tensor, GgTensor};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

fn save(dir: &tempfile::TempDir, name: &str, bytes: &[u8]) -> PathBuf {
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    path
}

fn manifest(bytes: &[u8]) -> Manifest {
    let dir = tempfile::tempdir().unwrap();
    let path = save(&dir, "model", bytes);
    build_manifest(&[path], &ManifestOptions::default()).unwrap()
}

fn refused(bytes: &[u8], expected: &[&str]) {
    let dir = tempfile::tempdir().unwrap();
    let path = save(&dir, "model", bytes);
    let err = build_manifest(std::slice::from_ref(&path), &ManifestOptions::default())
        .expect_err("must refuse fixture")
        .to_string();
    assert!(err.contains(path.to_str().unwrap()), "path absent: {err}");
    for message in expected {
        assert!(err.contains(message), "expected {message:?}: {err}");
    }
}

fn alignment_metadata(alignment: u32) -> Vec<Vec<u8>> {
    let mut kv = Vec::new();
    crate::tests::string(&mut kv, "general.alignment");
    kv.extend(4u32.to_le_bytes());
    kv.extend(alignment.to_le_bytes());
    vec![kv]
}

/// Regression: GGUF experts use ne0 block rows and the outermost expert axis.
#[test]
fn manifest_gguf_experts_match_independent_slices() {
    let mut tensors = Vec::new();
    let mut offset = 0;
    let names: Vec<String> = (0..2)
        .flat_map(|layer| {
            ["gate", "up", "down"].map(move |role| format!("blk.{layer}.ffn_{role}_exps.weight"))
        })
        .collect();
    for (i, name) in names.iter().enumerate() {
        let slice = if i % 2 == 0 { 2 * 144 } else { 2 * 256 * 2 };
        tensors.push(GgTensor {
            name,
            dims: &[256, 2, 4],
            ty: if i % 2 == 0 { 12 } else { 1 },
            offset,
            bytes: (0..4)
                .flat_map(|expert| vec![(i * 4 + expert) as u8; slice])
                .collect(),
        });
        offset += (4 * slice) as u64;
        offset = offset.next_multiple_of(32);
    }
    for (name, data) in [
        ("blk.0.attn_q.weight", 91),
        ("blk.0.ffn_gate_inp.weight", 92),
        ("blk.1.ffn_up_shexp.weight", 93),
        ("token_embd.weight", 94),
    ] {
        tensors.push(GgTensor {
            name,
            dims: &[8],
            ty: 0,
            offset,
            bytes: vec![data; 32],
        });
        offset += 32;
    }
    let (bytes, start) = gguf_with_start(3, alignment_metadata(32), 32, &tensors);
    let dir = tempfile::tempdir().unwrap();
    let path = save(&dir, "weights.gguf", &bytes);
    let result = build_manifest(std::slice::from_ref(&path), &ManifestOptions::default()).unwrap();
    assert_eq!(result.rows.len(), 28);
    let mut reader = File::open(&path).unwrap();
    for (i, source) in tensors[..6].iter().enumerate() {
        let role = [Role::Gate, Role::Up, Role::Down][i % 3];
        let ne0 = source.dims[0];
        let ne1 = source.dims[1];
        let slice: u64 = if i % 2 == 0 {
            ne1 * (ne0 / 256 * 144)
        } else {
            ne1 * ne0 * 2
        };
        for expert in 0..4 {
            let row = result
                .rows
                .iter()
                .find(|r| r.tensor == source.name && r.expert == Some(expert))
                .unwrap();
            assert_eq!(
                (row.layer, row.expert, row.role),
                (Some((i / 3) as u32), Some(expert), role)
            );
            assert_eq!(row.shape, [256, 2]);
            let expert_offset = if i % 2 == 0 {
                u64::from(expert) * ne1 * (ne0 / 256 * 144)
            } else {
                u64::from(expert) * ne1 * ne0 * 2
            };
            assert_eq!(
                (row.offset, row.length),
                (start as u64 + source.offset + expert_offset, slice)
            );
            assert_eq!(row.format, if i % 2 == 0 { "Q4_K" } else { "F16" });
            reader.seek(SeekFrom::Start(row.offset)).unwrap();
            let mut actual = vec![0; row.length as usize];
            reader.read_exact(&mut actual).unwrap();
            assert_eq!(
                actual,
                vec![(i * 4 + expert as usize) as u8; slice as usize]
            );
        }
    }
    for (name, layer, role) in [
        ("blk.0.attn_q.weight", Some(0), Role::Other),
        ("blk.0.ffn_gate_inp.weight", Some(0), Role::Router),
        ("blk.1.ffn_up_shexp.weight", Some(1), Role::SharedExpert),
        ("token_embd.weight", None, Role::Other),
    ] {
        let row = result.rows.iter().find(|r| r.tensor == name).unwrap();
        assert_eq!((row.layer, row.expert, row.role), (layer, None, role));
    }
}

/// Regression: index weight_map resolves each shard once and covers every tensor exactly once.
#[test]
fn manifest_sharded_safetensors_follow_weight_map() {
    let dir = tempfile::tempdir().unwrap();
    let groups = [
        vec![
            (
                "model.layers.0.mlp.experts.0.gate_proj.weight",
                Some(0),
                Some(0),
                Role::Gate,
            ),
            (
                "model.layers.0.mlp.experts.0.up_proj.weight",
                Some(0),
                Some(0),
                Role::Up,
            ),
            (
                "model.layers.0.mlp.experts.0.down_proj.weight",
                Some(0),
                Some(0),
                Role::Down,
            ),
            (
                "model.layers.0.mlp.gate.weight",
                Some(0),
                None,
                Role::Router,
            ),
        ],
        vec![
            (
                "model.layers.1.block_sparse_moe.experts.3.w1.weight",
                Some(1),
                Some(3),
                Role::Gate,
            ),
            (
                "model.layers.1.block_sparse_moe.experts.3.w3.weight",
                Some(1),
                Some(3),
                Role::Up,
            ),
            (
                "model.layers.1.block_sparse_moe.experts.3.w2.weight",
                Some(1),
                Some(3),
                Role::Down,
            ),
            (
                "model.layers.1.mlp.shared_expert.up_proj.weight",
                Some(1),
                None,
                Role::SharedExpert,
            ),
            ("model.embed_tokens.weight", None, None, Role::Other),
        ],
    ];
    let mut weights = serde_json::Map::new();
    let mut expected = Vec::new();
    let mut total = 0;
    let mut starts = BTreeMap::new();
    for (shard, group) in groups.iter().enumerate() {
        let filename = format!("shard-{shard}.safetensors");
        let mut header = serde_json::Map::new();
        for (i, &(name, layer, expert, role)) in group.iter().enumerate() {
            header.insert(
                name.into(),
                tensor("U8", &[3], 3 * i as u64, 3 * i as u64 + 3),
            );
            weights.insert(name.into(), json!(filename));
            expected.push((
                name.to_string(),
                dir.path().join(&filename),
                layer,
                expert,
                role,
            ));
        }
        let bytes = safetensors(Value::Object(header), &vec![shard as u8; 3 * group.len()]);
        starts.insert(
            dir.path().join(&filename),
            8 + u64::from_le_bytes(bytes[..8].try_into().unwrap()),
        );
        save(&dir, &filename, &bytes);
        total += 3 * group.len() as u64;
    }
    let index = save(
        &dir,
        "model.safetensors.index.json",
        &serde_json::to_vec(&json!({"metadata":{"ignored":true},"weight_map":weights})).unwrap(),
    );
    let m = build_manifest(&[index], &ManifestOptions::default()).unwrap();
    assert_eq!(m.rows.len(), expected.len());
    for (tensor, file, layer, expert, role) in expected {
        let row = m.rows.iter().find(|r| r.tensor == tensor).unwrap();
        assert_eq!(
            (&row.file, row.layer, row.expert, row.role),
            (&file, layer, expert, role)
        );
    }
    assert_eq!(m.rows.iter().map(|r| r.length).sum::<u64>(), total);
    for (file, mut next) in starts {
        let mut rows: Vec<_> = m.rows.iter().filter(|r| r.file == file).collect();
        rows.sort_by_key(|r| r.offset);
        for row in rows {
            assert_eq!(row.offset, next);
            next += row.length;
        }
        assert_eq!(next, std::fs::metadata(file).unwrap().len());
    }
}

/// Regression: fused BF16 gate/up tensors split contiguous leading-axis expert slices.
#[test]
fn manifest_fused_gate_up_proj_splits_per_expert() {
    let name = "model.layers.0.mlp.experts.gate_up_proj";
    let data: Vec<_> = (0..4).flat_map(|e| vec![e; 24]).collect();
    let bytes = safetensors(json!({name:tensor("BF16",&[4,6,2],0,96)}), &data);
    let start = 8 + u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let m = manifest(&bytes);
    assert_eq!(m.rows.len(), 4);
    for (e, row) in m.rows.iter().enumerate() {
        assert_eq!(
            (row.layer, row.expert, row.role),
            (Some(0), Some(e as u32), Role::GateUp)
        );
        assert_eq!(row.shape, [6, 2]);
        assert_eq!((row.offset, row.length), (start + e as u64 * 24, 24));
        assert_eq!(
            &bytes[row.offset as usize..(row.offset + row.length) as usize],
            vec![e as u8; 24]
        );
    }
}

/// Regression: unknown dtypes, unknown ggml layouts, and splitter size mismatches fail by tensor name.
#[test]
fn manifest_merged_expert_bad_length_refused() {
    let name = "model.layers.0.mlp.experts.gate_up_proj";
    refused(
        &safetensors(json!({name:tensor("X9",&[2,2,1],0,3)}), b"abc"),
        &[name, "not a multiple"],
    );
    refused(
        &gguf(
            3,
            vec![],
            32,
            &[GgTensor {
                name: "blk.0.ffn_up_exps.weight",
                dims: &[2, 2, 2],
                ty: 999,
                offset: 0,
                bytes: vec![1; 32],
            }],
        ),
        &["blk.0.ffn_up_exps.weight", "unknown ggml type 999"],
    );
    let tensor = Tensor {
        name: "blk.0.ffn_up_exps.weight".into(),
        offset: 32,
        size: 15,
        sidecar: json!({}),
        layout: Layout::Gguf {
            ty: 1,
            dims: vec![2, 2, 2],
        },
    };
    let err = tensor_rows(
        &tensor,
        Path::new("fixture.gguf"),
        &ManifestOptions::default(),
        100,
    )
    .err()
    .unwrap()
    .to_string();
    assert!(err.contains(&tensor.name), "{err}");
    assert!(err.contains("length"), "{err}");
}

/// Regression: hashes are SHA-256 of independent source ranges, including expert slices.
#[test]
fn manifest_hash_matches_sha256_of_ranges() {
    let name = "model.layers.0.mlp.experts.gate_up_proj";
    let payload: Vec<u8> = (0..32).collect();
    let bytes = safetensors(json!({name:tensor("U8",&[4,2,4],0,32)}), &payload);
    let dir = tempfile::tempdir().unwrap();
    let path = save(&dir, "model", &bytes);
    let m = build_manifest(
        &[path],
        &ManifestOptions {
            hash: true,
            expert_pattern: None,
        },
    )
    .unwrap();
    for (expert, row) in m.rows.iter().enumerate() {
        let expected = format!(
            "{:x}",
            Sha256::digest(&payload[expert * 8..(expert + 1) * 8])
        );
        assert_eq!(row.sha256.as_deref(), Some(expected.as_str()));
    }
}

/// Regression: a huge zero-sized shape must be rejected without expanding its experts.
#[test]
fn manifest_merged_expert_expansion_bound() {
    let name = "model.layers.0.mlp.experts.gate_up_proj";
    refused(
        &safetensors(json!({name:tensor("BF16",&[4294967297,0,1],0,0)}), b""),
        &[name],
    );
}

/// Regression: a zero-byte merged tensor has no expert bytes to map.
#[test]
fn manifest_merged_expert_zero_bytes_refused() {
    let name = "model.layers.0.mlp.experts.gate_up_proj";
    refused(
        &safetensors(json!({name:tensor("BF16",&[4,0,1],0,0)}), b""),
        &[name, "zero"],
    );
}

/// Regression: the merged expert count cap applies before per-expert iteration.
#[test]
fn manifest_merged_expert_count_cap() {
    let name = "model.layers.0.mlp.experts.gate_up_proj";
    let count = 65_537;
    refused(
        &safetensors(
            json!({name:tensor("U8",&[count,1,1],0,count)}),
            &vec![1; count as usize],
        ),
        &[name, "n_expert 65537", "count limit", "65536"],
    );
}

/// Regression: exactly 65,536 merged experts fit within the production limits.
#[test]
fn manifest_merged_expert_count_at_limit() {
    assert_eq!(crate::manifest::MAX_EXPERTS, 65_536);
    assert_eq!(crate::manifest::MAX_ROWS, 16_777_216);
    let name = "model.layers.0.mlp.experts.gate_up_proj";
    let count = 65_536;
    let m = manifest(&safetensors(
        json!({name:tensor("U8",&[count,1,1],0,count)}),
        &vec![1; count as usize],
    ));
    assert_eq!(m.rows.len(), count as usize);
    for (expert, row) in m.rows.iter().enumerate() {
        assert_eq!(row.expert, Some(expert as u32));
        assert_eq!(row.role, Role::GateUp);
        assert_eq!(row.length, 1);
        assert_eq!(row.offset, m.rows[0].offset + expert as u64);
    }
}

/// Regression: total rows fail closed before expanding a tensor beyond the remaining budget.
#[test]
fn manifest_total_row_cap() {
    let dir = tempfile::tempdir().unwrap();
    let name = "model.layers.0.mlp.experts.gate_up_proj";
    let bytes = safetensors(
        json!({"aaa":tensor("U8",&[1],0,1),name:tensor("U8",&[3,1,1],1,4)}),
        b"abcd",
    );
    let path = save(&dir, "model", &bytes);
    let err = build_manifest_with_limit(&[path], &ManifestOptions::default(), 3)
        .err()
        .unwrap()
        .to_string();
    assert!(err.contains(name), "{err}");
    assert!(err.contains("row"), "{err}");
}

/// Regression: a 2-D fused name and merged down projection remain one Other tensor.
#[test]
fn manifest_fused_nonexpert_axis_and_down_are_other() {
    let names = [
        "model.layers.2.mlp.experts.gate_up_proj",
        "model.layers.2.mlp.experts.down_proj",
        "model.layers.2.mlp.experts.0.gate_up_proj.weight",
        "model.layers.2.mlp.experts.gate_up_proj.weight_scale",
        "model.layers.2.mlp.experts.0.gate.weight",
    ];
    for name in names {
        let m = manifest(&safetensors(json!({name:tensor("U8",&[2,2],0,4)}), b"abcd"));
        assert_eq!(m.rows.len(), 1);
        assert_eq!(
            (m.rows[0].layer, m.rows[0].expert, m.rows[0].role),
            (Some(2), None, Role::Other)
        );
    }
    let name = "model.layers.2.mlp.experts.down_proj";
    let m = manifest(&safetensors(
        json!({name:tensor("U8",&[2,2,2],0,8)}),
        b"abcdefgh",
    ));
    assert_eq!(m.rows.len(), 1);
    assert_eq!(m.rows[0].shape, [2, 2, 2]);
    assert_eq!((m.rows[0].expert, m.rows[0].role), (None, Role::Other));
}

/// Regression: packed six-bit values cannot produce fractional-byte expert slices.
#[test]
fn manifest_packed_f6_fractional_experts_refused() {
    let name = "model.layers.0.mlp.experts.gate_up_proj";
    refused(
        &safetensors(json!({name:tensor("F6_E2M3",&[2,2,1],0,3)}), b"abc"),
        &[name, "not a multiple"],
    );
}

/// Regression: GGUF merged expert names require three dimensions.
#[test]
fn manifest_gguf_merged_requires_three_dims() {
    refused(
        &gguf(
            3,
            vec![],
            32,
            &[GgTensor {
                name: "blk.0.ffn_up_exps.weight",
                dims: &[2, 2],
                ty: 1,
                offset: 0,
                bytes: vec![1; 8],
            }],
        ),
        &["blk.0.ffn_up_exps.weight"],
    );
}

/// Regression: manifest range coverage refuses overlaps accepted by mounts.
#[test]
fn manifest_overlapping_ranges_refused() {
    refused(
        &safetensors(
            json!({"a":tensor("U8",&[2],0,2),"b":tensor("U8",&[2],1,3)}),
            b"abc",
        ),
        &["a", "b", "overlap"],
    );
    refused(
        &gguf(
            3,
            vec![],
            32,
            &[
                GgTensor {
                    name: "blk.0.ffn_up_exps.weight",
                    dims: &[2, 2, 2],
                    ty: 1,
                    offset: 0,
                    bytes: vec![1; 16],
                },
                GgTensor {
                    name: "blk.1.ffn_up_exps.weight",
                    dims: &[2, 2, 2],
                    ty: 1,
                    offset: 0,
                    bytes: vec![1; 16],
                },
            ],
        ),
        &[
            "blk.0.ffn_up_exps.weight",
            "blk.1.ffn_up_exps.weight",
            "overlap",
        ],
    );
}

/// Regression: directory inputs are refused before opening them.
#[test]
fn manifest_directory_refused() {
    let dir = tempfile::tempdir().unwrap();
    let err = build_manifest(&[dir.path().to_path_buf()], &ManifestOptions::default())
        .err()
        .unwrap()
        .to_string();
    assert!(err.contains("not a regular file"), "{err}");
}

/// Regression: repeated paths, hard links and index/direct duplication never count bytes twice.
#[test]
fn manifest_duplicate_file_identity_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = save(
        &dir,
        "shard",
        &safetensors(json!({"a":tensor("U8",&[1],0,1)}), b"a"),
    );
    let link = dir.path().join("hardlink");
    std::fs::hard_link(&path, &link).unwrap();
    let index = save(&dir, "model.index.json", br#"{"weight_map":{"a":"shard"}}"#);
    for inputs in [
        vec![path.clone(), path.clone()],
        vec![path.clone(), link],
        vec![index, path],
    ] {
        let err = build_manifest(&inputs, &ManifestOptions::default())
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains("given more than once"), "{err}");
    }
}

fn index_refused(index: &[u8], shards: &[(&str, Vec<u8>)], expected: &str) {
    let dir = tempfile::tempdir().unwrap();
    for (name, bytes) in shards {
        save(&dir, name, bytes);
    }
    let path = save(&dir, "model.index.json", index);
    let err = build_manifest(&[path], &ManifestOptions::default())
        .err()
        .unwrap()
        .to_string();
    assert!(err.contains(expected), "expected {expected:?}: {err}");
}

/// Regression: shard names must consist of exactly one normal path component.
#[test]
fn manifest_shard_name_refusals() {
    for name in [
        "../shard",
        "/tmp/shard",
        "a/b",
        "a\\b",
        "..",
        ".",
        "",
        "bad\0name",
        "a/",
    ] {
        let index = serde_json::to_vec(&json!({"weight_map":{"a":name}})).unwrap();
        index_refused(&index, &[], "not a plain file name");
    }
}

/// Regression: weight_map must be a bijection with the actual safetensors shard tensors.
#[test]
fn manifest_weight_map_consistency_refusals() {
    let a = safetensors(json!({"a":tensor("U8",&[1],0,1)}), b"a");
    let b = safetensors(json!({"b":tensor("U8",&[1],0,1)}), b"b");
    index_refused(
        br#"{"weight_map":{"missing":"s"}}"#,
        &[("s", a.clone())],
        "missing",
    );
    index_refused(
        br#"{"weight_map":{"a":"s"}}"#,
        &[(
            "s",
            safetensors(
                json!({"a":tensor("U8",&[1],0,1),"b":tensor("U8",&[1],1,2)}),
                b"ab",
            ),
        )],
        "not in weight_map",
    );
    let copy = safetensors(
        json!({"a":tensor("U8",&[1],0,1),"b":tensor("U8",&[1],1,2)}),
        b"xy",
    );
    index_refused(
        br#"{"weight_map":{"a":"s1","b":"s2"}}"#,
        &[("s1", a), ("s2", copy)],
        "mapped to",
    );
    index_refused(
        br#"{"weight_map":{"a":"s","a":"s"}}"#,
        &[("s", b)],
        "duplicate",
    );
    for index in [
        br#"{}"#.as_slice(),
        br#"{"weight_map":[]}"#,
        br#"{"weight_map":{"a":7}}"#,
    ] {
        let dir = tempfile::tempdir().unwrap();
        let path = save(&dir, "model.index.json", index);
        assert!(build_manifest(&[path], &ManifestOptions::default()).is_err());
    }
    index_refused(
        br#"{"weight_map":{},"weight_map":{}}"#,
        &[],
        "duplicate field `weight_map`",
    );
    index_refused(
        br#"{"weight_map":{"a":"s"}}"#,
        &[(
            "s",
            gguf(
                3,
                vec![],
                32,
                &[GgTensor {
                    name: "a",
                    dims: &[1],
                    ty: 24,
                    offset: 0,
                    bytes: vec![1],
                }],
            ),
        )],
        "safetensors",
    );
}

/// Regression: a positional root array cannot substitute for the named weight_map field.
#[test]
fn manifest_index_root_array_refused() {
    index_refused(
        br#"[{"a":"s.safetensors"}]"#,
        &[(
            "s.safetensors",
            safetensors(json!({"a":tensor("U8",&[1],0,1)}), b"a"),
        )],
        "weight_map",
    );
}

/// Regression: invalid standalone regex syntax cannot escape the whole-name wrapper.
#[test]
fn manifest_expert_pattern_wrapper_escape_refused() {
    let pattern = r"a^)|ffn\.(?P<layer>\d+)\.ex\.(?P<expert>\d+)\.(?P<role>gate)(?:";
    let err = compile_expert_pattern(pattern).unwrap_err().to_string();
    assert!(err.contains("invalid expert pattern"), "{err}");
}

/// Regression: trailing verbose-mode comments must not swallow whole-name anchors.
#[test]
fn manifest_expert_pattern_trailing_comment() {
    let dir = tempfile::tempdir().unwrap();
    for pattern in [
        r"(?x)custom\.(?P<layer>\d+)\.(?P<expert>\d+)\.(?P<role>gate|gate_up) # trailing comment",
        r"(?mx)custom\.(?P<layer>\d+)\.(?P<expert>\d+)\.(?P<role>gate|gate_up) # trailing comment",
        "custom\\.(?P<layer>\\d+)\\.(?P<expert>\\d+)\\.(?P<role>gate|gate_up)\n",
    ] {
        let opts = ManifestOptions {
            hash: false,
            expert_pattern: Some(compile_expert_pattern(pattern).unwrap()),
        };
        let literal_newline = pattern.ends_with('\n');
        for (name, role) in [
            ("custom.2.3.gate", Role::Gate),
            ("custom.2.3.gate_up", Role::GateUp),
            ("prefix.custom.2.3.gate", Role::Other),
            ("custom.2.3.gate.suffix", Role::Other),
            ("prefix\ncustom.2.3.gate", Role::Other),
            ("custom.2.3.gate\nsuffix", Role::Other),
        ] {
            let name = if literal_newline {
                format!("{name}\n")
            } else {
                name.to_owned()
            };
            let path = save(
                &dir,
                "model",
                &safetensors(json!({&name:tensor("U8",&[1],0,1)}), b"a"),
            );
            let m = build_manifest(&[path], &opts).unwrap();
            assert_eq!(m.rows[0].role, role, "{pattern:?}: {name:?}");
            if role != Role::Other {
                assert_eq!((m.rows[0].layer, m.rows[0].expert), (Some(2), Some(3)));
            }
        }
    }
}

/// Regression: explicit expert captures take precedence over an overflowing prefix layer.
#[test]
fn manifest_expert_pattern_precedes_fallback_layer() {
    let dir = tempfile::tempdir().unwrap();
    for (name, pattern) in [
        (
            "prefix.layers.4294967296.custom.2.3.gate",
            Some(r".*\.custom\.(?P<layer>\d+)\.(?P<expert>\d+)\.(?P<role>gate)"),
        ),
        (
            "prefix.layers.4294967296.layers.2.mlp.experts.3.gate_proj.weight",
            None,
        ),
        ("prefix.layers.4294967296.layers.2.mlp.gate.weight", None),
    ] {
        let opts = ManifestOptions {
            hash: false,
            expert_pattern: pattern.map(|p| compile_expert_pattern(p).unwrap()),
        };
        let path = save(
            &dir,
            "model",
            &safetensors(json!({name:tensor("U8",&[1],0,1)}), b"a"),
        );
        let m = build_manifest(&[path], &opts).unwrap();
        assert_eq!(m.rows.len(), 1);
        assert_eq!(m.rows[0].layer, Some(2));
        if name.ends_with("mlp.gate.weight") {
            assert_eq!((m.rows[0].expert, m.rows[0].role), (None, Role::Router));
        } else {
            assert_eq!((m.rows[0].expert, m.rows[0].role), (Some(3), Role::Gate));
        }
    }
}

/// Regression: custom patterns need all groups, participating captures, valid roles and u32 IDs.
#[test]
fn manifest_expert_pattern_validation() {
    assert!(compile_expert_pattern(r"(?P<layer>\d+)\.(?P<expert>\d+)").is_err());
    let name = "custom.2.3.gate";
    let dir = tempfile::tempdir().unwrap();
    let path = save(
        &dir,
        "model",
        &safetensors(json!({name:tensor("U8",&[1],0,1)}), b"a"),
    );
    for pattern in [
        r"custom\.(?P<layer>\d+)\.(?P<expert>\d+)\.(?:gate|(?P<role>up))",
        r"custom\.(?P<layer>\d+)\.(?P<expert>\d+)\.(?P<role>g[a-z]+)",
    ] {
        let opts = ManifestOptions {
            hash: false,
            expert_pattern: Some(compile_expert_pattern(pattern).unwrap()),
        };
        let result = build_manifest(std::slice::from_ref(&path), &opts);
        if pattern.contains("g[a-z]") {
            assert_eq!(result.unwrap().rows[0].role, Role::Gate);
        } else {
            let err = result.err().unwrap().to_string();
            assert!(err.contains(name), "{err}");
        }
    }
    for name in [
        "custom.4294967296.1.gate",
        "custom.1.4294967296.gate",
        "custom.1.2.invalid",
    ] {
        let path = save(
            &dir,
            "bad",
            &safetensors(json!({name:tensor("U8",&[1],0,1)}), b"a"),
        );
        let opts = ManifestOptions {
            hash: false,
            expert_pattern: Some(
                compile_expert_pattern(
                    r"custom\.(?P<layer>\d+)\.(?P<expert>\d+)\.(?P<role>[a-z_]+)",
                )
                .unwrap(),
            ),
        };
        let err = build_manifest(&[path], &opts).err().unwrap().to_string();
        assert!(err.contains(name), "{err}");
    }
}

/// Regression: custom aliases classify only whole-name matches and never double-emit fused names.
#[test]
fn manifest_custom_aliases_and_precedence() {
    let dir = tempfile::tempdir().unwrap();
    let pattern = r"ffn\.(?P<layer>\d+)\.ex\.(?P<expert>\d+)\.(?P<role>gate|up|down|gate_up|gate_up_proj)\.weight";
    for (alias, role) in [
        ("gate", Role::Gate),
        ("up", Role::Up),
        ("down", Role::Down),
        ("gate_up", Role::GateUp),
        ("gate_up_proj", Role::GateUp),
    ] {
        let name = format!("ffn.2.ex.3.{alias}.weight");
        let bytes = safetensors(json!({&name:tensor("U8",&[1],0,1)}), b"a");
        let path = save(&dir, "model", &bytes);
        let opts = ManifestOptions {
            hash: false,
            expert_pattern: Some(compile_expert_pattern(pattern).unwrap()),
        };
        let m = build_manifest(&[path], &opts).unwrap();
        assert_eq!(
            (m.rows[0].layer, m.rows[0].expert, m.rows[0].role),
            (Some(2), Some(3), role)
        );
    }
    for name in [
        "prefix.ffn.2.ex.3.gate.weight",
        "ffn.2.ex.3.gate.weight.suffix",
    ] {
        let path = save(
            &dir,
            "model",
            &safetensors(json!({name:tensor("U8",&[1],0,1)}), b"a"),
        );
        let opts = ManifestOptions {
            hash: false,
            expert_pattern: Some(compile_expert_pattern(pattern).unwrap()),
        };
        let m = build_manifest(&[path], &opts).unwrap();
        assert_eq!(m.rows[0].role, Role::Other);
    }
    let name = "model.layers.0.mlp.experts.gate_up_proj";
    let path = save(
        &dir,
        "model",
        &safetensors(json!({name:tensor("U8",&[2,1,1],0,2)}), b"ab"),
    );
    let opts = ManifestOptions{hash:false,expert_pattern:Some(compile_expert_pattern(r"model.layers\.(?P<layer>\d+)\.mlp\.experts\.(?P<role>gate_up_proj)(?P<expert>\d*)").unwrap())};
    let m = build_manifest(&[path], &opts).unwrap();
    assert_eq!(m.rows.len(), 2);
    assert!(m.rows.iter().all(|r| r.role == Role::GateUp));
}

/// Regression: Layout metadata must leave exact pre-R2 mount payload and sidecar bytes unchanged.
#[test]
fn manifest_layout_preserves_sidecar_and_mount_bytes() {
    // Golden bytes captured by mounting these fixtures before adding Layout.
    let fixtures: Vec<(Vec<u8>, &[u8], &[u8])> = vec![
        (
            safetensors(json!({"weight":tensor("U8",&[3],0,3)}), b"abc"),
            b"abc",
            br#"{
  "absolute_file_offset": 66,
  "byte_length": 3,
  "data_offsets": [
    0,
    3
  ],
  "dtype": "U8",
  "format": "safetensors",
  "name": "weight",
  "overlapping": false,
  "path": "weight",
  "shape": [
    3
  ],
  "size_check": "validated"
}"#,
        ),
        (
            gguf(
                3,
                vec![],
                32,
                &[GgTensor {
                    name: "weight",
                    dims: &[2],
                    ty: 1,
                    offset: 0,
                    bytes: b"abcd".to_vec(),
                }],
            ),
            b"abcd",
            br#"{
  "absolute_file_offset": 64,
  "alignment": 32,
  "byte_length": 4,
  "data_offset": 0,
  "data_section_start": 64,
  "dims": [
    2
  ],
  "format": "gguf",
  "ggml_type": 1,
  "ggml_type_name": "F16",
  "name": "weight",
  "overlapping": false,
  "path": "weight",
  "size_source": "ggml_block_layout",
  "version": 3
}"#,
        ),
    ];
    for (bytes, payload, sidecar) in fixtures {
        let source = TensorsMountSource::open_from_reader(
            Cursor::new(bytes),
            "virtual",
            None,
            &OpenOptions {
                index_in_memory: true,
                ..OpenOptions::default()
            },
            "test",
        )
        .unwrap();
        for (path, expected) in [("/weight", payload), ("/weight.json", sidecar)] {
            let info = source.lookup(path, 0).unwrap();
            let mut actual = Vec::new();
            MountSource::open(&source, &info, 0)
                .unwrap()
                .read_to_end(&mut actual)
                .unwrap();
            assert_eq!(actual, expected, "{path}");
        }
    }
}

/// Regression: both shrinking and growing a parsed file invalidate hash generation.
#[test]
fn manifest_hash_refuses_changed_file_length() {
    for growth in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let name = "weight";
        let bytes = safetensors(json!({name:tensor("U8",&[3],0,3)}), b"abc");
        let path = save(&dir, "model", &bytes);
        let mut reader = File::open(&path).unwrap();
        let parsed = parse(&mut reader, bytes.len() as u64).unwrap();
        let mut rows =
            tensor_rows(&parsed.tensors[0], &path, &ManifestOptions::default(), 100).unwrap();
        let writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        writer
            .set_len(bytes.len() as u64 + if growth { 1 } else { 0 } - if growth { 0 } else { 1 })
            .unwrap();
        let err = crate::manifest::hash_rows(&mut reader, &path, bytes.len() as u64, &mut rows)
            .err()
            .unwrap()
            .to_string();
        assert!(err.contains(name), "{err}");
        assert!(err.contains(path.to_str().unwrap()), "{err}");
        assert!(err.contains("length changed"), "{err}");
    }
}

/// Regression: an EOF during hash reads reports the file and tensor whose length changed.
#[test]
fn manifest_hash_short_read_reports_changed_file_length() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = safetensors(json!({"weight":tensor("U8",&[3],0,3)}), b"abc");
    let path = save(&dir, "model", &bytes);
    let mut reader = File::open(&path).unwrap();
    let mut rows = manifest(&bytes).rows;
    // Force the same short read as truncation after the pre-read metadata check,
    // without relying on a concurrent file mutation winning a race.
    rows[0].length += 1;
    let err = crate::manifest::hash_rows(&mut reader, &path, bytes.len() as u64, &mut rows)
        .unwrap_err()
        .to_string();
    assert!(err.contains(path.to_str().unwrap()), "{err}");
    assert!(err.contains("tensor weight"), "{err}");
    assert!(
        err.contains("file length changed between parse and hash read"),
        "{err}"
    );
    assert!(rows[0].sha256.is_none());
}

/// Regression: descriptor exhaustion names the shard and explains the open-handle limit.
#[test]
fn manifest_shard_emfile_is_actionable() {
    let code = if std::env::consts::OS == "windows" {
        4
    } else {
        24
    };
    let path = Path::new("shard-7.safetensors");
    let err =
        crate::manifest::open_error(path, std::io::Error::from_raw_os_error(code)).to_string();
    assert!(err.contains("shard-7.safetensors"), "{err}");
    assert!(
        err.contains("too many shards open; raise ulimit -n"),
        "{err}"
    );
    let other = crate::manifest::open_error(path, std::io::Error::from_raw_os_error(2)).to_string();
    assert!(other.contains("shard-7.safetensors"), "{other}");
    assert!(!other.contains("too many shards open"), "{other}");
}

/// Regression: dense future types and empty tensors retain their original ranges.
#[test]
fn manifest_unknown_dense_and_empty_tensors() {
    let m = manifest(&safetensors(
        json!({"future":tensor("X9",&[999],0,3),"empty":tensor("U8",&[0],3,3)}),
        b"abc",
    ));
    assert_eq!(m.rows.len(), 2);
    assert_eq!(m.rows.iter().map(|r| r.length).sum::<u64>(), 3);
    assert!(m.rows.iter().all(|r| r.sha256.is_none()));
    let m = manifest(&gguf(
        3,
        vec![],
        32,
        &[GgTensor {
            name: "future",
            dims: &[1],
            ty: 999,
            offset: 0,
            bytes: b"abc".to_vec(),
        }],
    ));
    assert_eq!(m.rows[0].format, "UNKNOWN(999)");
    assert_eq!(m.rows[0].length, 3);
}

/// Regression: layer capture overflow is named even in fixed classification rules.
#[test]
fn manifest_fixed_layer_capture_overflow() {
    for name in [
        "model.layers.4294967296.mlp.gate.weight",
        "model.layers.4294967296.mlp.experts.0.gate_proj.weight",
        "model.layers.4294967296.self_attn.q_proj.weight",
        "model.layers.4294967296.mlp.shared_expert.up_proj.weight",
    ] {
        refused(
            &safetensors(json!({name:tensor("U8",&[1],0,1)}), b"a"),
            &[name, "u32"],
        );
    }
    let name = "blk.4294967296.ffn_up_exps.weight";
    refused(
        &gguf(
            3,
            vec![],
            32,
            &[GgTensor {
                name,
                dims: &[1, 1, 1],
                ty: 24,
                offset: 0,
                bytes: vec![1],
            }],
        ),
        &[name, "u32"],
    );
}
