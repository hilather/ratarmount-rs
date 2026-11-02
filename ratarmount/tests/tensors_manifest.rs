#![cfg_attr(not(internal_read_inventory), allow(unfulfilled_lint_expectations))]

//! Regression: tensor byte maps must stay deterministic and fail closed without FUSE.

use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use clap::Parser;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

// Exercise the production output helper's failure seam in this targeted test
// target, including cleanup after an error delivered from the writer.
#[path = "../src/tensors_cmd.rs"]
mod tensors_cmd;

struct Fixture {
    bytes: Vec<u8>,
    start: usize,
    ranges: BTreeMap<String, (usize, usize)>,
}

fn safetensors(entries: &[(&str, &str, &[u64], Vec<u8>)]) -> Fixture {
    let mut header = serde_json::Map::new();
    let mut payload = Vec::new();
    let mut ranges = BTreeMap::new();
    for (name, dtype, shape, bytes) in entries {
        let begin = payload.len();
        payload.extend_from_slice(bytes);
        let end = payload.len();
        ranges.insert((*name).to_string(), (4096 + begin, 4096 + end));
        header.insert(
            (*name).to_string(),
            json!({"dtype":dtype,"shape":shape,"data_offsets":[begin,end]}),
        );
    }
    let mut encoded = serde_json::to_vec(&header).unwrap();
    assert!(encoded.len() <= 4088);
    encoded.resize(4088, b' ');
    let mut bytes = (encoded.len() as u64).to_le_bytes().to_vec();
    bytes.extend(encoded);
    bytes.extend(payload);
    Fixture {
        bytes,
        start: 4096,
        ranges,
    }
}

fn command(dir: &Path, arguments: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ratarmount"));
    command
        .current_dir(dir)
        .args(["tensors", "manifest"])
        .args(arguments);
    command
}

fn run(dir: &Path, arguments: &[&str]) -> Output {
    command(dir, arguments).output().unwrap()
}

fn success(output: &Output) {
    assert!(
        output.status.success(),
        "status {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn refusal(output: &Output, text: &str) {
    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(text),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn lines(output: &Output) -> Vec<Value> {
    success(output);
    String::from_utf8(output.stdout.clone())
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[test]
fn tensors_manifest_dtype_change_diff() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let fixture = |dtype, n| {
        safetensors(&[
            ("before", "U8", &[8], vec![1; 8]),
            ("changed", dtype, &[2048], vec![2; n]),
            ("after", "U8", &[8], vec![3; 8]),
        ])
    };
    let f32 = fixture("F32", 8192);
    let f16 = fixture("F16", 4096);
    assert_eq!(f32.start, f16.start);
    assert_eq!(f32.ranges["before"], f16.ranges["before"]);
    assert_eq!(f32.ranges["changed"].0, f16.ranges["changed"].0);
    assert_eq!(f32.ranges["after"].0 - f16.ranges["after"].0, 4096);
    fs::write(first.path().join("model.safetensors"), &f32.bytes).unwrap();
    fs::write(second.path().join("model.safetensors"), &f16.bytes).unwrap();
    let a = run(first.path(), &["model.safetensors"]);
    let b = run(second.path(), &["model.safetensors"]);
    let aa = lines(&a);
    let bb = lines(&b);
    assert_eq!(aa[0], bb[0]);
    let literal_a = String::from_utf8(a.stdout).unwrap();
    let literal_b = String::from_utf8(b.stdout).unwrap();
    let changed: Vec<_> = literal_a
        .lines()
        .zip(literal_b.lines())
        .filter(|(a, b)| a != b)
        .map(|(a, _)| serde_json::from_str::<Value>(a).unwrap()["tensor"].clone())
        .collect();
    assert_eq!(changed, [json!("changed"), json!("after")]);
    for (a, b) in aa.iter().skip(1).zip(bb.iter().skip(1)) {
        let mut expected = a.clone();
        match a["tensor"].as_str().unwrap() {
            "before" => {}
            "changed" => {
                expected["format"] = json!("F16");
                expected["length"] = json!(4096);
            }
            "after" => expected["offset"] = json!(a["offset"].as_u64().unwrap() - 4096),
            other => panic!("unexpected tensor {other}"),
        }
        assert_eq!(&expected, b);
    }
}

#[test]
fn tensors_manifest_literal_order_keys_and_nulls() {
    let dir = tempfile::tempdir().unwrap();
    let names = [
        "token_embd.weight",
        "model.layers.0.mlp.gate.weight",
        "model.layers.0.mlp.shared_expert.up_proj.weight",
        "model.layers.0.attn.weight",
        "model.layers.0.mlp.experts.0.gate_proj.weight",
        "model.layers.0.mlp.experts.0.up_proj.weight",
        "model.layers.0.mlp.experts.0.down_proj.weight",
        "model.layers.0.mlp.experts.gate_up_proj",
    ];
    let entries: Vec<_> = names
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let shape: &[u64] = if i == 7 { &[1, 1, 1] } else { &[1] };
            (*name, "U8", shape, vec![i as u8])
        })
        .collect();
    fs::write(
        dir.path().join("model.safetensors"),
        safetensors(&entries).bytes,
    )
    .unwrap();
    let output = run(dir.path(), &["model.safetensors"]);
    success(&output);
    let expected = concat!(
        "{\"manifest\":1,\"inputs\":[\"model.safetensors\"],\"generator\":\"ratarmount ",
        env!("CARGO_PKG_VERSION"),
        "\"}\n",
        "{\"file\":\"model.safetensors\",\"tensor\":\"token_embd.weight\",\"layer\":null,\"expert\":null,\"role\":\"Other\",\"format\":\"U8\",\"shape\":[1],\"offset\":4096,\"length\":1,\"aligned_4k\":true,\"sha256\":null}\n",
        "{\"file\":\"model.safetensors\",\"tensor\":\"model.layers.0.mlp.gate.weight\",\"layer\":0,\"expert\":null,\"role\":\"Router\",\"format\":\"U8\",\"shape\":[1],\"offset\":4097,\"length\":1,\"aligned_4k\":false,\"sha256\":null}\n",
        "{\"file\":\"model.safetensors\",\"tensor\":\"model.layers.0.mlp.shared_expert.up_proj.weight\",\"layer\":0,\"expert\":null,\"role\":\"SharedExpert\",\"format\":\"U8\",\"shape\":[1],\"offset\":4098,\"length\":1,\"aligned_4k\":false,\"sha256\":null}\n",
        "{\"file\":\"model.safetensors\",\"tensor\":\"model.layers.0.attn.weight\",\"layer\":0,\"expert\":null,\"role\":\"Other\",\"format\":\"U8\",\"shape\":[1],\"offset\":4099,\"length\":1,\"aligned_4k\":false,\"sha256\":null}\n",
        "{\"file\":\"model.safetensors\",\"tensor\":\"model.layers.0.mlp.experts.0.gate_proj.weight\",\"layer\":0,\"expert\":0,\"role\":\"Gate\",\"format\":\"U8\",\"shape\":[1],\"offset\":4100,\"length\":1,\"aligned_4k\":false,\"sha256\":null}\n",
        "{\"file\":\"model.safetensors\",\"tensor\":\"model.layers.0.mlp.experts.0.up_proj.weight\",\"layer\":0,\"expert\":0,\"role\":\"Up\",\"format\":\"U8\",\"shape\":[1],\"offset\":4101,\"length\":1,\"aligned_4k\":false,\"sha256\":null}\n",
        "{\"file\":\"model.safetensors\",\"tensor\":\"model.layers.0.mlp.experts.0.down_proj.weight\",\"layer\":0,\"expert\":0,\"role\":\"Down\",\"format\":\"U8\",\"shape\":[1],\"offset\":4102,\"length\":1,\"aligned_4k\":false,\"sha256\":null}\n",
        "{\"file\":\"model.safetensors\",\"tensor\":\"model.layers.0.mlp.experts.gate_up_proj\",\"layer\":0,\"expert\":0,\"role\":\"GateUp\",\"format\":\"U8\",\"shape\":[1,1],\"offset\":4103,\"length\":1,\"aligned_4k\":false,\"sha256\":null}\n",
    );
    assert_eq!(output.stdout, expected.as_bytes());
}

#[test]
fn tensors_manifest_shards_and_independent_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let a = safetensors(&[
        (
            "model.layers.0.mlp.experts.0.gate_proj.weight",
            "U8",
            &[2],
            vec![11, 12],
        ),
        (
            "model.layers.0.mlp.experts.0.up_proj.weight",
            "U8",
            &[2],
            vec![13, 14],
        ),
        (
            "model.layers.0.mlp.experts.0.down_proj.weight",
            "U8",
            &[2],
            vec![15, 16],
        ),
        ("model.layers.0.mlp.gate.weight", "U8", &[2], vec![17, 18]),
    ]);
    let b = safetensors(&[
        (
            "model.layers.1.block_sparse_moe.experts.1.w1.weight",
            "U8",
            &[2],
            vec![21, 22],
        ),
        (
            "model.layers.1.block_sparse_moe.experts.1.w3.weight",
            "U8",
            &[2],
            vec![23, 24],
        ),
        (
            "model.layers.1.block_sparse_moe.experts.1.w2.weight",
            "U8",
            &[2],
            vec![25, 26],
        ),
        (
            "model.layers.1.mlp.shared_expert.up_proj.weight",
            "U8",
            &[2],
            vec![27, 28],
        ),
        ("embedding.weight", "U8", &[2], vec![29, 30]),
    ]);
    fs::write(dir.path().join("a.safetensors"), &a.bytes).unwrap();
    fs::write(dir.path().join("b.safetensors"), &b.bytes).unwrap();
    let weight_map: BTreeMap<_, _> = a
        .ranges
        .keys()
        .map(|name| (name.clone(), "a.safetensors"))
        .chain(b.ranges.keys().map(|name| (name.clone(), "b.safetensors")))
        .collect();
    fs::write(
        dir.path().join("model.safetensors.index.json"),
        serde_json::to_vec(&json!({"weight_map":weight_map})).unwrap(),
    )
    .unwrap();
    let output = run(dir.path(), &["model.safetensors.index.json", "--hash"]);
    let parsed = lines(&output);
    assert_eq!(parsed.len(), 10);
    let mut coverage = BTreeMap::<String, u64>::new();
    for row in &parsed[1..] {
        let name = row["tensor"].as_str().unwrap();
        let shard = weight_map[name];
        assert_eq!(row["file"], shard);
        let fixture = if shard == "a.safetensors" { &a } else { &b };
        let (begin, end) = fixture.ranges[name];
        assert_eq!(row["offset"], begin);
        assert_eq!(row["length"], end - begin);
        let digest = format!("{:x}", Sha256::digest(&fixture.bytes[begin..end]));
        assert_eq!(row["sha256"], digest);
        assert_eq!(digest.len(), 64);
        assert!(digest
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        *coverage.entry(shard.to_string()).or_default() += row["length"].as_u64().unwrap();
    }
    assert_eq!(coverage["a.safetensors"], (a.bytes.len() - a.start) as u64);
    assert_eq!(coverage["b.safetensors"], (b.bytes.len() - b.start) as u64);
}

#[test]
fn tensors_manifest_custom_pattern_and_output_file() {
    let dir = tempfile::tempdir().unwrap();
    let fixture = safetensors(&[
        ("ffn.7.ex.2.down.weight", "U8", &[1], vec![1]),
        ("ffn.7.ex.2.up.weight", "U8", &[1], vec![2]),
        ("ffn.7.ex.2.gate.weight", "U8", &[1], vec![3]),
    ]);
    fs::write(dir.path().join("model.safetensors"), fixture.bytes).unwrap();
    let pattern = r"ffn\.(?P<layer>\d+)\.ex\.(?P<expert>\d+)\.(?P<role>gate|up|down)\.weight";
    let args = ["model.safetensors", "--expert-pattern", pattern];
    let stdout = run(dir.path(), &args);
    let parsed = lines(&stdout);
    assert_eq!(parsed[1]["role"], "Gate");
    assert_eq!(parsed[2]["role"], "Up");
    assert_eq!(parsed[3]["role"], "Down");
    for row in &parsed[1..] {
        assert_eq!(row["layer"], 7);
        assert_eq!(row["expert"], 2);
    }
    let mut output_args = args.to_vec();
    output_args.extend(["-o", "manifest.jsonl"]);
    let output = run(dir.path(), &output_args);
    success(&output);
    assert!(output.stdout.is_empty());
    assert_eq!(
        fs::read(dir.path().join("manifest.jsonl")).unwrap(),
        stdout.stdout
    );
    refusal(&run(dir.path(), &output_args), "manifest.jsonl");
    assert_eq!(
        fs::read(dir.path().join("manifest.jsonl")).unwrap(),
        stdout.stdout
    );
    refusal(
        &run(dir.path(), &["missing.safetensors", "-o", "missing.jsonl"]),
        "missing.safetensors",
    );
    assert!(!dir.path().join("missing.jsonl").exists());
}

#[test]
fn tensors_manifest_argument_and_duplicate_refusals() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("model.safetensors"),
        safetensors(&[("x", "U8", &[1], vec![1])]).bytes,
    )
    .unwrap();
    refusal(
        &run(dir.path(), &["hf://x"]),
        "remote inputs are not supported",
    );
    refusal(&run(dir.path(), &["hf://x"]), "scheme://");
    refusal(&run(dir.path(), &["hf://x"]), "local path");
    refusal(
        &run(dir.path(), &["model.safetensors", "model.safetensors"]),
        "given more than once",
    );
    refusal(
        &run(
            dir.path(),
            &[
                "model.safetensors",
                "--expert-pattern",
                r"(?P<layer>\d+)\.(?P<expert>\d+)",
            ],
        ),
        "role",
    );
}

/// Regression: an invalid standalone pattern must not escape whole-name anchoring.
#[test]
fn tensors_manifest_malformed_expert_pattern_refused() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("model.safetensors"),
        safetensors(&[("prefix.ffn.7.ex.2.gate", "U8", &[1], vec![1])]).bytes,
    )
    .unwrap();
    let output = run(
        dir.path(),
        &[
            "model.safetensors",
            "--expert-pattern",
            r"a^)|ffn\.(?P<layer>\d+)\.ex\.(?P<expert>\d+)\.(?P<role>gate)(?:",
        ],
    );
    refusal(&output, "invalid expert pattern");
    assert!(output.stdout.is_empty());
}

/// Regression: a positional root array cannot stand in for the named weight_map field.
#[test]
fn tensors_manifest_root_array_index_refused() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("s.safetensors"),
        safetensors(&[("a", "U8", &[1], vec![1])]).bytes,
    )
    .unwrap();
    fs::write(
        dir.path().join("model.index.json"),
        br#"[{"a":"s.safetensors"}]"#,
    )
    .unwrap();
    let output = run(dir.path(), &["model.index.json"]);
    refusal(&output, "weight_map");
    assert!(output.stdout.is_empty());
}

#[test]
fn tensors_manifest_output_failure_removes_partial_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("partial.jsonl");
    let result = tensors_cmd::write_output(&path, |out| {
        out.write_all(&[b'x'; 20_000])?;
        Err(io::Error::other("injected write failure").into())
    });
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("injected write failure"));
    assert!(!path.exists());

    // Also exercise run from the included production module, keeping this
    // failure seam in the same targeted integration test as the binary paths.
    let input = dir.path().join("model.safetensors");
    fs::write(&input, safetensors(&[("x", "U8", &[1], vec![1])]).bytes).unwrap();
    let args = tensors_cmd::TensorsArgs::try_parse_from([
        "ratarmount tensors",
        "manifest",
        input.to_str().unwrap(),
        "-o",
        path.to_str().unwrap(),
    ])
    .unwrap();
    tensors_cmd::run(&args).unwrap();
    assert!(path.is_file());
}

#[test]
fn tensors_manifest_stdout_flush_failure_exits_two() {
    let dir = tempfile::tempdir().unwrap();
    let full = match OpenOptions::new().write(true).open("/dev/full") {
        Ok(full) => full,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            eprintln!("skip: /dev/full is unavailable");
            return;
        }
        Err(error) => panic!("open /dev/full: {error}"),
    };
    fs::write(
        dir.path().join("model.safetensors"),
        safetensors(&[("x", "U8", &[1], vec![1])]).bytes,
    )
    .unwrap();
    let output = command(dir.path(), &["model.safetensors"])
        .stdout(Stdio::from(full))
        .output()
        .unwrap();
    refusal(&output, "tensors:");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
}

#[test]
fn tensors_manifest_stdout_dead_before_launch_is_neutralized() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("model.safetensors"),
        safetensors(&[("x", "U8", &[1], vec![1])]).bytes,
    )
    .unwrap();
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let output = command(dir.path(), &["model.safetensors"])
        .stdout(Stdio::from(writer))
        .output()
        .unwrap();
    success(&output);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
}

#[test]
fn tensors_manifest_writerless_fifo_refused_without_hanging() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("shard.safetensors");
    let status = match Command::new("mkfifo").arg(&fifo).status() {
        Ok(status) => status,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            eprintln!("skip: mkfifo is unavailable; library directory refusal tests regular-file validation");
            return;
        }
        Err(error) => panic!("mkfifo: {error}"),
    };
    assert!(status.success());
    fs::write(
        dir.path().join("model.index.json"),
        br#"{"weight_map":{"x":"shard.safetensors"}}"#,
    )
    .unwrap();
    for input in ["shard.safetensors", "model.index.json"] {
        let mut child = command(dir.path(), &[input])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("manifest blocked opening writerless FIFO {input}");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        refusal(&child.wait_with_output().unwrap(), "not a regular file");
    }
}
