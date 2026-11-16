//! Deterministic byte maps for local checkpoints, independent of mounting.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::File;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, LazyLock};

use regex::Regex;
use same_file::Handle;
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};

use crate::{elements, gguf::ggml_layout, invalid, parse, Layout, Result, Tensor, MAX_HEADER_SIZE};

pub(crate) const MAX_EXPERTS: u64 = 65_536;
pub(crate) const MAX_ROWS: usize = 16_777_216;
const HASH_BUFFER_SIZE: usize = 1024 * 1024;

/// Declaration order is the manifest's role sort order.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
pub enum Role {
    Gate,
    Up,
    Down,
    GateUp,
    Router,
    SharedExpert,
    Other,
}

/// One contiguous tensor or expert range. Field order is the JSONL contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ManifestRow {
    pub file: PathBuf,
    pub tensor: String,
    pub layer: Option<u32>,
    pub expert: Option<u32>,
    pub role: Role,
    pub format: String,
    pub shape: Vec<u64>,
    pub offset: u64,
    pub length: u64,
    pub aligned_4k: bool,
    pub sha256: Option<String>,
}

#[derive(Debug)]
pub struct ExpertPattern(Regex);

#[derive(Debug, Default)]
pub struct ManifestOptions {
    pub hash: bool,
    pub expert_pattern: Option<ExpertPattern>,
}

#[derive(Debug)]
pub struct Manifest {
    pub inputs: Vec<PathBuf>,
    pub rows: Vec<ManifestRow>,
}

pub fn compile_expert_pattern(pattern: &str) -> Result<ExpertPattern> {
    // Reject syntax that could close the wrapper and escape whole-name anchoring.
    Regex::new(pattern).map_err(|e| invalid(format!("invalid expert pattern: {e}")))?;
    let regex = Regex::new(&format!(r"\A(?:{pattern})\z"))
        // A trailing verbose-mode comment can swallow the closing wrapper.
        // Only add a newline on failure, so ordinary literal newlines are unchanged.
        .or_else(|_| Regex::new(&format!("\\A(?:{pattern}\n)\\z")))
        .map_err(|e| invalid(format!("invalid expert pattern: {e}")))?;
    for name in ["layer", "expert", "role"] {
        if !regex.capture_names().flatten().any(|n| n == name) {
            return Err(invalid(format!(
                "expert pattern missing named group {name}"
            )));
        }
    }
    Ok(ExpertPattern(regex))
}

static DEFAULT_EXPERT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:.*\.)?layers\.(?P<layer>\d+)\.(?:mlp|block_sparse_moe)\.experts\.(?P<expert>\d+)\.(?P<role>gate_proj|up_proj|down_proj|w1|w3|w2)\.weight$")
        .expect("constant expert regex")
});
static FUSED: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:.*\.)?experts\.gate_up_proj(?:\.weight)?$").expect("constant fused regex")
});
static GGUF_EXPERT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^blk\.(\d+)\.ffn_(gate|up|down)_exps\.weight$")
        .expect("constant GGUF expert regex")
});
static GGUF_ROUTER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^blk\.(\d+)\.ffn_gate_inp\.weight$").expect("constant GGUF router regex")
});
static ST_ROUTER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(?:.*\.)?layers\.(\d+)\.(?:mlp|block_sparse_moe)\.gate\.weight$")
        .expect("constant safetensors router regex")
});
static GGUF_LAYER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|\.)blk\.(\d+)\.").expect("constant layer regex"));
static ST_LAYER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:^|\.)layers\.(\d+)\.").expect("constant layer regex"));
static SHARED: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\.shared_experts?\.").expect("constant shared regex"));

fn number(value: &str) -> Result<u32> {
    value
        .parse()
        .map_err(|_| invalid(format!("layer/expert capture {value:?} is not a u32")))
}

fn role(value: &str, custom: bool) -> Result<Role> {
    Ok(match value {
        "gate_proj" | "w1" => Role::Gate,
        "up_proj" | "w3" => Role::Up,
        "down_proj" | "w2" => Role::Down,
        "gate_up_proj" if custom => Role::GateUp,
        "gate" if custom => Role::Gate,
        "up" if custom => Role::Up,
        "down" if custom => Role::Down,
        "gate_up" if custom => Role::GateUp,
        _ => return Err(invalid(format!("unsupported expert role {value:?}"))),
    })
}

fn mul(a: u64, b: u64) -> Result<u64> {
    a.checked_mul(b)
        .ok_or_else(|| invalid("merged expert size overflow"))
}

fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b)
        .ok_or_else(|| invalid("merged expert offset overflow"))
}

fn check_count(n: u64, remaining: usize) -> Result<()> {
    if n == 0 || n > MAX_EXPERTS {
        return Err(invalid(format!(
            "n_expert {n} is outside the merged expert count limit 1..={MAX_EXPERTS}"
        )));
    }
    check_rows(n, remaining)
}

fn check_rows(n: u64, remaining: usize) -> Result<()> {
    if n > remaining as u64 {
        return Err(invalid("total manifest row limit exceeded"));
    }
    Ok(())
}

/// The production splitter; the remaining-row budget is checked before expansion.
pub(crate) fn tensor_rows(
    tensor: &Tensor,
    file: &Path,
    opts: &ManifestOptions,
    remaining: usize,
) -> Result<Vec<ManifestRow>> {
    tensor_rows_inner(tensor, file, opts, remaining)
        .map_err(|e| invalid(format!("{}: tensor {}: {e}", file.display(), tensor.name)))
}

fn tensor_rows_inner(
    tensor: &Tensor,
    file: &Path,
    opts: &ManifestOptions,
    remaining: usize,
) -> Result<Vec<ManifestRow>> {
    let name = &tensor.name;
    let (format, shape, layer_regex) = match &tensor.layout {
        Layout::Safetensors { dtype, shape, .. } => (dtype.clone(), shape, &*ST_LAYER),
        Layout::Gguf { ty, dims } => (
            ggml_layout(*ty)
                .map(|l| l.0.to_owned())
                .unwrap_or_else(|| format!("UNKNOWN({ty})")),
            dims,
            &*GGUF_LAYER,
        ),
    };
    let mut row = ManifestRow {
        file: file.to_path_buf(),
        tensor: name.clone(),
        layer: None,
        expert: None,
        role: Role::Other,
        format,
        shape: shape.clone(),
        offset: tensor.offset,
        length: tensor.size,
        aligned_4k: tensor.offset.is_multiple_of(4096),
        sha256: None,
    };
    let split = match &tensor.layout {
        Layout::Gguf { ty, dims } => {
            if let Some(c) = GGUF_EXPERT.captures(name) {
                row.layer = Some(number(&c[1])?);
                row.role = match &c[2] {
                    "gate" => Role::Gate,
                    "up" => Role::Up,
                    "down" => Role::Down,
                    _ => unreachable!("constant role regex"),
                };
                if dims.len() != 3 {
                    return Err(invalid("merged GGUF expert tensor requires exactly 3 dims"));
                }
                let n = dims[2];
                check_count(n, remaining)?;
                let (_, block, bytes) = ggml_layout(*ty).ok_or_else(|| {
                    invalid(format!(
                        "cannot split merged expert tensor: unknown ggml type {ty}"
                    ))
                })?;
                let slice = mul(dims[1], mul(dims[0] / block, bytes)?)?;
                if tensor.size != mul(n, slice)? {
                    return Err(invalid(
                        "merged expert length does not equal n_expert * slice_bytes",
                    ));
                }
                Some((n, slice, dims[..2].to_vec()))
            } else {
                if let Some(c) = GGUF_ROUTER.captures(name) {
                    row.layer = Some(number(&c[1])?);
                    row.role = Role::Router;
                } else if name.contains("_shexp") {
                    row.role = Role::SharedExpert;
                }
                None
            }
        }
        Layout::Safetensors {
            dtype,
            shape,
            size_checked,
        } => {
            if FUSED.is_match(name) {
                // A matrix has no expert axis; keep it as one unclassified tensor.
                if shape.len() == 2 {
                    None
                } else {
                    if shape.len() != 3 {
                        return Err(invalid(
                            "merged safetensors expert tensor requires exactly 3 dims",
                        ));
                    }
                    let n = shape[0];
                    check_count(n, remaining)?;
                    if !tensor.size.is_multiple_of(n) {
                        return Err(invalid(format!(
                            "merged expert length {} is not a multiple of n_expert {n}",
                            tensor.size
                        )));
                    }
                    let slice = tensor.size / n;
                    if *size_checked {
                        let bits = crate::safetensors::dtype_bits(dtype)
                            .ok_or_else(|| invalid("missing validated dtype layout"))?;
                        if mul(slice, 8)? != mul(elements(&shape[1..])?, bits)? {
                            return Err(invalid("merged expert slice shape/dtype size mismatch"));
                        }
                    }
                    row.role = Role::GateUp;
                    Some((n, slice, shape[1..].to_vec()))
                }
            } else if let Some(c) = opts
                .expert_pattern
                .as_ref()
                .map(|p| &p.0)
                .unwrap_or(&DEFAULT_EXPERT)
                .captures(name)
            {
                let capture = |key| {
                    c.name(key).map(|m| m.as_str()).ok_or_else(|| {
                        invalid(format!("expert pattern group {key} did not participate"))
                    })
                };
                row.layer = Some(number(capture("layer")?)?);
                row.expert = Some(number(capture("expert")?)?);
                row.role = role(capture("role")?, opts.expert_pattern.is_some())?;
                None
            } else {
                if let Some(c) = ST_ROUTER.captures(name) {
                    row.layer = Some(number(&c[1])?);
                    row.role = Role::Router;
                } else if SHARED.is_match(name) {
                    row.role = Role::SharedExpert;
                }
                None
            }
        }
    };
    if row.layer.is_none() {
        row.layer = layer_regex
            .captures(name)
            .map(|c| number(&c[1]))
            .transpose()?;
    }
    if let Some((n, slice, shape)) = split {
        if tensor.size == 0 || slice == 0 {
            return Err(invalid(
                "zero-byte merged expert tensor has no expert bytes to map",
            ));
        }
        let mut rows = Vec::with_capacity(n as usize);
        let mut end = tensor.offset;
        for e in 0..n {
            let offset = add(tensor.offset, mul(e, slice)?)?;
            if offset != end {
                return Err(invalid("merged expert ranges are not contiguous"));
            }
            end = add(offset, slice)?;
            rows.push(ManifestRow {
                expert: Some(e as u32),
                shape: shape.clone(),
                offset,
                length: slice,
                aligned_4k: offset.is_multiple_of(4096),
                ..row.clone()
            });
        }
        if end != add(tensor.offset, tensor.size)? {
            return Err(invalid("merged expert ranges do not cover tensor bytes"));
        }
        Ok(rows)
    } else {
        check_rows(1, remaining)?;
        Ok(vec![row])
    }
}

struct Input {
    path: PathBuf,
    handle: Handle,
    length: u64,
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| invalid(format!("{}: non-UTF-8 path", path.display())))
}

fn local_path(path: &Path) -> Result<()> {
    if path_text(path)?.contains("://") {
        return Err(invalid(format!("{}: remote inputs are not supported; scheme paths (scheme://) are refused; pass a local path", path.display())));
    }
    Ok(())
}

pub(crate) fn open_error(path: &Path, error: std::io::Error) -> crate::TensorsError {
    // Linux/macOS report EMFILE (24); Rust's Windows file API instead reports
    // Win32 ERROR_TOO_MANY_OPEN_FILES (4), not the CRT errno. The standard OS
    // constant selects the numeric code without target cfgs (inventory rule N4)
    // or another platform-specific acquisition API.
    let too_many_files = if std::env::consts::OS == "windows" {
        4
    } else {
        24
    };
    if error.raw_os_error() == Some(too_many_files) {
        invalid(format!(
            "{}: too many shards open; raise ulimit -n",
            path.display()
        ))
    } else {
        invalid(format!("{}: {error}", path.display()))
    }
}

fn open_input(
    path: &Path,
    inputs: &mut Vec<Input>,
    identities: &mut HashMap<u64, Vec<usize>>,
) -> Result<usize> {
    local_path(path)?;
    let before = std::fs::metadata(path).map_err(|e| open_error(path, e))?;
    if !before.is_file() {
        return Err(invalid(format!("{}: not a regular file", path.display())));
    }
    #[expect(
        clippy::disallowed_methods,
        reason = r#"internal-read:v1 {"id":"IR-R2-TENSORS-INPUT","item":"ratarmount_formats_tensors::manifest::open_input","disposition":"residual","category":"factory-and-format-readers","reason":"Read a user-selected local checkpoint or safetensors index using the same descriptor for identity, parsing and hashing","creation":{"policy":"none","basis":"Existing regular input only; no pathname is created"}}"#
    )]
    let file = File::open(path).map_err(|e| open_error(path, e))?;
    let after = file.metadata().map_err(|e| open_error(path, e))?;
    if !after.is_file() || before.len() != after.len() {
        return Err(invalid(format!(
            "{}: not a regular file or length changed while opening",
            path.display()
        )));
    }
    let handle = Handle::from_file(file).map_err(|e| open_error(path, e))?;
    let mut hasher = DefaultHasher::new();
    handle.hash(&mut hasher);
    let identity = hasher.finish();
    if identities
        .get(&identity)
        .is_some_and(|indices| indices.iter().any(|&i| inputs[i].handle == handle))
    {
        return Err(invalid(format!("{} given more than once", path.display())));
    }
    // Store indices by identity hash, checking equality on collisions, so the
    // descriptor used for identity is also the sole parser/hash descriptor.
    identities.entry(identity).or_default().push(inputs.len());
    inputs.push(Input {
        path: path.to_path_buf(),
        handle,
        length: after.len(),
    });
    Ok(inputs.len() - 1)
}

struct ShardIndex {
    weight_map: WeightMap,
}

impl<'de> Deserialize<'de> for ShardIndex {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct IndexVisitor;
        impl<'de> Visitor<'de> for IndexVisitor {
            type Value = ShardIndex;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an index object with a weight_map field")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut weight_map = None;
                while let Some(key) = map.next_key::<String>()? {
                    if key == "weight_map" {
                        if weight_map.is_some() {
                            return Err(serde::de::Error::duplicate_field("weight_map"));
                        }
                        weight_map = Some(map.next_value()?);
                    } else {
                        map.next_value::<serde::de::IgnoredAny>()?;
                    }
                }
                Ok(ShardIndex {
                    weight_map: weight_map
                        .ok_or_else(|| serde::de::Error::missing_field("weight_map"))?,
                })
            }
        }
        deserializer.deserialize_map(IndexVisitor)
    }
}

struct WeightMap(BTreeMap<String, String>);

impl<'de> Deserialize<'de> for WeightMap {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        struct MapVisitor;
        impl<'de> Visitor<'de> for MapVisitor {
            type Value = WeightMap;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a unique string-to-string weight_map")
            }
            fn visit_map<A: MapAccess<'de>>(
                self,
                mut map: A,
            ) -> std::result::Result<Self::Value, A::Error> {
                let mut values = BTreeMap::new();
                while let Some((name, shard)) = map.next_entry::<String, String>()? {
                    if values.insert(name, shard).is_some() {
                        return Err(serde::de::Error::custom("duplicate weight_map tensor"));
                    }
                }
                Ok(WeightMap(values))
            }
        }
        deserializer.deserialize_map(MapVisitor)
    }
}

fn shard_name(name: &str) -> Result<()> {
    let mut components = Path::new(name).components();
    if name.contains(['\0', '\\', '/'])
        || !matches!(components.next(), Some(Component::Normal(_)))
        || components.next().is_some()
    {
        return Err(invalid(format!(
            "weight_map shard {name:?} is not a plain file name"
        )));
    }
    Ok(())
}

fn no_overlaps(tensors: &[Tensor]) -> Result<()> {
    let mut ordered: Vec<_> = tensors.iter().filter(|t| t.size > 0).collect();
    ordered.sort_by_key(|t| t.offset);
    let mut furthest: Option<(u64, &str)> = None;
    for tensor in ordered {
        let end = add(tensor.offset, tensor.size)?;
        if let Some((max_end, name)) = furthest {
            if tensor.offset < max_end {
                return Err(invalid(format!(
                    "overlapping tensor ranges: {name} and {}",
                    tensor.name
                )));
            }
        }
        if furthest.is_none_or(|(max_end, _)| end > max_end) {
            furthest = Some((end, &tensor.name));
        }
    }
    Ok(())
}

/// Hash using the descriptor used to parse; reject length changes, even growth.
pub(crate) fn hash_rows(
    file: &mut File,
    path: &Path,
    parsed_len: u64,
    rows: &mut [ManifestRow],
) -> Result<()> {
    let mut buffer = vec![0; HASH_BUFFER_SIZE];
    for row in rows {
        let context = |e| invalid(format!("{}: tensor {}: {e}", path.display(), row.tensor));
        if file.metadata().map_err(context)?.len() != parsed_len {
            return Err(context(std::io::Error::other(
                "file length changed between parse and hash read",
            )));
        }
        file.seek(SeekFrom::Start(row.offset)).map_err(context)?;
        let mut left = row.length;
        let mut hash = Sha256::new();
        while left > 0 {
            let n = left.min(buffer.len() as u64) as usize;
            file.read_exact(&mut buffer[..n]).map_err(|e| {
                if e.kind() == std::io::ErrorKind::UnexpectedEof {
                    context(std::io::Error::other(
                        "file length changed between parse and hash read",
                    ))
                } else {
                    context(e)
                }
            })?;
            hash.update(&buffer[..n]);
            left -= n as u64;
        }
        if file.metadata().map_err(context)?.len() != parsed_len {
            return Err(context(std::io::Error::other(
                "file length changed between parse and hash read",
            )));
        }
        row.sha256 = Some(format!("{:x}", hash.finalize()));
    }
    Ok(())
}

pub fn build_manifest(inputs: &[PathBuf], opts: &ManifestOptions) -> Result<Manifest> {
    build_manifest_with_limit(inputs, opts, MAX_ROWS)
}

pub(crate) fn build_manifest_with_limit(
    inputs: &[PathBuf],
    opts: &ManifestOptions,
    max_rows: usize,
) -> Result<Manifest> {
    // Refuse all scheme inputs before any filesystem access.
    for path in inputs {
        local_path(path)?;
    }
    let mut opened = Vec::new();
    let mut identities = HashMap::new();
    let mut pending = Vec::new();
    for path in inputs {
        let i = open_input(path, &mut opened, &mut identities)?;
        if path_text(path)?.ends_with(".index.json") {
            let input = &mut opened[i];
            if input.length > MAX_HEADER_SIZE {
                return Err(invalid(format!(
                    "{}: index JSON too large (limit 100 MiB)",
                    path.display()
                )));
            }
            let mut bytes = Vec::new();
            input
                .handle
                .as_file_mut()
                .take(MAX_HEADER_SIZE + 1)
                .read_to_end(&mut bytes)
                .map_err(|e| open_error(path, e))?;
            if bytes.len() as u64 > MAX_HEADER_SIZE {
                return Err(invalid(format!(
                    "{}: index JSON too large (limit 100 MiB)",
                    path.display()
                )));
            }
            let index: ShardIndex = serde_json::from_slice(&bytes)
                .map_err(|e| invalid(format!("{}: {e}", path.display())))?;
            let map = Arc::new(index.weight_map.0);
            let shards: BTreeSet<_> = map.values().cloned().collect();
            for name in &shards {
                shard_name(name).map_err(|e| invalid(format!("{}: {e}", path.display())))?;
            }
            for name in shards {
                let shard = path.parent().unwrap_or_else(|| Path::new("")).join(&name);
                let j = open_input(&shard, &mut opened, &mut identities)?;
                pending.push((j, Some((name, map.clone()))));
            }
        } else {
            pending.push((i, None));
        }
    }
    let mut rows = Vec::new();
    for (i, mapping) in pending {
        let input = &mut opened[i];
        let parsed = parse(input.handle.as_file_mut(), input.length)
            .map_err(|e| invalid(format!("{}: {e}", input.path.display())))?;
        no_overlaps(&parsed.tensors)
            .map_err(|e| invalid(format!("{}: {e}", input.path.display())))?;
        if let Some((name, map)) = &mapping {
            if parsed.raw_header.is_none() {
                return Err(invalid(format!(
                    "{}: index shard must be safetensors",
                    input.path.display()
                )));
            }
            let names: BTreeSet<_> = parsed.tensors.iter().map(|t| t.name.as_str()).collect();
            for (tensor, shard) in map.iter() {
                if shard == name && !names.contains(tensor.as_str()) {
                    return Err(invalid(format!(
                        "{}: tensor {tensor} is missing from shard {name}",
                        input.path.display()
                    )));
                }
            }
            for tensor in &parsed.tensors {
                match map.get(&tensor.name) {
                    None => {
                        return Err(invalid(format!(
                            "{}: tensor {} is not in weight_map",
                            input.path.display(),
                            tensor.name
                        )))
                    }
                    Some(other) if other != name => {
                        return Err(invalid(format!(
                            "{}: tensor {} in {name} is mapped to {other}",
                            input.path.display(),
                            tensor.name
                        )))
                    }
                    Some(_) => (),
                }
            }
        }
        let begin = rows.len();
        for tensor in parsed.tensors {
            rows.extend(tensor_rows(
                &tensor,
                &input.path,
                opts,
                max_rows - rows.len(),
            )?);
        }
        if opts.hash {
            hash_rows(
                input.handle.as_file_mut(),
                &input.path,
                input.length,
                &mut rows[begin..],
            )?;
        }
    }
    rows.sort_by(|a, b| {
        (a.layer, a.expert, a.role, &a.file, a.offset, &a.tensor)
            .cmp(&(b.layer, b.expert, b.role, &b.file, b.offset, &b.tensor))
    });
    Ok(Manifest {
        inputs: inputs.to_vec(),
        rows,
    })
}

pub fn write_jsonl(manifest: &Manifest, generator: &str, out: &mut dyn Write) -> Result<()> {
    #[derive(Serialize)]
    struct Header<'a> {
        manifest: u32,
        inputs: &'a [PathBuf],
        generator: &'a str,
    }
    serde_json::to_writer(
        &mut *out,
        &Header {
            manifest: 1,
            inputs: &manifest.inputs,
            generator,
        },
    )?;
    writeln!(out)?;
    for row in &manifest.rows {
        serde_json::to_writer(&mut *out, row)?;
        writeln!(out)?;
    }
    Ok(())
}
