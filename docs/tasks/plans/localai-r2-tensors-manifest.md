# Local AI R2: `ratarmount tensors manifest` (expert manifest with per-tensor format)

**Status:** plan, not started (2026-11-01). Baseline `main` at `b84f8839527f546112ffc281146edcd8e0b1dbb5`. Branch `plan/localai-r2-tensors-manifest`.
**Source:** Matt's local-AI plan §5 "R2. Expert manifest with per-tensor format" (handoff copy `/workspace/handoffs/ratarmount-r2-tensors-manifest-spec.md`). Matt OK'd the work 2026-11-01 6:07 PM ET (relayed by Keystone, 6:08 PM ET).
**Dependencies:** none. R2 does not depend on R1a/R1b/R1c.
**Hands off:** R2 does **not** touch sandbox, supervisor or journal code: nothing under `ratarmount/src/sandbox/`, not `ratarmount/src/journal_cmd.rs`, not `ratarmount-fuse/src/oplog*`, not the compositing journal (`classify_mount_journal`, `recover_journal_at`), not `ratarmount/tests/sandbox.rs` or `fuse_journal.rs`, not `clients/python/ratarmount_sandbox.py`. Mud Turtle is working on R1c there. The only shared file is `ratarmount/src/main.rs` (three additive lines next to the existing verb dispatch, §5.6); if R1c edits the same hunk, whichever lands second rebases its own branch, no edits to R1c's lines.
**Gate:** every `AGENTS.md` CI command (fmt, clippy `-D warnings`, `cargo test --workspace`, both internal-read policy scripts) before every commit; an `AGENTS.md` regression-catalog row for each new test filter.
**Effort:** 3 to 4 days (spec).

## Files touched

New:
- `ratarmount-formats-tensors/src/manifest.rs` (library: types, `build_manifest`, JSONL writer).
- `ratarmount-formats-tensors/src/manifest_tests.rs` (unit tests, `#[cfg(test)]`, acceptance tests 1–5 plus refusals).
- `ratarmount/src/tensors_cmd.rs` (CLI verb).
- `ratarmount/tests/tensors_manifest.rs` (CLI integration test; acceptance test 6 and the CLI paths of 2 and 5).

Modified:
- `ratarmount-formats-tensors/src/lib.rs`: `mod manifest; pub use manifest::*` items; add typed layout info to the private `Tensor` struct (§5.1); no behaviour change for mounts.
- `ratarmount-formats-tensors/src/gguf.rs`, `src/safetensors.rs`: fill the new typed field where `Tensor` is built (one line each). Parsing and validation are unchanged.
- `ratarmount-formats-tensors/src/tests.rs`: existing fixture builders (`safetensors`, `tensor`, `gguf`, `GgTensor`, `string`) become `pub(crate)` so `manifest_tests.rs` reuses them. No test changes.
- `ratarmount-formats-tensors/Cargo.toml`: add `regex = "1"` and `sha2 = "0.10"` (both already in `Cargo.lock` via other workspace crates: regex 1.13.1, sha2 0.10.9; no new crates downloaded).
- `ratarmount/Cargo.toml`: add `ratarmount-formats-tensors.workspace = true` (workspace entry exists at root `Cargo.toml:72`).
- `ratarmount/src/main.rs`: `mod tensors_cmd;`, one `#[arg(skip)] tensors_command: Option<tensors_cmd::TensorsArgs>` field, one `raw[1] == "tensors"` pre-parse branch and one dispatch block, copied from the `journal` pattern (`main.rs:598`, `:835-843`, `:1612-1618`). Journal lines themselves are not edited.
- `packaging/internal-read-clippy/manifest.json`: reviewed entries for the new `#[expect(clippy::disallowed_methods)]` sites (§5.7). Generated as a candidate by the existing generator, then reviewed; CI never refreshes approvals.
- `docs/formats-tensors.md`: new "Expert manifest" section with the JSONL format; the "Sharded checkpoints" paragraph gains one sentence saying the manifest (not the mount) follows `weight_map`.
- `CHANGELOG.md` (Unreleased), `AGENTS.md` (regression catalog rows), `docs/tasks/plans/local-ai-roadmap.md` (R2 status line only if the roadmap tracks R items; otherwise untouched).

Not touched: `ratarmount-session/**` (no Session hook, §3), any other crate.

## 1. Goal

Give an inference engine (and the training-side R7 loader) a byte map of a local checkpoint: for every tensor, and for every expert inside a merged expert tensor, the file, absolute offset, length, storage format and logical shape, so the engine reads plain files itself. Two conversions of one checkpoint compare with `diff`/`jq`.

## 2. Scope (v1, locked)

- `ratarmount tensors manifest PATH... [-o FILE] [--hash] [--expert-pattern REGEX]`.
- Inputs: a local `.safetensors` file, a local `model.safetensors.index.json` (every shard it names), or a local `.gguf` file. Several PATHs may be mixed.
- Library: `ratarmount_formats_tensors::build_manifest(inputs, &ManifestOptions) -> Result<Manifest>` and `write_jsonl`.
- GGUF merged experts split per expert; safetensors per-expert names classified; safetensors fused `experts.gate_up_proj` split into per-expert `GateUp` rows; shards follow `weight_map`.
- JSONL output with a header line; every tensor byte covered exactly once.

## 3. Non-goals (refused or simply absent)

No reads at inference time, no prefetch, no FUSE expert serving, no dequantizing, no checkpoint writing, no `compare` command. No remote inputs: `hf://`, `http(s)://`, `file://` and any `scheme://` PATH is refused with `remote inputs are not supported`; PATHs inside archives or mounts-of-archives are not resolved (a PATH must be a regular file on the host). No `.index.json` for GGUF splits (`*-00001-of-0000N.gguf` are accepted only as individual files). **Session API hook skipped:** `Session` holds a type-erased `dyn MountSource` built by the factory and `TensorsMountSource` does not retain its input path list or parsed headers; adding `Session::tensor_manifest()` would need a downcast or a factory change. The spec allows skipping it; the CLI and library are the deliverable. No new mount behaviour: mounts, indexes and sidecar JSON are byte-identical.

## 4. Output format (documented in `docs/formats-tensors.md`)

Line 1 (header):
`{"manifest":1,"inputs":["<PATH as given>",...],"generator":"ratarmount <CARGO_PKG_VERSION>"}`

Each following line is one `ManifestRow`, serialized with serde in this key order:
`file, tensor, layer, expert, role, format, shape, offset, length, aligned_4k, sha256`.
- `file`: the shard path as given on the command line, or for index inputs `<index dir>/<weight_map value>` joined without canonicalization. Non-UTF-8 paths are refused (JSON needs strings).
- `layer`, `expert`: integers or `null`. `role`: one of `"Gate","Up","Down","GateUp","Router","SharedExpert","Other"`.
- `format`: safetensors dtype string verbatim; GGUF `ggml_layout` name, or `"UNKNOWN(<id>)"` for an unknown ggml type id.
- `shape`: logical shape of this row's slice. Safetensors: row-major, as in the header (per-expert slice drops the leading expert axis). GGUF: `ne` order as stored (`ne0` innermost), per-expert slice drops the outermost `ne2`. The doc states both conventions.
- `offset`: absolute file offset (already absolute in the parser: safetensors `8 + header_len + begin`, GGUF `data_start + info.offset`). `length` in bytes. `aligned_4k = offset % 4096 == 0`.
- `sha256`: lowercase hex with `--hash`, otherwise `null` (key always present so `jq` paths are stable).
- Sort key: `(layer, expert, role, file, offset, tensor)` with `Option` ordering `None < Some` (global tensors such as embeddings first) and `Role` in declaration order. Fully deterministic; no timestamps.
- Lines end in `\n`; output to stdout unless `-o`.

## 5. Design

### 5.1 Reuse the existing parser (no second parser)

`parse` (`lib.rs:78`) already dispatches to `gguf::parse` / `safetensors::parse`, validates every header and returns `Parsed { tensors: Vec<Tensor>, .. }` with absolute `offset` and `size`. Today the dtype/shape live only in the untyped `sidecar` JSON. Add one typed field to the private struct:

```rust
pub(crate) enum Layout {
    Safetensors { dtype: String, shape: Vec<u64>, size_checked: bool },
    Gguf { ty: u32, dims: Vec<u64> },
}
struct Tensor { name, offset, size, sidecar, layout: Layout }
```

`gguf::parse` and `safetensors::parse` set it from values they already hold. Mount code ignores the field. The manifest calls `crate::parse` and `gguf::ggml_layout` (`gguf.rs:826`) directly; it never reparses bytes.

Files are opened with `File::open` + `metadata()`; a PATH that is not a regular file (directory, FIFO, device) is refused before parsing. Each input is parsed once.

### 5.2 Public API

```rust
pub enum Role { Gate, Up, Down, GateUp, Router, SharedExpert, Other }  // serde: variant names
pub struct ManifestRow { file: PathBuf, tensor: String, layer: Option<u32>, expert: Option<u32>,
    role: Role, format: String, shape: Vec<u64>, offset: u64, length: u64,
    aligned_4k: bool, sha256: Option<String> }           // fields pub, as in the spec
pub struct ManifestOptions { pub hash: bool, pub expert_pattern: Option<regex::Regex> }
pub struct Manifest { pub inputs: Vec<PathBuf>, pub rows: Vec<ManifestRow> }
pub fn build_manifest(inputs: &[PathBuf], opts: &ManifestOptions) -> Result<Manifest>;
pub fn write_jsonl(m: &Manifest, generator: &str, out: &mut dyn Write) -> Result<()>;
pub fn compile_expert_pattern(s: &str) -> Result<regex::Regex>;  // validates named groups
```

Errors are `TensorsError::Invalid` with a message naming the file and tensor. The spec's `Result<Vec<ManifestRow>>` becomes `Result<Manifest>` so the header's input list travels with the rows; `rows` is exactly the spec's `Vec<ManifestRow>`.

### 5.3 Input classification

- Name ends in `.index.json` (case-sensitive, e.g. `model.safetensors.index.json`): safetensors index (§5.5).
- Otherwise call `parse`, which sniffs GGUF magic vs safetensors header, as the mount does. Anything that fails is refused with the parser's error.
- A file reached twice (same `(dev, ino)` from `metadata`, via two PATHs or an index plus a direct PATH) is refused (`<file> given more than once`) so no byte is counted twice. Identity is compared by `std::fs::canonicalize` result on all platforms (no target `cfg` in source, which the internal-read N4 rule refuses).

### 5.4 Classification rules

GGUF (fixed rules, regex anchored at both ends):
- `blk\.(\d+)\.ffn_(gate|up|down)_exps\.weight` → merged experts, split per expert (§5.4.1), role Gate/Up/Down.
- `blk\.(\d+)\.ffn_gate_inp\.weight` → `Router`, layer set.
- name containing `_shexp` → `SharedExpert`, layer from `blk\.(\d+)\.` if present.
- everything else → `Other`, `expert: null`, layer from `blk\.(\d+)\.` if present.

Safetensors:
- Default per-expert pattern (anchored; replaced entirely by `--expert-pattern`):
  `(?:.*\.)?layers\.(?P<layer>\d+)\.(?:mlp|block_sparse_moe)\.experts\.(?P<expert>\d+)\.(?P<role>gate_proj|up_proj|down_proj|w1|w3|w2)\.weight`
  Role map: `gate_proj|w1`→Gate, `up_proj|w3`→Up, `down_proj|w2`→Down, `gate_up_proj`→GateUp. A custom pattern must have groups `layer`, `expert`, `role` (checked by `compile_expert_pattern`; missing group = CLI error, exit 2); a `role` capture outside the map is refused naming the tensor; `layer`/`expert` must parse as `u32`.
- Fused rule (always on, not overridden): `(?:.*\.)?layers\.(?P<layer>\d+)\.(?:mlp\.)?experts\.gate_up_proj` (optionally followed by `.weight`) → split per expert along axis 0, role `GateUp`. Only `gate_up_proj` is split, per the spec; a merged `experts.down_proj` stays one `Other` row (non-blocking follow-up if R7 needs it).
- Router: `layers\.(\d+)\.(?:mlp|block_sparse_moe)\.gate\.weight` → `Router`. Shared experts: `\.shared_experts?\.` → `SharedExpert`.
- Unmatched → `Other`, `expert: null`, layer from `layers\.(\d+)\.` if present.
- The regexes are compiled once (`std::sync::LazyLock`).

#### 5.4.1 Splitting a merged tensor into experts

GGUF `*_exps.weight`: require exactly 3 dims `[ne0, ne1, n_expert]` (else refuse naming tensor). Known type: `(_, block, bytes) = ggml_layout(ty)`; `row_bytes = (ne0 / block) * bytes` (parser already guarantees `ne0 % block == 0`); `slice_bytes = ne1 * row_bytes`, all `checked_mul`. Refuse if `length != n_expert * slice_bytes`. Unknown type (`ggml_layout` is `None`, size inferred from the next offset and possibly including alignment padding): refuse (`cannot split merged expert tensor <name>: unknown ggml type <id>`). Expert `e` row: `offset + e*slice_bytes`, `length = slice_bytes`, shape `[ne0, ne1]`.

Safetensors fused `gate_up_proj`: require `shape.len() >= 2` and `shape[0] = n_expert > 0`. If the dtype size was validated (`size_checked`), `slice_bytes = length / n_expert` is exact by construction. If the dtype is unknown to `dtype_bits`, refuse unless `length % n_expert == 0` (error: `merged expert tensor <name>: length <L> is not a multiple of n_expert <N>`); then split evenly. Shape per row: `shape[1..]`.

Defensive invariant for both: `sum(rows.length) == tensor.size` and rows are contiguous; asserted in code (error, not panic).

### 5.5 Sharded safetensors

Read the index JSON with a 100 MiB cap (`MAX_HEADER_SIZE`) into `{"weight_map": {tensor: shard}}` (other keys ignored; `weight_map` missing or not a string map is refused). For each distinct shard name:
- the name must be a single normal path component: no `/`, `\`, `..`, `.`, empty, absolute, or NUL; otherwise refused (`weight_map shard <s> is not a plain file name`). Shards resolve in the index file's directory only. Symlinked shard files are followed (local, user-chosen input, same as the mount).
- parse once with `crate::parse`; must be safetensors (GGUF shard refused).
For each `weight_map` entry, the named shard must contain the tensor, else refused (spec). A tensor present in a shard header but absent from `weight_map` is also refused (`tensor <t> in <shard> is not in weight_map`) so the index and the bytes agree; tensor names in `weight_map` are unique by JSON object semantics (duplicate keys refused by reading with the same duplicate-rejecting map visitor pattern as `safetensors.rs`).

### 5.6 CLI (`ratarmount/src/tensors_cmd.rs`)

clap derive, same shape as `journal_cmd.rs`: `TensorsArgs { #[command(subcommand)] command: TensorsCommand }`, `TensorsCommand::Manifest { #[arg(required = true)] paths: Vec<PathBuf>, #[arg(short = 'o', long)] output: Option<PathBuf>, #[arg(long)] hash: bool, #[arg(long)] expert_pattern: Option<String> }`, with `after_help` example and exit status (0 success; 2 invalid arguments, input or I/O error). `main.rs` pre-parses `raw[1] == "tensors"` exactly like `journal` and dispatches `tensors_cmd::run`, printing `tensors: <error>` and exiting 2.
- stdout: buffered `BufWriter` on locked stdout; a broken pipe (`EPIPE`) exits 0 quietly like other CLI listers do (implementer checks the existing convention, e.g. `journal summarize`, and matches it).
- `-o FILE`: `OpenOptions::new().write(true).create_new(true)` (refuses an existing file; no clobber), written fully, then `sync_all`; on any error after creation the partial file is removed. The whole manifest is built before the file is created, so input errors never leave a file.
- The `generator` string is `ratarmount <env!("CARGO_PKG_VERSION")>`.

### 5.7 Internal-read inventory

New disallowed operations each get a direct `#[expect(clippy::disallowed_methods, reason = r#"internal-read:v1 {...}"#)]` with a new unique id and a reviewed manifest entry:
- `manifest.rs`: `File::open` of each input/shard (category `factory-and-format-readers`, disposition matching the existing tensors sites, creation `none`); `File::open` + read of the index JSON (creation `none`); hashing reuses the already-open handle (no new open).
- `tensors_cmd.rs`: `OpenOptions::create_new` for `-o` (creation policy `exclusive-new-file`, as the 9 existing `create_new` entries), and `remove_file` cleanup only if it is a disallowed item.
Exact ids/categories are taken from `packaging/internal-read-clippy/README.md` and `policy.json` at implementation time; the generator produces the candidate and the diff is reviewed. Both `test_policy.py` and `policy.py` must pass.

### 5.8 Hashing (`--hash`)

Per row, seek to `offset` and stream `length` bytes through `sha2::Sha256` with a 1 MiB buffer using the file handle opened for parsing (one handle per file). Reading stops with an error on short read. Without `--hash`, no payload byte is read (header-only cost, same as mounting).

## 6. Acceptance tests (all six from the spec)

Unit tests in `ratarmount-formats-tensors/src/manifest_tests.rs` (filter prefix `manifest_`), fixtures written to `tempfile` dirs with the existing builders:

1. `manifest_gguf_experts_match_independent_slices`: synthetic GGUF, 2 layers × 4 experts, `ffn_{gate,up,down}_exps.weight` in Q4_K (`ne0 = 256`) and F16, plus a dense F32 tensor and `ffn_gate_inp`. Payload bytes are a deterministic pattern unique per expert. Each expert row's `(offset, length)` range, read with `seek` + `read_exact` (the spec's `pread`; no Unix-only API so no target `cfg`), equals the slice the test computes independently from its own builder inputs (`data_start` from the builder, `e * ne1 * (ne0/256*144)` written out literally, not via `ggml_layout`).
2. `manifest_sharded_safetensors_follow_weight_map`: two shards + index JSON, per-expert names split across shards; every row's `file` is the shard that holds it; `sum(length)` equals the sum of `data_offsets` spans in both headers; additionally rows sorted by `(file, offset)` tile each shard's data section without gap or overlap.
3. `manifest_fused_gate_up_proj_splits_per_expert`: `model.layers.0.mlp.experts.gate_up_proj` `[4, 2*I, H]` BF16 → 4 `GateUp` rows, expert 0..3, shape `[2*I, H]`, contiguous, bytes equal the independent slices.
4. `manifest_merged_expert_bad_length_refused`: (a) safetensors fused `gate_up_proj` with an unknown dtype (`"X9"`, so the parser skips the size check) whose length is not a multiple of `shape[0]` → error contains the tensor name; (b) GGUF `blk.0.ffn_up_exps.weight` with an unknown ggml type id → error contains the tensor name; (c) unit test of the private splitter with a hand-built `length != n_expert * slice_bytes` → error with the name. (With known types the parser already ties length to shape, so (a)/(b) are the reachable cases; noted in the docs.)
5. `manifest_hash_matches_sha256_of_ranges`: `--hash` values equal `sha2::Sha256` computed in the test over the byte ranges sliced from the in-memory fixture buffer (independent of the manifest's reader).

CLI integration test `ratarmount/tests/tensors_manifest.rs` (filter `tensors_manifest`), running the built binary (`env!("CARGO_BIN_EXE_ratarmount")`):

6. `tensors_manifest_dtype_change_diff`: two safetensors fixtures that differ only in one tensor's dtype (F32 vs F16, same shape), written as `model.safetensors` in two temp dirs; the CLI runs with `current_dir` set to each dir and relative PATH `model.safetensors`, so headers and `file` fields are identical. A line diff of the two outputs shows exactly that tensor's row (changed `format`, `length`, `aligned_4k` if affected) and the rows of tensors stored after it (changed `offset` only); all other lines, including the header, are identical.

Plus CLI coverage in the same file: `-o` writes the same bytes as stdout and refuses an existing file; `--hash` emits 64-hex strings; `--expert-pattern` without a `role` group exits 2; an `hf://x` PATH exits 2 with `remote inputs are not supported`; the same file given twice exits 2.

Refusal unit tests (same `manifest_` prefix): shard name with `../`, absolute path or `/`; weight_map entry whose shard lacks the tensor; shard tensor missing from weight_map; GGUF `_exps` tensor with 2 dims; directory PATH; overlapping tensor ranges inside one file (see §7 risk 2).

## 7. Risks and decisions

1. **Coverage definition.** "Every byte covered exactly once" means every byte of every tensor's data range, not header or alignment padding bytes. Test 2 checks totals and tiling.
2. **Overlapping safetensors tensors.** The mount accepts overlaps and marks them (`overlapping` sidecar flag). A manifest with overlaps would count bytes twice, so `build_manifest` refuses overlapping non-empty ranges within one file, naming both tensors. Zero-length tensors are emitted with `length: 0`.
3. **Unknown types** cannot be split (GGUF) or are split only on exact divisibility (safetensors); dense unknown-type tensors are emitted with inferred length and `format: "UNKNOWN(<id>)"`.
4. **`main.rs` conflict with R1c**: additive lines only; see the header.
5. **Memory**: rows are built in memory (`Vec`); a 1-trillion-parameter MoE has ~10^5–10^6 rows, a few hundred MB at worst. Acceptable for v1; streaming is a non-goal.

## 8. Steps

1. Add `Layout` to `Tensor`; set it in both parsers; `cargo test -p ratarmount-formats-tensors` unchanged and green.
2. `manifest.rs` + `manifest_tests.rs` (tests 1–5, refusals); make fixture builders `pub(crate)`; Cargo deps.
3. `tensors_cmd.rs`, `main.rs` wiring, `ratarmount/Cargo.toml`; `ratarmount/tests/tensors_manifest.rs` (test 6 and CLI cases).
4. Internal-read expectations and manifest entries; run the generator, review the diff, both policy scripts.
5. Docs (`docs/formats-tensors.md`), CHANGELOG, AGENTS.md catalog rows:
   `TMPDIR=/var/tmp CARGO_BUILD_JOBS=2 flock /tmp/muse-cargo.lock cargo test -p ratarmount-formats-tensors --lib manifest_` · `TMPDIR=/var/tmp CARGO_BUILD_JOBS=2 flock /tmp/muse-cargo.lock cargo test -p ratarmount --test tensors_manifest`.
6. Full AGENTS.md gate; code review + skeptic (cap 3); PR signed "— Muse"; CI green; full head SHA to Keystone. No merge.
