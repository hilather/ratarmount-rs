# Safetensors and GGUF tensor mounts

Open a checkpoint as a directory: every tensor is a file holding exactly its
stored bytes, with a JSON sidecar for dtype and shape, so you can inspect,
diff, hash or partially read weights without loading a model. Works on local
files, on `hf://` mounts and inside TARs.


`ratarmount-formats-tensors` exposes a single safetensors shard or a little-endian
GGUF v2/v3 file as a read-only `MountSource`. Each tensor is a regular file
containing its original stored bytes. Quantized GGUF tensors stay quantized;
this crate does not decode, dequantize, reshape, or load a model into RAM.

The CLI and session factory select this backend automatically. The crate can
also be used directly:

```rust,ignore
use ratarmount_core::{MountSource, OpenOptions};
use ratarmount_formats_tensors::TensorsMountSource;

let source = TensorsMountSource::open(
    "model.safetensors", None, &OpenOptions::default(), "0.1.34", false,
)?;
let tensor = source.lookup("/model/layers/12/mlp/down_proj/weight", 0).unwrap();
let first_bytes = source.read(&tensor, 4096, 0)?;
```

## Names and generated files

Dots in tensor names become directory separators:
`model.layers.12.mlp.down_proj.weight` becomes
`model/layers/12/mlp/down_proj/weight`. Names are case sensitive.

Each component preserves ASCII letters, digits, `_`, and `-`; every other UTF-8
byte is percent encoded with uppercase hex. In particular `/`, `%`, and NUL
become `%2F`, `%25`, and `%00`. An empty component becomes `%EMPTY`, so leading,
trailing and consecutive dots, and an empty tensor name, remain distinct.
The exact components `__metadata__` and `__header__` are reserved: their first
underscore is escaped, producing `%5F_metadata__` and `%5F_header__`. This keeps
tensor sidecars distinct from the generated root JSON files. A literal `%` is
still escaped, so these names cannot collide with their percent-encoded text.

If a tensor's path is also a directory required by another tensor, the tensor
leaf receives `.tensor`. Thus `a.b` and `a.b.c` become `a/b.tensor` and `a/b/c`.
This rule depends only on the set of names, not input order. Literal dots have
already become separators, so `.tensor` and `.json` suffixes cannot collide
with input components. For example, `a.b.tensor` becomes `a/b/tensor`.

Every tensor has an adjacent `<leaf>.json` sidecar, including collision leaves
such as `a/b.tensor.json`. All sidecars contain the original `name`, mounted
`path`, `byte_length`, `absolute_file_offset`, and an `overlapping` boolean.
Overlaps are permitted and every participating nonempty tensor is marked;
zero-length ranges do not overlap.

Safetensors sidecars also contain `dtype`, `shape`, relative `data_offsets`, and
`size_check` (`validated` or `skipped_unknown_dtype`). The root has:

- `__metadata__.json`: the string-to-string metadata map, or `{}`.
- `__header__.json`: an exact byte-range view of the original JSON header,
  including its padding.

GGUF sidecars contain numeric `ggml_type`, `ggml_type_name`, `dims` in GGUF
storage order, `data_offset`, `data_section_start`, `alignment`, `version`, and
`size_source`. `__metadata__.json` contains every KV pair. Scalar integers,
booleans, UTF-8 strings, finite floating-point values and arrays become JSON
values. Nonfinite floats become the strings `NaN`, `Infinity`, or `-Infinity`.
Float32 values are promoted to float64 for JSON serialization.

Arrays with more than **1024 elements** become
`{"__summary__":true,"element_type":<GGUF numeric tag>,"length":N,"preview":[...]}`,
with the first **16 elements** in the preview. This keeps tokenizer metadata
manageable. All omitted elements are still parsed and validated. Nested
arrays are supported with a maximum nesting depth of 16. There is no GGUF
`__header__.json`, since its header is binary.

## Validation and limits

The public compile-time `MAX_HEADER_SIZE` constant defaults to **100 MiB**.
It limits safetensors JSON bytes and the entire GGUF binary header, excluding
alignment padding and tensor payloads. Change this constant when building if
a different header budget is required. No allocation uses an unchecked input
length. Offset, shape and byte-size arithmetic is checked.

Safetensors requires a UTF-8 JSON object beginning with `{`, valid unsigned
shape dimensions, ordered in-file offsets, and string metadata. Known dtypes
must match the shape's bit count exactly, including byte alignment for packed
dtypes. Supported size checks cover F64/F32/F16/BF16, signed and unsigned
8/16/32/64-bit integers, BOOL, C64, F8_E4M3/F8_E5M2/F8_E8M0,
F8_E4M3FNUZ/F8_E5M2FNUZ, F4, F6_E2M3, and F6_E3M2. Scalars use an empty shape;
any zero dimension gives an empty tensor. Unknown dtype strings remain
readable with the skipped check recorded in the sidecar. Overlapping ranges
and unused data gaps are allowed by this plugin.

GGUF supports metadata tags 0 through 12. `general.alignment` must be UINT32,
a nonzero power of two, and at most the header budget; its default is 32.
Tensor offsets must respect it. The data section starts at the aligned end
of the tensor-info table. Dimensions must be positive, with 1 through 4 axes.
Big-endian magic or version encodings are rejected explicitly.

Known GGML sizes cover F32/F16/BF16/F64, I8/I16/I32/I64, Q4_0/Q4_1,
Q5_0/Q5_1, Q8_0/Q8_1, Q2_K through Q8_K, IQ2_XXS/IQ2_XS/IQ3_XXS/IQ1_S,
IQ4_NL/IQ3_S/IQ2_S/IQ4_XS/IQ1_M, TQ1_0/TQ2_0, MXFP4/NVFP4, and Q1_0/Q2_0.
The first dimension must contain whole blocks. For unknown or removed enum
IDs, the size is the distance to the next *greater physical offset*, or data
end for the last tensor. Such ranges can include padding, and use
`ggml_type_name: "UNKNOWN"` and `size_source: "next_offset_or_data_end"`.
Known layouts use `size_source: "ggml_block_layout"` and exclude padding.

The dtype and block definitions follow the upstream
[safetensors implementation](https://github.com/huggingface/safetensors/blob/main/safetensors/src/tensor.rs),
[GGML type enumeration](https://github.com/ggml-org/ggml/blob/master/include/ggml.h),
and [GGML block structures](https://github.com/ggml-org/ggml/blob/master/src/ggml-common.h).

## Indexes and nested readers

Path opens follow the AR signature:
`open(path, index_path, options, product_version, recreate)`. SQLite indexes
store tensor offsets and generated sidecars. Remounts reuse them after the
shared backend/schema and archive tarstats checks (size, mtime and sampled
content hashes). A stale index rebuilds. The default path is
`<source>.index.sqlite`; `index_in_memory` and `index_compact_only` are honored.

`open_from_reader(reader, label, index_path, options, product_version)` accepts
any owned `Read + Seek + Send + 'static` source. The label is never opened as a
host path. `None` builds a memory/compact listing without reading tensor
payloads. An explicit SQLite index path permits reuse after size and shared
head/middle/tail fingerprint checks; these sampled checks are not whole-file
integrity verification. `clear_index_cache` forces a rebuild. No tensor body
is spooled to `/tmp`. Independent member cursors share the input reader under
a mutex and serve bounded `StenciledFile` ranges. Path opens use independent
file handles. Here “zero-copy” means no full-tensor copy or materialization;
ordinary reads still copy requested bytes into the caller's buffer.

`list_dirents` queries the shared index's cheap name/mode/size rows, so readdir
need not allocate tensor sidecar contents. Seek cost for a nested tensor
inherits the parent reader's compression/access characteristics. Explicit
nested fingerprint checks can force decompression in a progressive parent.
The session factory opens nested tensor containers through this reader API,
using a compact file table without a nested SQLite sidecar. These default
nested listings rebuild on open; they do not use shared `nestedindexes` blobs.

## Sharded checkpoints

A single shard file is fully supported. `model.safetensors.index.json` and its
`weight_map` are **not** a tensor container for this plugin. Cross-shard
aggregation in a folder or union mount is out of scope. Open individual shard
files (or their nested-reader views); this crate does not merge them into one
model tree or resolve referenced shard paths. The separate `tensors manifest`
command follows `weight_map` to describe all shards without mounting them.

## How it is selected

The session `tensors` feature enables both formats and is included in
`formats-all`, which the CLI enables. Top-level probes try Tensors after HTML
and before libarchive and TAR. `.safetensors` and `.gguf` suffixes select the
parser; extensionless files are recognized by their safetensors header layout
or GGUF magic. Recognized malformed inputs return a parser error.

`--use-backend safetensors`, `--use-backend gguf`, and `--use-backend tensors`
prioritize the same backend; `tensorsmountsource` is also accepted. Any alias
can open either format.

```bash
ratarmount model.safetensors mnt/
ratarmount --use-backend gguf model.gguf mnt/
ratarmount -r checkpoints.tar mnt/
# Read a tensor inside the TAR's model.safetensors shard:
cat mnt/model.safetensors/model/layers/12/mlp/down_proj/weight
```

Recursive mounts include `.safetensors` and `.gguf` in the default archive
selection and in `/archive` or `/all`. Explicit suffix selections remain
restrictive. Extensionless nested containers can be selected with
`--recursive-extensions '*'`. The reader dispatcher recognizes both formats
from an existing parent stream; it opens tensors without a temporary body
spool. Random-read cost still depends on the parent reader's compression.
Several checkpoints inside one TAR can open in parallel with the default
`--parallel-nested` setting. File-backed TAR member readers have independent
logical positions and use positional I/O without a shared read lock. Regressions
cover four simultaneous safetensors/GGUF opens and concurrent tensor reads without
temporary spooling, as well as parallel AR opens from the same kind of parent.

## Expert manifest

`ratarmount tensors manifest` describes the stored byte ranges in local
checkpoints without mounting them or loading their tensor payloads:

```bash
ratarmount tensors manifest model.gguf
ratarmount tensors manifest model.safetensors.index.json -o experts.jsonl
ratarmount tensors manifest first.safetensors second.gguf --hash
```

Inputs can mix safetensors files, safetensors `.index.json` files and GGUF
v2/v3 files. An input whose name ends in `.index.json` is treated as a
safetensors shard index; other inputs use the same format-sniffing parser as
the mount. The manifest does not change mounted tensor bytes, sidecars or
indexes. It does not dequantize, write checkpoints, prefetch or serve inference
reads, and there is no Session API hook.

### JSONL schema and ordering

The first line has these keys in this order:

```json
{"manifest":1,"inputs":["model.gguf"],"generator":"ratarmount <version>"}
```

Each later line describes one tensor or one expert slice. Keys occur in this
order, including keys whose value is `null`:

```json
{"file":"model.gguf","tensor":"blk.0.ffn_gate_exps.weight","layer":0,"expert":0,"role":"Gate","format":"Q4_K","shape":[256,2],"offset":4096,"length":288,"aligned_4k":true,"sha256":null}
```

`file` is the input path as given, or the index directory joined with the
`weight_map` shard name, without canonicalization. `tensor` is the original
name. `layer` and `expert` are unsigned 32-bit integers or `null`. `format` is
the safetensors dtype verbatim, or a GGML type name such as `F16` or `Q4_K`;
unknown GGML IDs use `UNKNOWN(<id>)`. `offset` is absolute in the file, and
`length` is the stored byte count. `aligned_4k` means `offset % 4096 == 0`.
`sha256` is a lowercase 64-character hex digest with `--hash`, otherwise `null`.

Safetensors shapes follow header order, with the innermost axis last
(row-major); a merged expert slice drops the leading expert axis. GGUF shapes
retain `ne` storage order, with `ne0` innermost; an expert slice drops the
outermost `ne2` axis. The manifest preserves these different conventions.

Rows sort by `(layer, expert, role, file, offset, tensor)`. For `layer` and
`expert`, `None < Some`, so global tensors sort before numbered layers. Role
order is `Gate`, `Up`, `Down`, `GateUp`, `Router`, `SharedExpert`, `Other`,
not alphabetical order. The original tensor name breaks ties after the file
and offset. There are no timestamps, and every line ends with a newline, so
manifests made with the same input paths can be compared with `diff` or `jq`.

### Classification and expert slices

Classification takes the first matching rule, producing exactly one
classification for each tensor. Merged/fused rules run before per-expert
patterns, then Router, SharedExpert and Other. Full-name rules are anchored;
layer extractors and shared-expert searches are substring searches.

GGUF uses fixed rules:

- `^blk\.(\d+)\.ffn_(gate|up|down)_exps\.weight$`: merged `Gate`, `Up` or
  `Down` experts. Exactly three dimensions `[ne0, ne1, n_expert]` are required.
  Each expert has shape `[ne0, ne1]` and a contiguous byte range computed from
  the known GGML block layout. Unknown GGML types cannot be split.
- `^blk\.(\d+)\.ffn_gate_inp\.weight$`: `Router`, with the captured layer.
- A name containing `_shexp`: `SharedExpert`.
- Everything else: `Other`, with `expert: null`.

SharedExpert and Other rows obtain a layer from the unanchored
`(?:^|\.)blk\.(\d+)\.` extractor when present.

Safetensors uses these rules:

- The always-enabled fused rule is
  `^(?:.*\.)?experts\.gate_up_proj(?:\.weight)?$`. A three-dimensional tensor
  has expert axis 0 and splits into `GateUp` rows. A two-dimensional matrix
  has no expert axis and remains one `Other` row. Names such as
  `gate_up_proj.weight_scale` do not match. The layer comes from the
  unanchored `(?:^|\.)layers\.(\d+)\.` extractor when present.
- The default per-expert pattern below gives `Gate` for `gate_proj` or `w1`,
  `Up` for `up_proj` or `w3`, and `Down` for `down_proj` or `w2`.
- `^(?:.*\.)?layers\.(\d+)\.(?:mlp|block_sparse_moe)\.gate\.weight$`:
  `Router`, with the captured layer.
- A name matching the substring `\.shared_experts?\.`: `SharedExpert`.
- Everything else: `Other`, with `expert: null`. SharedExpert and Other rows
  use the same unanchored `layers` extractor for a layer when present.

The default per-expert pattern, anchored with `^` and `$`, is exactly:

```text
(?:.*\.)?layers\.(?P<layer>\d+)\.(?:mlp|block_sparse_moe)\.experts\.(?P<expert>\d+)\.(?P<role>gate_proj|up_proj|down_proj|w1|w3|w2)\.weight
```

`--expert-pattern REGEX` replaces this pattern entirely; it does not replace
the fused rule or the fixed GGUF rules. It must contain named groups `layer`,
`expert` and `role`, and is anchored as `\A(?:REGEX)\z`. If compiling this
wrapper fails, compilation retries with a newline before the closing wrapper
so a trailing verbose-mode comment cannot swallow the wrapper or end anchor.
The newline is added only on that retry; literal newlines in ordinary patterns
are unchanged. For each match, all three groups must participate, both numbers
must fit `u32`, and `role` must be recognized. An invalid capture refuses the
tensor rather than silently classifying it as Other. Custom patterns accept
these role captures:

| Role | Captures |
|---|---|
| `Gate` | `gate_proj`, `w1`, `gate` |
| `Up` | `up_proj`, `w3`, `up` |
| `Down` | `down_proj`, `w2`, `down` |
| `GateUp` | `gate_up_proj`, `gate_up` |

The short aliases `gate`, `up`, `down`, and `gate_up` apply only to custom
patterns. The default pattern and its role map remain the six spellings above.
For example:

```bash
ratarmount tensors manifest model.safetensors \
  --expert-pattern 'ffn\.(?P<layer>\d+)\.ex\.(?P<expert>\d+)\.(?P<role>gate|up|down)\.weight'
```

A per-expert name such as `experts.0.gate_up_proj.weight` is not in the default
pattern and stays `Other` unless a custom pattern recognizes it. A merged
`experts.down_proj` also stays one `Other` row.

### Coverage, validation and limits

Coverage means every byte in every parsed tensor data range appears exactly
once. Header bytes and alignment padding bytes are excluded from this coverage
requirement. GGUF unknown-type ranges are inferred by the existing parser from
the next offset or data end and can contain undistinguished padding; those
inferred bytes remain in an unsplit row. Zero-length ordinary tensors get a
row with `length: 0`. Unlike a mount, the manifest refuses overlapping nonempty
tensor ranges, naming both tensors, so bytes cannot be counted twice.

Merged experts must have a positive expert count, nonzero total length and
nonzero bytes per slice. Before allocating or iterating expert rows, the
manifest refuses more than **65,536 experts in one merged tensor** or more
than **16,777,216 total rows in one manifest**, with an error naming the tensor
that exceeds the limit. Slice arithmetic and numeric captures are checked for
overflow. GGUF merged tensors require a known block layout and exactly three
dimensions. Safetensors fused expert tensors require exactly three dimensions
to split; two-dimensional matrices remain Other. Each safetensors slice must
occupy a whole number of bytes, including packed dtypes.

Acceptance test 4's `length is not a multiple of n_expert` failure cannot occur
for known non-packed safetensors dtypes or known GGML types: the parser already
ties byte length to shape and block layout. It is reachable for an unknown
safetensors dtype, whose size check is skipped, or a packed dtype whose whole
tensor is byte-aligned but whose individual expert is not. For example,
`F6_E2M3` shape `[2,2,1]` occupies three bytes and cannot be divided into two
byte-addressable expert slices. Unknown GGML types are refused before splitting;
a direct splitter regression also checks an inconsistent hand-built length.

A safetensors index is limited to **100 MiB** and must contain a string-to-string
`weight_map`. Duplicate keys are refused. Each distinct shard is parsed once
and must be safetensors. Every map entry must name a tensor present in its
shard, and every tensor in every shard must map back to that shard. A missing
entry, missing tensor, tensor copied into the wrong shard or GGUF shard is
refused. Shard names must have exactly one `Path::components()` component,
which must be `Component::Normal`; NUL, slash and backslash are also refused. Empty
names, `.`, `..`, absolute paths and directory traversal are therefore refused.
Shards resolve only in the index's directory; local symlinked shards are followed.

Paths must be UTF-8 local regular files. Any scheme path containing `://`,
including `hf://`, `http://`, `https://` and `file://`, is refused: pass a local
path. Directories, sockets, devices and writerless FIFOs are refused before
opening. The opened descriptor is checked again for regular-file type and the
pre-open length. A local process replacing a regular file with a FIFO between
those checks can still make the open block; this point-in-time check does not
close that race. Paths inside archives are not resolved, and there is no GGUF
split-index support; give individual GGUF parts as separate inputs.

File identity comes from the opened descriptor, so repeated input paths,
symlinks, hard links, and an index plus one of its shards are refused as duplicate
files. One open handle is retained per input file for identity checks, parsing
and optional hashing; hashing does not reopen or clone it. Large shard sets can
reach the process descriptor limit. An EMFILE failure names the shard and says
`too many shards open; raise ulimit -n`.

Without `--hash`, only headers are read. With it, each row's stored range is
streamed through SHA-256 using a 1 MiB buffer and the original handle. Short
reads are errors. A file whose length changed between parsing and hashing is
refused with an error naming the file and tensor.

### Output and library API

The default output is buffered stdout. After all inputs are validated, `-o FILE`
creates an unpredictable private temporary file in FILE's parent directory with
exclusive creation and permissions `0600` (subject to umask) on Unix. It writes
the manifest, explicitly flushes the output buffer, and calls `sync_all` before
publishing with `hard_link(temp, FILE)`. Publication refuses an existing path
and requires a filesystem that supports hard links. Any hard-link error fails
with an `output was not published` error; there is no rename or copy fallback.

Failures remove only the private temporary file, without reopening it for read
access; they never remove FILE. After publication, the temporary link is removed
and the parent directory is opened and synced. A directory open or sync failure
is reported as an error while the published FILE remains intact, so its
durability is unconfirmed. Some operating systems do not support opening or
syncing directories through these APIs and will report that error.

Success exits 0; invalid arguments, input errors and output errors exit 2, with
`tensors: <error>` on stderr for errors from the command. Stdout write or final
flush failures, including a pipe that breaks while writing, follow this error
path. The shared CLI startup code redirects stdout that is already broken at
launch to `/dev/null`; in that inherited case the command succeeds without
output.

The library exports `build_manifest(inputs, &ManifestOptions) -> Result<Manifest>`,
`write_jsonl(&manifest, generator, &mut writer)`, and
`compile_expert_pattern(&str) -> Result<ExpertPattern>`. `Manifest` retains the
input paths and public `rows`; `ManifestOptions` controls hashing and an optional
compiled expert pattern. JSONL headers and rows serialize from typed structs in
the documented key order, with null-valued keys present.

### Follow-ups

- Split merged safetensors `experts.down_proj` if a future loader needs it;
  v1 emits one `Other` row.
