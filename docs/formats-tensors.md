# Safetensors and GGUF tensor mounts

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
model tree or resolve referenced shard paths.

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
