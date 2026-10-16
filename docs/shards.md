# Dataset shards and index export

`ratarmount shard` packs a directory into WebDataset-style TAR shards, with a
standard ratarmount SQLite sidecar for each shard and a `shards.json` manifest.
Neither this command nor `export-index` needs FUSE.

```sh
ratarmount shard ./dataset -o ./shards --size 1G -j 4
ratarmount export-index ./shards/shards.json -o samples.parquet --format parquet
ratarmount export-index ./shards/shards.json --format jsonl > members.jsonl
ratarmount export-index ./shards/shard-000000.tar.zst --format csv -o members.csv
```

The output directory must be outside the input tree. Existing shard names and
`shards.json` are refused. Temporary archives and indexes are prepared in the
output filesystem before publishing the manifest; readers should use the
manifest as the completion marker. A failure while publishing can leave completed
shards without a manifest. Inputs must remain unchanged while sharding.

## Packing options

| Option | Behavior |
| --- | --- |
| `--prefix NAME` | Default `shard`; names are `shard-000000.tar.zst`, etc. |
| `--size SIZE` | Maximum encoded archive bytes, including its seek table; default `1G`. Binary K/M/G suffixes are accepted. One sample larger than this limit goes alone. Planning uses TAR sizes, so compressed shards may be smaller than the limit. |
| `--group-by-key[=true\|false]` | On by default. The key is the directory plus the basename before its first dot: `dir/0001.jpg` and `dir/0001.json` stay adjacent in the same shard. Members of a key sort by extension. |
| `--frame-size SIZE` | Independent zstd frames of at most this many decompressed bytes; default 8 MiB. |
| `--frame-per-sample` | One frame per sample, containing its headers, padding and payloads. TAR EOF shares the final sample frame. Mutually exclusive with an explicit `--frame-size`. |
| `--level LEVEL` | Zstd compression level, default 3; accepted range -7 through 22. |
| `--codec zstd\|none` | Zstd by default. `none` writes plain `.tar` shards. |
| `--align-members BYTES` | Align every member's data offset in the decompressed stream using a PAX `comment` record. Must be a multiple of 512, at most 16 MiB; off by default. |
| `--mtime SECONDS` | Fixed signed Unix mtime, default 0. |
| `--keep-metadata` | Preserve numeric uid/gid, permission bits and fractional mtime from the input's `lstat` metadata. User/group name fields remain empty, since filesystem metadata stores numeric IDs. |
| `--no-index` | Omit sidecars and set the manifest's index fields to null. |
| `-j N` | Build up to N shards concurrently; default 1. Does not change output order or bytes. |

Files and symlinks are included; directories are implicit. Symlinks, including
links to directories or missing targets, are stored as symlinks and never
traversed. Other file types produce an error. Paths and link targets must be
UTF-8. Traversal and grouping use byte order, and long paths and link targets use
POSIX PAX headers. Unless `--keep-metadata` is selected, files use mode 0644,
symlinks use mode 0777, uid/gid are 0, and user/group names are empty. Hardlinks
are packed as independent regular files. The same stable input and options
produce identical shards regardless of traversal order or `-j`.

The official zstd seekable table uses 32-bit frame lengths. An individual
`--frame-per-sample` frame (including TAR overhead) must fit those fields; use
fixed-size frames for larger samples. Sharding stages one plain TAR per active
shard on disk rather than holding a dataset-sized buffer in memory. Allow space
for staged TARs, encoded shards and sidecars. A conservative TAR-size plan is
split further if encoded output exceeds the limit; groups are never split.

For stored TAR members, block alignment can make reflink cloning of member
extents possible on supporting filesystems:

```sh
ratarmount shard ./dataset -o ./stored-shards --codec none --align-members 4096
```

The alignment applies to regular file data, including members with long PAX
names. Compression changes physical offsets, so zstd shards do not provide
stored-member extents. Alignment alone does not enable FUSE passthrough.

## Manifest and publication

`shards.json` has `format: "ratarmount-shards-v1"`, a `shards` array,
`total_members`, `total_bytes`, and `options`. Each shard records `name`, encoded
`size`, archive `sha256`, `members` (including symlinks), `samples`, `first_key`,
`last_key`, `index`, and `index_sha256`. Totals count members and encoded archive
bytes, excluding sidecars. Empty inputs produce an empty manifest. Operational
input/output paths and worker count are omitted from options for reproducibility.

The sidecar name is `<archive-name>.index.sqlite`. Sidecars are built through the
same session index job as other ratarmount archives, including `zstdblocks`.
They can be consumed by `--publish-index` and mounted with the normal index
policy. Sharding itself does not upload data or indexes.

## Exported columns

`export-index` accepts one or more local archives or SQLite sidecars, or a
`shards.json` manifest. Archives create/load an index using the normal index
location policy. Existing sidecar inputs are opened read-only. All `files` rows
are exported, including generated directories and archived historical versions;
row count can exceed the manifest's payload member count. Each input's rows are
ordered by directory, name, then header offset, in byte order. Manifest order
and command-line input order are preserved.

| Column | Meaning |
| --- | --- |
| `path`, `name` | Full archive-relative path with a leading slash; basename. |
| `size`, `mode`, `mtime`, `type` | Raw index values: integer bytes/mode/type and floating-point Unix mtime. Type is the index's integer TAR type code. |
| `link_target` | Index `linkname`, including empty values on ordinary files. |
| `offsetheader`, `offset` | Header location and data location in the decompressed archive stream. |
| `sha256` | The `user.hash.sha256` xattr if already present; export does not hash member payloads. |
| `shard` | Archive filename for multiple inputs or a manifest, otherwise null. |
| `frame` | Zero-based zstd frame containing the data start. |
| `frame_compressed_offset` | Frame start in the encoded archive. `frame_offset` is an alias for this column. |
| `frame_compressed_size` | Encoded frame length. |
| `frame_decompressed_offset` | Frame start in the decompressed stream. |
| `offset_within_frame` | `offset - frame_decompressed_offset`. |

Frame columns come from `zstdblocks` (including its EOF sentinel), or a scan of
the sibling archive's seek table/frames when no usable map is stored. A detached
sidecar with `zstdblocks` needs no payload file. Columns are null when a frame
cannot be determined, including non-zstd archives. For fixed-size frames a
member can span several frames; the columns describe its data start.

JSONL uses one JSON object per row, with nulls for missing values. CSV uses a
header, RFC 4180 quoting, and empty cells for nulls. Parquet has nullable UTF-8,
Int64, UInt64 (frame columns), and Float64 (mtime) columns. It writes Arrow
batches of up to 4096 rows and row groups of up to 32768 rows, with binary output
staged to a temporary file before
copying to the destination or stdout. File outputs are published only when the
export succeeds and cannot overwrite an input.

Parquet is enabled by default through the binary's `export-parquet` feature.
`cargo build -p ratarmount --no-default-features` retains JSONL and CSV and gives
an actionable error for Parquet. Arrow/Parquet 60.0.0 require Rust 1.88, below
the workspace MSRV of 1.90 ([upstream release notes](https://arrow.apache.org/blog/2026/09/29/arrow-rs-60.0.0/)).
