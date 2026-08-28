# Plan: P2 Hash / fingerprint fixed windows

| Field | Value |
|-------|--------|
| **Status** | Plan only — **do not implement in this PR** |
| **Backlog** | [`docs/tasks/vectors-optimization.md`](../vectors-optimization.md) § P2 “Hash / fingerprint fixed windows” |
| **Date** | 2026-08-28 |
| **Skeptic review** | Sweep results appended below. Stop at ACCEPT or BLOCKED (cap 3). |

---

## One-sentence goal

Stop fingerprint / tarstats / content-hash helpers from materializing a **member-sized or file-sized `Vec`**, while keeping today’s hash **values**, **windows**, and **progressive head-only** policy unchanged.

This is **not** solid-decode / full-inflate payload work.

---

## What the code already does (do not re-solve)

Nested and factory fingerprinting already sample windows. The missing work is **allocation shape**, not a new sampling algorithm.

| Surface | Location | Today |
|---------|----------|--------|
| Nested store/stencil fingerprint | `ratarmount-index/src/nested.rs` `NestedBodyFingerprint::from_seekable_body` | Head / mid / tail SHA-256 of [`NESTED_FINGERPRINT_SAMPLE`](../../../ratarmount-index/src/nested.rs) (**4096** bytes). Bodies `≤ 4096` are hashed in full **via the prefix window**. Mid is prefix when `body_size ≤ 2 * sample`. Always `seek(0)` before return. |
| Nested progressive fingerprint | `from_head_only` + factory `fingerprint_nested_body` | When `NestedOpenContext.body_seek_is_cheap == false`, **head + size only**; `suffix_sha256` / `mid_sha256` are empty. Mid/tail seeks would fully decompress a progressive parent member. |
| Factory routing | `ratarmount/src/factory.rs` `fingerprint_nested_body` (~L752) | `seek_is_cheap` → `from_seekable_body`, else `from_head_only`. Used by nested ZIP/TAR/7z/CPIO/AR durable open. |
| Cheap-seek flag | `ratarmount-compositing/src/automount.rs` `body_seek_is_cheap` | Set from `parent.member_seek_is_cheap(&fi)` on nested open. Default `true`. |
| Match / schema | `NestedBodyFingerprint::matches`, `nestedindexes` | Empty mid on either side is legacy-compatible (head/tail only). Blob v2 already stores mid hex. **Do not change schema or hex format.** |
| Tarstats edges | `archive_edge_hashes` | First/last **512** (`TARSTATS_SAMPLE_BYTES`). Heap `Vec` of 512. |
| Tarstats full hash | `archive_full_hash` | When `st_size ≤ TARSTATS_FULL_HASH_MAX` (**256 KiB**), **`read_to_end` into a `Vec`** then one-shot SHA-256. Policy **requires** a full-file digest; it does **not** require a full-file `Vec`. |
| Content-hash fill | `ratarmount-index/src/hashing.rs` `compute_hashes_limited` / `fill_content_hashes` | Already streams into `MultiHasher`. Leftover: **`vec![0u8; 1 MiB]` allocated per member**. |
| Remote tarstats | `ratarmount/src/remote_open.rs` `http_fingerprint` / `oci_fingerprint` | Edges via 512-byte Range / prefix read. Full hash when `size ≤ 256 KiB`: HTTP `fetch_http_range_bytes(0, size-1)` → `Vec`; OCI `read_to_end`. |

Existing regressions that **must stay green** (run filters separately; `cargo test` does not treat `|` as OR):

```text
cargo test -p ratarmount-index --lib regression_head_only
cargo test -p ratarmount --bin ratarmount regression_progressive_nested_fingerprint
cargo test -p ratarmount-index --lib check_tarstats
```

Also keep `fingerprint_roundtrip_and_mismatch`, `fill_content_hashes_from_temp_archive`, `hashing::stream_matches_one_shot`, and nested durable factory tests that call `from_seekable_body`.

---

## What is actually wrong

Honest leftover (do not claim “nested still slurps multi-GB bodies” — it does not):

1. **`archive_full_hash`** (and OCI/HTTP full-hash twins) build a **file-sized `Vec`** up to 256 KiB. That is the only local tarstats path that still violates “no full-body `Vec` unless policy requires,” and policy here only requires the **digest**.
2. **Nested constructors** heap-allocate 1–3 window `Vec`s and `prefix.clone()` for small-body suffix/mid. Windows are already bounded; the P2 bullet asks for **fixed buffers**.
3. **`compute_hashes_limited`** already streams, but the 1 MiB scratch buffer is oversized and is allocated **once per hashed member** during `--hashes` / `fill_content_hashes`.

ZIP `decode_plain_member_from_file` and 7z `read_member_bytes_io` still slurp **decoded payloads** before hashing. That is **inflate/decode**, not this item.

---

## Smallest correct change

One implementation PR later (not this plan PR). Prefer **`ratarmount-index` only** plus a thin remote/factory follow-through if the new helpers are reused. Do **not** touch `factory.rs` routing unless a helper signature change forces it (it should not).

### 1. Shared stream / window helpers (`ratarmount-index`)

Add small helpers next to existing hash code (prefer `hashing.rs`, used by `nested.rs` + `archive_*`):

| Helper | Behavior |
|--------|----------|
| `sha256_hex(data: &[u8]) -> String` | Collapse `nested::hex_sha256` and the one-shot SHA-256 in `archive_edge_hashes` / `hash_hex("sha256", …)`. Hex lowercase, same as today. |
| `sha256_hex_stream(reader, max_bytes) -> io::Result<String>` | Read at most `max_bytes` into a **fixed chunk** (`HASH_STREAM_CHUNK`, see below), `Sha256::update` each chunk, return hex. Never `read_to_end`. |
| Window fill | `read_exact` into a caller-supplied `&mut [u8]` (stack `[u8; N]`). |

`HASH_STREAM_CHUNK`: **64 KiB** (`64 * 1024`). Small enough to be a fixed scratch pad; large enough that `--hashes` on multi-MiB TAR members is not a syscall storm. Must be a named `pub(crate)` / `pub` const so tests can assert “no request larger than chunk” if they wrap `Read`.

Do **not** put `[u8; TARSTATS_FULL_HASH_MAX]` (256 KiB) on the stack.

### 2. Nested fingerprint: fixed windows only

Rewrite `from_seekable_body` / `from_head_only`:

- One stack buffer `[u8; NESTED_FINGERPRINT_SAMPLE]` (4096). If `NESTED_FINGERPRINT_SAMPLE` is ever raised above ~64 KiB, switch that const to a reused heap buffer of **exactly** the sample size — never `body_size`.
- Hash each window immediately; do **not** `prefix.clone()` for suffix/mid. Small body (`body_size ≤ sample`): suffix hex **equals** prefix hex (same bytes). Small-mid (`body_size ≤ 2 * sample`): mid hex **equals** prefix hex. Preserve those equalities — today’s `hex_sha256(&prefix.clone())` depends on them.
- `from_head_only`: still empty suffix/mid strings (not a hash of empty / prefix). Empty body: prefix of length 0, same hex as today (`sha256("")`).
- Always rewind to 0. Seek set unchanged (head / `body_size - sample` / `body_size / 2`).

**No API / schema change.** `matches()`, blob encode, and factory `fingerprint_nested_body` stay as-is.

### 3. Tarstats: edges stay 512; full hash streams

- `archive_edge_hashes`: stack `[u8; TARSTATS_SAMPLE_BYTES]`. Same first/last 512 policy.
- `archive_full_hash`: if `len > TARSTATS_FULL_HASH_MAX` → `Ok(None)` (unchanged). Else `sha256_hex_stream` of the whole file. **Do not** change `TARSTATS_FULL_HASH_MAX`. Digests must match today’s `Sha256::digest(&buf)` of the slurp.

### 4. Content-hash fill: fixed hasher scratch

- Change `compute_hashes_limited` scratch from `vec![0u8; 1024 * 1024]` to `vec![0u8; HASH_STREAM_CHUNK]` (or a stack `[u8; 65536]`).
- Optional same-PR hoist: pass `&mut [u8]` into an inner loop from `fill_content_hashes` so N members reuse one buffer. Not required if the chunk is 64 KiB.
- Keep `MultiHasher` streaming and algorithm set (`crc32`, `md5`, `sha1`, `sha256`). Known-vector tests must still pass.

### 5. Similar fingerprints (same PR, thin)

`http_fingerprint` / `oci_fingerprint` full-hash arms are the same policy as `archive_full_hash`.

- **OCI:** after prefix/suffix samples, `seek(0)` + `sha256_hex_stream(&mut blob, size)` instead of `read_to_end`.
- **HTTP:** `fetch_http_range_bytes` always returns a `Vec` today and is **only** used for these fingerprints. Smallest correct options (pick one, prefer A):
  - **A.** Add `hash_http_range_sha256(url, start, end_inclusive)` in `ratarmount-remote` that streams the ureq body into SHA-256 (fixed chunk). Use it for the **full-hash** Range (`0 .. size-1` when `size ≤ 256 KiB`). Edges may keep the 512-byte `Vec`.
  - **B.** Keep fetching the ≤256 KiB `Vec` for HTTP only; document as residual (network already paid; cap is policy). Do **not** leave OCI `read_to_end` if A or local stream is done.

Do not change `check_tarstats_matches_remote` rules.

---

## Explicit non-goals

| Out | Why |
|-----|-----|
| ZIP `decode_plain_member_from_file` / sequential `ZipFile` slurp | Deflate/store **payload** decode. Separate from metadata-window fingerprints. Sequential ZIP already streams into `compute_hashes_limited`; parallel path still materializes decoded bytes — residual. |
| 7z `read_member_bytes_io` then `Cursor::new(&bytes)` | Folder decode / solid unpack. Backlog: “Not solid-decode / full-inflate payload work.” |
| Full-content nested hash for multi-GB members | Documented residual in `embedded-nested-archives.md`. Same-size edits outside the three windows can still miss. |
| Changing `NESTED_FINGERPRINT_SAMPLE`, `TARSTATS_SAMPLE_BYTES`, `TARSTATS_FULL_HASH_MAX` | Policy knobs. This item is allocation, not sensitivity. |
| Changing `from_head_only` / `body_seek_is_cheap` routing | Already correct; regressing it reopens “first `cat` minutes” on progressive 7z parents. |
| Nested blob schema / hex case / `matches` empty-mid | Warm-index compatibility. |
| SIMD CRC / memchr on multi-MB inflate output | Separate P2 “True SIMD” row. |
| FUSE / list_dirents / SoA | Wrong toolbox. |
| README / parity tables | No user-visible capability change if digests and windows stay identical. |

---

## Tests (required in the later implementation PR)

Lowest layer first (`ratarmount-index`). Name new tests with `Regression:` + symptom.

| Test | Assert |
|------|--------|
| Nested large body byte budget | Custom `Read+Seek` over ≥ 1 MiB. `from_seekable_body` **reads ≤ `3 * NESTED_FINGERPRINT_SAMPLE`** payload bytes and never seeks except 0 / mid / tail / rewind. Digests equal a control that hashes the same three slices. |
| Nested small body policy | Body `< 4096`: prefix hex == SHA-256 of the **entire** body; suffix hex == prefix hex; mid hex == prefix hex. |
| Nested empty body | `body_size == 0`: prefix is SHA-256 of empty; no panic on `read_exact` of 0. |
| Head-only unchanged | Existing `regression_head_only_fingerprint_does_not_seek_mid_tail` stays; empty suffix/mid. |
| Factory progressive | Existing `regression_progressive_nested_fingerprint_skips_mid_tail` stays. |
| `archive_full_hash` stream == slurp | Temp file of `TARSTATS_FULL_HASH_MAX` bytes (and one smaller, one empty). Digest equals `hash_hex("sha256", &bytes)`. File of `TARSTATS_FULL_HASH_MAX + 1` → `None`. |
| `archive_edge_hashes` | First/last 512 of a file `> 512` match one-shot hashes of those slices; file `≤ 512` suffix == prefix. |
| `compute_hashes_limited` multi-chunk | Payload **larger than `HASH_STREAM_CHUNK`**. Streamed `(crc32, sha256)` equals `hash_hex` of the full slice. Existing `stream_matches_one_shot` / `fill_content_hashes_from_temp_archive` stay. |
| Tarstats warm reject | Existing `check_tarstats_matches_archive_rejects_size_or_mtime_mismatch` still sees `full_sha256` on tiny archives and still mismatches same-size edits. |

Optional (only if HTTP/OCI helpers change): unit-test the stream hasher with `Cursor`; do not add a live HTTP test.

**AGENTS.md:** add a catalog row in the **same implementation commit**, for example:

| Symptom / fix | Commands |
|---------------|----------|
| Fingerprint / tarstats full-hash slurps body `Vec` | `cargo test -p ratarmount-index --lib fingerprint` · `cargo test -p ratarmount-index --lib archive_full_hash` · `cargo test -p ratarmount-index --lib compute_hashes` · keep `regression_head_only` + `regression_progressive_nested_fingerprint` |

(Exact filter names follow the test fn names the implementer chooses.)

If a CLI is missing, skip with `eprintln!("skip: …")` **and** still keep the pure unit tests above.

---

## Docs (implementation PR)

| Doc | When |
|-----|------|
| This plan + backlog pointer | This plan-only PR |
| `vectors-optimization.md` checkboxes | Tick **only** when the implementation PR lands |
| `docs/embedded-nested-archives.md` fingerprint row | **No change** if windows/policy unchanged. One residual sentence only if we document “full_sha256 ≤ 256 KiB streams; no file `Vec`.” |
| README / parity-todo / mount-options | Skip (no user-facing capability) |
| Format-support-matrices | Skip (no nested open / tmp / `MountSource::open` change) |

---

## Implementation order (later PR)

1. Helpers + `archive_full_hash` / `archive_edge_hashes` + unit tests (hash equality).
2. Nested constructors + byte-budget / small-body tests.
3. `compute_hashes_limited` chunk const + multi-chunk test.
4. OCI (and HTTP A if chosen) stream full-hash.
5. `cargo fmt --all` **before** the commit. Then scoped clippy/test:

```bash
cargo fmt --all
cargo clippy -p ratarmount-index --all-targets -- -D warnings
cargo test -p ratarmount-index --lib
cargo test -p ratarmount --bin ratarmount regression_progressive_nested_fingerprint
```

If remote helpers change: also `-p ratarmount-remote` and `ratarmount` remote-open tests as applicable.

One commit is enough if tests + the AGENTS.md row travel with the code.

---

## Risk notes for the implementer

- **Digest drift:** stream vs slurp must be bit-identical (lowercase hex, full `max_bytes`, stop on EOF). Test empty, 1 byte, `sample`, `sample+1`, `2*sample`, `TARSTATS_FULL_HASH_MAX`.
- **`read_exact` vs short `Read`:** keep `read_exact` on windows (today’s contract). Stream helper should treat unexpected EOF like today’s `read_to_end` (hash what was read) **or** fail — pick one and test; prefer **fail** if `bytes_read != max_bytes && max_bytes == file_len` after a full-hash of a local file (local files should be exact). For `compute_hashes_limited`, today’s loop already stops on `n == 0` (best-effort short members) — **do not** tighten that.
- **Progressive path:** never add mid/tail seeks when `!seek_is_cheap`.
- **Factory ownership:** leave `ratarmount/src/factory.rs` alone unless a compile break forces a one-line import. Orchestrator owns factory glue.
- **MSRV 1.74:** no edition-2024 / `std` APIs newer than the workspace rust-version.

---

## Suggested file ownership (implementation)

| Path | Change |
|------|--------|
| `ratarmount-index/src/hashing.rs` | Stream helper, chunk const, `compute_hashes_limited` scratch |
| `ratarmount-index/src/lib.rs` | `archive_edge_hashes` / `archive_full_hash` |
| `ratarmount-index/src/nested.rs` | Fixed window buffers; reuse SHA-256 helper |
| `ratarmount/src/remote_open.rs` | OCI/HTTP full-hash call sites (thin) |
| `ratarmount-remote/src/lib.rs` | Optional `hash_http_range_sha256` (option A only) |
| `AGENTS.md` | New regression catalog row |

---

## Skeptic review log

*(Filled by skeptic-plan-review sweeps. Do not skip sweep 1.)*
