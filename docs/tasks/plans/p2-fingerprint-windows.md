# Plan: P2 Hash / fingerprint fixed windows

| Field | Value |
|-------|--------|
| **Status** | **Implemented** — `ad76363efedaa383d95a1061b251078c45112309`. Plan accepted on [`#11`](https://github.com/hilather/ratarmount-rs/pull/11) (`42a04d7933a035ed00dff0e79254547d0c42f2ca`). |
| **Backlog** | [`docs/tasks/vectors-optimization.md`](../vectors-optimization.md) § P2 “Hash / fingerprint fixed windows” — fingerprint boxes ticked in this PR |
| **Date** | 2026-08-28 |
| **Skeptic review (plan)** | **ACCEPT** after 3/3 sweeps (nits folded on 1–2; sweep 3 clean). Plan PR #11. |

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
| Remote tarstats | `ratarmount/src/remote_open.rs` `http_fingerprint` / `oci_fingerprint` | Edges via 512-byte Range / prefix read. Full hash when `size ≤ 256 KiB`: HTTP `fetch_http_range_bytes(0, size-1)` → `Vec` (**accepts HTTP 200 and `read_to_end`s the response**, not `end-start+1`); OCI `seek(0)` then **`read_to_end` of the blob** (not a `size`-capped read). |

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

ZIP `decode_plain_member_from_file` (STORE `read_file_range_at` **and** Deflate `read_to_end`) and 7z `read_member_bytes_io` still slurp **member payloads** before hashing. STORE is a full-member `Vec` closer to the content-hash bullet than inflate is; it stays a **labeled residual** (payload open path, not tarstats/nested windows). 7z folder decode is the same residual class.

---

## Smallest correct change

One implementation PR later (not this plan PR). Prefer **`ratarmount-index` only** plus a thin remote/factory follow-through if the new helpers are reused. Do **not** touch `factory.rs` routing unless a helper signature change forces it (it should not).

### 1. Shared stream / window helpers (`ratarmount-index`)

Add small helpers next to existing hash code (prefer `hashing.rs`, used by `nested.rs` + `archive_*`):

| Helper | Behavior |
|--------|----------|
| `sha256_hex(data: &[u8]) -> String` | Collapse `nested::hex_sha256` and the one-shot SHA-256 in `archive_edge_hashes` / `hash_hex("sha256", …)`. Hex lowercase, same as today. |
| `sha256_hex_stream(reader) -> io::Result<String>` | Stream **until EOF** (`n == 0`), `Sha256::update` each chunk, return hex. **Stop-on-short**: hash what was read (same as today’s `read_to_end`). Never `read_to_end` into a `Vec`. **Do not** fail when `bytes_read != expected_len` — that would turn a short local file into `IndexError::Io` via `check_tarstats_matches_archive` (`?` on `archive_full_hash`) instead of a digest / `Mismatch`. No `max_bytes` cap on this helper. **`pub` and re-export** so `oci_fingerprint` (`ratarmount/src/remote_open.rs`) can call it — `pub(crate)` will not compile across crates. **Do not** point `compute_hashes_limited` at this helper: that function must keep its `size` remaining loop (hashing past a TAR member is a digest break). |
| Window fill | `read_exact` into a caller-supplied `&mut [u8]` **sliced to the window length** (`&mut buf[..prefix_len]`). Never `read_exact` the full 4096 when `prefix_len < NESTED_FINGERPRINT_SAMPLE`. Hash `&buf[..prefix_len]` only — hashing the whole `[u8; 4096]` with trailing zeros **changes the digest**. |

`HASH_STREAM_CHUNK`: **64 KiB** (`64 * 1024`). Small enough to be a fixed scratch pad; large enough that `--hashes` on multi-MiB TAR members is not a syscall storm. Must be a named `pub(crate)` / `pub` const so tests can assert “no request larger than chunk” if they wrap `Read`.

Do **not** put `[u8; TARSTATS_FULL_HASH_MAX]` (256 KiB) on the stack.

### 2. Nested fingerprint: fixed windows only

Rewrite `from_seekable_body` / `from_head_only`:

- One stack buffer `[u8; NESTED_FINGERPRINT_SAMPLE]` (4096). If `NESTED_FINGERPRINT_SAMPLE` is ever raised above ~64 KiB, switch that const to a reused heap buffer of **exactly** the sample size — never `body_size`.
- Hash each window immediately; do **not** `prefix.clone()` for suffix/mid. Small body (`body_size ≤ sample`): suffix hex **equals** prefix hex (same bytes). Small-mid (`body_size ≤ 2 * sample`): mid hex **equals** prefix hex. Preserve those equalities — today’s `hex_sha256(&prefix.clone())` depends on them. In-place hash of `&buf[..len]` does **not** change the digest; hashing uninitialized / zero tail of the stack array **does**.
- `from_head_only`: still empty suffix/mid strings (not a hash of empty / prefix). Empty body (`body_size == 0`): prefix is `sha256("")`. **Seekable** empty body today always `read_exact`s a 0-length prefix (`nested.rs` ~L98–100; std returns `Ok(())`); suffix and mid are **`sha256("")`**, not empty strings. `matches()` treats empty mid as legacy-OK but **suffix is exact** — do not write empty suffix on the seekable path.
- `from_head_only` and `archive_edge_hashes` already guard `prefix_len == 0`; `from_seekable_body` does not. Either keep the 0-length `read_exact` or skip it; both are `Ok`. Always rewind to 0. Seek set unchanged (head / `body_size - sample` / `body_size / 2`).

**No API / schema change.** `matches()`, blob encode, and factory `fingerprint_nested_body` stay as-is.

### 3. Tarstats: edges stay 512; full hash streams

- `archive_edge_hashes`: stack `[u8; TARSTATS_SAMPLE_BYTES]`. Same first/last 512 policy.
- `archive_full_hash`: if `len > TARSTATS_FULL_HASH_MAX` → `Ok(None)` (unchanged). Else open the file and `sha256_hex_stream` **until EOF** (no second size cap). **Do not** change `TARSTATS_FULL_HASH_MAX`. Digests must match today’s `Sha256::digest(&buf)` of the slurp.

### 4. Content-hash fill: fixed hasher scratch

- Change `compute_hashes_limited` scratch from `vec![0u8; 1024 * 1024]` to `vec![0u8; HASH_STREAM_CHUNK]` (or a stack `[u8; 65536]`).
- Optional same-PR hoist: pass `&mut [u8]` into an inner loop from `fill_content_hashes` so N members reuse one buffer. Not required if the chunk is 64 KiB.
- Keep `MultiHasher` streaming and algorithm set (`crc32`, `md5`, `sha1`, `sha256`). Known-vector tests must still pass.

### 5. Similar fingerprints (same PR, thin)

`http_fingerprint` / `oci_fingerprint` full-hash arms are the same policy as `archive_full_hash`.

- **OCI:** after the existing `size ≤ TARSTATS_FULL_HASH_MAX` gate, `seek(0)` + `sha256_hex_stream(&mut blob)` **until EOF**. Do **not** pass `size` as a read cap — today’s full hash is `read_to_end` after `seek(0)`, so a blob whose length ≠ catalog `size` would change `full_sha256` if capped.
- **HTTP:** `fetch_http_range_bytes` is **only** used for these fingerprints. It accepts status **`206` or `200..300`** and `read_to_end`s the body (not `end-start+1`). If the server ignores `Range`, a length-capped stream changes the fingerprint. Keep `size == 0 → (None, None, None)` — that is **not** local `archive_full_hash` of empty. Smallest correct options (pick one, prefer A):
  - **A.** Add `hash_http_range_sha256(url, start, end_inclusive)` in `ratarmount-remote`. **Lock:** same status set as today (`206` or `200..300`); `end_inclusive` is **Range-header only**; stream the ureq body **to EOF**; **do not** rewrite `fetch_http_range_bytes` to cap at `end-start+1` or `Content-Length` (that changes fingerprints on HTTP 200 / ignored Range). Use the new helper for the **full-hash** GET when `0 < size ≤ 256 KiB`. Edges may keep the 512-byte `Vec`. If edges also move off the `Vec`, they must hash the response **to EOF** — a 512-byte read cap changes prefix/suffix hex on HTTP 200. Owner is `remote_open.rs` + `ratarmount-remote` (not factory).
  - **B.** Keep fetching the ≤256 KiB `Vec` for HTTP only; document as residual (network already paid; cap is policy). Do **not** leave OCI `read_to_end` if A or local stream is done.

Do not change `check_tarstats_matches_remote` rules.

---

## Explicit non-goals

| Out | Why |
|-----|-----|
| ZIP `decode_plain_member_from_file` / sequential `ZipFile` slurp | Member **payload** (STORE range `Vec` **and** Deflate inflate). Sequential ZIP already streams into `compute_hashes_limited`; parallel path still materializes decoded / stored bytes — **labeled residual**. |
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
| Nested small / boundary bodies | Body `< 4096` **and `== 4096`**: prefix == SHA-256 of the entire body; suffix == prefix; mid == prefix. Body `== 8192` (`2 * sample`): mid is still prefix (today: mid is prefix iff `body_size ≤ 2 * sample`); tail is the last 4096, not prefix. Body `> 8192`: three distinct windows. Hash `&buf[..window_len]` only. |
| Nested empty body | `from_seekable_body` with `body_size == 0`: prefix **and** suffix **and** mid are `sha256("")` (not empty strings). `from_head_only` empty: prefix `sha256("")`, suffix/mid empty strings. No panic. |
| Head-only unchanged | Existing `regression_head_only_fingerprint_does_not_seek_mid_tail` stays; empty suffix/mid. |
| Factory progressive | Existing `regression_progressive_nested_fingerprint_skips_mid_tail` stays. |
| `archive_full_hash` / `sha256_hex_stream` no slurp | Digest equals `hash_hex("sha256", &bytes)` for empty / small / `TARSTATS_FULL_HASH_MAX`. File of `TARSTATS_FULL_HASH_MAX + 1` → `None`. **Also** wrap a payload **larger than `HASH_STREAM_CHUNK`** so any `read` request `> HASH_STREAM_CHUNK` fails — a short reader never asks for more than 64 KiB, so `read_to_end` would stay green. You cannot unit-test “no `Vec`” without a custom allocator; the oversized-payload + chunk-size wrapper is the enforceable stand-in. |
| `archive_edge_hashes` | First/last 512 of a file `> 512` match one-shot hashes of those slices; file `≤ 512` suffix == prefix. **Also** 0-byte and 1-byte files: prefix hex == `hash_hex("sha256", &exact_bytes)` (catches a zero-padded `[u8; 512]`). |
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

- **Digest drift:** stream vs slurp must be bit-identical (lowercase hex). Test empty, 1 byte, `sample`, `sample+1`, `2*sample`, `TARSTATS_FULL_HASH_MAX`.
- **EOF policy (locked):** `sha256_hex_stream` and `compute_hashes_limited` **stop on `n == 0` and hash what was read**. Do **not** fail-closed on short local full-hash. Keep `read_exact` on **windows** (today’s nested/edge contract).
- **Window slice:** always hash `&buf[..window_len]`. Zero-padded stack tails are a silent digest break.
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

### Sweep 3 (2026-08-28) — VERDICT: ACCEPT

Fresh Task skeptic (final). No blockers. Current code matches every lock; plan is implementable as written without digest, schema, or progressive-path breaks. **Stop.** Do not implement on this branch.

### Sweep 2 (2026-08-28) — VERDICT: ACCEPT (nits folded)

Fresh Task skeptic (no resume). Folded lock-tightening before sweep 3:

1. HTTP option A: same status set (`206` or `200..300`); `end_inclusive` is Range-header only; stream to EOF; do not cap `fetch_http_range_bytes`. `size == 0` stays `(None, None, None)`. Edges-off-Vec must also EOF-hash.
2. `sha256_hex_stream` is `pub` + re-export for OCI; do not reuse it inside `compute_hashes_limited` (member `size` cap).
3. Tests: chunk wrapper must wrap payload `> HASH_STREAM_CHUNK`; edge 0-byte/1-byte exact hex; nested `== 4096` and `== 8192` boundaries.

### Sweep 1 (2026-08-28) — VERDICT: ACCEPT (nits folded)

Fresh Task skeptic. Picture of current code accepted. Nits were factual implementer traps; folded before sweep 2:

1. Lock `sha256_hex_stream` to stop-on-`n==0` (hash what was read). Dropped “prefer fail if short” (would turn short files into `IndexError::Io` on warm tarstats).
2. OCI full hash is `read_to_end` after `seek(0)`, not `size`-capped. HTTP Range helper accepts 200 and slurps the response body; option A must stream to EOF.
3. Digest-only `archive_full_hash` tests would stay green with `read_to_end`. Require a `Read` wrapper that rejects `read` requests `> HASH_STREAM_CHUNK`.
4. Seekable empty body: suffix/mid are `sha256("")`, not empty strings. Window fill must slice to `prefix_len`.
5. Parallel ZIP STORE `read_file_range_at` labeled as residual (full-member `Vec`, payload path).
