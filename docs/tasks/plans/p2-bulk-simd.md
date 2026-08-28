# Plan: P2 True SIMD (only on bulk)

| Field | Value |
|-------|--------|
| **Status** | Draft — skeptic-plan-review in progress |
| **Date** | 2026-08-28 |
| **Backlog** | [`docs/tasks/vectors-optimization.md`](../vectors-optimization.md) P2 “True SIMD (only on bulk)” |
| **Companion (not this work)** | [`docs/tasks/vectorize-steal-patterns.md`](../vectorize-steal-patterns.md) — systems patterns; **not** SIMD |
| **Workspace** | `rust-version = "1.74"`; default CI is `cargo fmt --all -- --check` then clippy+test (no `nfsv4` / `gzip-rapidgzip`) |
| **Audience** | Implementers who already know `--hashes`, 7z password trial, G3/rapidgzip inflate |

**Verdict (this document):** stop at skeptic **ACCEPT** or **BLOCKED**. Do not implement from this PR.

---

## 1. Problem

The density backlog’s last SIMD line is:

> CRC / memchr / bulk hash on **multi-MB buffers** (inflate output, full-file hash).
> **Not** a priority for short path-component lookups.

That is a *payload* problem, not a Vectorize / SoA problem. The reference for “when SIMD pays” is **zlib-rs / rapidgzip** (wide loops on decompressed or compressed streams), not Cloudflare Vectorize IVF/PQ.

This plan inventories the existing hash/CRC/scan paths, names the one remaining hand-rolled bulk-capable CRC, and specifies the **smallest correct change**. It does not propose a SIMD program, new CLI flags, or inflate-backend swaps.

---

## 2. Goals and non-goals

### Goals (implementation PR, after this plan is ACCEPTed)

1. Replace the **byte-at-a-time IEEE CRC-32** used on **decompressed 7z member/folder buffers** (password-trial path) with the workspace’s existing **`crc32fast`** crate (PCLMUL / SSE4.2 / NEON; scalar fallback).
2. Keep bit-identical IEEE CRC-32 (zlib / 7z / xz poly `0xEDB88320`, init `0xFFFFFFFF`, final XOR).
3. Add the lowest-layer regression tests in the same commit (known vector + existing encrypted-trial tests stay green).
4. Leave default CI / MSRV 1.74 green: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace` (or scoped `-p ratarmount-formats-sevenzip` + `-p ratarmount-index` if the helper lives in index).

### Non-goals (do not file as this P2)

| Item | Why |
|------|-----|
| SIMD on `StringPool` FNV-1a / path-component lookup | Explicit backlog non-goal; overhead dominates short strings |
| Nested fingerprint windows (`NESTED_FINGERPRINT_SAMPLE` = 4 KiB) | Separate P2 “fixed windows” item; not multi-MB |
| tarstats edges (512 B) / `TARSTATS_FULL_HASH_MAX` (256 KiB slurp) | Not multi-MB; already `sha2` |
| Hand-rolled `xz_seek::crc32_ieee` | Footer/index bodies are tens of bytes, not bulk |
| Adding `memchr` to WARC/HTTP/ZIP signature scans | Happy-path haystacks are headers / last-64 KiB EOCD, not inflate output |
| Turning on rapidgzip `crc32_enabled` | Adds work; currently off for keep_index cost (`gzip_rapidgzip.rs`) |
| G3 miniz → zlib-rs cold-checkpoint swap | Deferred in [`g3-polish-batch.md`](../g3-polish-batch.md); inflate SIMD is a different train |
| ISA-L / `gzip-rapidgzip` default-on | Feature-gated; MSRV 1.87; not default CI |
| Cloudflare Vectorize / IVF / PQ / ANN | Wrong domain — see vectorize-steal-patterns |
| New `--hashes` algorithms, CLI flags, or rayon in `hashing.rs` | ZIP already parallelizes inflate+hash (FR-4) |
| Streaming 7z CRC during decode (avoid the `Vec`) | RAM / decoder change; not SIMD |
| `sha2` `asm` / crate major bump | `sha2` 0.10 already uses SHA-NI via `cpufeatures` when present; `asm` is MSRV/CI risk |
| README / mount-option / nested-matrix updates | No user-visible flag or open-path change |

---

## 3. Inventory (existing paths)

Investigated 2026-08-28 on `main` (`5475d28` era). Prefer **existing crates** over new SIMD.

### 3.1 Already crate-backed (do not reimplement)

| Path | Crate | Buffer | Notes |
|------|-------|--------|-------|
| `--hashes` / `compute_hashes_limited` / `hash_hex` | `crc32fast` 1.5 + `sha2` 0.10 + `sha1` + `md-5` | 1 MiB stream chunks, any member size | **This is the full-file hash path.** CRC is already SIMD. SHA-256 uses SHA-NI when the CPU has it. |
| TAR `fill_content_hashes` | same | raw archive bytes at `offset` | Path-backed uncompressed TAR |
| ZIP `store_member_content_hashes` | same | **decompressed** member (`Cursor` over inflate output) | Parallel Stored/Deflate via `File::try_clone` |
| 7z `fill_member_content_hashes` | same | decoded member `Vec` then `compute_hashes_limited` | Inflate/decode dominates; hash is crate-SIMD |
| G3 / ZIP / CAB / XAR inflate | `flate2` / `miniz_oxide` / `zlib-rs` (GZIDX hard restore only) | codec output | Inflate SIMD belongs to those crates, not this P2 |
| Rapidgzip path | `rapidgzip-core` + zlib-rs or ISA-L | multi-MB gzip | Opt-in feature; CRC gated **off** on keep_index |

`crc32fast` and `sha2` are already in `Cargo.lock`. `memchr` 2.8.3 is a **transitive** dep (not used by our crates for bulk scan).

### 3.2 Hand-rolled IEEE CRC-32 (same poly, scalar byte loop)

```text
crc = 0xFFFFFFFF
for each byte:
    crc ^= byte
    8 shift/xor steps with 0xEDB88320
crc = !crc
```

| Site | Typical size | Bulk? |
|------|----------------|-------|
| `ratarmount-formats-sevenzip/src/parse.rs` `crc32` / `crc32_for_password_trial` | **Decompressed member or whole folder** on encrypted open; also 20-byte start/next-header | **Yes on trial** (inflate output). Headers are not the reason to change. |
| `ratarmount-compress/src/xz_seek.rs` `crc32_ieee` | xz index/footer (≪ 1 KiB) | **No** — leave alone |

Header checks (`parse.rs` ~1053 / ~1072) can keep calling the same function after the swap; speed is irrelevant there. Password trial (`lib.rs` ~652 / ~684 / ~701) is the only place this loop runs on multi-MB inflate output.

### 3.3 memchr-shaped scans (not this P2)

| Site | Haystack | Verdict |
|------|----------|---------|
| WARC `find_subslice` (`windows().position` for `\r\n\r\n`) | Remainder of slurped WARC from `pos` | Happy path stops at a short header. Do not add `memchr` “because the bullet listed it.” |
| HTTP `request.rs` header terminator | Request buffer | Small |
| ZIP EOCD `windows(4).rposition` | Tail of central directory | ≤ 64 KiB + comment |
| HTML doctype windows | Tiny prefix | Small |
| `StringPool::fnv1a64` | Path components | **Forbidden** |

No call site hashes or scans **inflate output** with a scalar `memchr`-equivalent today. Full-file hash is `crc32fast`/`sha2`, not a byte search.

### 3.4 What “zlib-rs / rapidgzip is the reference” means here

- SIMD only when the buffer is large enough that vector width amortizes (multi-MB inflate output, `--hashes` streams).
- Use a **maintained crate** that already has the wide implementation (`crc32fast`, `sha2`, zlib-rs, rapidgzip). Do not write `#[target_feature]` loops.
- Do **not** copy Vectorize (embeddings, IVF, PQ, ANN). That file already points P2 SIMD here.

---

## 4. Smallest correct change

One behavior-preserving swap, one crate already in the workspace, tests at the parse layer.

### 4.1 Code

1. Add `crc32fast = "1"` to `ratarmount-formats-sevenzip/Cargo.toml` (same version as `ratarmount-index`; lockfile already has 1.5.0).
2. Replace `parse::crc32` with:

   ```rust
   pub(crate) fn crc32(data: &[u8]) -> u32 {
       crc32fast::hash(data)
   }
   ```

   Keep `crc32_for_password_trial` as the alias so trial call sites stay readable.
3. Do **not** change `xz_seek::crc32_ieee`, `hashing.rs`, factory, FUSE, or inflate backends.
4. Do **not** export a new workspace-wide CRC helper unless a second *bulk* caller appears. Layering: format CRC stays in the format crate; `--hashes` stays in `ratarmount-index`.

Alternative (rejected for this pass): re-export `crc32fast::hash` from `ratarmount-index::hashing` to avoid a direct sevenzip dep. sevenzip already depends on index, but parse.rs should not grow an index-hashing import for a container CRC.

### 4.2 Why this and not a larger patch

- `--hashes` CRC/SHA is **already** the bulk-hash SIMD path. Re-tuning `sha2` features is speculation.
- 7z trial CRC is the **only** remaining scalar loop that runs on decompressed multi-MB buffers.
- Inflate still dominates trial wall time (AES/LZMA2). This change does **not** claim a user-visible mount speedup. It removes a known-wrong toolbox (hand-rolled CRC next to `crc32fast`) and makes the backlog item honest.
- If a later bench shows trial CRC ≥ a meaningful share of encrypted-open time, the same crate is already on the path. No second rewrite.

### 4.3 Compatibility

`crc32fast` implements ISO-HDLC / zlib / PNG CRC-32. 7z folder/file CRCs and the xz known vector `b"123456789" → 0xCBF4_3926` use that polynomial. Existing tests that compare trial CRC to archive `want` values must keep passing; a mismatch means **stop** (do not paper over with a different init).

---

## 5. Tests (same implementation commit)

AGENTS.md: every behavior change ships a regression test. Name/doc with `Regression:`.

| Test | Layer | Assert |
|------|-------|--------|
| `parse::crc32` known vector `b"123456789"` → `0xCBF4_3926` | `ratarmount-formats-sevenzip --lib` (next to existing `filetime` / `encrypted` tests) | Bit-identical to IEEE / xz vector |
| Empty and short buffers (`b""`, `b"a"`) match a second independent `crc32fast::hash` or the old formula on a tiny fixture | same | No off-by-init on empty |
| Existing `encrypted` / `encrypted_wrong_password` / `encrypted_store_aes` | same crate | Wrong password still fails; store+AES still exact bytes |
| `cargo test -p ratarmount-index --lib hashing` | no code change expected | `--hashes` vectors unchanged |

Do **not** add a CI microbench gate or invent MiB/s numbers. Optional local `criterion` is out of scope.

When implementing, add one AGENTS.md catalog row, for example:

```text
| 7z password-trial CRC uses crc32fast (IEEE) | `cargo test -p ratarmount-formats-sevenzip --lib filetime` · `… encrypted` · new `crc32` known-vector filter |
```

(Use the actual new test filter name.)

---

## 6. Docs (implementation PR)

| Doc | Change |
|-----|--------|
| [`vectors-optimization.md`](../vectors-optimization.md) P2 SIMD | Mark `[x]`; one-line residual: `--hashes` already crate-SIMD; 7z trial CRC now `crc32fast`; memchr/path SIMD still non-goals |
| This plan | Set status Implemented + commit SHA |
| README / parity / mount-options / embedded-nested | **None** (no user-visible capability) |
| `vectorize-steal-patterns.md` | No change (already points here) |

---

## 7. Implementation order (after ACCEPT)

1. `crc32fast` dep + `parse::crc32` swap + known-vector unit test.
2. Run: `cargo fmt --all` · `cargo clippy -p ratarmount-formats-sevenzip --all-targets -- -D warnings` · `cargo test -p ratarmount-formats-sevenzip --lib` (include `encrypted`, `crc32` / `filetime` filters separately — `cargo test` does not treat `\|` as OR).
3. Workspace clippy+test before merge if anything outside sevenzip touched (should not be).
4. Flip backlog checkbox + AGENTS.md row in the **same** commit.
5. Stop. Do not “also” retouch xz, WARC, or `sha2`.

---

## 8. Risks

| Risk | Mitigation |
|------|------------|
| `crc32fast` init/poly disagrees with 7z on some length | Known vector + existing trial tests; fail closed |
| Reviewer treats this as an inflate or `--hashes` perf claim | PR text: correctness/hygiene; no MiB/s |
| Scope creep into G3/rapidgzip/ISA-L | Listed as non-goals; those trains have their own docs |
| MSRV 1.74 | `crc32fast` 1.5 already built on default CI |
| macOS / non-x86 | `crc32fast` has scalar + NEON; no `#[cfg(target_arch)]` in our code |

---

## 9. Skeptic-plan-review

Process: **never skip sweep 1**. Each sweep is a **fresh** skeptic (not the author). Fold blockers into this file. **Cap 3** skeptic sweeps; if still unresolved → **BLOCKED**. Stop at **ACCEPT** or **BLOCKED**. This PR does not implement.

| Sweep | Role | Verdict | Folded into |
|-------|------|---------|-------------|
| 0 | Author inventory + smallest-change draft | — | §§1–8 |
| 1 | Fresh skeptic (required) | *pending* | |
| 2 | Fresh skeptic (only if sweep 1 is not ACCEPT) | | |
| 3 | Fresh skeptic (last) | | |

**Final:** *pending sweep 1*

---

## Related

- Density backlog: [`docs/tasks/vectors-optimization.md`](../vectors-optimization.md)
- Vectorize systems (not SIMD): [`docs/tasks/vectorize-steal-patterns.md`](../vectorize-steal-patterns.md)
- Gzip inflate trains: [`docs/gzip-binding-decision.md`](../../gzip-binding-decision.md), [`g3-polish-batch.md`](../g3-polish-batch.md), [`rapidgzip-perf-batch.md`](../rapidgzip-perf-batch.md)
- Code: `ratarmount-index/src/hashing.rs`, `ratarmount-formats-sevenzip/src/parse.rs`, `ratarmount-formats-zip/src/lib.rs` (`store_member_content_hashes`), `ratarmount-compress/src/xz_seek.rs`
