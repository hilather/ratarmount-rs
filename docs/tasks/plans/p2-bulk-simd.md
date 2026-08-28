# Plan: P2 True SIMD (only on bulk)

| Field | Value |
|-------|--------|
| **Status** | **Implemented** (`09f75f171fab3cbbad94ac3ec371595bc67bd531`; hygiene swap only — not True SIMD on multi-MB) |
| **Date** | 2026-08-28 |
| **Backlog** | [`docs/tasks/vectors-optimization.md`](../vectors-optimization.md) P2 “True SIMD (only on bulk)” — marked **`~`**, not `[x]` |
| **Companion (not this work)** | [`docs/tasks/vectorize-steal-patterns.md`](../vectorize-steal-patterns.md) — systems patterns; **not** SIMD |
| **Workspace** | `rust-version = "1.74"`; default CI is `cargo fmt --all -- --check` then clippy+test (no `nfsv4` / `gzip-rapidgzip`) |
| **Audience** | Implementers who already know `--hashes`, 7z password trial, G3/rapidgzip inflate |
| **Inventory HEAD** | Plan branch on top of `main` `5475d28`; implementation on `cursor/p2-bulk-simd-implement-3830` |
| **Supersedes** | Plan-only PR [#12](https://github.com/hilather/ratarmount-rs/pull/12) (`cursor/p2-bulk-simd-plan-aea4`) |

**Verdict (this document):** skeptic-plan-review **ACCEPT** (PR #12). Implementation follows §§4–7. Hygiene, not a thruput program. Do not claim True SIMD on multi-MB landed.

---

## 1. Problem

The density backlog’s last SIMD line is:

> CRC / memchr / bulk hash on **multi-MB buffers** (inflate output, full-file hash).
> **Not** a priority for short path-component lookups.

That is a *payload* problem, not a Vectorize / SoA problem. The reference for “when SIMD pays” is **zlib-rs / rapidgzip** (wide loops on decompressed or compressed streams), not Cloudflare Vectorize IVF/PQ.

**Sweep 1 correction:** the multi-MB CRC/hash work the bullet names is **already** `crc32fast` + `sha2` on `--hashes` / `compute_hashes_limited` (1 MiB stream chunks, including ZIP/7z inflate output). There is **no** memchr-on-inflate-output path. The remaining hand-rolled IEEE CRC is 7z `parse::crc32`, and its hot password-trial site hashes the **first non-empty file only** — shipped fixtures are 15 bytes, not multi-MB.

This plan therefore does **not** invent a new SIMD program. It (1) records the inventory, (2) specifies a **hygiene swap** of that last scalar payload CRC onto `crc32fast`, and (3) requires an honest `~` backlog residual instead of marking the P2 line `[x]` as “True SIMD on multi-MB buffers.”

---

## 2. Goals and non-goals

### Goals (implementation PR, after this plan is ACCEPTed)

1. Replace the **byte-at-a-time IEEE CRC-32** in `ratarmount-formats-sevenzip/src/parse.rs` with the workspace’s existing **`crc32fast`** crate (x86: PCLMUL + SSE4.2; aarch64: ARM CRC32 insn, not NEON; else scalar). Same function serves StartHeader (20 bytes), NextHeader (`next_header_size` packed bytes), and password-trial member/folder slices.
2. Keep bit-identical IEEE CRC-32 (zlib / 7z / xz poly `0xEDB88320`, init `0xFFFFFFFF`, final XOR).
3. Add the lowest-layer regression tests in the same commit (**hardcoded** IEEE vectors, not tautological crate-vs-crate). Existing encrypted-trial tests stay green.
4. Leave default CI / MSRV 1.74 green: `cargo fmt --all` before commit; `cargo clippy -p ratarmount-formats-sevenzip --all-targets -- -D warnings`; `cargo test -p ratarmount-formats-sevenzip --lib` (plus `hashing` on index if untouched). Workspace clippy+test only if Rust outside sevenzip changes (it should not).
5. Close the backlog line as **`~`**, not `[x]` — see §6.

### Non-goals (do not file as this P2)

| Item | Why |
|------|-----|
| SIMD on `StringPool` FNV-1a / path-component lookup | Explicit backlog non-goal; overhead dominates short strings |
| Nested fingerprint windows (`NESTED_FINGERPRINT_SAMPLE` = 4 KiB) | Separate P2 “fixed windows” item; not multi-MB |
| tarstats edges (512 B) / `TARSTATS_FULL_HASH_MAX` (256 KiB slurp) | Not multi-MB; already `sha2` |
| Hand-rolled `xz_seek::crc32_ieee` | Footer/index bodies are tens of bytes, not bulk |
| Adding `memchr` to WARC/HTTP/ZIP/SMB scans | No inflate-output haystack exists; see §3.3 |
| Retuning rapidgzip keep_index CRC | Default path/`from_reader` **already verify CRC** (`open_with_threads` / `open_seekable_gzip_rapidgzip`). Only `_fast` and `RATARMOUNT_RAPIDGZIP_NO_CRC` disable it. Do not flip that knob in this P2. |
| G3 miniz → zlib-rs cold-checkpoint swap | Deferred in [`g3-polish-batch.md`](../g3-polish-batch.md); inflate SIMD is a different train |
| ISA-L / `gzip-rapidgzip` default-on | Feature-gated; MSRV 1.87; not default CI |
| Cloudflare Vectorize / IVF / PQ / ANN | Wrong domain — see vectorize-steal-patterns |
| New `--hashes` algorithms, CLI flags, or rayon in `hashing.rs` | ZIP already parallelizes inflate+hash (FR-4) |
| Streaming 7z CRC during decode (avoid the `Vec`) | RAM / decoder change; not SIMD |
| 7z CRC on every `open`/`cat` | Today CRC runs at header parse + password trial only |
| `sha2` `asm` / crate major bump | x86 SHA-NI is already on via `cpufeatures` in sha2 0.10.9; aarch64 hardware SHA in that crate is behind `asm`. `asm` is `SHOULD NOT` for library crates and an MSRV/CI risk. Do not enable it. |
| README / mount-option / nested-matrix updates | No user-visible flag or open-path change |
| Claiming this PR “lands True SIMD on multi-MB buffers” | `--hashes` already did; trial CRC is usually a small first member |

---

## 3. Inventory (existing paths)

Investigated 2026-08-28. Prefer **existing crates** over new SIMD.

### 3.1 Already crate-backed (do not reimplement)

| Path | Crate | Buffer | Notes |
|------|-------|--------|-------|
| `--hashes` / `compute_hashes_limited` / `hash_hex` | `crc32fast` 1.5 + `sha2` 0.10 + `sha1` + `md-5` | 1 MiB stream chunks (`hashing.rs`), any member size | **This is the full-file hash path.** CRC is already SIMD. SHA-256 uses SHA-NI on **x86/x86_64** via `cpufeatures`; not aarch64 without `asm`. |
| TAR `fill_content_hashes` | same | raw archive bytes at `offset` | Path-backed uncompressed TAR |
| ZIP `store_member_content_hashes` | same | **decompressed** member (`Cursor` over inflate output) | Parallel Stored/Deflate via `File::try_clone` |
| 7z `fill_member_content_hashes` | same | decoded member `Vec` then `compute_hashes_limited` | Inflate/decode dominates; hash is crate-SIMD |
| G3 / ZIP / CAB / XAR inflate | `flate2` / `miniz_oxide` / `zlib-rs` (GZIDX hard restore only) | codec output | Inflate SIMD belongs to those crates, not this P2 |
| Rapidgzip path | `rapidgzip-core` + zlib-rs or ISA-L | multi-MB gzip | Opt-in feature; keep_index **CRC on by default** (crate-internal, not our scalar loop). `_fast` / `RATARMOUNT_RAPIDGZIP_NO_CRC` opt out. |

`crc32fast` and `sha2` are already in `Cargo.lock`. `memchr` 2.8.3 is a **transitive** dep (no `use memchr` in this workspace). `flate2` already pulls `crc32fast` transitively; sevenzip still needs a **direct** dep to call it from `parse.rs`.

### 3.2 Hand-rolled IEEE CRC-32 (same poly, scalar byte loop)

```text
crc = 0xFFFFFFFF
for each byte:
    crc ^= byte
    8 shift/xor steps with 0xEDB88320
crc = !crc
```

Verified the same poly/init/xor as `crc32fast::hash` (ISO-HDLC / zlib). xz already asserts `b"123456789" → 0xCBF4_3926`. `hashing.rs` asserts `b"abc"` CRC hex `352441c2`.

| Site | What is hashed | Typical size | Bulk? |
|------|----------------|--------------|-------|
| `parse::crc32` StartHeader | 20-byte `start_data` (offset + size + CRC fields) | 20 B | **No** |
| `parse::crc32` NextHeader | packed `header_data` of length `next_header_size` | packed 7z header; can grow with file count; **not** inflate output | **No** (metadata) |
| `parse::crc32_for_password_trial` | First non-empty file only (`resolve_password_for_archive` finds `size > 0 && !is_dir`, then `try_decrypt_entry_io`) | Shipped `ensure_encrypted_hello_fixture` / store+AES: `b"secret content\n"` (**15 B**). Decode vs CRC: unused progressive decoder + only `entry.crc` still **decodes the whole folder** then CRCs the **member slice**. Folder-wide CRC runs when `folder.has_crc`. A 3 MiB first member exists in `regression_aes_lzma2_solid_*` when `a.bin` is first. | **Usually no.** Occasional large first member is why the swap is slightly more than xz-footer hygiene — still not a thruput program. |
| `xz_seek::crc32_ieee` | xz index/footer | ≪ 1 KiB | **No** — leave alone |

7z does **not** CRC decompressed members on `open`/`cat` — only header parse + password trial.

The swap still applies to **all** `parse::crc32` callers (headers ride along automatically). Do not describe trial CRC as “the multi-MB inflate-output path.”

### 3.3 memchr-shaped scans (not this P2)

| Site | Haystack | Verdict |
|------|----------|---------|
| WARC `find_subslice` (`windows().position` for `\r\n\r\n`) | Remainder of slurped WARC from `pos` | Happy path stops at a short header |
| HTTP `request.rs` header terminator | Request buffer | Small |
| ZIP **production** `find_eocd_in_tail` | Last `EOCD_SEARCH_MAX` (65 535 + 22) bytes | ≤ ~64 KiB tail; **not** the test-only `windows(4).rposition` at zip `lib.rs` ~3247 |
| HTML doctype windows | Tiny prefix | Small |
| SMB `extract_ntlm` `windows(8)` for `NTLMSSP\0` | Negotiate blob | Tiny |
| `StringPool::fnv1a64` | Path components | **Forbidden** |

No call site scans **inflate output** with `memchr` or `windows().position`. Full-file hash is `crc32fast`/`sha2`, not a byte search. Do not add the `memchr` crate “because the backlog bullet listed it.”

### 3.4 What “zlib-rs / rapidgzip is the reference” means here

- SIMD only when the buffer is large enough that vector width amortizes. That situation **already** exists on `--hashes` streams, not on typical 7z password trial.
- Use a **maintained crate** that already has the wide implementation (`crc32fast`, `sha2`, zlib-rs, rapidgzip). Do not write `#[target_feature]` loops.
- Do **not** copy Vectorize (embeddings, IVF, PQ, ANN). That file already points P2 SIMD here.

---

## 4. Smallest correct change

One behavior-preserving swap, one crate already in the workspace, tests at the parse layer. **Hygiene**, not a thruput program.

### 4.1 Code

1. Add `crc32fast = "1"` to `ratarmount-formats-sevenzip/Cargo.toml` (same version as `ratarmount-index`; lockfile already has 1.5.0). Direct dep is required even though `flate2` pulls it transitively.
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

### 4.2 Why this and not a larger patch (or no patch)

- `--hashes` CRC/SHA is **already** the bulk-hash SIMD path. Re-tuning `sha2` features is speculation.
- 7z `parse::crc32` is the **only remaining hand-rolled payload/container CRC** besides xz footers (leave xz). It is **not** typically multi-MB.
- Inflate/decrypt still dominates encrypted-open wall time. This change does **not** claim a user-visible mount speedup.
- Shipping the swap without an honest residual would be a **no-op dressed as P2**. The implementation PR exists to (a) stop maintaining a scalar twin of `crc32fast`, (b) pin IEEE vectors, (c) mark the backlog `~` with the residual in §6.

### 4.3 Compatibility

`crc32fast` implements ISO-HDLC / zlib / PNG CRC-32. 7z folder/file CRCs and the xz known vector `b"123456789" → 0xCBF4_3926` use that polynomial. Existing tests that compare trial CRC to archive `want` values must keep passing; a mismatch means **stop** (do not paper over with a different init).

---

## 5. Tests (same implementation commit)

AGENTS.md: every behavior change ships a regression test. Name/doc with `Regression:`.

Pin **hardcoded** IEEE vectors (or a copy of the old 8-step loop on a tiny fixture). After `parse::crc32` becomes `crc32fast::hash`, asserting equality to a second `crc32fast::hash` is tautological and will not catch a wrong wrapper.

| Test | Layer | Assert |
|------|-------|--------|
| `parse::crc32` known vector `b"123456789"` → `0xCBF4_3926` | `ratarmount-formats-sevenzip --lib` | Bit-identical to IEEE / xz vector |
| Empty + one-byte: `b""` → `0x00000000`, `b"a"` → `0xE8B7BE43` (IEEE) | same | Hardcoded; catches init/xor mistakes |
| Existing `encrypted` / `encrypted_wrong_password` / `encrypted_store_aes` | same crate | Wrong password still fails; store+AES still exact bytes |
| `cargo test -p ratarmount-index --lib hashing` | no code change expected | `--hashes` vectors unchanged (`abc` / `foo\n`) |

Do **not** add a CI microbench gate or invent MiB/s numbers. Do **not** list `filetime` as a CRC filter (`filetime` is FILETIME→Unix only).

When implementing, add one AGENTS.md catalog row, for example:

```text
| 7z parse CRC uses crc32fast (IEEE) | `cargo test -p ratarmount-formats-sevenzip --lib crc32` · `cargo test -p ratarmount-formats-sevenzip --lib encrypted` · `cargo test -p ratarmount-formats-sevenzip --lib encrypted_wrong_password` · `cargo test -p ratarmount-formats-sevenzip --lib encrypted_store_aes` |
```

(Use the actual new test filter name. Run filters **separately** — `cargo test` does not treat `|` as OR.)

---

## 6. Docs (implementation PR)

| Doc | Change |
|-----|--------|
| [`vectors-optimization.md`](../vectors-optimization.md) P2 SIMD | Mark **`~`**, **not** `[x]`. Residual text must say: `--hashes` / inflate-output hash already `crc32fast`+`sha2`; 7z `parse::crc32` now `crc32fast` (trial is first file, usually small); **no** memchr-on-inflate path exists; path-component SIMD remains a non-goal. Do not redefine the checkbox as “True SIMD on multi-MB landed.” Optional clarifying gloss: “no remaining hand-rolled CRC/hash on payload buffers (memchr-on-inflate never existed).” |
| This plan | Set status Implemented + commit SHA |
| README / parity / mount-options / embedded-nested | **None** (no user-visible capability) |
| `vectorize-steal-patterns.md` | No change (already points here) |

---

## 7. Implementation order (after ACCEPT)

1. `crc32fast` dep + `parse::crc32` swap + hardcoded known-vector unit tests.
2. Run: `cargo fmt --all` · `cargo clippy -p ratarmount-formats-sevenzip --all-targets -- -D warnings` · `cargo test -p ratarmount-formats-sevenzip --lib` then the `encrypted*` filters **separately**.
3. Same-commit docs: vectors-optimization `~` + AGENTS.md catalog row. `cargo fmt --all` still required (AGENTS.md). Workspace clippy only if Rust outside sevenzip changed.
4. Stop. Do not “also” retouch xz, WARC, `sha2`, or mark the P2 line `[x]`.

---

## 8. Risks

| Risk | Mitigation |
|------|------------|
| `crc32fast` init/poly disagrees with 7z on some length | Hardcoded IEEE vectors + existing trial tests; fail closed |
| Reviewer treats this as an inflate or `--hashes` perf claim | PR text: hygiene; no MiB/s; backlog stays `~` |
| Scope creep into G3/rapidgzip/ISA-L | Listed as non-goals; those trains have their own docs |
| MSRV 1.74 | `crc32fast` 1.5 already built on default CI |
| macOS / non-x86 | `crc32fast` uses ARM CRC32 on aarch64, scalar elsewhere; no `#[cfg(target_arch)]` in our code |
| Closing P2 as done | Forbidden; see §6 |

---

## 9. Skeptic-plan-review

Process: **never skip sweep 1**. Each sweep is a **fresh** skeptic (not the author, not a prior skeptic). Fold blockers into this file. **Cap 3** skeptic sweeps; if still unresolved → **BLOCKED**. Stop at **ACCEPT** or **BLOCKED**. This PR does not implement.

| Sweep | Role | Verdict | Folded into |
|-------|------|---------|-------------|
| 0 | Author inventory + smallest-change draft | — | §§1–8 (superseded by sweep 1) |
| 1 | Fresh skeptic | **REVISE** | Trial is first-file / usually 15 B (§§1, 3.2, 4.2). NextHeader is `next_header_size`, not 20 B (§3.2). Do not mark P2 `[x]` (§6). Tests must pin hardcoded IEEE vectors (§5). ZIP production EOCD is `find_eocd_in_tail` (§3.3). SHA-NI is x86-only; `asm` stays off (§2). AGENTS.md catalog must not use `filetime` (§5). |
| 2 | Fresh skeptic (not sweep 1) | **ACCEPT** | No blockers. Factual nits folded here: rapidgzip keep_index CRC is **on** by default (§2/§3.1); `crc32fast` aarch64 is ARM CRC32 not NEON (§2/§8); trial decode-vs-CRC wording (§3.2). |
| 3 | *(not run — sweep 2 ACCEPT)* | — | |

**Final: ACCEPT** — implement from a later PR using §§4–7. Plan-only PR #12 is superseded by this implementation.

---

## 10. Implementation (this PR)

Followed §§4–7. `parse::crc32` is `crc32fast::hash`; `crc32_for_password_trial` remains the alias. P2 SIMD backlog is **`~`**. Did not touch `xz_seek::crc32_ieee`, `hashing.rs`, `sha2` asm, rapidgzip CRC knobs, inflate backends, `memchr`, path-component SIMD, or CLI flags.

Skeptic-code-review of the implementation diff (never skip sweep 1; cap 3; stop at ACCEPT or BLOCKED):

| Sweep | Role | Verdict | Folded into |
|-------|------|---------|-------------|
| 1 | Fresh skeptic (not the implementer) | **ACCEPT** | No blockers. Nit: plan SHA is the swap commit `09f75f1`, not the SHA-stamp follow-up (chicken-and-egg; §6 satisfied). |
| 2 | *(not run — sweep 1 ACCEPT)* | — | |
| 3 | *(not run)* | — | |

**Final: ACCEPT.** Hygiene swap only. Do not claim True SIMD on multi-MB landed.

---

## Related

- Density backlog: [`docs/tasks/vectors-optimization.md`](../vectors-optimization.md)
- Vectorize systems (not SIMD): [`docs/tasks/vectorize-steal-patterns.md`](../vectorize-steal-patterns.md)
- Gzip inflate trains: [`docs/gzip-binding-decision.md`](../../gzip-binding-decision.md), [`g3-polish-batch.md`](../g3-polish-batch.md), [`rapidgzip-perf-batch.md`](../rapidgzip-perf-batch.md)
- Code: `ratarmount-index/src/hashing.rs`, `ratarmount-formats-sevenzip/src/parse.rs` + `lib.rs` (`resolve_password_for_archive`, `try_decrypt_entry_io`), `ratarmount-formats-zip/src/lib.rs` (`store_member_content_hashes`, `find_eocd_in_tail`), `ratarmount-compress/src/xz_seek.rs`
