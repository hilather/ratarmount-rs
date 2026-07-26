# Gzip binding decision (PR-08a)

**Date:** 2026-07-25  
**Decision:** **G3** (pure Rust Tier A+B via `flate2`) for 1.0 alpha.

## Options considered

| Option | Description | Status |
|--------|-------------|--------|
| **G1** | Existing crate / C API over rapidgzip | Deferred; optional later if seek-table interop needed |
| **G2** | In-tree C++ shim over rapidgzip | Not default |
| **G3** | Pure `flate2` + materialize-to-temp for random access | **Chosen** |

## Implementation (alpha)

1. Detect gzip magic `1f 8b`.
2. Decompress with `flate2::read::MultiGzDecoder` into a `NamedTempFile`.
3. If body is TAR (ustar magic or `.tar.gz` / `.tgz` name): run `SQLiteIndexedTar` on the temp body.
4. Else: `SingleFileMountSource` with stripped name (`simple.gz` → `simple`).
5. Python gzip index blob import (**Tier C**) is **not** a 1.0 blocker; rebuild/materialize is OK.

## Kill criteria met

- `tests/simple.gz` mounts and md5 matches golden content.
- No dependency on rapidgzip C ABI for alpha path.
