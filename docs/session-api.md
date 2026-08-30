# Session API (`ratarmount-session`)

In-process embedder contract for [ratarmount-rs](https://github.com/hilather/ratarmount-rs). Desktop GUIs and other hosts browse, search, preview, and extract archives **without FUSE** and **without importing the `ratarmount` binary crate**.

This crate is the **supported embedder surface**. Path-depend it (`ratarmount-session = { path = "…" }`). It is **not** published on crates.io in this slice. Never treat the `ratarmount` binary crate as a library.

Related: [`docs/tasks/gui-embedder-support.md`](tasks/gui-embedder-support.md), [`docs/crates-io-policy.md`](crates-io-policy.md) (L3.5).

## Status (this slice)

| Surface | This crate today | Lands |
|---------|------------------|-------|
| Types (`SourceSpec`, `OpenRequest`, `DirCursor`, `FindCursor`, `DirEnt`, …) | **compile** | G0.1 |
| `Error` (no `Busy`) | **compile** | G0.1 |
| `Session` (`Send + Sync`, no `Clone`) | **`open` / `list_dirents_page` / `lookup` / `read_range` / `extract_to` / `find` / `Drop`** | G1.1–G1.6 / G3 |
| `IndexJob` | **`run` (blocking)** | G2 |
| `RangeReader` | **`Read + Send`** (capped; not `Sync`; no member `Vec`) | G1.4 |
| `Session::open` | **implemented** (catalog via `open_catalog_read_only`) | G1.1 |
| `open_with_job` | **implemented** (`OpenOptions.index_build` hooks) | G2 |
| `list_dirents_page` / `lookup` | **implemented** (SQL keyset; no `list()` dump) | G1.2 / G1.3 |
| `read_range` / `extract_to` | **implemented** (fill-loop + 64 KiB copy; no slurp) | G1.4 / G1.5 |
| `Session::find` | **implemented** (SQL `FindAfter` keyset; CLI first page still 10_000) | G3 |
| `IndexJob::run` | **implemented** (Always rebuild; cancel never `publish_tmp`) | G2 |
| `resolve_index` | **implemented** (`SiblingNotWritable`; `UserCache` → `local-index-v1`; CliCompat still `:memory:`) | G4 / PR6–PR7 |
| Factory (`open_path`, `build_mount_source_ex`) | **`pub mod factory`** (CLI share; Session remains the embedder API) | PR2 |
| Format crates (TAR/ZIP/7z always; other L2 via `formats-all`) | default `formats-all`; `--no-default-features` = TAR/ZIP/7z | G5.3 / PR9 |
| `OpenOptions` Debug | passwords printed as `[redacted N]` | G5.2 / PR3 |

`cargo tree -p ratarmount-session -i fuser` is empty (G0.3a). Default features must **not** pull fuse, nfs, smb, http, 9p, or sftp.

SQLite sidecar schema stays **`INDEX_VERSION` `"0.7.0"`**. No IVF, no `--readdir-order`.

## Types

```rust
pub enum SourceSpec { Path(PathBuf), Url(String) }

pub enum IndexPolicy { Sibling, UserCache, Explicit, Memory, Temp, CliCompat }

pub enum Recreate { Never, IfInvalid, Always }

pub struct OpenRequest {
    pub source: SourceSpec,
    pub index: IndexPolicy,
    pub explicit_index: Option<PathBuf>,  // required when index == Explicit
    pub extra_dirs: Vec<PathBuf>,         // --index-folders extras, not implicit sibling ""
    pub password: Option<secrecy::SecretString>,
    pub recursive: bool,
    pub recursion_depth: Option<i32>,
    pub recreate: Recreate,
}

pub enum DirCursor { Start, AfterName { name: String } }

pub enum FindCursor { Start, AfterPath { path: String, offsetheader: Option<i64> } }

pub struct DirPage {
    pub path: String,
    pub entries: Vec<DirEnt>,
    pub next_cursor: Option<DirCursor>,
    pub total_hint: Option<u64>,  // cheap COUNT on SQLite; None for live FolderMountSource
}

pub struct DirEnt {
    pub name: String,
    pub path: String,                 // archive-relative, leading `/`, no trailing `/`
    pub is_dir: bool,
    pub size: u64,
    pub mtime: Option<i64>,           // Unix seconds; None if the cheap row has no mtime
    pub mode: u32,
    pub archive_offset: Option<u64>,  // catalog hint only — do not fetch bytes with this
}

pub struct ReadRequest {
    pub path: String,
    pub offset: u64,
    pub max_len: u64,  // hard cap; 0 → empty reader; no “read the rest” sentinel
}

pub enum Overwrite { Skip, Replace }

pub struct ExtractRequest {
    pub members: Vec<String>,  // empty = every payload member (catalog walk, not list() Vec)
    pub dest_dir: PathBuf,
    pub overwrite: Overwrite,
    pub allow_unsafe_paths: bool,  // default false: reject `..`, absolute, Windows prefixes
}

pub struct ExtractProgress {
    pub files_done: u64,
    pub files_hint: Option<u64>,
    pub bytes_out: u64,
    pub current_path: Option<String>,
}

pub enum IndexPhase { Scan, Write, Fts, Finalize }

pub struct IndexProgress {
    pub phase: IndexPhase,
    pub bytes_scanned: u64,
    pub bytes_total_hint: Option<u64>,
    pub entries: u64,
    pub message: Option<String>,
}

pub struct FindOpts {
    pub fts: bool,
    pub offset_order: bool,
    pub include_hashes: bool,
    pub fill_hashes: Vec<String>,
    pub limit: u32,
    pub cursor: FindCursor,
}

pub struct FindPage {
    pub pattern: String,
    pub fts: bool,
    pub entries: Vec<DirEnt>,
    pub next_cursor: Option<FindCursor>,
    pub total_hint: Option<u64>,
}
```

`DirCursor` is for directory listing only. `find` uses `FindCursor`. Separate types so a directory cursor cannot be passed to locate. Do **not** put SQLite `rowid` on `DirEnt` or on the JS boundary. Napi opaque-encodes either cursor enum.

One `Session` holds **one** `SourceSpec` (GUI v1 = one archive per window). Multi-input union stays CLI `build_mount_source_ex`.

Passwords are `secrecy::SecretString` on this boundary only. They are **not** threaded through `OpenOptions.passwords: Vec<String>` in v1 (that field stays plaintext for ZIP/7z member decrypt). Never log secrets.

## `Session` methods

`Session` is a blocking, `Send + Sync` façade. Embedders that need a job id run it on a worker thread. **Do not `Clone` a session** — use `Arc<Session>`. `Drop` is the close API; there is no `close(self)`. Napi `close(sessionId)` drops the handle-table `Arc`.

**Landed (G1.1–G1.7 / G2 / G3 / G4.1–G4.5):** `open`, `open_with_job`, `list_dirents_page`, `lookup`, `read_range`, `extract_to`, `find`, `Drop`, `IndexJob::run`, `resolve_index`. Catalog is a second SQL-only `SqliteIndex` (`open_catalog_read_only`: no harness `println`, no second `MemIndex`) when the sidecar is a path-backed 0.7.x file. Compact-only / `:memory:` / Folder fall back to per-directory `MountSource::list_dirents` (never `list()`). `Recreate::Never` preflights missing/tarstats and TAR factory will not `create_index` when `read_only_index` is set. `IndexPolicy::Sibling` never falls back to `:memory:`. `IndexPolicy::UserCache` stores `{sha256}.sqlite` under `local-index-v1/` (2 GiB LRU); remote sidecar downloads stay in `meta-v3/`.

**`read_range`:** lookup + `MountSource::open` + seek + `RangeReader` (`Read + Send`, not `Sync`). Fill-loop on the inner `Read` (short read is not EOF). `max_len == 0` → empty reader. Does not call `MountSource::read` (that returns `Vec<u8>`).

**`extract_to`:** 64 KiB streaming copy; `Overwrite::{Skip,Replace}`; path-escape reject (`..`, absolute, Windows prefixes) unless `allow_unsafe_paths`. Extract-all (`members` empty) walks catalog keyset pages of 1024 (newest-wins per `fullpath`, exclusive `fullpath > ?`); does **not** call `list_visible_files_by_offset` or `list()`. Progress between members and every 8 MiB; cancel checked at those points. Cancel or copy IO error unlinks the truncated dest.

**`find`:** exclusive `(fullpath, offsetheader)` keyset (`FindCursor` / `SearchQuery.after`); it does not newest-wins-collapse versions. `ensure_fts5` is opt-in (`FindOpts.fts` / `fts:`), never a side effect of `open`. CLI `ratarmount find` still prints the first page at `DEFAULT_SEARCH_LIMIT` (10_000) and keeps Unix `silence_stdout` in `ratarmount/src/find.rs`.

**`Drop`:** if this session holds the unique `Arc` to the mount source, `MountSource::close` runs. The catalog RO connection is dropped (no `publish_tmp`). `IndexPolicy::Temp` unlinks the temp sqlite.

**Not in this slice:** optional L2 feature split, `http-export`, and Windows library compile (PR9–PR11).

```rust
impl Session {
    /// Blocking. May build an index when `recreate` requires it.
    pub fn open(req: OpenRequest) -> Result<Self, Error>;

    /// Same as `open` with progress/cancel hooks.
    pub fn open_with_job(req: OpenRequest, hooks: &IndexBuildHooks) -> Result<Self, Error>;

    pub fn list_dirents_page(
        &self,
        path: &str,
        cursor: DirCursor,
        limit: u32,
    ) -> Result<DirPage, Error>;

    pub fn lookup(&self, path: &str) -> Result<Option<DirEnt>, Error>;

    /// Seek + bounded reader. Never returns the member as `Vec<u8>`.
    pub fn read_range(&self, req: ReadRequest) -> Result<RangeReader, Error>;

    /// Stream members to `dest_dir`. `progress` may be called between members
    /// and every 8 MiB copied. `cancel` checked at those points.
    pub fn extract_to(
        &self,
        req: ExtractRequest,
        progress: Option<&dyn Fn(ExtractProgress)>,
        cancel: Option<&AtomicBool>,
    ) -> Result<(), Error>;

    pub fn find(&self, pattern: &str, opts: FindOpts) -> Result<FindPage, Error>;
}
```

There is no `IndexJob::start` / `Session::from_open` (napi-shaped). Optional `Session::start_http` is feature `http-export` (G5.4, after W2).

Default `list_dirents_page` limit if 0 is passed: **200**. Engine cap `MAX_DIR_PAGE = 10_000`. Default `Session::find` limit if 0 is passed: **200** (`DEFAULT_FIND_PAGE`). CLI `find` first-page TSV stays **10_000**.

### Find (G3)

`Session::find` shares `SearchQuery` with CLI `ratarmount find`:

- Exclusive composite keyset `FindAfter { fullpath, offsetheader }` (`FindCursor::AfterPath`). Locate keeps every version (no newest-wins).
- Prefers sidecar SQL. If there is no catalog and `search_cheap` is `Some`, page that `Vec` only (it is already the full answer). Do not merge sidecar + `search_cheap`.
- `--offset-order` / `FindOpts.offset_order` re-sorts **that page** only.
- `ensure_fts5` runs only when `FindOpts.fts` or the pattern has an `fts:` prefix — never as a side effect of `Session::open`.
- Shared `query_index` lives in `ratarmount-session`. CLI argv + Unix `silence_stdout` wrapping `factory::open_path` stay in `ratarmount/src/find.rs`.

## Errors

```rust
pub enum Error {
    NotFound,
    SiblingNotWritable(PathBuf),
    NotWritable(PathBuf),
    BadPassword,
    UnsupportedFormat(String),
    CorruptIndex(String),
    Cancelled,
    PathEscape(String),
    Internal(String),
}
```

Engine v1 **does not produce `Busy`**. Two `IndexJob`s on the same dest use distinct `{pid}.{seq}` tmps and last `publish_tmp` wins. Napi may synthesize `Busy` when its handle table already has an in-flight job for that window (`retryable: true`). Engine retryable: `NotWritable`, `SiblingNotWritable`.

| `Recreate` | Missing sidecar | tarstats mismatch |
|------------|-----------------|-------------------|
| `Never` | `NotFound` (including unwritable sibling parent) | `CorruptIndex` — never build, never `:memory:` |
| `IfInvalid` | build (`IndexJob::run`) | build — **not** an error on `open` |
| `Always` | build | build |

`PermissionDenied` from factory / `MountSource::open` maps to `BadPassword` **only** when passwords were supplied (or the error mentions password). Other permission failures → `NotWritable` with the archive path. Factory `not found:` → `NotFound`. Warm-index failure under `Recreate::Never` (`corrupt or mismatched index`) → `CorruptIndex`. Probe-miss `UnsupportedFormat` is only mapped when the message contains `unsupported format` (otherwise `Internal` — first-slice residual). Do not flatten to EIO.

## Index policy

`IndexPolicy` is the GUI `index.policy` mapping. Session default for GUI is **`Sibling`**. CLI maps today’s flags to **`CliCompat`** (Python last-resort `:memory:` stays there only).

| Policy | Where the 0.7.x sidecar lives |
|--------|-------------------------------|
| `Sibling` | `{archive}.index.ptr` + `{archive}.index.{id}.sqlite`, else `{archive}.index.sqlite`. Parent not writable and no usable file → **`SiblingNotWritable`**. No auto-fallback to user cache or `:memory:`. `scheme://` sources are **not** local parents (`https://host` is not mkdir'd); `Session::open` leaves `index_file_path` unset so remote sibling GET can run. `Recreate::Never` + missing sidecar is **`NotFound`** even if the parent is unwritable. |
| `UserCache` | `local-index-v1/` (`{sha256}.sqlite` + `{sha256}.json`, 2 GiB LRU). Extra dirs are load-only. URL sources **pin** `{hex}.sqlite` (remote GET may copy a `meta-v3` hit onto it). Never flattened `$XDG_CACHE_HOME/ratarmount/*.index.sqlite`. Never writes local-archive indexes into `meta-v3`. |
| `Explicit` | `OpenRequest.explicit_index` |
| `Memory` | `:memory:` — tests / `RGUI_FAKE` only; GUI settings must not persist this |
| `Temp` | Platform temp, unlinked on `Session` drop **and** on failed `open` (RAII guard). Unix pid dir is `0700`. Stale-pid sweep waits for G4. Confirm in UI. **Not** the fallback when sibling fails. |
| `CliCompat` | Today’s CLI/Python folder order, including `:memory:` last resort. Not a GUI policy id. |

`resolve_index` (G4) is the embedder helper. Existing `resolve_index_location` stays the Python/CLI helper (`CliCompat` last-resort `:memory:` unchanged). `Session::open` and `IndexJob::run` call `resolve_index` for every policy. Factory `resolved_index` keeps `IndexPolicy::CliCompat` so CLI/Python still fall back to `:memory:`. `Recreate::Never` never falls back to `:memory:` (missing sidecar → `NotFound`; tarstats mismatch → `CorruptIndex`).

```rust
pub fn resolve_index(
    archive: &Path,
    policy: IndexPolicy,
    explicit_index: Option<&Path>,
    extra_dirs: &[PathBuf],
    recreate: bool,
) -> Result<IndexLocation, Error>;
```

`IndexPolicy::UserCache` writes under `local-index-v1/` (never `meta-v3/`). `Recreate::Never` + missing cache entry is `NotFound` (no allocate).

## `local-index-v1` ≠ `meta-v3`

| Store | Role |
|-------|------|
| `local-index-v1/` | Local-archive index cache when policy is `UserCache` (Linux `$XDG_CACHE_HOME/ratarmount/local-index-v1/`, macOS `~/Library/Caches/ratarmount/local-index-v1/` unless XDG override, Windows `%LOCALAPPDATA%\ratarmount\local-index-v1\`) |
| `meta-v3/` | **Remote sidecar download LRU only** (256 MiB, `RATARMOUNT_META_CACHE_BYTES`). Do not put local-archive indexes there. |

Do not migrate `meta-v3` onto macOS Library/Caches. Env `RATARMOUNT_LOCAL_INDEX_DIR` / `RATARMOUNT_LOCAL_INDEX_CACHE_BYTES` (default 2 GiB) land with G4.

## `read_range` / extract (no slurp)

- **No `read_all`.** `MountSource::read` returns `Vec<u8>` and is **not** the embedder API.
- `read_range(path, offset, max_len)` returns `RangeReader: Read + Send` (not `Sync`) capped at `max_len`. `max_len == 0` → empty reader. There is no “read the rest of the file” sentinel.
- Preview cap (64 MiB) is GUI-native; the engine just takes `max_len`.
- Extract is a **streaming copy** (64 KiB buffer, loop until `Ok(0)`), not `read_range(0, size)` into a `Vec`.
- Extract-all walks the catalog with a newest-wins `fullpath > ?` keyset (page 1024), not `list()` / `list_visible_files_by_offset` dumped into a `Vec`.
- `extractPlan` (conflict sample) stays in the **GUI**, not engine v1.
- Path escape (`..`, absolute, Windows prefixes) → `Error::PathEscape` unless `allow_unsafe_paths`.

## `IndexJob` (blocking)

Engine stays **blocking**. Napi owns threads / `job_id`. There is no `IndexJob::start` / `Session::from_open`.

```rust
pub struct IndexJob;

impl IndexJob {
    /// Cold rebuild (`Recreate::Always`). On success the sidecar is published
    /// (tmp+rename) and the returned location stays readable after `run`
    /// returns (including `IndexPolicy::Temp`).
    pub fn run(req: OpenRequest, hooks: IndexBuildHooks) -> Result<IndexLocation, Error>;
}
```

`IndexJob::run` rebuilds then returns the location. `Session::open_with_job` opens (and may rebuild) with the same hooks. Cancel is cooperative: it **never** `publish_tmp`; `Drop` of the unpublished writer unlinks `{dest}.tmp.{pid}.{seq}` and the previous sidecar stays valid (V-2a).

`run` indexes the **outer** archive only (it does not eager-AutoMount nested archives). Nested TAR flatten during the outer parse still honors cancel (fail-closed before publish). CLI `--no-mount` control flow (hashes / `--publish-index` / `-w`) stays in `main.rs` — not folded into `IndexJob` in v1.

Progress: one `Scan` when a **cold** build actually starts (`Recreate::Always`, or `IfInvalid` with missing/mismatched sidecar) — not on warm remount. Then Write ticks per `insert_files_batch_soa` (512 rows) and/or every 8 MiB of TAR `pos`, and one `Finalize` before `publish_tmp`. `IndexBuildHooks` live on `OpenOptions.index_build`; `create_writable_for_open` installs them (TAR/ZIP/7z also set the one-liner after create).

Normal `IndexJob` does **not** create `files_fts`. FTS is opt-in (`FindOpts.fts` / `fts:` prefix).

## Overlay / write

GUI v1 is **read-mostly**. Overlay write, live commit, and `--commit-overlay` are out of Session v1.

## Feature graph

This crate is the **supported embedder API** (`Session`). Archive factory glue (`open_path`, `build_mount_source_ex`, nested openers, remote URL open) lives here as **`pub mod factory`** so the CLI can share it without importing a FUSE binary crate. Embedders should use `Session`; `factory` is public for the CLI.

TAR/ZIP/7z + compress + compositing + remote are **always** compiled. Other L2 is optional (`ar`, `asar`, `cab`, `cpio`, `ext4`, `fat`, `git`, `html`, `iso9660`, `libarchive`, `ogg`, `pdf`, `sqlar`, `squashfs`, `warc`, `xar`), bundled as **`formats-all`**. In-tree default is `formats-all` so the factory test matrix still runs; embedders who want the slim graph use `--no-default-features` (G5.3). Probe **order** of enabled backends is `DEFAULT_FORMAT_PROBE_ORDER` (do not reorder). Session **must not** depend on `ratarmount-fuse`, `ratarmount-nfs`, `ratarmount-smb`, `ratarmount-9p`, or `ratarmount-sftp`. Optional: `gzip-rapidgzip` (forwarded from the binary); later `http-export`.

Example: `cargo run -p ratarmount-session --example session-list -- archive.tar`.
