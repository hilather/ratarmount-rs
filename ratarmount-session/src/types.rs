//! Public types for the Session API contract.

use secrecy::SecretString;
use std::path::PathBuf;

/// What to open. Paths are OS paths; URLs use the same schemes as the CLI
/// (`http(s):`, `s3://`, `gs://`, `oci://`, `docker://`, …).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SourceSpec {
    Path(PathBuf),
    Url(String),
}

/// Where the 0.7.x sidecar should live. Maps to GUI `index.policy`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexPolicy {
    /// `{archive}.index.ptr` + `{archive}.index.{id}.sqlite`, else well-known
    /// `{archive}.index.sqlite`. Not writable → [`crate::Error::SiblingNotWritable`].
    Sibling,
    /// `local-index-v1/` (local file://) or `meta-v3/` (remote URL after sibling GET miss).
    UserCache,
    /// Caller-chosen file ([`OpenRequest::explicit_index`]).
    Explicit,
    /// `:memory:` — tests / `RGUI_FAKE` only. GUI settings must not persist this.
    Memory,
    /// Platform temp, unlinked on [`crate::Session`] drop. Confirm in UI.
    Temp,
    /// Today’s CLI/Python order including `:memory:` last resort.
    /// Not a GUI policy id.
    CliCompat,
}

/// When to rebuild a sidecar relative to the archive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recreate {
    Never,
    IfInvalid,
    Always,
}

/// Arguments to `Session::open`.
#[derive(Clone, Debug)]
pub struct OpenRequest {
    pub source: SourceSpec,
    pub index: IndexPolicy,
    /// Required when `index == Explicit`.
    pub explicit_index: Option<PathBuf>,
    /// Maps to `--index-folders` extra dirs (not including the implicit sibling `""`).
    pub extra_dirs: Vec<PathBuf>,
    pub password: Option<SecretString>,
    pub recursive: bool,
    pub recursion_depth: Option<i32>,
    pub recreate: Recreate,
}

/// Opaque keyset for **directory listing**. Napi encodes as `cursor: string`.
/// `find` rejects this type — use [`FindCursor`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DirCursor {
    Start,
    /// Exclusive: first newest-wins name strictly after this (UTF-8).
    AfterName {
        name: String,
    },
}

/// Opaque keyset for **locate**. Composite because `files` may hold multiple
/// rows per full path (`ORDER BY fullpath, offsetheader`, no newest-wins).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum FindCursor {
    #[default]
    Start,
    /// Exclusive: `(fullpath, offsetheader)` lexicographic after this pair.
    AfterPath {
        path: String,
        offsetheader: Option<i64>,
    },
}

/// One page of directory entries.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirPage {
    pub path: String,
    pub entries: Vec<DirEnt>,
    pub next_cursor: Option<DirCursor>,
    /// Cheap `COUNT` when the backend is SQLite `files`; `None` for live FolderMountSource.
    pub total_hint: Option<u64>,
}

/// One directory or locate hit. No `rowid` — do not treat [`Self::archive_offset`] as a fetch key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirEnt {
    pub name: String,
    /// Archive-relative, leading `/`, no trailing `/` (`files.path` + `files.name`).
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    /// Unix seconds (truncated `FileInfo.mtime`). `None` if the cheap row has no mtime.
    pub mtime: Option<i64>,
    pub mode: u32,
    /// Catalog hint (`offsetheader` ≥ 0). Embedders must not use this to fetch bytes.
    pub archive_offset: Option<u64>,
}

/// Bounded ranged read. There is no `read_all` and no “read the rest” sentinel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadRequest {
    pub path: String,
    pub offset: u64,
    /// Hard cap. `0` → empty reader.
    pub max_len: u64,
}

/// Existing dest file policy for extract. Never `ask` — that is UI-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Overwrite {
    Skip,
    Replace,
}

/// Streaming extract request. Empty [`Self::members`] means every payload member.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtractRequest {
    /// Empty = every payload member (walk catalog, not `list()` fat map).
    pub members: Vec<String>,
    pub dest_dir: PathBuf,
    pub overwrite: Overwrite,
    /// Default false: reject `..`, absolute, and Windows prefixes in member paths.
    pub allow_unsafe_paths: bool,
}

/// Progress tick while extracting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtractProgress {
    pub files_done: u64,
    pub files_hint: Option<u64>,
    pub bytes_out: u64,
    pub current_path: Option<String>,
}

/// Index-build phase for [`IndexProgress`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexPhase {
    Scan,
    Write,
    Fts,
    Finalize,
}

/// Structured index-build progress (GUI `indexProgress`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IndexProgress {
    pub phase: IndexPhase,
    pub bytes_scanned: u64,
    pub bytes_total_hint: Option<u64>,
    pub entries: u64,
    pub message: Option<String>,
}

/// Locate options. `ensure_fts5` runs only when [`Self::fts`] is set, never as a
/// side effect of open. [`Self::limit`] `0` means the session default page (200).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct FindOpts {
    pub fts: bool,
    pub offset_order: bool,
    pub include_hashes: bool,
    /// Algorithms to compute into `user.hash.*` before searching (CLI `--hashes`).
    /// Empty = do not fill.
    pub fill_hashes: Vec<String>,
    pub limit: u32,
    pub cursor: FindCursor,
}

/// One page of locate hits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FindPage {
    pub pattern: String,
    pub fts: bool,
    pub entries: Vec<DirEnt>,
    pub next_cursor: Option<FindCursor>,
    pub total_hint: Option<u64>,
}
