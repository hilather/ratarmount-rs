//! TAR indexing and open-by-offset (Phase 1–3).
//!
//! `backendName` must be exactly `SQLiteIndexedTar` for Python interop.
//!
//! Nested TAR foundation: while indexing the outer archive, regular members that look
//! like nested TARs (name ends with `.tar` or ustar/GNU magic at the member data
//! offset) are recorded in metadata (`nestedTarMembers`) and marked `istar=true`.
//! Call [`SqliteIndexedTar::list_nested_tar_members`] / [`SqliteIndexedTar::open_nested_tar_from_index`]
//! to list them or open via stencil without AutoMount.
//!
//! Flattened recursive rows: nested TAR headers are also walked (seek on the outer
//! stream, no temp file) and inserted into the **outer** SQLite index with paths like
//! `/inner.tar/payload.txt` and **absolute** outer-stream offsets. The nested member
//! itself gains a generated directory version (Python recursive index parity) so
//! `list`/`lookup` work without AutoMount. Size gate: when recursion is disabled,
//! nested members larger than [`NESTED_FLATTEN_MAX_BYTES`] are only side-listed.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ratarmount_compress::{
    FileSegment, SeekRead, SeekableBody, SegmentedFile, SharedSeekableGzip, StenciledFile,
};
use ratarmount_core::{
    normpath, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions,
    SQLiteIndexedTarUserData, UserData,
};
use ratarmount_index::{FileRow, IndexError, SqliteIndex};
use tempfile::NamedTempFile;
use thiserror::Error;

/// Exact string stored in index metadata (Python `SQLiteIndexedTar`).
pub const BACKEND_NAME: &str = "SQLiteIndexedTar";

/// Metadata key for the JSON list of nested TAR members `(path, offset, size)`.
pub const NESTED_TAR_MEMBERS_KEY: &str = "nestedTarMembers";

/// Max nested TAR size to walk into the outer index when recursion is disabled.
///
/// With `OpenOptions::recursive` or a positive `recursion_depth`, nested members are
/// flattened without this size gate (Python `SQLiteIndexedTar` recursive parity).
/// Keeps cold index of huge nested TARs fast in the default non-recursive case.
pub const NESTED_FLATTEN_MAX_BYTES: u64 = 64 * 1024 * 1024;

const BLOCK_SIZE: u64 = 512;

/// `linkname` marker for GNU dumpdir whiteout rows (name deleted in a later dumpdir).
///
/// Stored so list/lookup can hide the name when the newest version is this tombstone.
/// Not a valid path component; the leading NUL makes accidental collisions with real
/// link targets extremely unlikely.
const DUMPDIR_DELETE_LINKNAME: &str = "\0GNU.dumpdir.delete";

/// A nested TAR member discovered while indexing an outer archive.
///
/// `path` is the outer archive member path as stored in the index (leading `/`).
/// `offset` / `size` are absolute positions in the outer (uncompressed) TAR stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NestedTarMember {
    pub path: String,
    pub offset: u64,
    pub size: u64,
}

/// In-progress nested member with header metadata needed to emit a generated directory row.
#[derive(Clone, Debug)]
struct NestedPending {
    member: NestedTarMember,
    offsetheader: u64,
    mtime: f64,
    mode_bits: u32,
    uid: i64,
    gid: i64,
}

/// Python `determine_recursion_depth`: `recursion_depth` wins; else `recursive` → unbounded; else 0.
fn max_recursion_depth(options: &OpenOptions) -> i32 {
    match options.recursion_depth {
        Some(d) => d,
        None if options.recursive => i32::MAX,
        None => 0,
    }
}

/// Whether to walk nested headers into the outer index at this recursion level.
fn should_flatten_nested(options: &OpenOptions, nested_size: u64, content_depth: i32) -> bool {
    let max = max_recursion_depth(options);
    // content_depth is the recursiondepth stored on nested file rows (1 = first nested layer).
    // Flatten when the outer recursive budget allows that depth, or (default) one size-limited layer.
    if content_depth <= max {
        return true;
    }
    // Default non-recursive: still flatten one layer of small nested TARs for lookup without AutoMount.
    max == 0 && content_depth == 1 && nested_size <= NESTED_FLATTEN_MAX_BYTES
}

#[derive(Debug, Error)]
pub enum TarError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, TarError>;

/// Mutex-backed `Read + Seek` for concurrent stencil opens (HTTP Range / Cursor / remote).
struct SharedSeekReader {
    inner: Mutex<Box<dyn SeekRead>>,
}

impl SharedSeekReader {
    fn new<R: SeekRead + 'static>(reader: R) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Box::new(reader)),
        })
    }

    fn open_reader(self: &Arc<Self>) -> PositionedSeekReader {
        PositionedSeekReader {
            shared: Arc::clone(self),
            pos: 0,
        }
    }
}

/// Independent logical cursor over a [`SharedSeekReader`].
struct PositionedSeekReader {
    shared: Arc<SharedSeekReader>,
    pos: u64,
}

impl Read for PositionedSeekReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut guard = self
            .shared
            .inner
            .lock()
            .map_err(|_| io::Error::other("shared seek reader poisoned"))?;
        guard.seek(SeekFrom::Start(self.pos))?;
        let n = guard.read(buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for PositionedSeekReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::Current(o) => self.pos as i64 + o,
            SeekFrom::End(o) => {
                let mut guard = self
                    .shared
                    .inner
                    .lock()
                    .map_err(|_| io::Error::other("shared seek reader poisoned"))?;
                let end = guard.seek(SeekFrom::End(0))? as i64;
                end + o
            }
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

/// Where uncompressed TAR bytes live for open/read.
enum ContentBackend {
    /// Plain file (uncompressed archive or materialised temp body).
    File {
        file: File,
        _keep: Option<NamedTempFile>,
    },
    /// Seekable gzip (checkpoint decoder).
    Gzip(Arc<SharedSeekableGzip>),
    /// Generic seekable body (bzip2/xz/zstd DecodedBody or multi-frame zstd).
    Body(Arc<dyn SeekableBody>),
    /// Any `Read + Seek` shared under a mutex (remote / in-memory / tempfile reader).
    Shared(Arc<SharedSeekReader>),
}

impl ContentBackend {
    fn open_reader(&self) -> io::Result<ContentReader> {
        match self {
            Self::File { file, .. } => Ok(ContentReader::File(file.try_clone()?)),
            Self::Gzip(g) => Ok(ContentReader::Gzip(g.reader()?)),
            Self::Body(b) => Ok(ContentReader::Dyn(b.open_reader()?)),
            Self::Shared(s) => Ok(ContentReader::Shared(s.open_reader())),
        }
    }
}

/// Concrete reader used by open paths.
enum ContentReader {
    File(File),
    Gzip(ratarmount_compress::SeekableGzipReader),
    Dyn(Box<dyn SeekRead>),
    Shared(PositionedSeekReader),
}

impl Read for ContentReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::File(f) => f.read(buf),
            Self::Gzip(g) => g.read(buf),
            Self::Dyn(r) => r.read(buf),
            Self::Shared(r) => r.read(buf),
        }
    }
}

impl Seek for ContentReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match self {
            Self::File(f) => f.seek(pos),
            Self::Gzip(g) => g.seek(pos),
            Self::Dyn(r) => r.seek(pos),
            Self::Shared(r) => r.seek(pos),
        }
    }
}

/// TAR archive backed by a SQLite index (read path + optional build).
pub struct SqliteIndexedTar {
    /// Original archive path (for logs / tarstats).
    archive_path: PathBuf,
    /// Path used for content reads (uncompressed body; may be a temp file).
    #[allow(dead_code)]
    data_path: PathBuf,
    backend: ContentBackend,
    index: SqliteIndex,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl SqliteIndexedTar {
    /// Open existing index; `data_path` is the uncompressed content source.
    /// On success, takes ownership of `materialised` (if any).
    pub fn open_with_existing_index(
        archive_path: impl AsRef<Path>,
        data_path: impl AsRef<Path>,
        index_path: impl AsRef<Path>,
        options: OpenOptions,
        materialised: &mut Option<NamedTempFile>,
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        let data_path = data_path.as_ref().to_path_buf();
        let index = SqliteIndex::open_read_only(index_path.as_ref())?;
        index.check_backend_name(BACKEND_NAME)?;
        let data_file = File::open(&data_path)?;
        Ok(Self {
            archive_path,
            data_path,
            backend: ContentBackend::File {
                file: data_file,
                _keep: materialised.take(),
            },
            index,
            options,
        })
    }

    /// Open existing index with a seekable-gzip body (no materialize).
    pub fn open_with_existing_index_gzip(
        archive_path: impl AsRef<Path>,
        gzip: Arc<SharedSeekableGzip>,
        index_path: impl AsRef<Path>,
        options: OpenOptions,
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        let data_path = gzip.path().to_path_buf();
        let index = SqliteIndex::open_read_only(index_path.as_ref())?;
        index.check_backend_name(BACKEND_NAME)?;
        Ok(Self {
            archive_path,
            data_path,
            backend: ContentBackend::Gzip(gzip),
            index,
            options,
        })
    }

    /// Build a new index by parsing TAR data at `data_path` (uncompressed).
    /// Logs use `archive_path` (original user-facing path).
    /// `index_path`: `Some(path)` for on-disk index, `None` for `:memory:`.
    /// On success, takes ownership of `materialised` (if any).
    pub fn create_index(
        archive_path: impl AsRef<Path>,
        data_path: impl AsRef<Path>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
        materialised: &mut Option<NamedTempFile>,
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        let data_path = data_path.as_ref().to_path_buf();
        let mut file = File::open(&data_path)?;
        let backend = ContentBackend::File {
            file: file.try_clone()?,
            _keep: materialised.take(),
        };
        Self::build_index_from_reader(
            archive_path,
            data_path,
            &mut file,
            index_path,
            options,
            product_version,
            backend,
        )
    }

    /// Build index from a seekable-gzip body (G3 Tier B — no materialize).
    pub fn create_index_gzip(
        archive_path: impl AsRef<Path>,
        gzip: Arc<SharedSeekableGzip>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        let data_path = gzip.path().to_path_buf();
        let mut reader = gzip.reader()?;
        let backend = ContentBackend::Gzip(Arc::clone(&gzip));
        Self::build_index_from_reader(
            archive_path,
            data_path,
            &mut reader,
            index_path,
            options,
            product_version,
            backend,
        )
    }

    /// Open existing index with a generic seekable body (bzip2/xz/zstd).
    pub fn open_with_existing_index_body(
        archive_path: impl AsRef<Path>,
        body: Arc<dyn SeekableBody>,
        index_path: impl AsRef<Path>,
        options: OpenOptions,
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        let data_path = body.path().to_path_buf();
        let index = SqliteIndex::open_read_only(index_path.as_ref())?;
        index.check_backend_name(BACKEND_NAME)?;
        Ok(Self {
            archive_path,
            data_path,
            backend: ContentBackend::Body(body),
            index,
            options,
        })
    }

    /// Build index from a generic seekable body (bzip2/xz/zstd).
    pub fn create_index_body(
        archive_path: impl AsRef<Path>,
        body: Arc<dyn SeekableBody>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        let data_path = body.path().to_path_buf();
        let mut reader = body.open_reader().map_err(TarError::Io)?;
        let backend = ContentBackend::Body(body);
        Self::build_index_from_reader(
            archive_path,
            data_path,
            &mut reader,
            index_path,
            options,
            product_version,
            backend,
        )
    }

    /// Index and open an uncompressed TAR from any `Read + Seek` source.
    ///
    /// Intended for HTTP Range / remote streams and in-memory archives: no on-disk
    /// archive path is required. `archive_label` is used for logs and index metadata
    /// (may be a URL or virtual name). The reader is retained under a mutex for
    /// concurrent stencil opens.
    ///
    /// `index_path`: `Some(path)` for on-disk index, `None` for `:memory:`.
    ///
    /// Alias of [`Self::create_index_from_reader`].
    pub fn open_from_reader<R>(
        reader: R,
        archive_label: impl AsRef<Path>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
    ) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        Self::create_index_from_reader(reader, archive_label, index_path, options, product_version)
    }

    /// Index and open an uncompressed TAR from any `Read + Seek` source.
    ///
    /// See [`Self::open_from_reader`].
    pub fn create_index_from_reader<R>(
        mut reader: R,
        archive_label: impl AsRef<Path>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
    ) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        let archive_path = archive_label.as_ref().to_path_buf();
        let data_path = archive_path.clone();
        let size = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;

        println!(
            "Creating offset dictionary for {} ...",
            archive_path.display()
        );
        let t0 = Instant::now();

        let index = SqliteIndex::create_writable(index_path)?;
        index.begin_write()?;
        let is_gnu_incremental = parse_tar_into_index(&mut reader, &index, options)?;

        index.store_versions(product_version)?;
        index.store_metadata_key_value("backendName", BACKEND_NAME)?;
        index.store_metadata_key_value(
            "isGnuIncremental",
            if is_gnu_incremental { "1" } else { "0" },
        )?;
        store_tarstats_for_label(&index, &archive_path, size)?;
        store_arguments(&index, options)?;
        index.commit_write()?;

        let secs = t0.elapsed().as_secs_f64();
        println!(
            "Creating offset dictionary for {} took {secs:.2}s",
            archive_path.display()
        );

        // Rewind and retain for member open.
        reader.seek(SeekFrom::Start(0))?;
        let backend = ContentBackend::Shared(SharedSeekReader::new(reader));
        let index = index.into_read_only()?;
        Ok(Self {
            archive_path,
            data_path,
            backend,
            index,
            options: options.clone(),
        })
    }

    /// Open an existing index with a `Read + Seek` content source (no re-index).
    ///
    /// The reader must match the archive that produced `index_path`. `archive_label`
    /// is display-only.
    pub fn open_with_existing_index_from_reader<R>(
        reader: R,
        archive_label: impl AsRef<Path>,
        index_path: impl AsRef<Path>,
        options: OpenOptions,
    ) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        let archive_path = archive_label.as_ref().to_path_buf();
        let data_path = archive_path.clone();
        let index = SqliteIndex::open_read_only(index_path.as_ref())?;
        index.check_backend_name(BACKEND_NAME)?;
        Ok(Self {
            archive_path,
            data_path,
            backend: ContentBackend::Shared(SharedSeekReader::new(reader)),
            index,
            options,
        })
    }

    fn build_index_from_reader<R: Read + Seek>(
        archive_path: PathBuf,
        data_path: PathBuf,
        reader: &mut R,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
        backend: ContentBackend,
    ) -> Result<Self> {
        println!(
            "Creating offset dictionary for {} ...",
            archive_path.display()
        );
        let t0 = Instant::now();

        let index = SqliteIndex::create_writable(index_path)?;
        index.begin_write()?;
        let is_gnu_incremental = parse_tar_into_index(reader, &index, options)?;

        index.store_versions(product_version)?;
        index.store_metadata_key_value("backendName", BACKEND_NAME)?;
        index.store_metadata_key_value(
            "isGnuIncremental",
            if is_gnu_incremental { "1" } else { "0" },
        )?;
        // Nested / virtual labels (e.g. `inner.tar.gz` inside a 7z) are not real
        // host paths — use label-safe stats (path metadata when present).
        let size_hint = std::fs::metadata(&archive_path)
            .or_else(|_| std::fs::metadata(&data_path))
            .map(|m| m.len())
            .unwrap_or(0);
        store_tarstats_for_label(&index, &archive_path, size_hint)?;
        store_arguments(&index, options)?;
        index.commit_write()?;

        let secs = t0.elapsed().as_secs_f64();
        println!(
            "Creating offset dictionary for {} took {secs:.2}s",
            archive_path.display()
        );

        let index = index.into_read_only()?;
        Ok(Self {
            archive_path,
            data_path,
            backend,
            index,
            options: options.clone(),
        })
    }

    pub fn index(&self) -> &SqliteIndex {
        &self.index
    }

    pub fn archive_path(&self) -> &Path {
        &self.archive_path
    }

    /// Nested TAR members recorded during outer-archive indexing (`nestedTarMembers` metadata).
    ///
    /// Empty when the index was built without detection, has no nested TARs, or predates this key.
    pub fn list_nested_tar_members(&self) -> Result<Vec<NestedTarMember>> {
        let meta = self.index.metadata()?;
        Ok(match meta.get(NESTED_TAR_MEMBERS_KEY) {
            Some(json) => parse_nested_tar_members_json(json),
            None => Vec::new(),
        })
    }

    /// Open a nested TAR member by stenciling its outer byte range and indexing in-place.
    ///
    /// `member_path` is the outer member path (with or without leading `/`). Does not use
    /// AutoMount; the returned mount source is a standalone [`SqliteIndexedTar`] over the
    /// member bytes. Index is in-memory.
    pub fn open_nested_tar_from_index(&self, member_path: &str) -> Result<Self> {
        let want = normpath(member_path);
        let members = self.list_nested_tar_members()?;
        let nested = members
            .iter()
            .find(|m| paths_equal_nested(&m.path, &want))
            .ok_or_else(|| TarError::Msg(format!("nested TAR member not found: {want}")))?
            .clone();

        // Always stencil from nestedTarMembers coordinates (absolute outer stream range).
        // After flattened recursive indexing, lookup(0) is a generated directory version,
        // so MountSource::open on the member path is not reliable.
        let outer = self.backend.open_reader().map_err(TarError::Io)?;
        let reader: Box<dyn ratarmount_core::ArchiveRead> = Box::new(StenciledFile::new(
            outer,
            vec![(nested.offset, nested.size)],
        ));

        let label = format!("{}{}", self.archive_path.display(), nested.path);
        // Nested open: do not inherit recursive AutoMount intent; this API is explicit.
        let opts = OpenOptions {
            recursive: false,
            recursion_depth: Some(0),
            index_in_memory: true,
            ..self.options.clone()
        };
        Self::open_from_reader(reader, PathBuf::from(label), None, &opts, "0.1.0")
    }
}

fn paths_equal_nested(a: &str, b: &str) -> bool {
    normpath(a) == normpath(b)
}

impl MountSource for SqliteIndexedTar {
    fn list(&self, path: &str) -> Option<ListResult> {
        let mut map = self.index.list(path).ok().flatten()?;
        // Newest row wins in the index map; drop dumpdir whiteouts so deleted names vanish.
        map.retain(|_, fi| !is_dumpdir_tombstone(fi));
        Some(ListResult::Infos(map))
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        // Prefer list() so tombstones are filtered consistently with Infos.
        let ListResult::Infos(infos) = self.list(path)? else {
            return None;
        };
        let modes = infos.into_iter().map(|(n, fi)| (n, fi.mode)).collect();
        Some(ListModeResult::Modes(modes))
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        let fi = self.index.lookup(path, file_version).ok().flatten()?;
        // Version 0 (newest): hide dumpdir-deleted names. Older versions remain queryable.
        if is_dumpdir_tombstone(&fi) {
            return None;
        }
        Some(fi)
    }

    fn versions(&self, path: &str) -> u32 {
        // If the newest version is a dumpdir whiteout, treat the path as absent.
        if let Ok(Some(fi)) = self.index.lookup(path, 0) {
            if is_dumpdir_tombstone(&fi) {
                return 0;
            }
        }
        self.index.version_count(path).unwrap_or(0)
    }

    fn open(
        &self,
        file_info: &FileInfo,
        _buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        if is_dumpdir_tombstone(file_info) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "dumpdir-deleted member",
            ));
        }
        let ud = tar_userdata(file_info)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing TAR userdata"))?;
        if file_info.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "is a directory",
            ));
        }
        if file_info.size == 0 && !ud.issparse {
            return Ok(Box::new(std::io::Cursor::new(Vec::new())));
        }
        let reader = self.backend.open_reader()?;
        if ud.issparse {
            let header_off = ud
                .offsetheader
                .unwrap_or(ud.offset.saturating_sub(BLOCK_SIZE));
            return open_sparse_member(reader, header_off, ud.offset, file_info.size);
        }
        Ok(Box::new(StenciledFile::new(
            reader,
            vec![(ud.offset, file_info.size)],
        )))
    }

    fn is_immutable(&self) -> bool {
        true
    }

    /// Xattr keys from the SQLite index: content hashes (`user.hash.*`) and archive-stored
    /// filesystem xattrs (`SCHILY.xattr` / `LIBARCHIVE.xattr` → real FS names).
    fn list_xattr(&self, file_info: &FileInfo) -> Vec<String> {
        let Some(oh) = tar_offsetheader(file_info) else {
            return Vec::new();
        };
        self.index.list_xattr_keys(oh).unwrap_or_default()
    }

    /// One xattr value from the index (hash digests or PAX-stored FS xattr bytes).
    fn get_xattr(&self, file_info: &FileInfo, key: &str) -> Option<Vec<u8>> {
        let oh = tar_offsetheader(file_info)?;
        self.index.get_xattr(oh, key).ok().flatten()
    }
}

/// `offsetheader` used as the xattrs table key (Python interop).
fn tar_offsetheader(fi: &FileInfo) -> Option<i64> {
    tar_userdata(fi)
        .and_then(|ud| ud.offsetheader)
        .map(|v| v as i64)
}

fn tar_userdata(fi: &FileInfo) -> Option<&SQLiteIndexedTarUserData> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Tar(t) => Some(t),
        _ => None,
    })
}

/// True when this index row is a GNU dumpdir whiteout (deleted name).
fn is_dumpdir_tombstone(fi: &FileInfo) -> bool {
    fi.linkname == DUMPDIR_DELETE_LINKNAME
}

/// Parse GNU dumpdir payload: `Cfilename\0…\0` (trailing lone NUL ends the dumpdir).
///
/// Control codes (GNU tar manual): `Y` present+dumped, `N` present+not dumped,
/// `D` subdirectory, plus rename `R`/`T`/`X` (ignored for presence tracking).
fn parse_dumpdir_entries(payload: &[u8]) -> Vec<(u8, String)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < payload.len() {
        if payload[i] == 0 {
            break;
        }
        let status = payload[i];
        i += 1;
        let start = i;
        while i < payload.len() && payload[i] != 0 {
            i += 1;
        }
        let name = String::from_utf8_lossy(&payload[start..i]).into_owned();
        if i < payload.len() {
            i += 1; // skip trailing NUL of this record
        }
        if !name.is_empty() {
            out.push((status, name));
        }
    }
    out
}

/// Names that still exist in the directory according to dumpdir (`Y`/`N`/`D`).
fn dumpdir_present_names(entries: &[(u8, String)]) -> std::collections::HashSet<String> {
    entries
        .iter()
        .filter_map(|(c, n)| match *c {
            b'Y' | b'N' | b'D' => Some(n.clone()),
            _ => None,
        })
        .collect()
}

/// Normalize dumpdir member path to a directory full path (`/foo`).
fn dumpdir_dir_full_path(full_name: &str) -> String {
    let mut full = full_name.trim_end_matches('/').to_string();
    while full.starts_with("./") {
        full = full[2..].to_string();
    }
    if full.is_empty() || full == "." {
        return String::from("/");
    }
    normpath(&full)
}

/// SQL `path` column for direct children of a dumpdir directory.
fn dumpdir_children_sql_path(dir_full: &str) -> String {
    if dir_full == "/" {
        String::new()
    } else {
        dir_full.to_string()
    }
}

/// When a later dumpdir omits names that a prior dumpdir listed, insert whiteout rows.
///
/// Single-archive multi-snapshot MVP (concatenated incremental levels): names present in
/// an earlier dumpdir for the same directory but absent from the current one are
/// tombstoned so list/lookup hide them. Multi-archive union / `.snar` merge is residual.
#[allow(clippy::too_many_arguments)]
fn apply_dumpdir_deletes(
    batch: &mut Vec<FileRow>,
    full_name: &str,
    offsetheader: u64,
    payload: &[u8],
    mtime: f64,
    uid: i64,
    gid: i64,
    recursiondepth: i64,
    dumpdir_state: &mut std::collections::HashMap<String, std::collections::HashSet<String>>,
) {
    let dir_full = dumpdir_dir_full_path(full_name);
    let entries = parse_dumpdir_entries(payload);
    let present = dumpdir_present_names(&entries);
    if let Some(prev) = dumpdir_state.get(&dir_full) {
        let child_path = dumpdir_children_sql_path(&dir_full);
        for (tomb_i, name) in (0_i64..).zip(prev.difference(&present)) {
            // Unique PK: dumpdir already uses offsetheader and +1 for reg/dir dual entry.
            let oh = offsetheader as i64 + 2 + tomb_i;
            batch.push(FileRow::new(
                child_path.clone(),
                name.clone(),
                oh,
                0,
                0,
                mtime,
                0, // mode 0: not a live file/dir
                b'D' as i64,
                DUMPDIR_DELETE_LINKNAME,
                uid,
                gid,
                false,
                false,
                true, // isgenerated
                recursiondepth,
            ));
        }
    }
    dumpdir_state.insert(dir_full, present);
}

pub fn default_index_path(archive: &Path) -> PathBuf {
    let mut s = archive.as_os_str().to_os_string();
    s.push(".index.sqlite");
    PathBuf::from(s)
}

/// Store tarstats from path metadata when available; otherwise synthetic size-only stats.
///
/// Used for reader-based / nested opens where `archive_label` may be a URL or virtual name.
fn store_tarstats_for_label(index: &SqliteIndex, path: &Path, size: u64) -> Result<()> {
    if path.exists() {
        if let Ok(meta) = std::fs::metadata(path) {
            let json = serde_json_tarstats(&meta);
            index.store_metadata_key_value("tarstats", &json)?;
            return Ok(());
        }
    }
    let json = format!("{{\"st_size\":{size},\"st_mtime\":0,\"st_mtime_ns\":0}}");
    index.store_metadata_key_value("tarstats", &json)?;
    Ok(())
}

fn serde_json_tarstats(meta: &std::fs::Metadata) -> String {
    use std::os::unix::fs::MetadataExt;
    format!(
        "{{\"st_size\":{},\"st_mtime\":{},\"st_mtime_ns\":{}}}",
        meta.size(),
        meta.mtime(),
        meta.mtime_nsec()
    )
}

fn store_arguments(index: &SqliteIndex, options: &OpenOptions) -> Result<()> {
    let json = format!(
        "{{\"ignoreZeros\":{},\"gnuIncremental\":{},\"recursive\":{}}}",
        options.ignore_zeros,
        match options.gnu_incremental {
            Some(true) => "true",
            Some(false) => "false",
            None => "null",
        },
        options.recursive
    );
    index.store_metadata_key_value("arguments", &json)?;
    Ok(())
}

/// Flush threshold for batched SQLite inserts during TAR parse.
const BATCH_FLUSH: usize = 512;

fn pad512(n: u64) -> u64 {
    n.div_ceil(BLOCK_SIZE) * BLOCK_SIZE
}

/// Parsed pax records plus accumulated GNU sparse 0.0 offset/numbytes pairs.
struct PaxParsed {
    map: std::collections::HashMap<String, String>,
    /// Ordered sparse pairs from repeated `GNU.sparse.offset` / `numbytes` (format 0.0).
    sparse_pairs: Vec<(u64, u64)>,
    /// Filesystem xattrs from `SCHILY.xattr.*` / `LIBARCHIVE.xattr.*` (FS key → value bytes).
    /// Vendor pax keywords (MPE/ZOS/…) are intentionally not stored here.
    fs_xattrs: std::collections::HashMap<String, Vec<u8>>,
}

impl PaxParsed {
    fn empty() -> Self {
        Self {
            map: std::collections::HashMap::new(),
            sparse_pairs: Vec::new(),
            fs_xattrs: std::collections::HashMap::new(),
        }
    }
}

/// PAX prefixes for filesystem extended attributes (Python `SQLiteIndexedTar` / FR-3).
const SCHILY_XATTR_PREFIX: &str = "SCHILY.xattr.";
const LIBARCHIVE_XATTR_PREFIX: &str = "LIBARCHIVE.xattr.";

/// urllib.parse.unquote-style percent-decode (does not treat `+` as space).
fn percent_decode_str(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h1), Some(h2)) =
                (from_hex_digit(bytes[i + 1]), from_hex_digit(bytes[i + 2]))
            {
                out.push((h1 << 4) | h2);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn from_hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Python `decode_unpadded_base64`: pad to multiple of 4 then standard base64 decode.
fn decode_unpadded_base64(data: &str) -> Option<Vec<u8>> {
    let pad = (4 - (data.len() % 4)) % 4;
    let mut padded = data.as_bytes().to_vec();
    padded.extend(std::iter::repeat_n(b'=', pad));
    base64_std_decode(&padded)
}

/// Minimal standard base64 decoder (no external crate; A–Z a–z 0–9 + /).
fn base64_std_decode(input: &[u8]) -> Option<Vec<u8>> {
    fn dec(b: u8) -> Option<u8> {
        match b {
            b'A'..=b'Z' => Some(b - b'A'),
            b'a'..=b'z' => Some(b - b'a' + 26),
            b'0'..=b'9' => Some(b - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            b'=' => Some(0), // padding handled by length
            _ => None,
        }
    }
    let filtered: Vec<u8> = input
        .iter()
        .copied()
        .filter(|&b| !b.is_ascii_whitespace())
        .collect();
    if !filtered.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(filtered.len() / 4 * 3);
    for chunk in filtered.chunks_exact(4) {
        let (a, b, c, d) = (
            dec(chunk[0])?,
            dec(chunk[1])?,
            dec(chunk[2])?,
            dec(chunk[3])?,
        );
        out.push((a << 2) | (b >> 4));
        if chunk[2] != b'=' {
            out.push(((b & 0x0f) << 4) | (c >> 2));
        }
        if chunk[3] != b'=' {
            out.push(((c & 0x03) << 6) | d);
        }
    }
    Some(out)
}

/// Build FS xattr map from pax keys: SCHILY first, then LIBARCHIVE overwrites (Python parity).
///
/// - `SCHILY.xattr.<name>` → value is raw bytes from the pax record
/// - `LIBARCHIVE.xattr.<name>` → key is percent-decoded; value is unpadded base64
fn fs_xattrs_from_pax_entries(
    schily: std::collections::HashMap<String, Vec<u8>>,
    libarchive: std::collections::HashMap<String, Vec<u8>>,
) -> std::collections::HashMap<String, Vec<u8>> {
    let mut fs_xattrs = schily;
    for (enc_key, b64_val) in libarchive {
        let name = percent_decode_str(&enc_key);
        let Ok(s) = std::str::from_utf8(&b64_val) else {
            continue;
        };
        if let Some(decoded) = decode_unpadded_base64(s.trim()) {
            fs_xattrs.insert(name, decoded);
        }
    }
    fs_xattrs
}

/// Append `(offsetheader, key, value)` rows for index insert.
fn push_xattr_rows(
    out: &mut Vec<(i64, String, Vec<u8>)>,
    offsetheader: u64,
    fs_xattrs: &std::collections::HashMap<String, Vec<u8>>,
) {
    let oh = offsetheader as i64;
    for (key, value) in fs_xattrs {
        out.push((oh, key.clone(), value.clone()));
    }
}

/// Parse pax extended header records (`LEN key=value\n` …).
fn parse_pax_records(data: &[u8]) -> PaxParsed {
    let mut map = std::collections::HashMap::new();
    let mut sparse_pairs = Vec::new();
    let mut schily_xattrs: std::collections::HashMap<String, Vec<u8>> =
        std::collections::HashMap::new();
    let mut libarchive_xattrs: std::collections::HashMap<String, Vec<u8>> =
        std::collections::HashMap::new();
    let mut pending_offset: Option<u64> = None;
    let mut i = 0usize;
    while i < data.len() {
        if data[i] == 0 {
            break;
        }
        let rest = &data[i..];
        let Some(sp) = rest.iter().position(|&b| b == b' ') else {
            break;
        };
        let Ok(len_str) = std::str::from_utf8(&rest[..sp]) else {
            break;
        };
        let Ok(rec_len) = len_str.parse::<usize>() else {
            break;
        };
        if rec_len == 0 || i + rec_len > data.len() {
            break;
        }
        let record = &data[i..i + rec_len];
        if let Some(eq) = record.iter().position(|&b| b == b'=') {
            let key_start = sp + 1;
            if key_start < eq {
                let key = String::from_utf8_lossy(&record[key_start..eq]).into_owned();
                let mut val_end = rec_len;
                if val_end > 0 && record[val_end - 1] == b'\n' {
                    val_end -= 1;
                }
                let val_raw = &record[eq + 1..val_end];
                let val = String::from_utf8_lossy(val_raw).into_owned();
                if key == "GNU.sparse.offset" {
                    pending_offset = val.parse().ok();
                } else if key == "GNU.sparse.numbytes" {
                    if let (Some(off), Ok(len)) = (pending_offset.take(), val.parse::<u64>()) {
                        sparse_pairs.push((off, len));
                    }
                } else if let Some(suffix) = key.strip_prefix(SCHILY_XATTR_PREFIX) {
                    // Raw value bytes (binary-safe); do not use UTF-8 lossy form.
                    schily_xattrs.insert(suffix.to_string(), val_raw.to_vec());
                } else if let Some(suffix) = key.strip_prefix(LIBARCHIVE_XATTR_PREFIX) {
                    libarchive_xattrs.insert(suffix.to_string(), val_raw.to_vec());
                }
                map.insert(key, val);
            }
        }
        i += rec_len;
    }
    let fs_xattrs = fs_xattrs_from_pax_entries(schily_xattrs, libarchive_xattrs);
    PaxParsed {
        map,
        sparse_pairs,
        fs_xattrs,
    }
}

/// GNU sparse 1.0 map at the start of the data blocks: `N\noff\nlen\n…` then 512-pad.
/// Returns `(map pairs, absolute offset of first content byte)`.
fn parse_sparse_1_0_map<R: Read + Seek>(
    reader: &mut R,
    data_start: u64,
) -> Result<(Vec<(u64, u64)>, u64)> {
    reader.seek(SeekFrom::Start(data_start))?;
    let mut buf = vec![0u8; 512 * 64];
    let n = reader.read(&mut buf)?;
    buf.truncate(n);
    let bytes = buf.as_slice();
    let Some(nl0) = bytes.iter().position(|&b| b == b'\n') else {
        return Err(TarError::Msg("sparse 1.0 map missing count".into()));
    };
    let count: usize = std::str::from_utf8(&bytes[..nl0])
        .unwrap_or("0")
        .trim()
        .parse()
        .unwrap_or(0);
    let mut pos_in_buf = nl0 + 1;
    let mut map = Vec::with_capacity(count);
    for _ in 0..count {
        let Some(nl1) = bytes[pos_in_buf..].iter().position(|&b| b == b'\n') else {
            break;
        };
        let off_s = std::str::from_utf8(&bytes[pos_in_buf..pos_in_buf + nl1]).unwrap_or("0");
        pos_in_buf += nl1 + 1;
        let Some(nl2) = bytes[pos_in_buf..].iter().position(|&b| b == b'\n') else {
            break;
        };
        let len_s = std::str::from_utf8(&bytes[pos_in_buf..pos_in_buf + nl2]).unwrap_or("0");
        pos_in_buf += nl2 + 1;
        let off: u64 = off_s.trim().parse().unwrap_or(0);
        let len: u64 = len_s.trim().parse().unwrap_or(0);
        if off != 0 || len != 0 {
            map.push((off, len));
        }
    }
    let content_off = data_start + pad512(pos_in_buf as u64);
    Ok((map, content_off))
}

fn sparse_map_from_pax(pax: &PaxParsed) -> Vec<(u64, u64)> {
    // 0.1: GNU.sparse.map = "off,len,off,len,..."
    if let Some(m) = pax.map.get("GNU.sparse.map") {
        let nums: Vec<u64> = m.split(',').filter_map(|s| s.trim().parse().ok()).collect();
        let mut out = Vec::new();
        let mut i = 0;
        while i + 1 < nums.len() {
            let off = nums[i];
            let len = nums[i + 1];
            if off != 0 || len != 0 {
                out.push((off, len));
            }
            i += 2;
        }
        return out;
    }
    // 0.0: accumulated pairs
    if !pax.sparse_pairs.is_empty() {
        return pax.sparse_pairs.clone();
    }
    Vec::new()
}

/// Scan headers for GNU dumpdir typeflag `D` (Python `_detect_gnu_incremental`).
fn detect_gnu_incremental<R: Read + Seek>(reader: &mut R, ignore_zeros: bool) -> Result<bool> {
    let old_pos = reader.stream_position()?;
    let result = (|| -> Result<bool> {
        reader.seek(SeekFrom::Start(0))?;
        let mut pos: u64 = 0;
        let mut header = [0u8; 512];
        let mut remaining: u32 = 10_000;
        let t0 = Instant::now();

        loop {
            if remaining == 0 || t0.elapsed().as_secs_f64() > 3.0 {
                return Ok(false);
            }
            reader.seek(SeekFrom::Start(pos))?;
            let n = reader.read(&mut header)?;
            if n < 512 {
                return Ok(false);
            }

            if header.iter().all(|&b| b == 0) {
                pos += BLOCK_SIZE;
                reader.seek(SeekFrom::Start(pos))?;
                let mut next = [0u8; 512];
                let n2 = reader.read(&mut next)?;
                if n2 < 512 || next.iter().all(|&b| b == 0) {
                    if ignore_zeros {
                        continue;
                    }
                    return Ok(false);
                }
                // Zero block then non-zero without ignore_zeros → end of archive.
                return Ok(false);
            }

            let typeflag = header[156];
            if typeflag == b'D' {
                return Ok(true);
            }
            remaining -= 1;

            let size = parse_octal(&header[124..136]).unwrap_or(0);
            pos = pos + BLOCK_SIZE + pad512(size);
        }
    })();
    reader.seek(SeekFrom::Start(old_pos))?;
    result
}

/// Strip GNU incremental octal-timestamp prefix when it matches the raw ustar prefix field.
///
/// Python: `_fix_incremental_backup_name_prefixes`. Also requires the first path component
/// to look like an octal timestamp (digits 0–7 only).
fn fix_incremental_backup_name_prefixes(name: &str, header: &[u8; 512]) -> String {
    let Some((prefix, rest)) = name.split_once('/') else {
        return name.to_string();
    };
    if prefix.is_empty() {
        return name.to_string();
    }
    // Incremental timestamp prefixes are octal digit strings.
    if !prefix.bytes().all(|b| b.is_ascii_digit() && b <= b'7') {
        return name.to_string();
    }
    let encoded = prefix.as_bytes();
    let raw_prefix = &header[345..500];
    // Match first C-string in the 155-byte prefix field (may hold two timestamps).
    if raw_prefix.starts_with(encoded) && raw_prefix.get(encoded.len()) == Some(&0) {
        return rest.to_string();
    }
    name.to_string()
}

/// Returns whether the archive was treated as GNU incremental (`isGnuIncremental`).
fn parse_tar_into_index<R: Read + Seek>(
    reader: &mut R,
    index: &SqliteIndex,
    options: &OpenOptions,
) -> Result<bool> {
    let mut pos: u64 = 0;
    let mut header = [0u8; 512];
    let mut generated_dirs: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    let mut batch: Vec<FileRow> = Vec::with_capacity(BATCH_FLUSH);
    let mut pax_global: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut pax_global_xattrs: std::collections::HashMap<String, Vec<u8>> =
        std::collections::HashMap::new();
    let mut pax_pending: PaxParsed = PaxParsed::empty();
    let mut pax_header_start: Option<u64> = None;
    let mut nested_pending: Vec<NestedPending> = Vec::new();
    let mut xattr_batch: Vec<(i64, String, Vec<u8>)> = Vec::with_capacity(BATCH_FLUSH);
    // Prior dumpdir present-name sets per directory (for delete whiteouts).
    let mut dumpdir_state: std::collections::HashMap<String, std::collections::HashSet<String>> =
        std::collections::HashMap::new();

    let mut is_gnu_incremental = match options.gnu_incremental {
        Some(v) => v,
        None => detect_gnu_incremental(reader, options.ignore_zeros)?,
    };

    let flush = |batch: &mut Vec<FileRow>| -> Result<()> {
        if !batch.is_empty() {
            index.insert_files_batch(batch)?;
            batch.clear();
        }
        Ok(())
    };
    let flush_xattrs = |batch: &mut Vec<(i64, String, Vec<u8>)>| -> Result<()> {
        if !batch.is_empty() {
            index.insert_xattrs_batch(batch)?;
            batch.clear();
        }
        Ok(())
    };

    loop {
        reader.seek(SeekFrom::Start(pos))?;
        let n = reader.read(&mut header)?;
        if n == 0 {
            break;
        }
        if n < 512 {
            break;
        }

        if header.iter().all(|&b| b == 0) {
            if options.ignore_zeros {
                pos += BLOCK_SIZE;
                continue;
            }
            pos += BLOCK_SIZE;
            reader.seek(SeekFrom::Start(pos))?;
            let mut next = [0u8; 512];
            let n2 = reader.read(&mut next)?;
            if n2 < 512 || next.iter().all(|&b| b == 0) {
                break;
            }
            break;
        }

        let size = parse_octal(&header[124..136]).unwrap_or(0);
        let mtime = parse_octal(&header[136..148]).unwrap_or(0) as f64;
        let mode_bits = parse_octal(&header[100..108]).unwrap_or(0o644) as u32;
        let uid = parse_octal(&header[108..116]).unwrap_or(0) as i64;
        let gid = parse_octal(&header[116..124]).unwrap_or(0) as i64;
        let typeflag = header[156];
        let linkname = cstr_field_encoded(&header[157..257], &options.encoding);

        // PAX extended / global headers — apply to next file (or global).
        if typeflag == b'x' || typeflag == b'g' {
            let body_off = pos + BLOCK_SIZE;
            let mut body = vec![0u8; size as usize];
            reader.seek(SeekFrom::Start(body_off))?;
            if size > 0 {
                reader.read_exact(&mut body)?;
            }
            let recs = parse_pax_records(&body);
            if typeflag == b'g' {
                pax_global.extend(recs.map);
                pax_global_xattrs.extend(recs.fs_xattrs);
            } else {
                pax_pending = recs;
                pax_header_start = Some(pos);
            }
            pos = body_off + pad512(size);
            continue;
        }

        // GNU long name / long link
        if typeflag == b'L' || typeflag == b'K' {
            let data_off_long = pos + BLOCK_SIZE;
            let mut long = vec![0u8; size as usize];
            reader.seek(SeekFrom::Start(data_off_long))?;
            if size > 0 {
                reader.read_exact(&mut long)?;
            }
            while long.last() == Some(&0) {
                long.pop();
            }
            let long_str = decode_bytes(&long, &options.encoding);
            pos = data_off_long + pad512(size);
            if typeflag == b'L' {
                pax_pending.map.insert("path".into(), long_str);
            } else {
                pax_pending.map.insert("linkpath".into(), long_str);
            }
            continue;
        }

        // Merge pax for this member.
        let mut pax_map = pax_global.clone();
        let pending = std::mem::replace(&mut pax_pending, PaxParsed::empty());
        pax_map.extend(pending.map.iter().map(|(k, v)| (k.clone(), v.clone())));
        let pax_for_sparse = PaxParsed {
            map: pax_map.clone(),
            sparse_pairs: pending.sparse_pairs,
            fs_xattrs: std::collections::HashMap::new(),
        };
        let mut member_fs_xattrs = pax_global_xattrs.clone();
        member_fs_xattrs.extend(pending.fs_xattrs);
        let member_header_start = pax_header_start.take().unwrap_or(pos);

        let mut name = if let Some(p) = pax_map.get("path") {
            p.clone()
        } else if let Some(p) = pax_map.get("GNU.sparse.name") {
            p.clone()
        } else {
            parse_name(&header, &options.encoding)
        };
        let linkname = pax_map.get("linkpath").cloned().unwrap_or(linkname);
        let mtime = pax_map
            .get("mtime")
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(mtime);

        // Dumpdir members mark GNU incremental archives (Python `_process_tar_info`).
        if typeflag == b'D' && !is_gnu_incremental {
            is_gnu_incremental = true;
        }

        if is_gnu_incremental {
            name = fix_incremental_backup_name_prefixes(&name, &header);
        }

        let mut issparse = false;
        let mut logical_size = size;
        let mut data_off = pos + BLOCK_SIZE;
        let mut on_tape = size; // bytes to skip after ustar header (size field)

        // Old GNU sparse typeflag 'S'
        if typeflag == b'S' {
            issparse = true;
            logical_size = parse_octal(&header[483..495]).unwrap_or(size);
            let mut is_extended = header[482] != 0;
            while is_extended {
                let mut ext = [0u8; 512];
                reader.seek(SeekFrom::Start(data_off))?;
                reader.read_exact(&mut ext)?;
                is_extended = ext[504] != 0;
                data_off += BLOCK_SIZE;
            }
            on_tape = size;
        }

        // PAX GNU sparse 0.0 / 0.1 / 1.0
        let is_pax_sparse = pax_map.contains_key("GNU.sparse.size")
            || pax_map.contains_key("GNU.sparse.realsize")
            || pax_map.contains_key("GNU.sparse.map")
            || pax_map.get("GNU.sparse.major").map(|s| s.as_str()) == Some("1")
            || !pax_for_sparse.sparse_pairs.is_empty();
        if is_pax_sparse {
            issparse = true;
            if let Some(n) = pax_map.get("GNU.sparse.name") {
                name = n.clone();
            }
            logical_size = pax_map
                .get("GNU.sparse.realsize")
                .or_else(|| pax_map.get("GNU.sparse.size"))
                .and_then(|s| s.parse().ok())
                .unwrap_or(size);
            if pax_map.get("GNU.sparse.major").map(|s| s.as_str()) == Some("1") {
                let (_map, content_off) = parse_sparse_1_0_map(reader, data_off)?;
                data_off = content_off;
                on_tape = size;
            } else {
                let _ = sparse_map_from_pax(&pax_for_sparse);
                on_tape = size;
            }
        }

        // Skip junk placeholder paths if any slipped through.
        if name.contains("PaxHeaders/") || name.starts_with("./PaxHeaders/") {
            pos = pos + BLOCK_SIZE + pad512(on_tape);
            continue;
        }

        // Nested TAR detection: name ends with `.tar` or ustar/GNU magic at data offset.
        let mut istar = false;
        if !issparse && is_regular_tar_member(typeflag, &name) && logical_size >= BLOCK_SIZE {
            let by_name = name_looks_like_tar(&name);
            let by_magic = peek_tar_magic_at(reader, data_off)?;
            if by_name || by_magic {
                istar = true;
                let member_path = normalize_member_path(&name);
                nested_pending.push(NestedPending {
                    member: NestedTarMember {
                        path: member_path,
                        offset: data_off,
                        size: logical_size,
                    },
                    offsetheader: member_header_start,
                    mtime,
                    mode_bits,
                    uid,
                    gid,
                });
            }
        }

        if typeflag == b'D' {
            // Parse dumpdir payload for multi-snapshot delete whiteouts (B-10 MVP).
            let mut payload = vec![0u8; logical_size as usize];
            if logical_size > 0 {
                reader.seek(SeekFrom::Start(data_off))?;
                reader.read_exact(&mut payload)?;
            }
            apply_dumpdir_deletes(
                &mut batch,
                &name,
                member_header_start,
                &payload,
                mtime,
                uid,
                gid,
                0,
                &mut dumpdir_state,
            );
            // Dumpdir: regular meta entry (S_IFREG, dumpdir size) + directory entry (size 0).
            push_dumpdir_entries(
                &mut batch,
                &name,
                member_header_start,
                data_off,
                logical_size,
                mtime,
                mode_bits,
                &linkname,
                uid,
                gid,
                0,
                &mut generated_dirs,
            )?;
        } else {
            push_entry(
                &mut batch,
                &name,
                member_header_start,
                data_off,
                if typeflag == b'5' || name.ends_with('/') {
                    0
                } else {
                    logical_size
                },
                mtime,
                mode_bits,
                typeflag,
                &linkname,
                uid,
                gid,
                issparse,
                istar,
                0,
                &mut generated_dirs,
            )?;
        }
        // Archive-stored FS xattrs (LIBARCHIVE./SCHILY.xattr.*) keyed by offsetheader.
        if !member_fs_xattrs.is_empty() {
            push_xattr_rows(&mut xattr_batch, member_header_start, &member_fs_xattrs);
        }
        if batch.len() >= BATCH_FLUSH {
            flush(&mut batch)?;
        }
        if xattr_batch.len() >= BATCH_FLUSH {
            flush_xattrs(&mut xattr_batch)?;
        }

        pos = if typeflag == b'5' || typeflag == b'1' || typeflag == b'2' {
            if on_tape == 0 {
                pos + BLOCK_SIZE
            } else {
                // rare: dir with data
                pos + BLOCK_SIZE + pad512(on_tape)
            }
        } else {
            // Always advance by ustar header + padded size field (includes sparse map for 1.0).
            pos + BLOCK_SIZE + pad512(on_tape)
        };
        let _ = mtime; // used
    }

    flush(&mut batch)?;
    flush_xattrs(&mut xattr_batch)?;

    let nested_members: Vec<NestedTarMember> =
        nested_pending.iter().map(|n| n.member.clone()).collect();
    store_nested_tar_members(index, &nested_members)?;

    // Flatten nested TAR headers into outer index paths (absolute offsets).
    flatten_nested_tars(
        reader,
        index,
        options,
        &nested_pending,
        1,
        &mut is_gnu_incremental,
        &mut generated_dirs,
    )?;

    Ok(is_gnu_incremental)
}

/// Walk nested TAR members and insert flattened path rows into the outer index.
///
/// `content_depth` is the `recursiondepth` column for rows written at this layer (1 = first nested).
fn flatten_nested_tars<R: Read + Seek>(
    reader: &mut R,
    index: &SqliteIndex,
    options: &OpenOptions,
    nested: &[NestedPending],
    content_depth: i32,
    is_gnu_incremental: &mut bool,
    generated_dirs: &mut std::collections::BTreeSet<String>,
) -> Result<()> {
    if nested.is_empty() || content_depth < 0 {
        return Ok(());
    }
    // Guard against pathological recursion depth.
    if content_depth > 64 {
        return Ok(());
    }

    let mut batch: Vec<FileRow> = Vec::with_capacity(BATCH_FLUSH);
    let mut xattr_batch: Vec<(i64, String, Vec<u8>)> = Vec::with_capacity(BATCH_FLUSH);
    let mut deeper: Vec<NestedPending> = Vec::new();

    let flush = |batch: &mut Vec<FileRow>| -> Result<()> {
        if !batch.is_empty() {
            index.insert_files_batch(batch)?;
            batch.clear();
        }
        Ok(())
    };
    let flush_xattrs = |batch: &mut Vec<(i64, String, Vec<u8>)>| -> Result<()> {
        if !batch.is_empty() {
            index.insert_xattrs_batch(batch)?;
            batch.clear();
        }
        Ok(())
    };

    for pending in nested {
        if !should_flatten_nested(options, pending.member.size, content_depth) {
            continue;
        }
        let path_prefix = pending.member.path.clone();
        let region_start = pending.member.offset;
        let region_end = pending.member.offset.saturating_add(pending.member.size);

        // Avoid ensure_parent_dirs synthesizing offsetheader=0 for the nest root (would
        // shadow version ordering vs the real file row and the generated directory row).
        generated_dirs.insert(path_prefix.clone());

        let mut found_any = false;
        match walk_tar_region(
            reader,
            options,
            &path_prefix,
            region_start,
            region_end,
            content_depth,
            is_gnu_incremental,
            &mut batch,
            &mut xattr_batch,
            generated_dirs,
            &mut deeper,
            &mut found_any,
        ) {
            Ok(()) => {}
            Err(e) => {
                // Nested content may not be a valid TAR despite magic/name; keep side-list only.
                log::debug!("skip flatten of nested TAR {}: {e}", pending.member.path);
                continue;
            }
        }

        if !found_any {
            continue;
        }

        // Python: after recursive index succeeds, add a generated directory version of the
        // nested archive (higher offsetheader) and keep the original file row with istar.
        push_nested_member_as_directory(&mut batch, pending, content_depth, generated_dirs);
        if batch.len() >= BATCH_FLUSH {
            flush(&mut batch)?;
        }
        if xattr_batch.len() >= BATCH_FLUSH {
            flush_xattrs(&mut xattr_batch)?;
        }
    }

    flush(&mut batch)?;
    flush_xattrs(&mut xattr_batch)?;

    // Depth-first further nesting (Python walks each nested after its parent layer's files).
    if !deeper.is_empty() {
        flatten_nested_tars(
            reader,
            index,
            options,
            &deeper,
            content_depth + 1,
            is_gnu_incremental,
            generated_dirs,
        )?;
    }
    Ok(())
}

/// Emit a generated directory version of a nested TAR member so `lookup` returns a dir
/// and `list` under that path works (Python recursive index parity).
fn push_nested_member_as_directory(
    batch: &mut Vec<FileRow>,
    pending: &NestedPending,
    content_depth: i32,
    generated_dirs: &mut std::collections::BTreeSet<String>,
) {
    let full_path = pending.member.path.trim_end_matches('/');
    let (path, name) = match full_path.rsplit_once('/') {
        Some(("", n)) => (String::new(), n.to_string()),
        Some((p, n)) => (p.to_string(), n.to_string()),
        None => (String::new(), full_path.to_string()),
    };
    if name.is_empty() {
        return;
    }
    generated_dirs.insert(full_path.to_string());
    let mode = ((pending.mode_bits & 0o7777) | ratarmount_core::S_IFDIR) as i64;
    batch.push(FileRow::new(
        path,
        name,
        pending.offsetheader as i64 + 1,
        pending.member.offset as i64 + 1,
        0,
        pending.mtime,
        mode,
        b'5' as i64,
        "",
        pending.uid,
        pending.gid,
        true,  // istar
        false, // issparse
        true,  // isgenerated
        i64::from(content_depth),
    ));
}

/// Join outer path prefix with an inner member name (`/inner.tar` + `a/b` → `/inner.tar/a/b`).
fn join_path_prefix(prefix: &str, name: &str) -> String {
    let mut name = name.to_string();
    while name.starts_with("./") {
        name = name[2..].to_string();
    }
    name = name.trim_start_matches('/').to_string();
    if prefix.is_empty() {
        return name;
    }
    let prefix = prefix.trim_end_matches('/');
    if name.is_empty() {
        prefix.to_string()
    } else {
        format!("{prefix}/{name}")
    }
}

/// Parse one nested TAR region in absolute outer-stream coordinates and push rows under `path_prefix`.
#[allow(clippy::too_many_arguments)]
fn walk_tar_region<R: Read + Seek>(
    reader: &mut R,
    options: &OpenOptions,
    path_prefix: &str,
    region_start: u64,
    region_end: u64,
    recursion_depth: i32,
    is_gnu_incremental: &mut bool,
    batch: &mut Vec<FileRow>,
    xattr_batch: &mut Vec<(i64, String, Vec<u8>)>,
    generated_dirs: &mut std::collections::BTreeSet<String>,
    nested_out: &mut Vec<NestedPending>,
    found_any: &mut bool,
) -> Result<()> {
    if region_end <= region_start + BLOCK_SIZE {
        return Ok(());
    }

    let mut pos = region_start;
    let mut header = [0u8; 512];
    let mut pax_global: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut pax_global_xattrs: std::collections::HashMap<String, Vec<u8>> =
        std::collections::HashMap::new();
    let mut pax_pending = PaxParsed::empty();
    let mut pax_header_start: Option<u64> = None;

    loop {
        if pos + BLOCK_SIZE > region_end {
            break;
        }
        reader.seek(SeekFrom::Start(pos))?;
        let n = reader.read(&mut header)?;
        if n < 512 {
            break;
        }

        if header.iter().all(|&b| b == 0) {
            if options.ignore_zeros {
                pos += BLOCK_SIZE;
                continue;
            }
            // Double zero block ends the nested archive.
            let next_pos = pos + BLOCK_SIZE;
            if next_pos + BLOCK_SIZE <= region_end {
                reader.seek(SeekFrom::Start(next_pos))?;
                let mut next = [0u8; 512];
                let n2 = reader.read(&mut next)?;
                if n2 < 512 || next.iter().all(|&b| b == 0) {
                    break;
                }
            }
            break;
        }

        let size = parse_octal(&header[124..136]).unwrap_or(0);
        let mtime = parse_octal(&header[136..148]).unwrap_or(0) as f64;
        let mode_bits = parse_octal(&header[100..108]).unwrap_or(0o644) as u32;
        let uid = parse_octal(&header[108..116]).unwrap_or(0) as i64;
        let gid = parse_octal(&header[116..124]).unwrap_or(0) as i64;
        let typeflag = header[156];
        let linkname = cstr_field_encoded(&header[157..257], &options.encoding);

        if typeflag == b'x' || typeflag == b'g' {
            let body_off = pos + BLOCK_SIZE;
            if body_off + size > region_end {
                break;
            }
            let mut body = vec![0u8; size as usize];
            reader.seek(SeekFrom::Start(body_off))?;
            if size > 0 {
                reader.read_exact(&mut body)?;
            }
            let recs = parse_pax_records(&body);
            if typeflag == b'g' {
                pax_global.extend(recs.map);
                pax_global_xattrs.extend(recs.fs_xattrs);
            } else {
                pax_pending = recs;
                pax_header_start = Some(pos);
            }
            pos = body_off + pad512(size);
            continue;
        }

        if typeflag == b'L' || typeflag == b'K' {
            let data_off_long = pos + BLOCK_SIZE;
            if data_off_long + size > region_end {
                break;
            }
            let mut long = vec![0u8; size as usize];
            reader.seek(SeekFrom::Start(data_off_long))?;
            if size > 0 {
                reader.read_exact(&mut long)?;
            }
            while long.last() == Some(&0) {
                long.pop();
            }
            let long_str = decode_bytes(&long, &options.encoding);
            pos = data_off_long + pad512(size);
            if typeflag == b'L' {
                pax_pending.map.insert("path".into(), long_str);
            } else {
                pax_pending.map.insert("linkpath".into(), long_str);
            }
            continue;
        }

        let mut pax_map = pax_global.clone();
        let pending = std::mem::replace(&mut pax_pending, PaxParsed::empty());
        pax_map.extend(pending.map.iter().map(|(k, v)| (k.clone(), v.clone())));
        let pax_for_sparse = PaxParsed {
            map: pax_map.clone(),
            sparse_pairs: pending.sparse_pairs,
            fs_xattrs: std::collections::HashMap::new(),
        };
        let mut member_fs_xattrs = pax_global_xattrs.clone();
        member_fs_xattrs.extend(pending.fs_xattrs);
        let member_header_start = pax_header_start.take().unwrap_or(pos);

        let mut name = if let Some(p) = pax_map.get("path") {
            p.clone()
        } else if let Some(p) = pax_map.get("GNU.sparse.name") {
            p.clone()
        } else {
            parse_name(&header, &options.encoding)
        };
        let linkname = pax_map.get("linkpath").cloned().unwrap_or(linkname);
        let mtime = pax_map
            .get("mtime")
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(mtime);

        if typeflag == b'D' && !*is_gnu_incremental {
            *is_gnu_incremental = true;
        }
        if *is_gnu_incremental {
            name = fix_incremental_backup_name_prefixes(&name, &header);
        }

        let mut issparse = false;
        let mut logical_size = size;
        let mut data_off = pos + BLOCK_SIZE;
        let mut on_tape = size;

        if typeflag == b'S' {
            issparse = true;
            logical_size = parse_octal(&header[483..495]).unwrap_or(size);
            let mut is_extended = header[482] != 0;
            while is_extended {
                if data_off + BLOCK_SIZE > region_end {
                    break;
                }
                let mut ext = [0u8; 512];
                reader.seek(SeekFrom::Start(data_off))?;
                reader.read_exact(&mut ext)?;
                is_extended = ext[504] != 0;
                data_off += BLOCK_SIZE;
            }
            on_tape = size;
        }

        let is_pax_sparse = pax_map.contains_key("GNU.sparse.size")
            || pax_map.contains_key("GNU.sparse.realsize")
            || pax_map.contains_key("GNU.sparse.map")
            || pax_map.get("GNU.sparse.major").map(|s| s.as_str()) == Some("1")
            || !pax_for_sparse.sparse_pairs.is_empty();
        if is_pax_sparse {
            issparse = true;
            if let Some(n) = pax_map.get("GNU.sparse.name") {
                name = n.clone();
            }
            logical_size = pax_map
                .get("GNU.sparse.realsize")
                .or_else(|| pax_map.get("GNU.sparse.size"))
                .and_then(|s| s.parse().ok())
                .unwrap_or(size);
            if pax_map.get("GNU.sparse.major").map(|s| s.as_str()) == Some("1") {
                if data_off < region_end {
                    let (_map, content_off) = parse_sparse_1_0_map(reader, data_off)?;
                    data_off = content_off.min(region_end);
                }
                on_tape = size;
            } else {
                let _ = sparse_map_from_pax(&pax_for_sparse);
                on_tape = size;
            }
        }

        if name.contains("PaxHeaders/") || name.starts_with("./PaxHeaders/") {
            pos = pos + BLOCK_SIZE + pad512(on_tape);
            continue;
        }

        let full_name = join_path_prefix(path_prefix, &name);

        let mut istar = false;
        if !issparse
            && is_regular_tar_member(typeflag, &name)
            && logical_size >= BLOCK_SIZE
            && data_off + logical_size.min(BLOCK_SIZE) <= region_end
        {
            let by_name = name_looks_like_tar(&name);
            let by_magic = peek_tar_magic_at(reader, data_off)?;
            if by_name || by_magic {
                istar = true;
                nested_out.push(NestedPending {
                    member: NestedTarMember {
                        path: normalize_member_path(&full_name),
                        offset: data_off,
                        size: logical_size,
                    },
                    offsetheader: member_header_start,
                    mtime,
                    mode_bits,
                    uid,
                    gid,
                });
            }
        }

        if typeflag == b'D' {
            push_dumpdir_entries(
                batch,
                &full_name,
                member_header_start,
                data_off,
                logical_size,
                mtime,
                mode_bits,
                &linkname,
                uid,
                gid,
                i64::from(recursion_depth),
                generated_dirs,
            )?;
        } else {
            push_entry(
                batch,
                &full_name,
                member_header_start,
                data_off,
                if typeflag == b'5' || name.ends_with('/') {
                    0
                } else {
                    logical_size
                },
                mtime,
                mode_bits,
                typeflag,
                &linkname,
                uid,
                gid,
                issparse,
                istar,
                i64::from(recursion_depth),
                generated_dirs,
            )?;
        }
        if !member_fs_xattrs.is_empty() {
            push_xattr_rows(xattr_batch, member_header_start, &member_fs_xattrs);
        }
        *found_any = true;

        pos = if typeflag == b'5' || typeflag == b'1' || typeflag == b'2' {
            if on_tape == 0 {
                pos + BLOCK_SIZE
            } else {
                pos + BLOCK_SIZE + pad512(on_tape)
            }
        } else {
            pos + BLOCK_SIZE + pad512(on_tape)
        };
        if pos > region_end {
            break;
        }
    }

    Ok(())
}

/// Regular-file typeflags eligible for nested-TAR detection.
fn is_regular_tar_member(typeflag: u8, name: &str) -> bool {
    if name.ends_with('/') {
        return false;
    }
    matches!(typeflag, b'0' | b'\0' | b'7' /* contiguous */)
        || (typeflag != b'1'
            && typeflag != b'2'
            && typeflag != b'3'
            && typeflag != b'4'
            && typeflag != b'5'
            && typeflag != b'6'
            && typeflag != b'D'
            && typeflag != b'S'
            && typeflag != b'L'
            && typeflag != b'K'
            && typeflag != b'x'
            && typeflag != b'g'
            && typeflag != b'X')
}

fn name_looks_like_tar(name: &str) -> bool {
    name.to_ascii_lowercase().ends_with(".tar")
}

fn normalize_member_path(name: &str) -> String {
    let mut full = name.trim_end_matches('/').to_string();
    while full.starts_with("./") {
        full = full[2..].to_string();
    }
    normpath(&full)
}

/// TAR magic at member data offset + 257: `ustar` or GNU.
fn peek_tar_magic_at<R: Read + Seek>(reader: &mut R, data_off: u64) -> Result<bool> {
    if reader
        .seek(SeekFrom::Start(data_off.saturating_add(257)))
        .is_err()
    {
        return Ok(false);
    }
    let mut magic = [0u8; 5];
    let n = match reader.read(&mut magic) {
        Ok(n) => n,
        Err(_) => return Ok(false),
    };
    Ok(n == 5 && (&magic == b"ustar" || &magic == b"GNU  " || magic.starts_with(b"ustar")))
}

fn store_nested_tar_members(index: &SqliteIndex, members: &[NestedTarMember]) -> Result<()> {
    let json = format_nested_tar_members_json(members);
    index.store_metadata_key_value(NESTED_TAR_MEMBERS_KEY, &json)?;
    Ok(())
}

fn format_nested_tar_members_json(members: &[NestedTarMember]) -> String {
    let mut json = String::from("[");
    for (i, m) in members.iter().enumerate() {
        if i > 0 {
            json.push(',');
        }
        json.push('{');
        json.push_str("\"path\":");
        json.push_str(&json_escape_string(&m.path));
        json.push_str(",\"offset\":");
        json.push_str(&m.offset.to_string());
        json.push_str(",\"size\":");
        json.push_str(&m.size.to_string());
        json.push('}');
    }
    json.push(']');
    json
}

fn json_escape_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Parse the compact JSON written by [`format_nested_tar_members_json`].
fn parse_nested_tar_members_json(s: &str) -> Vec<NestedTarMember> {
    let s = s.trim();
    if s.is_empty() || s == "[]" {
        return Vec::new();
    }
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        // Find next object starting with {
        while i < bytes.len() && bytes[i] != b'{' {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let obj_start = i;
        i += 1;
        let mut depth = 1i32;
        while i < bytes.len() && depth > 0 {
            match bytes[i] {
                b'{' => depth += 1,
                b'}' => depth -= 1,
                b'"' => {
                    i += 1;
                    while i < bytes.len() {
                        if bytes[i] == b'\\' {
                            i += 2;
                            continue;
                        }
                        if bytes[i] == b'"' {
                            break;
                        }
                        i += 1;
                    }
                }
                _ => {}
            }
            i += 1;
        }
        let obj = &s[obj_start..i.min(s.len())];
        if let Some(m) = parse_one_nested_member_object(obj) {
            out.push(m);
        }
    }
    out
}

fn parse_one_nested_member_object(obj: &str) -> Option<NestedTarMember> {
    let path = json_extract_string_field(obj, "path")?;
    let offset = json_extract_u64_field(obj, "offset")?;
    let size = json_extract_u64_field(obj, "size")?;
    Some(NestedTarMember { path, offset, size })
}

fn json_extract_string_field(obj: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let rest = obj.split_once(&needle)?.1.trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    let mut out = String::new();
    let mut chars = rest[1..].chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => return Some(out),
            '\\' => match chars.next()? {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    let h: String = chars.by_ref().take(4).collect();
                    if h.len() != 4 {
                        return None;
                    }
                    let code = u32::from_str_radix(&h, 16).ok()?;
                    out.push(char::from_u32(code)?);
                }
                other => out.push(other),
            },
            c => out.push(c),
        }
    }
    None
}

fn json_extract_u64_field(obj: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\"");
    let rest = obj.split_once(&needle)?.1.trim_start();
    let rest = rest.strip_prefix(':')?.trim_start();
    let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    num.parse().ok()
}

#[allow(clippy::too_many_arguments)]
fn push_entry(
    batch: &mut Vec<FileRow>,
    full_name: &str,
    offsetheader: u64,
    offset: u64,
    size: u64,
    mtime: f64,
    mode_bits: u32,
    typeflag: u8,
    linkname: &str,
    uid: i64,
    gid: i64,
    issparse: bool,
    istar: bool,
    recursiondepth: i64,
    generated_dirs: &mut std::collections::BTreeSet<String>,
) -> Result<()> {
    let is_dir = typeflag == b'5' || full_name.ends_with('/');
    let mut full = full_name.trim_end_matches('/').to_string();
    if full.is_empty() {
        return Ok(());
    }
    while full.starts_with("./") {
        full = full[2..].to_string();
    }
    let full_path = normpath(&full);
    let (path, name) = match full_path.rsplit_once('/') {
        Some(("", n)) => (String::new(), n.to_string()),
        Some((p, n)) => (p.to_string(), n.to_string()),
        None => (String::new(), full_path.clone()),
    };

    ensure_parent_dirs(batch, &path, generated_dirs, mtime, uid, gid);

    let ifmt = if is_dir {
        ratarmount_core::S_IFDIR
    } else if typeflag == b'2' {
        ratarmount_core::S_IFLNK
    } else {
        ratarmount_core::S_IFREG
    };
    let mode = (mode_bits & 0o7777) | ifmt;

    // typeflag 'S' is not a digit — store as 0 like Python/sqlite silent conversion, or as byte value.
    // Keep raw byte for diagnostics; Python notes it becomes 0 for non-digit typeflags in some paths.
    let type_store = if typeflag == b'S' {
        b'S' as i64
    } else {
        typeflag as i64
    };

    batch.push(FileRow::new(
        path,
        name,
        offsetheader as i64,
        offset as i64,
        if is_dir { 0 } else { size as i64 },
        mtime,
        mode as i64,
        type_store,
        linkname,
        uid,
        gid,
        istar,
        issparse,
        false,
        recursiondepth,
    ));
    Ok(())
}

/// GNU dumpdir (typeflag `D`): store as regular-file meta plus a directory entry.
///
/// Python `_process_tar_info` adds the dumpdir payload as `S_IFREG` and a second
/// row with `offsetheader + 1`, size 0, and `mode | S_IFDIR` so the name is listable
/// as a directory (newest version wins by higher `offsetheader`).
#[allow(clippy::too_many_arguments)]
fn push_dumpdir_entries(
    batch: &mut Vec<FileRow>,
    full_name: &str,
    offsetheader: u64,
    offset: u64,
    size: u64,
    mtime: f64,
    mode_bits: u32,
    linkname: &str,
    uid: i64,
    gid: i64,
    recursiondepth: i64,
    generated_dirs: &mut std::collections::BTreeSet<String>,
) -> Result<()> {
    let mut full = full_name.trim_end_matches('/').to_string();
    if full.is_empty() {
        return Ok(());
    }
    while full.starts_with("./") {
        full = full[2..].to_string();
    }
    let full_path = normpath(&full);
    let (path, name) = match full_path.rsplit_once('/') {
        Some(("", n)) => (String::new(), n.to_string()),
        Some((p, n)) => (p.to_string(), n.to_string()),
        None => (String::new(), full_path.clone()),
    };

    ensure_parent_dirs(batch, &path, generated_dirs, mtime, uid, gid);

    let mode_reg = ((mode_bits & 0o7777) | ratarmount_core::S_IFREG) as i64;
    let mode_dir = ((mode_bits & 0o7777) | ratarmount_core::S_IFDIR) as i64;
    let type_store = b'D' as i64;

    // Dumpdir metadata (regular file with dumpdir payload size).
    batch.push(FileRow::new(
        path.clone(),
        name.clone(),
        offsetheader as i64,
        offset as i64,
        size as i64,
        mtime,
        mode_reg,
        type_store,
        linkname,
        uid,
        gid,
        false,
        false,
        false,
        recursiondepth,
    ));

    // Directory side so children can be listed; unique PK via offsetheader+1.
    batch.push(FileRow::new(
        path.clone(),
        name.clone(),
        offsetheader as i64 + 1,
        offset as i64,
        0,
        mtime,
        mode_dir,
        type_store,
        linkname,
        uid,
        gid,
        false,
        false,
        false,
        recursiondepth,
    ));

    // Prevent `ensure_parent_dirs` from synthesizing a generated parent later.
    let dir_key = if path.is_empty() {
        format!("/{name}")
    } else {
        format!("{path}/{name}")
    };
    generated_dirs.insert(dir_key);

    Ok(())
}

fn ensure_parent_dirs(
    batch: &mut Vec<FileRow>,
    path: &str,
    generated: &mut std::collections::BTreeSet<String>,
    mtime: f64,
    uid: i64,
    gid: i64,
) {
    if path.is_empty() {
        return;
    }
    let parts: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|p| !p.is_empty())
        .collect();
    let mut cur = String::new();
    for (i, part) in parts.iter().enumerate() {
        let parent = if i == 0 { String::new() } else { cur.clone() };
        cur = if parent.is_empty() {
            format!("/{part}")
        } else {
            format!("{parent}/{part}")
        };
        if generated.contains(&cur) {
            continue;
        }
        generated.insert(cur.clone());
        let mode = (ratarmount_core::S_IFDIR | 0o755) as i64;
        batch.push(FileRow::new(
            parent,
            (*part).to_string(),
            0,
            0,
            0,
            mtime,
            mode,
            b'5' as i64,
            "",
            uid,
            gid,
            false,
            false,
            true,
            0,
        ));
    }
}

/// Build a segmented view from a sparse map + on-tape data cursor.
fn segments_from_map(
    map: &[(u64, u64)],
    mut tar_cursor: u64,
    logical_size: u64,
) -> io::Result<Vec<FileSegment>> {
    let mut segments: Vec<FileSegment> = Vec::new();
    let mut last_end: u64 = 0;
    for &(off, num) in map {
        if off == 0 && num == 0 {
            continue;
        }
        if off < last_end {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "sparse map not sorted / overlapping",
            ));
        }
        if off > last_end {
            segments.push(FileSegment::Zero {
                len: off - last_end,
            });
        }
        if num > 0 {
            segments.push(FileSegment::Data {
                file_offset: tar_cursor,
                len: num,
            });
            tar_cursor += num;
        }
        last_end = off + num;
    }
    if last_end < logical_size {
        segments.push(FileSegment::Zero {
            len: logical_size - last_end,
        });
    }
    Ok(segments)
}

/// Open a sparse member: re-read map from old GNU `S` or PAX 0.0/0.1/1.0 headers.
fn open_sparse_member<R: Read + Seek + Send + 'static>(
    mut file: R,
    header_offset: u64,
    data_offset: u64,
    logical_size: u64,
) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
    let mut pos = header_offset;
    let mut header = [0u8; 512];
    file.seek(SeekFrom::Start(pos))?;
    file.read_exact(&mut header)?;
    let mut pax = PaxParsed::empty();

    // Optional PAX 'x' header before the file header.
    if header[156] == b'x' {
        let size = parse_octal(&header[124..136]).unwrap_or(0);
        let body_off = pos + BLOCK_SIZE;
        let mut body = vec![0u8; size as usize];
        file.seek(SeekFrom::Start(body_off))?;
        if size > 0 {
            file.read_exact(&mut body)?;
        }
        pax = parse_pax_records(&body);
        pos = body_off + pad512(size);
        file.seek(SeekFrom::Start(pos))?;
        file.read_exact(&mut header)?;
    }

    let typeflag = header[156];
    let mut real_size = logical_size;
    for key in ["GNU.sparse.realsize", "GNU.sparse.size"] {
        if let Some(v) = pax.map.get(key) {
            if let Ok(n) = v.parse::<u64>() {
                real_size = n;
            }
        }
    }
    if typeflag == b'S' {
        real_size = parse_octal(&header[483..495]).unwrap_or(real_size);
    }

    let mut map: Vec<(u64, u64)> = Vec::new();
    let mut content_off = pos + BLOCK_SIZE;

    if typeflag == b'S' {
        for i in 0..4 {
            let base = 386 + i * 24;
            let off = parse_octal(&header[base..base + 12]).unwrap_or(0);
            let num = parse_octal(&header[base + 12..base + 24]).unwrap_or(0);
            if num > 0 || off > 0 {
                map.push((off, num));
            }
        }
        let mut is_extended = header[482] != 0;
        while is_extended {
            let mut ext = [0u8; 512];
            file.seek(SeekFrom::Start(content_off))?;
            file.read_exact(&mut ext)?;
            for i in 0..21 {
                let base = i * 24;
                if base + 24 > 504 {
                    break;
                }
                let off = parse_octal(&ext[base..base + 12]).unwrap_or(0);
                let num = parse_octal(&ext[base + 12..base + 24]).unwrap_or(0);
                if off != 0 || num != 0 {
                    map.push((off, num));
                }
            }
            is_extended = ext[504] != 0;
            content_off += BLOCK_SIZE;
        }
    } else if pax.map.get("GNU.sparse.major").map(|s| s.as_str()) == Some("1") {
        let (m, c) = parse_sparse_1_0_map(&mut file, content_off)
            .map_err(|e| io::Error::other(e.to_string()))?;
        map = m;
        content_off = c;
    } else {
        map = sparse_map_from_pax(&pax);
        if data_offset > 0 {
            content_off = data_offset;
        }
    }

    // If reparse found no map, fall back to contiguous slice of logical size.
    if map.is_empty() {
        let stencil = StenciledFile::new(file, vec![(data_offset.max(content_off), real_size)]);
        return Ok(Box::new(stencil));
    }

    let segments = segments_from_map(&map, content_off, real_size)?;
    Ok(Box::new(SegmentedFile::new(file, segments)))
}

fn parse_name(header: &[u8; 512], encoding: &str) -> String {
    let prefix = cstr_field_encoded(&header[345..500], encoding);
    let name = cstr_field_encoded(&header[0..100], encoding);
    if prefix.is_empty() {
        name
    } else {
        format!("{prefix}/{name}")
    }
}

/// NUL-terminated header field as UTF-8 (for octal / binary-safe numeric fields).
fn cstr_field(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// NUL-terminated field decoded with the configured archive encoding (`-e`).
fn cstr_field_encoded(bytes: &[u8], encoding: &str) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    decode_bytes(&bytes[..end], encoding)
}

/// Decode archive path/name bytes using Python-compatible encoding labels.
fn decode_bytes(bytes: &[u8], encoding: &str) -> String {
    let enc = encoding.trim();
    if enc.is_empty()
        || enc.eq_ignore_ascii_case("utf-8")
        || enc.eq_ignore_ascii_case("utf8")
        || enc.eq_ignore_ascii_case("ascii")
    {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    // Common aliases Python accepts
    let lowered = enc.to_ascii_lowercase();
    let label: &str = match lowered.as_str() {
        "latin1" | "latin-1" | "iso-8859-1" | "iso8859-1" => "iso-8859-1",
        "cp1252" | "windows-1252" => "windows-1252",
        "cp437" => "ibm437",
        other => other,
    };
    if let Some(enc) = encoding_rs::Encoding::for_label(label.as_bytes()) {
        let (cow, _, _) = enc.decode(bytes);
        cow.into_owned()
    } else {
        // Unknown label: fall back to lossy UTF-8 rather than failing the whole archive.
        String::from_utf8_lossy(bytes).into_owned()
    }
}

fn parse_octal(bytes: &[u8]) -> Option<u64> {
    let s = cstr_field(bytes);
    let s = s.trim();
    if s.is_empty() {
        return Some(0);
    }
    if !bytes.is_empty() && (bytes[0] & 0x80) != 0 {
        return parse_base256(bytes);
    }
    u64::from_str_radix(s, 8).ok()
}

fn parse_base256(bytes: &[u8]) -> Option<u64> {
    let mut v: u64 = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let b = if i == 0 { b & 0x7f } else { b };
        v = (v << 8) | u64::from(b);
    }
    Some(v)
}

/// Where single-file payload bytes live for [`SingleFileMountSource::open`].
enum SingleFileBackend {
    /// Host path (optional NamedTempFile keep-alive for materialised decompress).
    Path {
        path: PathBuf,
        _keep: Option<NamedTempFile>,
    },
    /// Seekable uncompressed body (gzip checkpoints, DecodedBody, …) — no host path.
    Body(Arc<dyn SeekableBody>),
}

/// Single decompressed file presented as a mount (Python SingleFileMountSource).
///
/// Prefer [`Self::from_seekable_body`] when the payload is already a
/// [`SeekableBody`] so factory can serve plain `.gz`/`.bz2`/… without spooling
/// to a NamedTempFile.
pub struct SingleFileMountSource {
    name: String,
    size: u64,
    backend: SingleFileBackend,
    mtime: f64,
    mode: u32,
    uid: u32,
    gid: u32,
}

impl SingleFileMountSource {
    /// Path-backed single file (existing factory materialize path).
    pub fn new(
        name: String,
        data_path: PathBuf,
        size: u64,
        materialised: Option<NamedTempFile>,
    ) -> io::Result<Self> {
        let meta = std::fs::metadata(&data_path)?;
        use std::os::unix::fs::MetadataExt;
        Ok(Self {
            name,
            size,
            backend: SingleFileBackend::Path {
                path: data_path,
                _keep: materialised,
            },
            mtime: meta.mtime() as f64,
            mode: ratarmount_core::S_IFREG | 0o644,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        })
    }

    /// Single file over a seekable uncompressed body (no host path / temp).
    ///
    /// Size comes from [`SeekableBody::size`]; mtime is 0 (virtual label).
    pub fn from_seekable_body(name: String, body: Arc<dyn SeekableBody>) -> io::Result<Self> {
        let size = body.size();
        Ok(Self {
            name,
            size,
            backend: SingleFileBackend::Body(body),
            mtime: 0.0,
            mode: ratarmount_core::S_IFREG | 0o644,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
        })
    }

    fn file_info(&self) -> FileInfo {
        FileInfo {
            size: self.size,
            mtime: self.mtime,
            mode: self.mode,
            linkname: String::new(),
            uid: self.uid,
            gid: self.gid,
            userdata: vec![UserData::Tar(SQLiteIndexedTarUserData {
                offset: 0,
                offsetheader: None,
                istar: false,
                issparse: false,
                isgenerated: false,
                recursiondepth: 0,
            })],
        }
    }
}

impl MountSource for SingleFileMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        let path = normpath(path);
        if path != "/" {
            return None;
        }
        let mut map = std::collections::BTreeMap::new();
        map.insert(self.name.clone(), self.file_info());
        Some(ListResult::Infos(map))
    }

    fn lookup(&self, path: &str, _file_version: i32) -> Option<FileInfo> {
        let path = normpath(path);
        if path == "/" {
            return Some(ratarmount_core::create_root_file_info());
        }
        if path == format!("/{}", self.name) || path.trim_start_matches('/') == self.name {
            return Some(self.file_info());
        }
        None
    }

    fn open(
        &self,
        file_info: &FileInfo,
        _buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        if file_info.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "is a directory",
            ));
        }
        match &self.backend {
            SingleFileBackend::Path { path, .. } => {
                let file = File::open(path)?;
                Ok(Box::new(StenciledFile::new(file, vec![(0, self.size)])))
            }
            SingleFileBackend::Body(body) => {
                let reader = body.open_reader()?;
                Ok(Box::new(StenciledFile::new(reader, vec![(0, self.size)])))
            }
        }
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    #[test]
    fn multi_version_count_updated_file() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let path = Path::new(&root).join("tests/updated-file.tar");
        if !path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("i.sqlite");
        let mut mat = None;
        let m = SqliteIndexedTar::create_index(
            &path,
            &path,
            Some(&idx),
            &OpenOptions::default(),
            "0.1.0",
            &mut mat,
        )
        .unwrap();
        assert_eq!(m.versions("/foo/fighter/ufo"), 3);
        let latest = m.lookup("/foo/fighter/ufo", 0).unwrap();
        let oldest = m.lookup("/foo/fighter/ufo", 1).unwrap();
        assert_ne!(latest.size, oldest.size);
    }

    #[test]
    fn index_simple_tar_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("t.tar");
        let src = dir.path().join("data");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("hello.txt"), b"hello world\n").unwrap();
        let status = Command::new("tar")
            .args(["-cf"])
            .arg(&tar_path)
            .arg("-C")
            .arg(&src)
            .arg("hello.txt")
            .status()
            .expect("tar");
        assert!(status.success());

        let idx_path = dir.path().join("t.tar.index.sqlite");
        let opts = OpenOptions::default();
        let mut mat = None;
        let m = SqliteIndexedTar::create_index(
            &tar_path,
            &tar_path,
            Some(&idx_path),
            &opts,
            "0.1.0",
            &mut mat,
        )
        .expect("create index");
        let fi = m.lookup("/hello.txt", 0).expect("lookup hello");
        assert_eq!(fi.size, 12);
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = String::new();
        r.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "hello world\n");
        // Plain text member is not a nested TAR.
        assert!(m.list_nested_tar_members().unwrap().is_empty());
    }

    /// Outer TAR with an inner TAR member: detect via metadata, open nested via stencil.
    #[test]
    fn nested_tar_member_index_and_open_via_stencil() {
        let dir = tempfile::tempdir().unwrap();

        // Build inner.tar containing nested-hello.txt
        let inner_src = dir.path().join("inner_src");
        std::fs::create_dir_all(&inner_src).unwrap();
        std::fs::write(inner_src.join("nested-hello.txt"), b"from nested tar\n").unwrap();
        let inner_tar = dir.path().join("inner.tar");
        let status = Command::new("tar")
            .args(["-cf"])
            .arg(&inner_tar)
            .arg("-C")
            .arg(&inner_src)
            .arg("nested-hello.txt")
            .status()
            .expect("tar inner");
        assert!(status.success(), "inner tar failed");

        // Build outer.tar containing inner.tar + a plain file
        let outer_src = dir.path().join("outer_src");
        std::fs::create_dir_all(&outer_src).unwrap();
        std::fs::copy(&inner_tar, outer_src.join("inner.tar")).unwrap();
        std::fs::write(outer_src.join("plain.txt"), b"plain\n").unwrap();
        let outer_tar = dir.path().join("outer.tar");
        let status = Command::new("tar")
            .args(["-cf"])
            .arg(&outer_tar)
            .arg("-C")
            .arg(&outer_src)
            .arg("inner.tar")
            .arg("plain.txt")
            .status()
            .expect("tar outer");
        assert!(status.success(), "outer tar failed");

        let idx_path = dir.path().join("outer.tar.index.sqlite");
        let opts = OpenOptions::default();
        let mut mat = None;
        let outer = SqliteIndexedTar::create_index(
            &outer_tar,
            &outer_tar,
            Some(&idx_path),
            &opts,
            "0.1.0",
            &mut mat,
        )
        .expect("index outer");

        // After flatten, newest version of /inner.tar is a generated directory (Python parity).
        // File version (raw nested archive bytes) is version 1 (oldest).
        let fi_dir = outer
            .lookup("/inner.tar", 0)
            .expect("lookup /inner.tar dir");
        assert_eq!(
            fi_dir.mode & ratarmount_core::S_IFMT,
            ratarmount_core::S_IFDIR,
            "flattened nested TAR becomes a directory"
        );
        let fi_file = outer
            .lookup("/inner.tar", 1)
            .expect("lookup /inner.tar file version");
        assert!(fi_file.size > 0);
        let ud = tar_userdata(&fi_file).expect("tar userdata");
        assert!(ud.istar, "nested TAR should set istar");

        let nested = outer.list_nested_tar_members().expect("list nested");
        assert_eq!(nested.len(), 1, "expected one nested tar: {nested:?}");
        assert_eq!(nested[0].path, "/inner.tar");
        assert_eq!(nested[0].size, fi_file.size);
        assert_eq!(nested[0].offset, ud.offset);

        // Open nested TAR via stencil without AutoMount; read inner content.
        let nested_ms = outer
            .open_nested_tar_from_index("inner.tar")
            .expect("open nested");
        let nested_fi = nested_ms
            .lookup("/nested-hello.txt", 0)
            .expect("lookup nested-hello.txt");
        assert_eq!(nested_fi.size, b"from nested tar\n".len() as u64);
        let mut r = nested_ms.open(&nested_fi, 0).unwrap();
        let mut buf = String::new();
        r.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "from nested tar\n");

        // Metadata key is present on the outer index.
        let meta = outer.index().metadata().unwrap();
        assert!(meta.contains_key(NESTED_TAR_MEMBERS_KEY));
        assert!(meta[NESTED_TAR_MEMBERS_KEY].contains("inner.tar"));
    }

    /// Flattened recursive rows: outer lookup/list/open of inner paths without AutoMount.
    #[test]
    fn nested_tar_flattened_path_rows_lookup_and_open() {
        let dir = tempfile::tempdir().unwrap();

        let inner_src = dir.path().join("inner_src");
        std::fs::create_dir_all(inner_src.join("subdir")).unwrap();
        std::fs::write(inner_src.join("payload.txt"), b"payload-bytes\n").unwrap();
        std::fs::write(inner_src.join("subdir").join("deep.txt"), b"deep\n").unwrap();
        let inner_tar = dir.path().join("inner.tar");
        let status = Command::new("tar")
            .args(["-cf"])
            .arg(&inner_tar)
            .arg("-C")
            .arg(&inner_src)
            .arg("payload.txt")
            .arg("subdir")
            .status()
            .expect("tar inner");
        assert!(status.success(), "inner tar failed");

        let outer_src = dir.path().join("outer_src");
        std::fs::create_dir_all(&outer_src).unwrap();
        std::fs::copy(&inner_tar, outer_src.join("inner.tar")).unwrap();
        std::fs::write(outer_src.join("plain.txt"), b"plain\n").unwrap();
        let outer_tar = dir.path().join("outer.tar");
        let status = Command::new("tar")
            .args(["-cf"])
            .arg(&outer_tar)
            .arg("-C")
            .arg(&outer_src)
            .arg("inner.tar")
            .arg("plain.txt")
            .status()
            .expect("tar outer");
        assert!(status.success(), "outer tar failed");

        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let mut mat = None;
        let outer =
            SqliteIndexedTar::create_index(&outer_tar, &outer_tar, None, &opts, "0.1.0", &mut mat)
                .expect("index outer");

        // Flattened path exists on the outer mount (no AutoMount).
        let fi = outer
            .lookup("/inner.tar/payload.txt", 0)
            .expect("lookup /inner.tar/payload.txt");
        assert_eq!(fi.size, b"payload-bytes\n".len() as u64);
        let ud = tar_userdata(&fi).expect("userdata");
        assert_eq!(ud.recursiondepth, 1);
        assert!(ud.offset > 0, "absolute outer offset");

        let mut r = outer.open(&fi, 0).expect("open flattened");
        let mut buf = String::new();
        r.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "payload-bytes\n");

        // Nested directory listing under the prefix.
        let listing = outer.list("/inner.tar").expect("list /inner.tar");
        match listing {
            ListResult::Infos(map) => {
                assert!(
                    map.contains_key("payload.txt"),
                    "keys: {:?}",
                    map.keys().collect::<Vec<_>>()
                );
                assert!(map.contains_key("subdir"), "keys: {:?}", map.keys());
            }
            other => panic!("unexpected list: {other:?}"),
        }

        let deep = outer
            .lookup("/inner.tar/subdir/deep.txt", 0)
            .expect("deep path");
        assert_eq!(deep.size, b"deep\n".len() as u64);
        let mut r = outer.open(&deep, 0).unwrap();
        let mut buf = String::new();
        r.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "deep\n");

        // Root still lists plain.txt and inner.tar.
        let root = outer.list("/").expect("list root");
        match root {
            ListResult::Infos(map) => {
                assert!(map.contains_key("inner.tar"));
                assert!(map.contains_key("plain.txt"));
            }
            other => panic!("unexpected root list: {other:?}"),
        }
    }

    #[test]
    fn nested_flatten_respects_size_limit_when_not_recursive() {
        // Synthetic oversized nested region should not be flattened without recursive.
        // Build a small real archive but exercise should_flatten_nested directly.
        assert!(should_flatten_nested(
            &OpenOptions::default(),
            NESTED_FLATTEN_MAX_BYTES,
            1
        ));
        assert!(!should_flatten_nested(
            &OpenOptions::default(),
            NESTED_FLATTEN_MAX_BYTES + 1,
            1
        ));
        // recursive: no size gate
        let rec = OpenOptions {
            recursive: true,
            ..OpenOptions::default()
        };
        assert!(should_flatten_nested(&rec, NESTED_FLATTEN_MAX_BYTES + 1, 1));
        // Explicit depth 0: still size-limited one layer (our cold-index default enhancement)
        let d0 = OpenOptions {
            recursion_depth: Some(0),
            ..OpenOptions::default()
        };
        assert!(should_flatten_nested(&d0, 1024, 1));
        assert!(!should_flatten_nested(&d0, 1024, 2));
        // recursion_depth 1 allows depth-1 content always
        let d1 = OpenOptions {
            recursion_depth: Some(1),
            ..OpenOptions::default()
        };
        assert!(should_flatten_nested(&d1, NESTED_FLATTEN_MAX_BYTES + 1, 1));
        assert!(!should_flatten_nested(&d1, 1024, 2));
    }

    #[test]
    fn join_path_prefix_helpers() {
        assert_eq!(
            join_path_prefix("/inner.tar", "payload.txt"),
            "/inner.tar/payload.txt"
        );
        assert_eq!(join_path_prefix("/inner.tar", "./a/b"), "/inner.tar/a/b");
        assert_eq!(join_path_prefix("", "x"), "x");
    }

    #[test]
    fn nested_tar_members_json_roundtrip() {
        let members = vec![
            NestedTarMember {
                path: "/a/b.tar".into(),
                offset: 1024,
                size: 4096,
            },
            NestedTarMember {
                path: r#"/weird"quote.tar"#.into(),
                offset: 0,
                size: 512,
            },
        ];
        let json = format_nested_tar_members_json(&members);
        let parsed = parse_nested_tar_members_json(&json);
        assert_eq!(parsed, members);
        assert!(parse_nested_tar_members_json("[]").is_empty());
        assert!(parse_nested_tar_members_json("").is_empty());
    }

    /// Minimal ustar with one regular file (for in-memory reader tests).
    fn synthetic_ustar(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut hdr = [0u8; 512];
        let name_bytes = name.as_bytes();
        assert!(name_bytes.len() < 100);
        hdr[..name_bytes.len()].copy_from_slice(name_bytes);
        // mode 0644 octal
        hdr[100..108].copy_from_slice(b"0000644\0");
        // uid/gid
        hdr[108..116].copy_from_slice(b"0000000\0");
        hdr[116..124].copy_from_slice(b"0000000\0");
        // size octal
        let size_str = format!("{:011o}", payload.len());
        hdr[124..135].copy_from_slice(size_str.as_bytes());
        hdr[135] = 0;
        // mtime
        hdr[136..148].copy_from_slice(b"00000000000\0");
        // checksum placeholder spaces
        hdr[148..156].copy_from_slice(b"        ");
        // typeflag regular
        hdr[156] = b'0';
        // magic / version
        hdr[257..265].copy_from_slice(b"ustar\0  ");
        // checksum
        let sum: u32 = hdr.iter().map(|&b| b as u32).sum();
        let cksum = format!("{sum:06o}\0 ");
        hdr[148..156].copy_from_slice(cksum.as_bytes());
        out.extend_from_slice(&hdr);
        out.extend_from_slice(payload);
        // pad payload to 512
        let pad = (512 - (payload.len() % 512)) % 512;
        out.extend(std::iter::repeat_n(0u8, pad));
        // two zero blocks
        out.extend(std::iter::repeat_n(0u8, 1024));
        out
    }

    #[test]
    fn open_from_cursor_index_list_read() {
        let bytes = synthetic_ustar("hello.txt", b"hello world\n");
        let cursor = std::io::Cursor::new(bytes);
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let m = SqliteIndexedTar::open_from_reader(
            cursor,
            Path::new("memory://synthetic.tar"),
            None,
            &opts,
            "0.1.0",
        )
        .expect("open_from_reader");
        let root = m.list("/").expect("list root");
        match root {
            ListResult::Infos(map) => {
                assert!(map.contains_key("hello.txt"), "keys: {:?}", map.keys());
            }
            other => panic!("unexpected list: {other:?}"),
        }
        let fi = m.lookup("/hello.txt", 0).expect("lookup");
        assert_eq!(fi.size, 12);
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = String::new();
        r.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "hello world\n");
    }

    #[test]
    fn open_from_tempfile_reader_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("t.tar");
        let src = dir.path().join("data");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("a.txt"), b"from-tempfile\n").unwrap();
        let status = Command::new("tar")
            .args(["-cf"])
            .arg(&tar_path)
            .arg("-C")
            .arg(&src)
            .arg("a.txt")
            .status()
            .expect("tar");
        assert!(status.success());

        let file = File::open(&tar_path).unwrap();
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let m = SqliteIndexedTar::create_index_from_reader(
            file,
            Path::new("label-only.tar"),
            None,
            &opts,
            "0.1.0",
        )
        .expect("create_index_from_reader");
        let fi = m.lookup("/a.txt", 0).expect("lookup");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = String::new();
        r.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "from-tempfile\n");
    }

    #[test]
    fn open_with_existing_index_from_reader() {
        let bytes = synthetic_ustar("x.bin", b"xyz");
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("i.sqlite");
        let opts = OpenOptions::default();
        let m1 = SqliteIndexedTar::create_index_from_reader(
            std::io::Cursor::new(bytes.clone()),
            Path::new("virt.tar"),
            Some(&idx),
            &opts,
            "0.1.0",
        )
        .expect("index");
        drop(m1);

        let m2 = SqliteIndexedTar::open_with_existing_index_from_reader(
            std::io::Cursor::new(bytes),
            Path::new("virt.tar"),
            &idx,
            opts,
        )
        .expect("reopen");
        let fi = m2.lookup("/x.bin", 0).expect("lookup");
        let mut r = m2.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"xyz");
    }

    #[test]
    fn sparse_fixtures_pax_and_gnu() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        for name in [
            "sparse.gnu.tar",
            "sparse.pax.sparse-0.0.tar",
            "sparse.pax.sparse-0.1.tar",
            "sparse.pax.sparse-1.0.tar",
        ] {
            let path = std::path::PathBuf::from(&root).join("tests").join(name);
            if !path.exists() {
                eprintln!("skip missing {name}");
                continue;
            }
            let dir = tempfile::tempdir().unwrap();
            let idx = dir.path().join("i.sqlite");
            let mut mat = None;
            let m = SqliteIndexedTar::create_index(
                &path,
                &path,
                Some(&idx),
                &OpenOptions::default(),
                "0.1.0",
                &mut mat,
            )
            .unwrap_or_else(|e| panic!("{name}: {e}"));
            // Must not expose PaxHeaders / GNUSparseFile placeholders as real content names.
            let root_list = m.list("/").expect("root");
            if let ListResult::Infos(map) = root_list {
                for k in map.keys() {
                    assert!(
                        !k.contains("PaxHeaders") && !k.starts_with("GNUSparseFile"),
                        "{name}: unexpected entry {k}"
                    );
                }
            }
            let fi = m
                .lookup("/sparse-512B", 0)
                .unwrap_or_else(|| panic!("{name}: missing sparse-512B"));
            assert_eq!(fi.size, 512, "{name} logical size");
            let ud = tar_userdata(&fi).unwrap();
            assert!(ud.issparse, "{name} should be sparse");
            let mut r = m.open(&fi, 0).unwrap();
            let mut buf = vec![0u8; 512];
            r.read_exact(&mut buf).unwrap();
            assert!(buf.iter().all(|&b| b == 0), "{name}: 512B should be holes");

            let fi2 = m.lookup("/sparse-513B", 0).expect("sparse-513B");
            assert_eq!(fi2.size, 513);
            let mut r = m.open(&fi2, 0).unwrap();
            let mut buf = vec![0u8; 513];
            r.read_exact(&mut buf).unwrap();
            assert!(buf[..512].iter().all(|&b| b == 0));
            // one data byte at offset 512
            assert_ne!(buf[512], 0, "{name}: expected data byte at 512");
        }
    }

    #[test]
    fn index_gnu_sparse_tar() {
        // GNU tar --sparse stores typeflag 'S' members with hole maps.
        let dir = tempfile::tempdir().unwrap();
        let sparse_path = dir.path().join("holey.bin");
        // 1 MiB hole + 8 bytes data + 1 MiB hole → logical ~2MiB+8, tiny on disk.
        let status = Command::new("truncate")
            .args(["-s", "1048576"])
            .arg(&sparse_path)
            .status();
        if status.map(|s| !s.success()).unwrap_or(true) {
            eprintln!("skip: truncate not available");
            return;
        }
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&sparse_path)
                .unwrap();
            f.write_all(b"SPARSE!!").unwrap();
        }
        let status = Command::new("truncate")
            .args(["-s", "2097160"]) // 2*1MiB + 8
            .arg(&sparse_path)
            .status()
            .expect("truncate grow");
        assert!(status.success());

        let tar_path = dir.path().join("sparse.tar");
        let status = Command::new("tar")
            .args(["--sparse", "-cf"])
            .arg(&tar_path)
            .arg("-C")
            .arg(dir.path())
            .arg("holey.bin")
            .status()
            .expect("tar --sparse");
        if !status.success() {
            eprintln!("skip: tar --sparse failed");
            return;
        }

        let idx_path = dir.path().join("sparse.tar.index.sqlite");
        let opts = OpenOptions::default();
        let mut mat = None;
        let m = SqliteIndexedTar::create_index(
            &tar_path,
            &tar_path,
            Some(&idx_path),
            &opts,
            "0.1.0",
            &mut mat,
        )
        .expect("create index");
        let fi = m.lookup("/holey.bin", 0).expect("lookup sparse");
        assert!(
            fi.size >= 2_097_160,
            "expected logical sparse size, got {}",
            fi.size
        );
        let ud = tar_userdata(&fi).expect("userdata");
        // If tar used sparse format, issparse should be set; some tars may store non-sparse.
        let mut r = m.open(&fi, 0).unwrap();
        r.seek(SeekFrom::Start(1_048_576)).unwrap();
        let mut magic = [0u8; 8];
        r.read_exact(&mut magic).unwrap();
        assert_eq!(&magic, b"SPARSE!!", "data at hole boundary");
        if ud.issparse {
            r.seek(SeekFrom::Start(0)).unwrap();
            let mut z = [0u8; 16];
            r.read_exact(&mut z).unwrap();
            assert!(z.iter().all(|&b| b == 0), "leading hole should be zeros");
        }
    }

    fn py_test_root() -> PathBuf {
        PathBuf::from(
            std::env::var("RATARMOUNT_PY_ROOT")
                .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into()),
        )
    }

    fn open_fixture(name: &str, gnu: Option<bool>) -> Option<SqliteIndexedTar> {
        let path = py_test_root().join("tests").join(name);
        if !path.exists() {
            eprintln!("skip missing fixture {name}");
            return None;
        }
        let opts = OpenOptions {
            gnu_incremental: gnu,
            ..OpenOptions::default()
        };
        let mut mat = None;
        Some(
            SqliteIndexedTar::create_index(&path, &path, None, &opts, "0.1.0", &mut mat)
                .unwrap_or_else(|e| panic!("{name}: {e}")),
        )
    }

    #[test]
    fn gnu_incremental_detect_dumpdir_strips_prefix() {
        // incremental-backup.level.0.tar has typeflag 'D' → auto-detect strips octal prefixes.
        let Some(m) = open_fixture("incremental-backup.level.0.tar", None) else {
            return;
        };
        let meta = m.index().metadata().unwrap();
        assert_eq!(
            meta.get("isGnuIncremental").map(String::as_str),
            Some("1"),
            "metadata isGnuIncremental"
        );

        let root = m.list("/").expect("root list");
        if let ListResult::Infos(map) = root {
            assert!(
                map.contains_key("foo"),
                "dir foo from dumpdir: {:?}",
                map.keys()
            );
            assert!(
                map.contains_key("root-file.txt"),
                "root-file.txt: {:?}",
                map.keys()
            );
            assert!(
                !map.keys().any(|k| k.chars().all(|c| c.is_ascii_digit())),
                "octal timestamp dirs should be stripped: {:?}",
                map.keys()
            );
            let foo = map.get("foo").unwrap();
            assert_eq!(
                foo.mode & ratarmount_core::S_IFMT,
                ratarmount_core::S_IFDIR,
                "lookup /foo is directory"
            );
            assert_eq!(foo.size, 0);
        } else {
            panic!("expected Infos");
        }

        // Dumpdir also creates a regular-file version (size > 0).
        assert_eq!(m.versions("/foo"), 2);
        let dump_meta = m.lookup("/foo", 1).expect("older dumpdir version");
        assert_eq!(
            dump_meta.mode & ratarmount_core::S_IFMT,
            ratarmount_core::S_IFREG
        );
        assert!(dump_meta.size > 0);

        for child in ["1", "2", "3"] {
            let fi = m
                .lookup(&format!("/foo/{child}"), 0)
                .unwrap_or_else(|| panic!("missing /foo/{child}"));
            assert!(fi.size > 0);
        }

        let fi = m.lookup("/root-file.txt", 0).expect("root-file.txt");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = String::new();
        r.read_to_string(&mut buf).unwrap();
        assert!(!buf.is_empty());
    }

    #[test]
    fn gnu_incremental_force_strips_single_file() {
        // No typeflag D — only forced gnu_incremental=Some(true) strips the prefix.
        let Some(m) = open_fixture("single-file-incremental.tar", Some(true)) else {
            return;
        };
        let meta = m.index().metadata().unwrap();
        assert_eq!(meta.get("isGnuIncremental").map(String::as_str), Some("1"));

        assert!(m.lookup("/foo", 0).is_some(), "stripped path /foo");
        assert!(
            m.lookup("/14130613451/foo", 0).is_none(),
            "prefixed path should not exist when forced"
        );
        let fi = m.lookup("/foo", 0).unwrap();
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"bar\n");
    }

    #[test]
    fn gnu_incremental_off_keeps_prefix_without_dumpdir() {
        let Some(m) = open_fixture("single-file-incremental.tar", Some(false)) else {
            return;
        };
        let meta = m.index().metadata().unwrap();
        assert_eq!(meta.get("isGnuIncremental").map(String::as_str), Some("0"));
        assert!(m.lookup("/14130613451/foo", 0).is_some());
        assert!(m.lookup("/foo", 0).is_none());
    }

    #[test]
    fn gnu_incremental_detect_without_dumpdir_keeps_prefix() {
        // Auto-detect finds no 'D' → leave names as tarfile-joined prefix/name.
        let Some(m) = open_fixture("single-file-incremental.tar", None) else {
            return;
        };
        let meta = m.index().metadata().unwrap();
        assert_eq!(meta.get("isGnuIncremental").map(String::as_str), Some("0"));
        assert!(m.lookup("/14130613451/foo", 0).is_some());
    }

    #[test]
    fn gnu_incremental_force_absolute_path() {
        let Some(m) = open_fixture("absolute-file-incremental.tar", Some(true)) else {
            return;
        };
        assert!(m.lookup("/tmp/foo", 0).is_some());
        assert!(m.lookup("/14130612002/tmp/foo", 0).is_none());
    }

    #[test]
    fn gnu_incremental_mockup_does_not_strip_without_raw_prefix() {
        // Mockup stores the timestamp in the name field with empty ustar prefix → do not strip.
        let Some(m) = open_fixture("single-file-incremental-mockup.tar", Some(true)) else {
            return;
        };
        assert!(
            m.lookup("/14130613451/foo", 0).is_some(),
            "mockup must keep embedded prefix path"
        );
        assert!(m.lookup("/foo", 0).is_none());
    }

    #[test]
    fn gnu_incremental_level1_moved_file() {
        let Some(m) = open_fixture("incremental-backup.level.1.tar", None) else {
            return;
        };
        assert_eq!(
            m.index()
                .metadata()
                .unwrap()
                .get("isGnuIncremental")
                .map(String::as_str),
            Some("1")
        );
        assert!(m.lookup("/foo/3", 0).is_some());
        assert!(m.lookup("/foo/moved", 0).is_some());
        let fi = m.lookup("/foo", 0).expect("foo dir");
        assert_eq!(fi.mode & ratarmount_core::S_IFMT, ratarmount_core::S_IFDIR);
    }

    #[test]
    fn fix_incremental_name_helpers() {
        let mut header = [0u8; 512];
        let prefix = b"14130613451";
        header[345..345 + prefix.len()].copy_from_slice(prefix);
        // second timestamp + NULs already zero
        assert_eq!(
            fix_incremental_backup_name_prefixes("14130613451/foo", &header),
            "foo"
        );
        assert_eq!(
            fix_incremental_backup_name_prefixes("14130613451//tmp/foo", &header),
            "/tmp/foo"
        );
        // non-octal first component
        assert_eq!(
            fix_incremental_backup_name_prefixes("notoctal/foo", &header),
            "notoctal/foo"
        );
        // mismatch vs raw prefix
        assert_eq!(
            fix_incremental_backup_name_prefixes("99999999999/foo", &header),
            "99999999999/foo"
        );
        // empty raw prefix (mockup style)
        let empty = [0u8; 512];
        assert_eq!(
            fix_incremental_backup_name_prefixes("14130613451/foo", &empty),
            "14130613451/foo"
        );
    }

    #[test]
    fn parse_dumpdir_entries_y_n_d() {
        // Fixture-style: Y1\0Y2\0Y3\0\0 and mixed status codes.
        let payload = b"Y1\0Nunchanged\0Dsubdir\0Y3\0\0";
        let entries = parse_dumpdir_entries(payload);
        assert_eq!(
            entries,
            vec![
                (b'Y', "1".into()),
                (b'N', "unchanged".into()),
                (b'D', "subdir".into()),
                (b'Y', "3".into()),
            ]
        );
        let present = dumpdir_present_names(&entries);
        assert!(present.contains("1"));
        assert!(present.contains("unchanged"));
        assert!(present.contains("subdir"));
        assert!(present.contains("3"));
        assert!(!present.contains("missing"));
    }

    /// Regression: sparse map offsets / realsize above 8 GiB must stay u64 and must not
    /// materialize an 8+ GiB buffer (holes are Zero segments; data is seeked).
    #[test]
    fn sparse_map_offset_above_8gib() {
        const NINE_GIB: u64 = 9 * 1024 * 1024 * 1024;
        let map = vec![(NINE_GIB, 4u64)];
        let logical = NINE_GIB + 4;
        let segments = segments_from_map(&map, /*tar_cursor=*/ 0, logical).expect("segments");
        assert_eq!(segments.len(), 2);
        match &segments[0] {
            FileSegment::Zero { len } => assert_eq!(*len, NINE_GIB, "leading hole"),
            other => panic!("expected Zero hole, got {other:?}"),
        }
        match &segments[1] {
            FileSegment::Data { file_offset, len } => {
                assert_eq!(*file_offset, 0);
                assert_eq!(*len, 4);
            }
            other => panic!("expected Data, got {other:?}"),
        }

        // Pax 0.1 map string with large offsets parses as u64 pairs.
        let mut pax = PaxParsed::empty();
        pax.map.insert(
            "GNU.sparse.map".into(),
            format!("{NINE_GIB},4,{},8", NINE_GIB + 100),
        );
        let from_pax = sparse_map_from_pax(&pax);
        assert_eq!(from_pax, vec![(NINE_GIB, 4), (NINE_GIB + 100, 8)]);

        // Sparse 1.0 textual map with large offsets.
        let map_text = format!("1\n{NINE_GIB}\n4\n");
        let map_text_len = map_text.len() as u64;
        let mut map_buf = map_text.into_bytes();
        let pad = (512 - (map_buf.len() % 512)) % 512;
        map_buf.extend(std::iter::repeat_n(0u8, pad));
        map_buf.extend_from_slice(b"DATA");
        let (m1, content_off) =
            parse_sparse_1_0_map(&mut std::io::Cursor::new(map_buf), 0).expect("1.0 map");
        assert_eq!(m1, vec![(NINE_GIB, 4)]);
        assert_eq!(content_off, pad512(map_text_len));

        // Read far extent via SegmentedFile without allocating 9 GiB.
        let backing = b"ABCD";
        let segs = segments_from_map(&map, 0, logical).unwrap();
        let mut r = SegmentedFile::new(std::io::Cursor::new(backing.to_vec()), segs);
        r.seek(SeekFrom::Start(NINE_GIB)).unwrap();
        let mut buf = [0u8; 4];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"ABCD");
        // Hole byte at start is zero without materializing the hole.
        r.seek(SeekFrom::Start(0)).unwrap();
        let mut z = [0u8; 1];
        r.read_exact(&mut z).unwrap();
        assert_eq!(z[0], 0);
    }

    /// Handcrafted dual dumpdir: first lists 1,2,3; second lists 3,moved → 1 and 2 deleted.
    ///
    /// Regression: GNU incremental dumpdir delete residual (B-10 / #73 MVP — single archive).
    #[test]
    fn gnu_incremental_dumpdir_deletes_omitted_names() {
        fn oct_field(n: u64, width: usize) -> Vec<u8> {
            let s = format!("{:0width$o}", n, width = width.saturating_sub(1));
            let mut v = s.into_bytes();
            v.push(0);
            v.resize(width, 0);
            v
        }
        fn gnu_header(name: &str, size: u64, typeflag: u8) -> [u8; 512] {
            let mut h = [0u8; 512];
            let nb = name.as_bytes();
            assert!(nb.len() < 100, "name too long for ustar name field");
            h[..nb.len()].copy_from_slice(nb);
            h[100..108].copy_from_slice(&oct_field(0o700, 8));
            h[108..116].copy_from_slice(&oct_field(0, 8));
            h[116..124].copy_from_slice(&oct_field(0, 8));
            h[124..136].copy_from_slice(&oct_field(size, 12));
            h[136..148].copy_from_slice(&oct_field(0, 12));
            h[156] = typeflag;
            // GNU tar magic
            h[257..265].copy_from_slice(b"ustar  \0");
            h[148..156].copy_from_slice(b"        ");
            let csum: u32 = h.iter().map(|&b| b as u32).sum();
            let cs = format!("{csum:06o}\0 ");
            h[148..156].copy_from_slice(cs.as_bytes());
            h
        }
        fn pad_payload(p: &[u8]) -> Vec<u8> {
            let mut v = p.to_vec();
            let n = (512 - (v.len() % 512)) % 512;
            v.extend(std::iter::repeat_n(0u8, n));
            v
        }
        fn append_member(out: &mut Vec<u8>, name: &str, typeflag: u8, payload: &[u8]) {
            out.extend_from_slice(&gnu_header(name, payload.len() as u64, typeflag));
            out.extend(pad_payload(payload));
        }

        let mut tar = Vec::new();
        // Snapshot A
        append_member(&mut tar, "foo/", b'D', b"Y1\0Y2\0Y3\0\0");
        append_member(&mut tar, "foo/1", b'0', b"one\n");
        append_member(&mut tar, "foo/2", b'0', b"two\n");
        append_member(&mut tar, "foo/3", b'0', b"three\n");
        // Snapshot B — 1 and 2 gone from dumpdir; 3 updated; moved added
        append_member(&mut tar, "foo/", b'D', b"Y3\0Ymoved\0\0");
        append_member(&mut tar, "foo/3", b'0', b"THREE\n");
        append_member(&mut tar, "foo/moved", b'0', b"mv\n");
        tar.extend(std::iter::repeat_n(0u8, 1024));

        let m = SqliteIndexedTar::create_index_from_reader(
            std::io::Cursor::new(tar),
            Path::new("incremental-deletes.tar"),
            None,
            &OpenOptions::default(),
            "0.1.0",
        )
        .expect("index dual-dumpdir tar");

        assert_eq!(
            m.index()
                .metadata()
                .unwrap()
                .get("isGnuIncremental")
                .map(String::as_str),
            Some("1")
        );

        // Deleted names must not appear as live children.
        assert!(
            m.lookup("/foo/1", 0).is_none(),
            "foo/1 should be dumpdir-deleted"
        );
        assert!(
            m.lookup("/foo/2", 0).is_none(),
            "foo/2 should be dumpdir-deleted"
        );
        assert_eq!(m.versions("/foo/1"), 0);
        assert_eq!(m.versions("/foo/2"), 0);

        let fi3 = m.lookup("/foo/3", 0).expect("foo/3 still live");
        let mut r = m.open(&fi3, 0).unwrap();
        let mut buf = String::new();
        r.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "THREE\n");

        let fim = m.lookup("/foo/moved", 0).expect("foo/moved");
        let mut r = m.open(&fim, 0).unwrap();
        let mut buf = String::new();
        r.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "mv\n");

        let ListResult::Infos(map) = m.list("/foo").expect("list /foo") else {
            panic!("expected Infos");
        };
        assert!(
            !map.contains_key("1") && !map.contains_key("2"),
            "deleted names must be omitted from list: {:?}",
            map.keys().collect::<Vec<_>>()
        );
        assert!(map.contains_key("3"), "3 present: {:?}", map.keys());
        assert!(map.contains_key("moved"), "moved present: {:?}", map.keys());
    }

    /// After `--hashes sha256` fill, MountSource xattrs expose `user.hash.sha256` (Python parity).
    #[test]
    fn get_xattr_user_hash_after_fill() {
        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("t.tar");
        let src = dir.path().join("data");
        std::fs::create_dir_all(&src).unwrap();
        let content = b"hello world\n";
        std::fs::write(src.join("hello.txt"), content).unwrap();
        let status = Command::new("tar")
            .args(["-cf"])
            .arg(&tar_path)
            .arg("-C")
            .arg(&src)
            .arg("hello.txt")
            .status()
            .expect("tar");
        assert!(status.success());

        let idx_path = dir.path().join("t.tar.index.sqlite");
        {
            let opts = OpenOptions::default();
            let mut mat = None;
            let _m = SqliteIndexedTar::create_index(
                &tar_path,
                &tar_path,
                Some(&idx_path),
                &opts,
                "0.1.0",
                &mut mat,
            )
            .expect("create index");
        }

        // Same path as CLI `--hashes sha256`: open index writable and fill.
        {
            let idx = ratarmount_index::SqliteIndex::open_writable(&idx_path).unwrap();
            ratarmount_index::fill_content_hashes(
                &idx,
                &tar_path,
                &["sha256".into(), "crc32".into()],
            )
            .unwrap();
        }

        let mut mat = None;
        let m = SqliteIndexedTar::open_with_existing_index(
            &tar_path,
            &tar_path,
            &idx_path,
            OpenOptions::default(),
            &mut mat,
        )
        .expect("reopen with index");

        let fi = m.lookup("/hello.txt", 0).expect("lookup hello.txt");
        let mut keys = m.list_xattr(&fi);
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "user.hash.crc32".to_string(),
                "user.hash.sha256".to_string()
            ]
        );

        let sha = m
            .get_xattr(&fi, "user.hash.sha256")
            .expect("user.hash.sha256 present");
        assert_eq!(
            sha.as_slice(),
            b"a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447"
        );
        let crc = m
            .get_xattr(&fi, "user.hash.crc32")
            .expect("user.hash.crc32 present");
        assert_eq!(crc.as_slice(), b"af083b2d");
        assert!(m.get_xattr(&fi, "user.hash.md5").is_none());
        assert!(m.get_xattr(&fi, "missing").is_none());
    }

    /// Regression: TAR PAX `LIBARCHIVE.xattr.*` / `SCHILY.xattr.*` → index + list_xattr/get_xattr.
    /// Vendor MPE/ZOS pax keys must not appear as filesystem xattrs (maintainer #145).
    #[test]
    fn pax_libarchive_schily_xattrs_synthetic() {
        // Build a pax-format TAR with both SCHILY (raw) and LIBARCHIVE (base64) xattrs.
        let tar_bytes = build_pax_xattr_tar(
            "foo.txt",
            b"hello\n",
            &[
                ("SCHILY.xattr.user.tags", b"mytag".as_slice()),
                // base64("mytag") without padding = bXl0YWc — overwrites SCHILY for same key
                ("LIBARCHIVE.xattr.user.tags", b"bXl0YWc"),
                ("SCHILY.xattr.user.comment", b"hello world"),
                // binary-ish SCHILY (NUL-terminated Haiku-style string)
                ("SCHILY.xattr.user.haiku.META:nick", b"Nick\0"),
                // percent-encoded key in LIBARCHIVE prefix
                (
                    "LIBARCHIVE.xattr.user.foo%2Fbar",
                    // base64("ab") = YWI
                    b"YWI",
                ),
                // Vendor keyword — must NOT become an xattr
                ("MPE.FILECODE", b"0"),
                ("ZOS.FILETAG", b"x"),
            ],
        );

        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("xattrs.tar");
        std::fs::write(&tar_path, &tar_bytes).unwrap();

        let mut mat = None;
        let m = SqliteIndexedTar::create_index(
            &tar_path,
            &tar_path,
            None,
            &OpenOptions::default(),
            "0.1.0",
            &mut mat,
        )
        .expect("index synthetic pax xattr tar");

        let fi = m.lookup("/foo.txt", 0).expect("lookup foo.txt");
        let mut keys = m.list_xattr(&fi);
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "user.comment".to_string(),
                "user.foo/bar".to_string(),
                "user.haiku.META:nick".to_string(),
                "user.tags".to_string(),
            ],
            "FS xattr keys only (no MPE/ZOS); LIBARCHIVE key percent-decoded"
        );

        // LIBARCHIVE overwrites SCHILY for user.tags → still "mytag"
        assert_eq!(
            m.get_xattr(&fi, "user.tags").as_deref(),
            Some(b"mytag".as_slice())
        );
        assert_eq!(
            m.get_xattr(&fi, "user.comment").as_deref(),
            Some(b"hello world".as_slice())
        );
        assert_eq!(
            m.get_xattr(&fi, "user.haiku.META:nick").as_deref(),
            Some(b"Nick\0".as_slice()),
            "SCHILY binary value preserved"
        );
        assert_eq!(
            m.get_xattr(&fi, "user.foo/bar").as_deref(),
            Some(b"ab".as_slice())
        );
        // Vendor keys must not be exposed under any name
        assert!(m.get_xattr(&fi, "MPE.FILECODE").is_none());
        assert!(m.get_xattr(&fi, "FILECODE").is_none());
        assert!(m.get_xattr(&fi, "user.pax.MPE.FILECODE").is_none());
    }

    /// Unit helpers: unpadded base64 + percent-decode match Python.
    #[test]
    fn pax_xattr_decode_helpers() {
        assert_eq!(
            decode_unpadded_base64("bXl0YWc").as_deref(),
            Some(b"mytag".as_slice())
        );
        assert_eq!(
            decode_unpadded_base64("bXl0YWc=").as_deref(),
            Some(b"mytag".as_slice())
        );
        assert_eq!(
            decode_unpadded_base64("TmljawA").as_deref(),
            Some(b"Nick\0".as_slice())
        );
        assert_eq!(percent_decode_str("user.foo%2Fbar"), "user.foo/bar");
        assert_eq!(percent_decode_str("a+b"), "a+b"); // not unquote_plus
        assert_eq!(percent_decode_str("plain"), "plain");

        // SCHILY then LIBARCHIVE overwrite (same as parse_pax_records order policy)
        let mut schily = std::collections::HashMap::new();
        schily.insert("user.tags".into(), b"from-schily".to_vec());
        let mut liba = std::collections::HashMap::new();
        liba.insert("user.tags".into(), b"ZnJvbS1saWJh".to_vec()); // base64("from-liba")
        let merged = fs_xattrs_from_pax_entries(schily, liba);
        assert_eq!(
            merged.get("user.tags").map(Vec::as_slice),
            Some(b"from-liba".as_slice())
        );
    }

    /// Optional Python fixture: file-with-attribute.bsd.tar.bz2 (bsdtar dual SCHILY+LIBARCHIVE).
    #[test]
    fn pax_xattrs_python_bsd_fixture_if_present() {
        let root = py_test_root();
        let bz2_path = root.join("tests/file-with-attribute.bsd.tar.bz2");
        if !bz2_path.exists() {
            eprintln!("skip: missing fixture {}", bz2_path.display());
            return;
        }
        // Decompress to plain TAR for create_index (no factory compress path here).
        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("file-with-attribute.bsd.tar");
        let status = Command::new("bunzip2")
            .args(["-k", "-c"])
            .arg(&bz2_path)
            .stdout(std::fs::File::create(&tar_path).unwrap())
            .status();
        let Ok(status) = status else {
            eprintln!("skip: bunzip2 not available");
            return;
        };
        if !status.success() {
            eprintln!("skip: bunzip2 failed on fixture");
            return;
        }

        let mut mat = None;
        let m = SqliteIndexedTar::create_index(
            &tar_path,
            &tar_path,
            None,
            &OpenOptions::default(),
            "0.1.0",
            &mut mat,
        )
        .expect("index bsd xattr fixture");

        let fi = m.lookup("/foo", 0).expect("lookup /foo");
        let keys = m.list_xattr(&fi);
        assert!(
            keys.iter().any(|k| k == "user.tags"),
            "expected user.tags, got {keys:?}"
        );
        assert_eq!(
            m.get_xattr(&fi, "user.tags").as_deref(),
            Some(b"mytag".as_slice())
        );

        let fi2 = m.lookup("/foo2", 0).expect("lookup /foo2");
        assert_eq!(
            m.get_xattr(&fi2, "user.tags").as_deref(),
            Some(b"mytag2".as_slice())
        );
    }

    /// Optional Python fixture: file-with-attribute.gnu.tar.bz2 (SCHILY only).
    #[test]
    fn pax_xattrs_python_gnu_fixture_if_present() {
        let root = py_test_root();
        let bz2_path = root.join("tests/file-with-attribute.gnu.tar.bz2");
        if !bz2_path.exists() {
            eprintln!("skip: missing fixture {}", bz2_path.display());
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("file-with-attribute.gnu.tar");
        let status = Command::new("bunzip2")
            .args(["-k", "-c"])
            .arg(&bz2_path)
            .stdout(std::fs::File::create(&tar_path).unwrap())
            .status();
        let Ok(status) = status else {
            eprintln!("skip: bunzip2 not available");
            return;
        };
        if !status.success() {
            eprintln!("skip: bunzip2 failed on fixture");
            return;
        }

        let mut mat = None;
        let m = SqliteIndexedTar::create_index(
            &tar_path,
            &tar_path,
            None,
            &OpenOptions::default(),
            "0.1.0",
            &mut mat,
        )
        .expect("index gnu xattr fixture");

        let fi = m.lookup("/foo", 0).expect("lookup /foo");
        assert_eq!(
            m.get_xattr(&fi, "user.tags").as_deref(),
            Some(b"mytag".as_slice())
        );
    }

    /// Build a minimal ustar+pax archive with the given extended header records.
    fn build_pax_xattr_tar(name: &str, payload: &[u8], pax_kvs: &[(&str, &[u8])]) -> Vec<u8> {
        fn pad512(mut b: Vec<u8>) -> Vec<u8> {
            let n = (512 - (b.len() % 512)) % 512;
            b.extend(std::iter::repeat_n(0u8, n));
            b
        }
        fn oct_field(n: u64, width: usize) -> Vec<u8> {
            let s = format!("{:0width$o}", n, width = width.saturating_sub(1));
            let mut v = s.into_bytes();
            v.push(0);
            v.resize(width, 0);
            v
        }
        fn ustar_header(name: &str, size: u64, typeflag: u8, mode: u32) -> [u8; 512] {
            let mut h = [0u8; 512];
            let nb = name.as_bytes();
            let nlen = nb.len().min(100);
            h[..nlen].copy_from_slice(&nb[..nlen]);
            h[100..108].copy_from_slice(&oct_field(mode as u64, 8));
            h[108..116].copy_from_slice(&oct_field(0, 8));
            h[116..124].copy_from_slice(&oct_field(0, 8));
            h[124..136].copy_from_slice(&oct_field(size, 12));
            h[136..148].copy_from_slice(&oct_field(0, 12));
            h[156] = typeflag;
            h[257..263].copy_from_slice(b"ustar\0");
            h[263..265].copy_from_slice(b"00");
            // checksum
            h[148..156].copy_from_slice(b"        ");
            let csum: u32 = h.iter().map(|&b| b as u32).sum();
            let cs = format!("{csum:06o}\0 ");
            h[148..156].copy_from_slice(cs.as_bytes());
            h
        }
        fn pax_record(key: &str, value: &[u8]) -> Vec<u8> {
            // LEN includes digits + space + key + '=' + value + '\n'
            for len_digits in 1..8 {
                let mut body = Vec::new();
                body.push(b' ');
                body.extend_from_slice(key.as_bytes());
                body.push(b'=');
                body.extend_from_slice(value);
                body.push(b'\n');
                let total = len_digits + body.len();
                if total.to_string().len() == len_digits {
                    let mut rec = total.to_string().into_bytes();
                    rec.extend(body);
                    return rec;
                }
            }
            panic!("pax record too long for {key}");
        }

        let mut pax_body = Vec::new();
        pax_body.extend(pax_record("path", name.as_bytes()));
        for (k, v) in pax_kvs {
            pax_body.extend(pax_record(k, v));
        }
        let pax_name = format!("PaxHeaders.0/{name}");
        let mut out = Vec::new();
        out.extend_from_slice(&ustar_header(&pax_name, pax_body.len() as u64, b'x', 0o644));
        out.extend(pad512(pax_body));
        out.extend_from_slice(&ustar_header(name, payload.len() as u64, b'0', 0o644));
        out.extend(pad512(payload.to_vec()));
        out.extend(std::iter::repeat_n(0u8, 1024));
        out
    }

    /// Single-file over `DecodedBody` (no host path): list, full read, mid-seek.
    #[test]
    fn single_file_from_seekable_body_list_read_seek() {
        let payload = b"abcdefghijklmnopqrstuvwxyz0123456789";
        let body: Arc<dyn SeekableBody> = ratarmount_compress::DecodedBody::from_bytes(
            Path::new("virtual.bin"),
            "test",
            payload.to_vec(),
        );
        let src = SingleFileMountSource::from_seekable_body("payload.bin".into(), body)
            .expect("from_seekable_body");

        // list root → single name
        let ListResult::Infos(map) = src.list("/").expect("list /") else {
            panic!("expected Infos");
        };
        assert_eq!(map.len(), 1);
        assert!(map.contains_key("payload.bin"));
        assert_eq!(map["payload.bin"].size, payload.len() as u64);

        let fi = src.lookup("/payload.bin", 0).expect("lookup");
        assert_eq!(fi.size, payload.len() as u64);
        assert_eq!(fi.mtime, 0.0);

        // full read
        let mut r = src.open(&fi, 0).unwrap();
        let mut full = Vec::new();
        r.read_to_end(&mut full).unwrap();
        assert_eq!(full.as_slice(), payload);

        // mid-seek: jump to offset 10, read rest
        let mut r = src.open(&fi, 0).unwrap();
        r.seek(SeekFrom::Start(10)).unwrap();
        let mut mid = Vec::new();
        r.read_to_end(&mut mid).unwrap();
        assert_eq!(mid.as_slice(), &payload[10..]);

        // seek-from-end + partial read
        let mut r = src.open(&fi, 0).unwrap();
        r.seek(SeekFrom::End(-4)).unwrap();
        let mut tail = [0u8; 4];
        r.read_exact(&mut tail).unwrap();
        assert_eq!(&tail, b"6789");
    }

    /// Path-backed constructor still works (regression).
    #[test]
    fn single_file_from_path_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("hello.txt");
        std::fs::write(&path, b"hello path\n").unwrap();
        let size = std::fs::metadata(&path).unwrap().len();
        let src = SingleFileMountSource::new("hello.txt".into(), path, size, None).unwrap();
        let fi = src.lookup("/hello.txt", 0).unwrap();
        assert_eq!(fi.size, 11);
        let mut r = src.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello path\n");
    }
}
