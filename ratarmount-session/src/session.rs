//! Blocking [`Session`] façade: `open`, listing, lookup, `Drop`.

#[cfg(test)]
use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ratarmount_core::{
    is_dir_mode, query_normpath, FileInfo, IndexBuildHooks, IndexBuildTick, MountSource,
    OpenOptions, UserData,
};
use ratarmount_index::{
    enforce_local_index_budget_if_path, find_existing_sibling_index,
    find_existing_user_cache_index, looks_like_url_archive, IndexError, IndexLocation, PagedDirent,
    SqliteIndex, MAX_DIR_PAGE,
};
use secrecy::ExposeSecret;

use crate::factory::{self, CompositingOptions, MountBundle};
use crate::resolve::resolve_index;
use crate::types::{
    DirCursor, DirEnt, DirPage, IndexPolicy, MemberExtent, OffsetCursor, OffsetPage, OpenRequest,
    Recreate, SourceSpec,
};
use crate::Error;

/// Default `list_dirents_page` limit when the caller passes `0`.
pub const DEFAULT_DIR_PAGE: u32 = 200;

#[cfg(test)]
thread_local! {
    #[allow(clippy::missing_const_for_thread_local)]
    static INJECT_CATALOG_OPEN_ERR: Cell<bool> = Cell::new(false);
}

/// Unlinks a Temp sidecar unless [`Self::disarm`] is called after a successful open.
struct TempSqliteGuard {
    path: Option<PathBuf>,
}

impl TempSqliteGuard {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempSqliteGuard {
    fn drop(&mut self) {
        if let Some(p) = self.path.take() {
            unlink_sqlite(&p);
        }
    }
}

/// Blocking, `Send + Sync` façade over an archive.
///
/// Embedders share a session with [`std::sync::Arc`]. This type does **not**
/// implement [`Clone`]. `Drop` is the close API (no `close(self)`).
pub struct Session {
    pub(crate) source: OpenedSource,
    pub(crate) catalog: Option<SqliteIndex>,
    pub(crate) loc: CatalogLoc,
    catalog_writes_allowed: bool,
}

pub(crate) enum OpenedSource {
    #[allow(dead_code)]
    Local(Arc<dyn MountSource>),
    Bundle(MountBundle),
}

impl OpenedSource {
    pub(crate) fn source(&self) -> &Arc<dyn MountSource> {
        match self {
            Self::Local(s) => s,
            Self::Bundle(b) => &b.source,
        }
    }

    fn source_mut(&mut self) -> &mut Arc<dyn MountSource> {
        match self {
            Self::Local(s) => s,
            Self::Bundle(b) => &mut b.source,
        }
    }
}

/// Path or memory flag for the 0.7.x sidecar used as the paging catalog.
pub(crate) enum CatalogLoc {
    None,
    Memory,
    Path(PathBuf),
    /// Unlink the sqlite (and journals) on [`Session`] drop. [`IndexPolicy::Temp`].
    Temp(PathBuf),
}

impl CatalogLoc {
    pub(crate) fn path(&self) -> Option<&Path> {
        match self {
            Self::Path(p) | Self::Temp(p) => Some(p.as_path()),
            Self::None | Self::Memory => None,
        }
    }
}

impl Session {
    /// Blocking. Embedders that need a job id run this on a worker thread.
    ///
    /// [`IndexPolicy::Sibling`] + unwritable parent → [`Error::SiblingNotWritable`]
    /// (never `:memory:`). [`IndexPolicy::UserCache`] stores `{hex}.sqlite` under
    /// `local-index-v1/` (never `meta-v3/`, never the flattened XDG parent).
    /// [`Recreate::Never`] never builds and never falls back to `:memory:`.
    pub fn open(req: OpenRequest) -> Result<Self, Error> {
        Self::open_with_job(req, &IndexBuildHooks::default())
    }

    /// Same as [`Self::open`] with progress/cancel hooks copied onto
    /// [`OpenOptions::index_build`]. Scan ticks only when a cold build starts.
    pub fn open_with_job(req: OpenRequest, hooks: &IndexBuildHooks) -> Result<Self, Error> {
        if hooks.is_cancelled() {
            return Err(Error::Cancelled);
        }

        let mut options = open_options(&req, hooks);
        let had_passwords = !options.passwords.is_empty();

        let recreate_flag = matches!(req.recreate, Recreate::Always);
        let archive_path = match &req.source {
            SourceSpec::Path(p) => p.clone(),
            SourceSpec::Url(url) => PathBuf::from(url),
        };
        let remote_archive =
            matches!(&req.source, SourceSpec::Url(_)) || looks_like_url_archive(&archive_path);

        if !remote_archive {
            ratarmount_compositing::recover_journal_at(
                &archive_path,
                None,
                ratarmount_compositing::Owner::Inode,
            )
            .map_err(|e| Error::Internal(e.to_string()))?;
        }

        let (loc, mut temp_guard, index_in_memory, index_file_path) = if req.index
            == IndexPolicy::Sibling
            && matches!(req.recreate, Recreate::Never)
        {
            match find_existing_sibling_index(&archive_path, &req.extra_dirs) {
                Some(p) => (CatalogLoc::Path(p.clone()), None, false, Some(p)),
                None => return Err(Error::NotFound),
            }
        } else if req.index == IndexPolicy::UserCache && matches!(req.recreate, Recreate::Never) {
            match find_existing_user_cache_index(&archive_path, &req.extra_dirs) {
                Some(p) => (CatalogLoc::Path(p.clone()), None, false, Some(p)),
                None => return Err(Error::NotFound),
            }
        } else if req.index == IndexPolicy::Sibling && remote_archive {
            match find_existing_sibling_index(&archive_path, &req.extra_dirs) {
                Some(p) => (CatalogLoc::Path(p.clone()), None, false, Some(p)),
                // Leave index_file_path unset so remote sibling GET can run.
                None => (CatalogLoc::None, None, false, None),
            }
        } else {
            let resolved = resolve_index(
                &archive_path,
                req.index,
                req.explicit_index.as_deref(),
                &req.extra_dirs,
                recreate_flag,
            )?;
            if matches!(req.index, IndexPolicy::Sibling) && resolved.is_memory() {
                return Err(Error::Internal(
                    "IndexPolicy::Sibling must not use :memory:".into(),
                ));
            }
            match (req.index, resolved) {
                (IndexPolicy::Temp, IndexLocation::Path(p)) => (
                    CatalogLoc::Temp(p.clone()),
                    Some(TempSqliteGuard::new(p.clone())),
                    false,
                    Some(p),
                ),
                (IndexPolicy::Temp, IndexLocation::Memory) => {
                    return Err(Error::Internal(
                        "IndexPolicy::Temp must not use :memory:".into(),
                    ));
                }
                (_, IndexLocation::Memory) => (CatalogLoc::Memory, None, true, None),
                (_, IndexLocation::Path(p)) => (CatalogLoc::Path(p.clone()), None, false, Some(p)),
            }
        };

        options.index_in_memory = index_in_memory;
        options.index_file_path = index_file_path;

        if matches!(req.recreate, Recreate::Never) {
            check_recreate_never(&archive_path, &loc)?;
        }

        // Skip tarstats catalog open when nobody is listening (Session::open).
        if hooks.on_progress.is_some() && will_cold_build(req.recreate, &archive_path, &loc) {
            let bytes_total_hint = match &req.source {
                SourceSpec::Path(p) => std::fs::metadata(p).ok().map(|m| m.len()),
                SourceSpec::Url(_) => None,
            };
            hooks.emit(IndexBuildTick {
                phase: IndexBuildTick::PHASE_SCAN,
                bytes_scanned: 0,
                bytes_total_hint,
                entries: 0,
            });
        }

        let comp = CompositingOptions {
            recursive: req.recursive,
            // Eager AutoMount indexes nested archives after outer `publish_tmp`.
            // A cancellable open must not replace dest and then fail as Cancelled.
            lazy: hooks.cancel.is_some(),
            file_versions: true,
            disable_union_mount: false,
            ..CompositingOptions::default()
        };
        let mut bundle = factory::build_mount_source_ex(
            std::slice::from_ref(&archive_path),
            &mut options,
            recreate_flag,
            comp,
        )
        .map_err(|e| map_factory_error(e, had_passwords, &archive_path))?;
        bundle.source =
            ratarmount_compositing::maybe_wrap_payload_cache(bundle.source, index_in_memory);
        let source = OpenedSource::Bundle(bundle);
        if let Some(p) = loc.path() {
            // WHY: allocate evicts before the sqlite body exists; trim after publish.
            enforce_local_index_budget_if_path(p);
        }

        let catalog = open_catalog_if_path(&loc)?;
        if let Some(g) = &mut temp_guard {
            g.disarm();
        }

        Ok(Self {
            source,
            catalog,
            loc,
            catalog_writes_allowed: options.write_index
                && !options.read_only_index
                && !remote_archive,
        })
    }

    pub fn list_dirents_page(
        &self,
        path: &str,
        cursor: DirCursor,
        limit: u32,
    ) -> Result<DirPage, Error> {
        let limit = if limit == 0 {
            DEFAULT_DIR_PAGE
        } else {
            limit.min(MAX_DIR_PAGE)
        };
        let after = match &cursor {
            DirCursor::Start => None,
            DirCursor::AfterName { name } => Some(name.as_str()),
        };
        let parent = page_parent_path(path);

        if let Some(ref cat) = self.catalog {
            let (rows, next_name, total_hint) = cat
                .list_dirents_page(path, after, limit)
                .map_err(|e| Error::Internal(e.to_string()))?;
            let entries: Vec<DirEnt> = rows
                .into_iter()
                .map(|r| dirent_from_paged(&parent, r))
                .collect();
            let next_cursor = next_name.map(|name| DirCursor::AfterName { name });
            return Ok(DirPage {
                path: parent,
                entries,
                next_cursor,
                total_hint,
            });
        }

        // No SQL catalog: page this directory only via MountSource::list_dirents.
        // Do not call list() (fat FileInfo map).
        let mut dents = self.source.source().list_dirents(path).unwrap_or_default();
        dents.sort_by(|a, b| a.name.cmp(&b.name));
        let after = after.unwrap_or("");
        let mut entries = Vec::new();
        for d in dents {
            if d.name.is_empty() || d.name.as_str() <= after {
                continue;
            }
            entries.push(DirEnt {
                path: join_archive_path(&parent, &d.name),
                name: d.name,
                is_dir: is_dir_mode(d.mode),
                size: d.size,
                mtime: None,
                mode: d.mode,
                archive_offset: None,
            });
            if entries.len() as u32 > limit {
                break;
            }
        }
        let next_cursor = if entries.len() as u32 > limit {
            entries.pop();
            entries.last().map(|e| DirCursor::AfterName {
                name: e.name.clone(),
            })
        } else {
            None
        };
        Ok(DirPage {
            path: parent,
            entries,
            next_cursor,
            total_hint: None,
        })
    }

    pub fn lookup(&self, path: &str) -> Result<Option<DirEnt>, Error> {
        Ok(self
            .source
            .source()
            .lookup(path, 0)
            .map(|fi| dirent_from_file_info(path, &fi)))
    }

    /// Return the actual data-byte extent of a local, top-level plain TAR file.
    ///
    /// Compressed/remote/split archives, recursive sessions, sparse/generated
    /// members, directories and links return `None`. Missing members return
    /// [`Error::NotFound`], as in [`Self::read_range`]. The caller must keep the
    /// backing archive unchanged for the lifetime of any mapping or read.
    pub fn member_extent(&self, path: &str) -> Result<Option<MemberExtent>, Error> {
        let path = query_normpath(path);
        let fi = self
            .mount_source()
            .lookup(&path, 0)
            .ok_or(Error::NotFound)?;
        let file = match &self.source {
            OpenedSource::Bundle(b) => b.plain_tar_file.as_ref(),
            OpenedSource::Local(_) => None,
        };
        let Some(file) = file else {
            return Ok(None);
        };
        if fi.mode & ratarmount_core::S_IFMT != ratarmount_core::S_IFREG || !fi.linkname.is_empty()
        {
            return Ok(None);
        }
        let Some(ud) = fi.userdata.iter().find_map(|data| match data {
            UserData::Tar(ud) => Some(ud),
            UserData::Other(_) => None,
        }) else {
            return Ok(None);
        };
        if ud.issparse || ud.isgenerated || ud.recursiondepth != 0 || ud.offsetheader.is_none() {
            return Ok(None);
        }
        let metadata = std::fs::metadata(file).map_err(crate::read::map_member_io)?;
        if !metadata.is_file()
            || ud
                .offset
                .checked_add(fi.size)
                .is_none_or(|end| end > metadata.len())
        {
            return Ok(None);
        }
        Ok(Some(MemberExtent {
            file: file.clone(),
            offset: ud.offset,
            len: fi.size,
        }))
    }

    /// Page newest-wins regular payload files by `(offsetheader, fullpath)`.
    ///
    /// Directories, symlinks, hardlinks, generated rows and dumpdir tombstones
    /// are omitted. Offsets are header hints in the logical (decompressed)
    /// stream, never byte extents. Unknown offsets sort last, by full path.
    /// The catalog must remain unchanged across pages. Requires a path-backed
    /// SQL catalog; unsupported sources return [`Error::UnsupportedFormat`].
    /// `0` uses the default page size; larger limits are capped at `MAX_DIR_PAGE`.
    pub fn iter_by_offset_page(
        &self,
        cursor: OffsetCursor,
        limit: u32,
    ) -> Result<OffsetPage, Error> {
        let cat = self.catalog().ok_or_else(|| {
            Error::UnsupportedFormat("offset paging requires a path-backed SQL catalog".into())
        })?;
        cat.prepare_offset_order_index(self.catalog_writes_allowed);
        let limit = if limit == 0 {
            DEFAULT_DIR_PAGE
        } else {
            limit.min(MAX_DIR_PAGE)
        };
        let after = match &cursor {
            OffsetCursor::Start => None,
            OffsetCursor::AfterOffset { offsetheader, path } => {
                Some((*offsetheader, path.as_str()))
            }
        };
        let mut rows = cat
            .list_visible_files_by_offset_page(after, limit + 1)
            .map_err(|e| Error::Internal(e.to_string()))?;
        let more = rows.len() > limit as usize;
        if more {
            rows.pop();
        }
        let entries: Vec<DirEnt> = rows
            .into_iter()
            .map(|row| {
                let path = join_archive_path(&row.path, &row.name);
                DirEnt {
                    path,
                    name: row.name,
                    is_dir: false,
                    size: row.cookie.size,
                    mtime: None,
                    mode: row.cookie.mode,
                    archive_offset: u64::try_from(row.cookie.offsetheader).ok(),
                }
            })
            .collect();
        let next = if more {
            entries.last().map(|entry| OffsetCursor::AfterOffset {
                offsetheader: entry.archive_offset.map(|offset| offset as i64),
                path: entry.path.clone(),
            })
        } else {
            None
        };
        Ok(OffsetPage { entries, next })
    }

    /// Start the HTTP Range server (CLI `--http`). Feature `http-export`.
    ///
    /// Default bind is [`crate::DEFAULT_HTTP_BIND`] (`127.0.0.1:20491`).
    /// Path-backed sidecars are served at `/.ratarmount-control/index.sqlite`.
    #[cfg(feature = "http-export")]
    pub fn start_http(&self, bind: std::net::SocketAddr) -> Result<crate::HttpHandle, Error> {
        crate::http::spawn(
            Arc::clone(self.source.source()),
            self.loc.path().map(Path::to_path_buf),
            bind,
        )
    }

    pub(crate) fn mount_source(&self) -> &dyn MountSource {
        self.source.source().as_ref()
    }

    pub(crate) fn catalog(&self) -> Option<&SqliteIndex> {
        self.catalog.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn stub() -> Self {
        Self {
            source: OpenedSource::Local(Arc::new(StubMount)),
            catalog: None,
            loc: CatalogLoc::None,
            catalog_writes_allowed: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn catalog_has_mem_index(&self) -> Option<bool> {
        self.catalog.as_ref().map(|c| c.has_mem_index())
    }

    #[cfg(test)]
    pub(crate) fn catalog_path(&self) -> Option<&Path> {
        self.loc.path()
    }

    #[cfg(test)]
    pub(crate) fn index_is_memory(&self) -> bool {
        matches!(self.loc, CatalogLoc::Memory)
    }

    #[cfg(test)]
    pub(crate) fn from_local_source(src: Arc<dyn MountSource>) -> Self {
        Self {
            source: OpenedSource::Local(src),
            catalog: None,
            loc: CatalogLoc::None,
            catalog_writes_allowed: false,
        }
    }

    /// Consume the session and return the sidecar location without unlinking
    /// [`IndexPolicy::Temp`] files ([`IndexJob::run`] keeps the published path).
    pub(crate) fn into_index_location(mut self) -> IndexLocation {
        let loc = std::mem::replace(&mut self.loc, CatalogLoc::None);
        match loc {
            CatalogLoc::Path(p) | CatalogLoc::Temp(p) => IndexLocation::Path(p),
            CatalogLoc::Memory | CatalogLoc::None => IndexLocation::Memory,
        }
    }
}

fn open_options(req: &OpenRequest, hooks: &IndexBuildHooks) -> OpenOptions {
    let (clear_index_cache, write_index, read_only_index) = match req.recreate {
        Recreate::Always => (true, true, false),
        Recreate::IfInvalid => (false, true, false),
        Recreate::Never => (false, false, true),
    };
    OpenOptions {
        recursive: req.recursive,
        recursion_depth: req.recursion_depth,
        parallelization: req.parallelization.clone(),
        passwords: req
            .password
            .as_ref()
            .map(|s| vec![s.expose_secret().clone()])
            .unwrap_or_default(),
        clear_index_cache,
        write_index,
        read_only_index,
        index_build: hooks.clone(),
        recover_journals: true,
        ..OpenOptions::default()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Some(src) = Arc::get_mut(self.source.source_mut()) {
            src.close();
        }
        if let Some(idx) = self.catalog.take() {
            drop(idx);
        }
        if let CatalogLoc::Temp(p) = &self.loc {
            unlink_sqlite(p);
        }
    }
}

#[cfg(test)]
struct StubMount;

#[cfg(test)]
impl MountSource for StubMount {
    fn list(&self, _path: &str) -> Option<ratarmount_core::ListResult> {
        None
    }
    fn lookup(&self, _path: &str, _file_version: i32) -> Option<FileInfo> {
        None
    }
    fn open(
        &self,
        _file_info: &FileInfo,
        _buffering: i32,
    ) -> std::io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        Err(std::io::Error::other("stub"))
    }
    fn is_immutable(&self) -> bool {
        true
    }
}

fn unlink_sqlite(path: &Path) {
    let _ = std::fs::remove_file(path);
    let p = path.as_os_str().to_string_lossy();
    let _ = std::fs::remove_file(format!("{p}-wal"));
    let _ = std::fs::remove_file(format!("{p}-shm"));
    let _ = std::fs::remove_file(format!("{p}-journal"));
}

/// `Recreate::Never`: missing sidecar → NotFound; tarstats mismatch → CorruptIndex.
/// Never `:memory:`.
fn check_recreate_never(archive: &Path, loc: &CatalogLoc) -> Result<(), Error> {
    match loc {
        CatalogLoc::Memory | CatalogLoc::None => Err(Error::NotFound),
        CatalogLoc::Path(p) | CatalogLoc::Temp(p) => {
            if !p.exists() {
                return Err(Error::NotFound);
            }
            let cat =
                SqliteIndex::open_lookup(p).map_err(|e| Error::CorruptIndex(e.to_string()))?;
            match cat.check_tarstats_matches_archive(archive) {
                Ok(()) => Ok(()),
                Err(IndexError::Mismatch(msg)) => Err(Error::CorruptIndex(msg)),
                Err(e) => Err(Error::CorruptIndex(e.to_string())),
            }
        }
    }
}

fn open_catalog_if_path(loc: &CatalogLoc) -> Result<Option<SqliteIndex>, Error> {
    #[cfg(test)]
    if INJECT_CATALOG_OPEN_ERR.with(|c| c.replace(false)) {
        return Err(Error::Internal("injected catalog open failure".into()));
    }
    let Some(p) = loc.path() else {
        return Ok(None);
    };
    if !p.exists() {
        return Ok(None);
    }
    // A read: it creates nothing beside the sidecar (see `open_lookup`).
    SqliteIndex::open_lookup(p)
        .map(Some)
        .map_err(|e| Error::Internal(e.to_string()))
}

fn will_cold_build(recreate: Recreate, archive: &Path, loc: &CatalogLoc) -> bool {
    match recreate {
        Recreate::Never => false,
        Recreate::Always => true,
        Recreate::IfInvalid => match loc.path() {
            None => true,
            Some(p) if !p.exists() => true,
            Some(p) => match SqliteIndex::open_lookup(p) {
                Ok(cat) => cat.check_tarstats_matches_archive(archive).is_err(),
                Err(_) => true,
            },
        },
    }
}

fn map_factory_error(msg: String, had_passwords: bool, archive: &Path) -> Error {
    let lower = msg.to_ascii_lowercase();
    if msg == IndexError::Cancelled.to_string() {
        Error::Cancelled
    } else if lower.starts_with("not found") || lower.contains("not found:") {
        Error::NotFound
    } else if lower.contains("permission denied") || lower.contains("eacces") {
        if had_passwords {
            Error::BadPassword
        } else {
            Error::NotWritable(archive.to_path_buf())
        }
    } else if had_passwords && lower.contains("password") {
        Error::BadPassword
    } else if lower.contains("corrupt") || lower.contains("mismatch") {
        Error::CorruptIndex(msg)
    } else if lower.contains("unsupported format") {
        Error::UnsupportedFormat(msg)
    } else {
        Error::Internal(msg)
    }
}

fn page_parent_path(path: &str) -> String {
    let p = query_normpath(path);
    if p == "/" {
        "/".into()
    } else {
        p.trim_end_matches('/').to_string()
    }
}

fn join_archive_path(parent: &str, name: &str) -> String {
    if parent.is_empty() || parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

fn dirent_from_paged(parent: &str, row: PagedDirent) -> DirEnt {
    DirEnt {
        path: join_archive_path(parent, &row.name),
        name: row.name,
        is_dir: is_dir_mode(row.mode),
        size: row.size,
        mtime: row.mtime.map(|m| m as i64),
        mode: row.mode,
        archive_offset: if row.offsetheader >= 0 {
            Some(row.offsetheader as u64)
        } else {
            None
        },
    }
}

fn dirent_from_file_info(path: &str, fi: &FileInfo) -> DirEnt {
    let full = page_parent_path(path);
    let name = if full == "/" {
        String::new()
    } else {
        full.rsplit('/').next().unwrap_or("").to_string()
    };
    DirEnt {
        name,
        path: full,
        is_dir: is_dir_mode(fi.mode),
        size: fi.size,
        mtime: Some(fi.mtime as i64),
        mode: fi.mode,
        archive_offset: archive_offset_from_info(fi),
    }
}

fn archive_offset_from_info(fi: &FileInfo) -> Option<u64> {
    fi.userdata.iter().rev().find_map(|ud| match ud {
        UserData::Tar(t) => t.offsetheader,
        UserData::Other(_) => None,
    })
}

#[cfg(test)]
mod tests;
