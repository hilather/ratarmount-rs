//! Blocking [`Session`] façade: `open`, listing, lookup, `Drop`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use ratarmount_core::{is_dir_mode, query_normpath, FileInfo, MountSource, OpenOptions, UserData};
use ratarmount_index::{
    resolve_index_location, IndexError, IndexLocation, PagedDirent, SqliteIndex, MAX_DIR_PAGE,
};
use secrecy::ExposeSecret;

use crate::factory::{self, CompositingOptions, MountBundle};
use crate::types::{DirCursor, DirEnt, DirPage, IndexPolicy, OpenRequest, Recreate, SourceSpec};
use crate::Error;

/// Default `list_dirents_page` limit when the caller passes `0`.
pub const DEFAULT_DIR_PAGE: u32 = 200;

static TEMP_INDEX_SEQ: AtomicU32 = AtomicU32::new(1);

/// Blocking, `Send + Sync` façade over an archive.
///
/// Embedders share a session with [`std::sync::Arc`]. This type does **not**
/// implement [`Clone`]. `Drop` is the close API (no `close(self)`).
pub struct Session {
    source: OpenedSource,
    catalog: Option<SqliteIndex>,
    loc: CatalogLoc,
}

enum OpenedSource {
    #[allow(dead_code)]
    Local(Arc<dyn MountSource>),
    Bundle(MountBundle),
}

impl OpenedSource {
    fn source(&self) -> &Arc<dyn MountSource> {
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
enum CatalogLoc {
    None,
    Memory,
    Path(PathBuf),
    /// Unlink the sqlite (and journals) on [`Session`] drop. [`IndexPolicy::Temp`].
    Temp(PathBuf),
}

impl CatalogLoc {
    fn path(&self) -> Option<&Path> {
        match self {
            Self::Path(p) | Self::Temp(p) => Some(p.as_path()),
            Self::None | Self::Memory => None,
        }
    }
}

impl Session {
    /// Blocking. Embedders that need a job id run this on a worker thread.
    ///
    /// `SiblingNotWritable` is **not** implemented here (G4 / PR6). Sibling /
    /// UserCache still go through factory `resolve_index_location` until then.
    /// [`Recreate::Never`] never falls back to `:memory:`.
    pub fn open(req: OpenRequest) -> Result<Self, Error> {
        let (clear_index_cache, write_index, read_only_index) = match req.recreate {
            Recreate::Always => (true, true, false),
            Recreate::IfInvalid => (false, true, false),
            Recreate::Never => (false, false, true),
        };
        let passwords = req
            .password
            .as_ref()
            .map(|s| vec![s.expose_secret().clone()])
            .unwrap_or_default();
        let had_passwords = !passwords.is_empty();

        let mut loc = CatalogLoc::None;
        let (index_in_memory, index_file_path, index_folders) = match &req.index {
            IndexPolicy::Memory => {
                loc = CatalogLoc::Memory;
                (true, None, Vec::new())
            }
            IndexPolicy::Explicit => {
                let p = req
                    .explicit_index
                    .clone()
                    .ok_or_else(|| Error::Internal("explicit_index required".into()))?;
                loc = CatalogLoc::Path(p.clone());
                (false, Some(p), Vec::new())
            }
            IndexPolicy::Temp => {
                let p = temp_index_path();
                if let Some(parent) = p.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| Error::Internal(e.to_string()))?;
                }
                loc = CatalogLoc::Temp(p.clone());
                (false, Some(p), Vec::new())
            }
            // Sibling / UserCache / CliCompat: factory `resolve_index_location`
            // until PR6 (`resolve_index` + `SiblingNotWritable`). Do not add a
            // Session-level `:memory:` fallback here.
            IndexPolicy::Sibling | IndexPolicy::UserCache | IndexPolicy::CliCompat => {
                (false, None, req.extra_dirs.clone())
            }
        };

        let options = OpenOptions {
            recursive: req.recursive,
            recursion_depth: req.recursion_depth,
            passwords,
            clear_index_cache,
            write_index,
            read_only_index,
            index_in_memory,
            index_file_path,
            index_folders,
            ..OpenOptions::default()
        };

        let recreate_flag = matches!(req.recreate, Recreate::Always);
        let archive_path = match &req.source {
            SourceSpec::Path(p) => p.clone(),
            SourceSpec::Url(url) => PathBuf::from(url),
        };
        if matches!(
            req.index,
            IndexPolicy::Sibling | IndexPolicy::UserCache | IndexPolicy::CliCompat
        ) {
            loc = loc_from_resolve(&archive_path, &options, recreate_flag);
        }
        if matches!(req.recreate, Recreate::Never) {
            check_recreate_never(&archive_path, &loc)?;
        }

        // Local paths still go through `open_path` inside `build_mount_source_ex`;
        // URLs use `open_remote_input`. Compositing: recursive from request,
        // lazy false, file_versions true (CLI default).
        let comp = CompositingOptions {
            recursive: req.recursive,
            lazy: false,
            file_versions: true,
            disable_union_mount: false,
            ..CompositingOptions::default()
        };
        let bundle = factory::build_mount_source_ex(
            std::slice::from_ref(&archive_path),
            &options,
            recreate_flag,
            comp,
        )
        .map_err(|e| map_factory_error(e, had_passwords))?;
        let source = OpenedSource::Bundle(bundle);

        let catalog = open_catalog_if_path(&loc)?;

        Ok(Self {
            source,
            catalog,
            loc,
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

    #[cfg(test)]
    pub(crate) fn stub() -> Self {
        Self {
            source: OpenedSource::Local(Arc::new(StubMount)),
            catalog: None,
            loc: CatalogLoc::None,
        }
    }

    #[cfg(test)]
    pub(crate) fn catalog_has_mem_index(&self) -> Option<bool> {
        self.catalog.as_ref().map(|c| c.has_mem_index())
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

fn temp_index_path() -> PathBuf {
    let seq = TEMP_INDEX_SEQ.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir()
        .join(format!("ratarmount-session-{}", std::process::id()))
        .join(format!("index-{seq}.sqlite"))
}

fn unlink_sqlite(path: &Path) {
    let _ = std::fs::remove_file(path);
    let p = path.as_os_str().to_string_lossy();
    let _ = std::fs::remove_file(format!("{p}-wal"));
    let _ = std::fs::remove_file(format!("{p}-shm"));
    let _ = std::fs::remove_file(format!("{p}-journal"));
}

fn loc_from_resolve(archive: &Path, options: &OpenOptions, recreate: bool) -> CatalogLoc {
    if options.index_in_memory {
        return CatalogLoc::Memory;
    }
    let explicit = options
        .index_file_path
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned());
    match resolve_index_location(
        archive,
        explicit.as_deref(),
        &options.index_folders,
        recreate || options.clear_index_cache,
    ) {
        IndexLocation::Memory => CatalogLoc::Memory,
        IndexLocation::Path(p) => CatalogLoc::Path(p),
    }
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
            let cat = SqliteIndex::open_catalog_read_only(p)
                .map_err(|e| Error::CorruptIndex(e.to_string()))?;
            match cat.check_tarstats_matches_archive(archive) {
                Ok(()) => Ok(()),
                Err(IndexError::Mismatch(msg)) => Err(Error::CorruptIndex(msg)),
                Err(e) => Err(Error::CorruptIndex(e.to_string())),
            }
        }
    }
}

fn open_catalog_if_path(loc: &CatalogLoc) -> Result<Option<SqliteIndex>, Error> {
    let Some(p) = loc.path() else {
        return Ok(None);
    };
    if !p.exists() {
        return Ok(None);
    }
    SqliteIndex::open_catalog_read_only(p)
        .map(Some)
        .map_err(|e| Error::Internal(e.to_string()))
}

fn map_factory_error(msg: String, had_passwords: bool) -> Error {
    let lower = msg.to_ascii_lowercase();
    if lower.contains("not found") {
        Error::NotFound
    } else if had_passwords && (lower.contains("permission denied") || lower.contains("password")) {
        Error::BadPassword
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
mod tests {
    use super::*;
    use crate::types::SourceSpec;
    use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};
    use std::io::Write;

    fn member_file<'a>(path: &'a str, bytes: &'a [u8]) -> UstarMember<'a> {
        UstarMember {
            path,
            payload: UstarPayload::File { bytes },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
        }
    }

    fn write_tar(path: &Path, members: &[UstarMember<'_>]) {
        let mut f = std::fs::File::create(path).unwrap();
        write_ustar_members(&mut f, members).unwrap();
        write_tar_eof(&mut f).unwrap();
        f.flush().unwrap();
    }

    fn open_tar(dir: &Path, name: &str, members: &[UstarMember<'_>]) -> Session {
        let tar = dir.join(name);
        write_tar(&tar, members);
        let idx = dir.join(format!("{name}.index.sqlite"));
        Session::open(OpenRequest {
            source: SourceSpec::Path(tar),
            index: IndexPolicy::Explicit,
            explicit_index: Some(idx),
            extra_dirs: Vec::new(),
            password: None,
            recursive: false,
            recursion_depth: None,
            recreate: Recreate::IfInvalid,
        })
        .expect("Session::open")
    }

    /// 1000 ustar members, page size 50 → 20 pages, no overlap/skip.
    #[test]
    fn list_dirents_page() {
        let dir = tempfile::tempdir().unwrap();
        let names: Vec<String> = (0..1000).map(|i| format!("f{i:04}.txt")).collect();
        let payload = b"x";
        let members: Vec<UstarMember<'_>> = names
            .iter()
            .map(|n| member_file(n.as_str(), payload))
            .collect();
        let session = open_tar(dir.path(), "page.tar", &members);

        let mut seen = Vec::new();
        let mut cursor = DirCursor::Start;
        let mut pages = 0u32;
        loop {
            let page = session.list_dirents_page("/", cursor, 50).expect("page");
            assert!(page.entries.len() <= 50);
            for e in &page.entries {
                assert!(!e.is_dir);
                assert!(e.path.starts_with('/'));
                assert!(!e.path.ends_with('/'));
                seen.push(e.name.clone());
            }
            pages += 1;
            match page.next_cursor {
                None => break,
                Some(next) => cursor = next,
            }
        }
        assert_eq!(pages, 20, "1000 / 50");
        assert_eq!(seen.len(), 1000);
        let mut uniq = seen.clone();
        uniq.sort();
        uniq.dedup();
        assert_eq!(uniq.len(), 1000, "no overlap");
        assert_eq!(seen, uniq, "name order");
        assert_eq!(seen.first().map(String::as_str), Some("f0000.txt"));
        assert_eq!(seen.last().map(String::as_str), Some("f0999.txt"));

        let last = session
            .list_dirents_page(
                "/",
                DirCursor::AfterName {
                    name: "f0999.txt".into(),
                },
                50,
            )
            .unwrap();
        assert!(last.entries.is_empty());
        assert!(last.next_cursor.is_none());
    }

    /// GNU incremental dumpdir tombstone is absent from page 1.
    #[test]
    fn list_dirents_page_dumpdir() {
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
            h[..nb.len()].copy_from_slice(nb);
            h[100..108].copy_from_slice(&oct_field(0o700, 8));
            h[108..116].copy_from_slice(&oct_field(0, 8));
            h[116..124].copy_from_slice(&oct_field(0, 8));
            h[124..136].copy_from_slice(&oct_field(size, 12));
            h[136..148].copy_from_slice(&oct_field(0, 12));
            h[156] = typeflag;
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
        append_member(&mut tar, "foo/", b'D', b"Y1\0Y2\0Y3\0\0");
        append_member(&mut tar, "foo/1", b'0', b"one\n");
        append_member(&mut tar, "foo/2", b'0', b"two\n");
        append_member(&mut tar, "foo/3", b'0', b"three\n");
        append_member(&mut tar, "foo/", b'D', b"Y3\0Ymoved\0\0");
        append_member(&mut tar, "foo/3", b'0', b"THREE\n");
        append_member(&mut tar, "foo/moved", b'0', b"mv\n");
        tar.extend(std::iter::repeat_n(0u8, 1024));

        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("inc.tar");
        std::fs::write(&tar_path, &tar).unwrap();
        let idx = dir.path().join("inc.tar.index.sqlite");
        let session = Session::open(OpenRequest {
            source: SourceSpec::Path(tar_path),
            index: IndexPolicy::Explicit,
            explicit_index: Some(idx),
            extra_dirs: Vec::new(),
            password: None,
            recursive: false,
            recursion_depth: None,
            recreate: Recreate::IfInvalid,
        })
        .expect("open dumpdir tar");

        let page = session
            .list_dirents_page("/foo", DirCursor::Start, 50)
            .expect("page 1");
        let names: Vec<&str> = page.entries.iter().map(|e| e.name.as_str()).collect();
        assert!(
            !names.contains(&"1") && !names.contains(&"2"),
            "dumpdir-deleted names must be absent: {names:?}"
        );
        assert!(names.contains(&"3"), "{names:?}");
        assert!(names.contains(&"moved"), "{names:?}");
    }

    /// Session::open of a tiny TAR emits one harness line; catalog has no MemIndex.
    ///
    /// libtest captures `println!`, so the line count is asserted on a child
    /// process of this test binary (`--nocapture`).
    #[test]
    fn catalog_open_silent() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"hi";
        let members = [member_file("a.txt", payload)];
        let tar = dir.path().join("tiny.tar");
        write_tar(&tar, &members);
        let idx = dir.path().join("tiny.tar.index.sqlite");
        let req = OpenRequest {
            source: SourceSpec::Path(tar),
            index: IndexPolicy::Explicit,
            explicit_index: Some(idx),
            extra_dirs: Vec::new(),
            password: None,
            recursive: false,
            recursion_depth: None,
            recreate: Recreate::IfInvalid,
        };
        if std::env::var_os("RATARMOUNT_CATALOG_OPEN_CHILD").is_some() {
            let session = Session::open(req).expect("open tiny tar");
            assert_eq!(
                session.catalog_has_mem_index(),
                Some(false),
                "catalog must not load a second MemIndex"
            );
            let hit = session.lookup("/a.txt").unwrap().expect("a.txt");
            assert_eq!(hit.name, "a.txt");
            assert_eq!(hit.size, 2);
            return;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .env("RATARMOUNT_CATALOG_OPEN_CHILD", "1")
            .args([
                "session::tests::catalog_open_silent",
                "--exact",
                "--nocapture",
            ])
            .output()
            .expect("spawn catalog_open_silent child");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "child failed: stdout={stdout} stderr={stderr}"
        );
        let n = stdout
            .matches("Successfully loaded offset dictionary")
            .count();
        assert_eq!(n, 1, "expected one harness line, got {n}: {stdout}");
    }
}
