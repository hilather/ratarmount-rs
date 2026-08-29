//! V-1 live `search_cheap` + overlay last-wins + SearchFn tests.

use std::io::{self, Cursor, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ratarmount_core::{
    format_cheap_hits_tsv, CheapDirent, CheapSearchHit, FileInfo, ListResult, MountSource,
};
use ratarmount_formats_tar::{
    write_tar_eof, write_ustar_members, SqliteIndexedTar, UstarMember, UstarPayload,
};
use ratarmount_formats_zip::ZipMountSource;
use ratarmount_index::{locate_pattern_matches, DEFAULT_SEARCH_LIMIT};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

use crate::control::{
    live_search_tsv, ControlFolderMountSource, ControlFolderOptions, CONTROL_DIR_PATH,
};
use crate::folder::FolderMountSource;
use crate::oci_whiteout::OciImageMountSource;
use crate::prefix::PrefixMountSource;
use crate::transform::TransformMountSource;
use crate::union::UnionMountSource;
use crate::versioning::FileVersionLayer;
use crate::write_overlay::WriteOverlay;
use crate::AutoMountLayer;

fn hit(path: &str, name: &str, size: i64, mtime: f64) -> CheapSearchHit {
    CheapSearchHit {
        path: path.into(),
        name: name.into(),
        size,
        mtime,
        offsetheader: Some(0),
    }
}

/// Catalog that implements `search_cheap` without FileInfo.
struct CheapBase {
    hits: Vec<CheapSearchHit>,
}

impl CheapBase {
    fn fits() -> Self {
        Self {
            hits: vec![
                hit("/a.fits", "a.fits", 4, 1.0),
                hit("/dir/b.fits", "b.fits", 5, 2.0),
                hit("/readme.txt", "readme.txt", 5, 3.0),
            ],
        }
    }

    /// Two GNU-incremental rows, same catalog path, different offsetheader.
    fn two_offsetheader() -> Self {
        Self {
            hits: vec![
                CheapSearchHit {
                    path: "/a.fits".into(),
                    name: "a.fits".into(),
                    size: 4,
                    mtime: 1.0,
                    offsetheader: Some(0),
                },
                CheapSearchHit {
                    path: "/a.fits".into(),
                    name: "a.fits".into(),
                    size: 8,
                    mtime: 2.0,
                    offsetheader: Some(512),
                },
            ],
        }
    }

    fn empty() -> Self {
        Self { hits: vec![] }
    }
}

impl MountSource for CheapBase {
    fn list(&self, _path: &str) -> Option<ListResult> {
        Some(ListResult::Names(
            self.hits.iter().map(|h| h.name.clone()).collect(),
        ))
    }
    fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
        let h = self.hits.iter().find(|h| h.path == path)?;
        Some(FileInfo {
            size: h.size as u64,
            mtime: h.mtime,
            mode: ratarmount_core::S_IFREG | 0o644,
            linkname: String::new(),
            uid: 0,
            gid: 0,
            userdata: vec![],
        })
    }
    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        if path != "/" {
            return Some(Vec::new());
        }
        Some(
            self.hits
                .iter()
                .map(|h| CheapDirent {
                    name: h.name.clone(),
                    mode: ratarmount_core::S_IFREG | 0o644,
                    size: h.size as u64,
                })
                .collect(),
        )
    }

    fn search_cheap(&self, pattern: &str) -> Option<Vec<CheapSearchHit>> {
        if pattern.starts_with("fts:") {
            return None;
        }
        Some(
            self.hits
                .iter()
                .filter(|h| locate_pattern_matches(pattern, &h.path, &h.name))
                .cloned()
                .collect(),
        )
    }
    fn open(&self, fi: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        // COW tests call ensure_modifiable, which copies the base body, then overwrite.
        Ok(Box::new(std::io::Cursor::new(vec![0u8; fi.size as usize])))
    }
    fn is_immutable(&self) -> bool {
        true
    }
}

/// Counts `search_cheap` so `fts:` never enters scan_glob.
struct SearchCheapSpy {
    inner: CheapBase,
    calls: AtomicUsize,
}

impl MountSource for SearchCheapSpy {
    fn list(&self, path: &str) -> Option<ListResult> {
        self.inner.list(path)
    }
    fn lookup(&self, path: &str, v: i32) -> Option<FileInfo> {
        self.inner.lookup(path, v)
    }
    fn search_cheap(&self, pattern: &str) -> Option<Vec<CheapSearchHit>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.inner.search_cheap(pattern)
    }
    fn open(&self, fi: &FileInfo, b: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        self.inner.open(fi, b)
    }
    fn is_immutable(&self) -> bool {
        true
    }
}

/// Counts `list()` / `lookup()` so Union locate stays FileInfo-free.
struct FileInfoSpy {
    inner: CheapBase,
    list_calls: AtomicUsize,
    lookup_calls: AtomicUsize,
}

impl MountSource for FileInfoSpy {
    fn list(&self, path: &str) -> Option<ListResult> {
        self.list_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.list(path)
    }
    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        self.inner.list_dirents(path)
    }
    fn lookup(&self, path: &str, v: i32) -> Option<FileInfo> {
        self.lookup_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.lookup(path, v)
    }
    fn search_cheap(&self, pattern: &str) -> Option<Vec<CheapSearchHit>> {
        self.inner.search_cheap(pattern)
    }
    fn open(&self, fi: &FileInfo, b: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        self.inner.open(fi, b)
    }
    fn is_immutable(&self) -> bool {
        true
    }
}

struct NoneBase;
impl MountSource for NoneBase {
    fn list(&self, _: &str) -> Option<ListResult> {
        Some(ListResult::Names(vec![]))
    }
    fn lookup(&self, _: &str, _: i32) -> Option<FileInfo> {
        None
    }
    fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        Err(io::Error::new(io::ErrorKind::NotFound, "none"))
    }
    fn is_immutable(&self) -> bool {
        true
    }
}

struct ListCallCounter {
    inner: Arc<dyn MountSource>,
    list_calls: AtomicUsize,
    dirent_calls: AtomicUsize,
    lookup_calls: AtomicUsize,
}

impl ListCallCounter {
    fn new(inner: Arc<dyn MountSource>) -> Self {
        Self {
            inner,
            list_calls: AtomicUsize::new(0),
            dirent_calls: AtomicUsize::new(0),
            lookup_calls: AtomicUsize::new(0),
        }
    }
}

impl MountSource for ListCallCounter {
    fn list(&self, path: &str) -> Option<ListResult> {
        self.list_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.list(path)
    }
    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        self.dirent_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.list_dirents(path)
    }
    fn lookup(&self, path: &str, v: i32) -> Option<FileInfo> {
        self.lookup_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.lookup(path, v)
    }
    fn search_cheap(&self, pattern: &str) -> Option<Vec<CheapSearchHit>> {
        self.inner.search_cheap(pattern)
    }
    fn open(&self, fi: &FileInfo, b: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        self.inner.open(fi, b)
    }
    fn is_immutable(&self) -> bool {
        self.inner.is_immutable()
    }
}

fn write_fits_zip(path: &std::path::Path) {
    write_zip(
        path,
        &[
            ("a.fits", b"fits".as_slice()),
            ("dir/b.fits", b"fits2".as_slice()),
            ("readme.txt", b"hello".as_slice()),
        ],
    );
}

fn write_zip(path: &std::path::Path, files: &[(&str, &[u8])]) {
    let file = std::fs::File::create(path).unwrap();
    let mut zw = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    for (name, bytes) in files {
        zw.start_file(*name, opts).unwrap();
        zw.write_all(bytes).unwrap();
    }
    zw.finish().unwrap();
}

fn write_fits_tar(path: &std::path::Path, files: &[(&str, &[u8])]) {
    let members: Vec<UstarMember<'_>> = files
        .iter()
        .map(|(p, bytes)| UstarMember {
            path: p,
            payload: UstarPayload::File { bytes },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
        })
        .collect();
    let mut buf = Vec::new();
    write_ustar_members(&mut buf, &members).expect("ustar");
    write_tar_eof(&mut buf).expect("eof");
    std::fs::write(path, buf).unwrap();
}

fn open_tar(path: &std::path::Path) -> SqliteIndexedTar {
    let opts = ratarmount_core::OpenOptions {
        index_in_memory: true,
        ..ratarmount_core::OpenOptions::default()
    };
    let bytes = std::fs::read(path).expect("read tar");
    SqliteIndexedTar::open_from_reader(Cursor::new(bytes), path, None, &opts, "test")
        .expect("open tar")
}

fn open_zip(path: &std::path::Path) -> ZipMountSource {
    let opts = ratarmount_core::OpenOptions {
        index_in_memory: true,
        ..ratarmount_core::OpenOptions::default()
    };
    ZipMountSource::open(path, None, &opts, "test", true).expect("open zip")
}

fn overlay_write(ov: &WriteOverlay, path: &str, bytes: &[u8]) {
    let fd = ov.create_file(path, 0o644).expect("create");
    {
        use std::os::unix::io::FromRawFd;
        let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
        f.write_all(bytes).unwrap();
    }
}

fn sidecar_ok(hits: Vec<CheapSearchHit>) -> impl Fn(&str) -> Result<Vec<CheapSearchHit>, String> {
    move |_| Ok(hits.clone())
}

fn sidecar_err() -> impl Fn(&str) -> Result<Vec<CheapSearchHit>, String> {
    |_| Err("search requires an on-disk index".into())
}

fn tsv_paths(tsv: &str) -> Vec<&str> {
    tsv.lines()
        .filter(|l| !l.is_empty() && !l.starts_with("error:"))
        .map(|l| l.split('\t').next().unwrap_or(""))
        .collect()
}

/// Regression: overlay create is visible on live search_cheap.
#[test]
fn search_cheap_overlay_create_visible() {
    let dir = tempfile::tempdir().unwrap();
    let ov = WriteOverlay::new(
        Arc::new(CheapBase::fits()) as Arc<dyn MountSource>,
        dir.path(),
    )
    .unwrap();
    overlay_write(&ov, "/new.fits", b"created");
    let hits = ov.search_cheap("*.fits").expect("Some");
    let paths: Vec<_> = hits.iter().map(|h| h.path.as_str()).collect();
    assert!(paths.contains(&"/a.fits"), "{paths:?}");
    assert!(paths.contains(&"/new.fits"), "create missing: {paths:?}");
    let created = hits.iter().find(|h| h.path == "/new.fits").unwrap();
    assert_eq!(created.size, 7);
}

/// Regression: overlay tombstone hides a catalog hit.
#[test]
fn search_cheap_overlay_tombstone_hidden() {
    let dir = tempfile::tempdir().unwrap();
    let ov = WriteOverlay::new(
        Arc::new(CheapBase::fits()) as Arc<dyn MountSource>,
        dir.path(),
    )
    .unwrap();
    ov.unlink("/a.fits").unwrap();
    let hits = ov.search_cheap("*.fits").expect("Some");
    let paths: Vec<_> = hits.iter().map(|h| h.path.as_str()).collect();
    assert!(!paths.contains(&"/a.fits"), "tombstone leaked: {paths:?}");
    assert!(paths.contains(&"/dir/b.fits"));
}

/// Regression: COW/replace overrides size/mtime with no duplicate TSV.
#[test]
fn search_cheap_overlay_cow_replace_no_duplicate() {
    let dir = tempfile::tempdir().unwrap();
    let ov = WriteOverlay::new(
        Arc::new(CheapBase::fits()) as Arc<dyn MountSource>,
        dir.path(),
    )
    .unwrap();
    ov.ensure_modifiable("/a.fits").unwrap();
    std::fs::write(ov.root().join("a.fits"), b"replaced-bytes").unwrap();
    let hits = ov.search_cheap("*.fits").expect("Some");
    let a: Vec<_> = hits.iter().filter(|h| h.path == "/a.fits").collect();
    assert_eq!(a.len(), 1, "duplicate TSV: {hits:?}");
    assert_eq!(a[0].size, 14);
}

/// Regression: empty overlay keeps every base offsetheader (D7, not last-only).
#[test]
fn search_cheap_overlay_keeps_two_offsetheader_when_empty() {
    let dir = tempfile::tempdir().unwrap();
    let ov = WriteOverlay::new(
        Arc::new(CheapBase::two_offsetheader()) as Arc<dyn MountSource>,
        dir.path(),
    )
    .unwrap();
    let hits = ov.search_cheap("*.fits").expect("Some");
    let a: Vec<_> = hits.iter().filter(|h| h.path == "/a.fits").collect();
    assert_eq!(
        a.len(),
        2,
        "empty overlay must keep both versions: {hits:?}"
    );
    assert_eq!(a[0].offsetheader, Some(0));
    assert_eq!(a[1].offsetheader, Some(512));
}

/// Regression: overlay host last-wins collapses same-path versions to one TSV row.
#[test]
fn search_cheap_overlay_cow_collapses_two_offsetheader() {
    let dir = tempfile::tempdir().unwrap();
    let ov = WriteOverlay::new(
        Arc::new(CheapBase::two_offsetheader()) as Arc<dyn MountSource>,
        dir.path(),
    )
    .unwrap();
    ov.ensure_modifiable("/a.fits").unwrap();
    std::fs::write(ov.root().join("a.fits"), b"replaced-bytes").unwrap();
    let hits = ov.search_cheap("*.fits").expect("Some");
    let a: Vec<_> = hits.iter().filter(|h| h.path == "/a.fits").collect();
    assert_eq!(a.len(), 1, "COW last-wins one row: {hits:?}");
    assert_eq!(a[0].size, 14);
}

/// Regression: WriteOverlay + base None → None (do not drop the catalog).
#[test]
fn search_cheap_overlay_base_none_is_none() {
    let dir = tempfile::tempdir().unwrap();
    let ov = WriteOverlay::new(Arc::new(NoneBase) as Arc<dyn MountSource>, dir.path()).unwrap();
    overlay_write(&ov, "/only.fits", b"x");
    assert!(
        ov.search_cheap("*.fits").is_none(),
        "base None must return None"
    );
}

/// Regression: SearchFn step 3 still shows overlay creates when base is None
/// and a real sidecar returned Ok (including empty).
#[test]
fn search_cheap_base_none_control_file_sidecar_ok() {
    let dir = tempfile::tempdir().unwrap();
    let ov = WriteOverlay::new(Arc::new(NoneBase) as Arc<dyn MountSource>, dir.path()).unwrap();
    overlay_write(&ov, "/only.fits", b"hello!");
    let tsv = live_search_tsv(&ov, Some(&ov), "*.fits", sidecar_ok(vec![]));
    assert!(
        tsv.contains("/only.fits\t6\t"),
        "control file must show overlay create via step 3: {tsv}"
    );
}

/// Regression: sidecar Err must not overlay-merge.
#[test]
fn search_cheap_sidecar_err_skips_overlay_merge() {
    let dir = tempfile::tempdir().unwrap();
    let ov = WriteOverlay::new(Arc::new(NoneBase) as Arc<dyn MountSource>, dir.path()).unwrap();
    overlay_write(&ov, "/only.fits", b"x");
    let tsv = live_search_tsv(&ov, Some(&ov), "*.fits", sidecar_err());
    assert!(tsv.starts_with("error:"), "{tsv}");
    assert!(!tsv.contains("/only.fits"), "{tsv}");
}

/// Regression: replace_base is used (current_base), not self.base.
#[test]
fn search_cheap_replace_base() {
    let dir = tempfile::tempdir().unwrap();
    let ov = WriteOverlay::new(
        Arc::new(CheapBase::fits()) as Arc<dyn MountSource>,
        dir.path(),
    )
    .unwrap();
    let before = ov.search_cheap("*.fits").unwrap();
    assert!(before.iter().any(|h| h.path == "/a.fits"));
    ov.replace_base(Arc::new(CheapBase {
        hits: vec![hit("/other.fits", "other.fits", 9, 1.0)],
    }) as Arc<dyn MountSource>);
    let after = ov.search_cheap("*.fits").unwrap();
    let paths: Vec<_> = after.iter().map(|h| h.path.as_str()).collect();
    assert!(paths.contains(&"/other.fits"), "{paths:?}");
    assert!(!paths.contains(&"/a.fits"), "stale base: {paths:?}");
}

/// Regression: `fts:` never enters scan_glob / search_cheap.
#[test]
fn search_cheap_fts_never_calls_scan() {
    let spy = SearchCheapSpy {
        inner: CheapBase::fits(),
        calls: AtomicUsize::new(0),
    };
    let tsv = live_search_tsv(
        &spy,
        None,
        "fts:fits",
        sidecar_ok(vec![hit("/a.fits", "a.fits", 4, 1.0)]),
    );
    assert_eq!(
        spy.calls.load(Ordering::SeqCst),
        0,
        "fts: called search_cheap"
    );
    assert!(tsv.contains("/a.fits"), "{tsv}");
}

/// Regression: Control(WriteOverlay) file ≡ SearchFn TSV for Some+COW.
#[test]
fn search_cheap_control_file_eq_socket_cow() {
    let dir = tempfile::tempdir().unwrap();
    let ov = WriteOverlay::new(
        Arc::new(CheapBase::fits()) as Arc<dyn MountSource>,
        dir.path(),
    )
    .unwrap();
    ov.ensure_modifiable("/a.fits").unwrap();
    std::fs::write(ov.root().join("a.fits"), b"replaced-bytes").unwrap();
    let ov = Arc::new(ov);
    let source: Arc<dyn MountSource> = Arc::clone(&ov) as Arc<dyn MountSource>;
    let on_search = {
        let src = Arc::clone(&source);
        let ov2 = Arc::clone(&ov);
        Arc::new(move |pat: &str| {
            live_search_tsv(src.as_ref(), Some(ov2.as_ref()), pat, sidecar_err())
        })
    };
    let ctrl = ControlFolderMountSource::new(
        source,
        ControlFolderOptions::enabled().with_on_search(Arc::clone(&on_search) as _),
    );
    let file = {
        let path = format!("{CONTROL_DIR_PATH}/search/*.fits");
        let fi = ctrl.lookup(&path, 0).expect("lookup");
        let mut r = ctrl.open(&fi, 0).unwrap();
        let mut s = String::new();
        std::io::Read::read_to_string(&mut r, &mut s).unwrap();
        s
    };
    let socket = on_search("*.fits");
    assert_eq!(file, socket, "control file ≡ socket");
    assert_eq!(file.matches("/a.fits").count(), 1);
    assert!(file.contains("/a.fits\t14\t"), "{file}");
}

/// Regression: file ≡ socket for base None + overlay create (sidecar Ok).
#[test]
fn search_cheap_control_file_eq_socket_none_create() {
    let dir = tempfile::tempdir().unwrap();
    let ov = WriteOverlay::new(Arc::new(NoneBase) as Arc<dyn MountSource>, dir.path()).unwrap();
    overlay_write(&ov, "/only.fits", b"hello!");
    let ov = Arc::new(ov);
    let source: Arc<dyn MountSource> = Arc::clone(&ov) as Arc<dyn MountSource>;
    let on_search = {
        let src = Arc::clone(&source);
        let ov2 = Arc::clone(&ov);
        Arc::new(move |pat: &str| {
            live_search_tsv(src.as_ref(), Some(ov2.as_ref()), pat, sidecar_ok(vec![]))
        })
    };
    let ctrl = ControlFolderMountSource::new(
        source,
        ControlFolderOptions::enabled().with_on_search(Arc::clone(&on_search) as _),
    );
    let path = format!("{CONTROL_DIR_PATH}/search/*.fits");
    let fi = ctrl.lookup(&path, 0).expect("lookup");
    let mut r = ctrl.open(&fi, 0).unwrap();
    let mut file = String::new();
    std::io::Read::read_to_string(&mut r, &mut file).unwrap();
    let socket = on_search("*.fits");
    assert_eq!(file, socket);
    assert!(file.contains("/only.fits\t6\t"), "{file}");
}

/// Regression: file ≡ socket for `fts:`.
#[test]
fn search_cheap_control_file_eq_socket_fts() {
    let spy = Arc::new(SearchCheapSpy {
        inner: CheapBase::fits(),
        calls: AtomicUsize::new(0),
    });
    let source: Arc<dyn MountSource> = Arc::clone(&spy) as Arc<dyn MountSource>;
    let sql = vec![hit("/a.fits", "a.fits", 4, 1.0)];
    let on_search = {
        let src = Arc::clone(&source);
        let sql = sql.clone();
        Arc::new(move |pat: &str| live_search_tsv(src.as_ref(), None, pat, sidecar_ok(sql.clone())))
    };
    let ctrl = ControlFolderMountSource::new(
        source,
        ControlFolderOptions::enabled().with_on_search(Arc::clone(&on_search) as _),
    );
    let path = format!("{CONTROL_DIR_PATH}/search/fts:fits");
    let fi = ctrl.lookup(&path, 0).expect("lookup");
    let mut r = ctrl.open(&fi, 0).unwrap();
    let mut file = String::new();
    std::io::Read::read_to_string(&mut r, &mut file).unwrap();
    let socket = on_search("fts:fits");
    assert_eq!(file, socket);
    assert_eq!(spy.calls.load(Ordering::SeqCst), 0);
    assert!(file.contains("/a.fits"), "{file}");
}

/// Regression: compact-only control TSV when format returns Some.
#[test]
fn search_cheap_compact_only_control_tsv() {
    let dir = tempfile::tempdir().unwrap();
    let zip_path = dir.path().join("a.zip");
    write_fits_zip(&zip_path);
    let zip = open_zip(&zip_path);
    let hits = zip.search_cheap("*.fits").expect("zip SoA Some");
    let paths: Vec<_> = hits.iter().map(|h| h.path.as_str()).collect();
    assert!(paths.contains(&"/a.fits"), "{paths:?}");
    let tsv = live_search_tsv(&zip, None, "*.fits", sidecar_err());
    assert!(tsv.contains("/a.fits"), "{tsv}");
    assert!(!tsv.starts_with("error:"), "{tsv}");
}

/// Regression: FileVersionLayer / Prefix / Transform / Control / AutoMount
/// forward without list(); no `.versions` hits.
#[test]
fn search_cheap_wrapper_forwards_parent_only() {
    let dir = tempfile::tempdir().unwrap();
    let zip_path = dir.path().join("a.zip");
    write_fits_zip(&zip_path);
    let zip = Arc::new(open_zip(&zip_path)) as Arc<dyn MountSource>;

    let vers = FileVersionLayer::new(Arc::clone(&zip));
    let vhits = vers.search_cheap("*.fits").expect("versions forward");
    assert!(
        vhits.iter().all(|h| !h.path.contains(".versions")),
        "no .versions hits: {vhits:?}"
    );
    assert!(vhits.iter().any(|h| h.path == "/a.fits"));

    let prefix = PrefixMountSource::new("data", Arc::clone(&zip));
    let phits = prefix.search_cheap("*.fits").expect("prefix forward");
    assert!(
        phits.iter().any(|h| h.path == "/a.fits"),
        "forward without rewriting: {phits:?}"
    );

    let xf = TransformMountSource::new("^/", "/x/", Arc::clone(&zip)).unwrap();
    let xhits = xf.search_cheap("*.fits").expect("transform forward");
    assert!(xhits.iter().any(|h| h.path == "/a.fits"));

    let ctrl = ControlFolderMountSource::new(Arc::clone(&zip), ControlFolderOptions::enabled());
    let chits = ctrl.search_cheap("*.fits").expect("control forward");
    assert!(chits.iter().any(|h| h.path == "/a.fits"));
    assert!(ctrl.search_cheap("fts:fits").is_none());

    let am = AutoMountLayer::new(
        Arc::clone(&zip),
        1,
        Arc::new(|_: &std::path::Path| Err(io::Error::other("no nested"))),
    );
    let ahits = am.search_cheap("*.fits").expect("automount parent");
    assert!(ahits.iter().any(|h| h.path == "/a.fits"));
}

/// Regression: Folder glob walks the host tree without `list()` / FileInfo.
#[test]
fn search_cheap_folder_globs_host() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.fits"), b"fits").unwrap();
    std::fs::create_dir(dir.path().join("nested")).unwrap();
    std::fs::write(dir.path().join("nested").join("b.fits"), b"fits2").unwrap();
    std::fs::write(dir.path().join("readme.txt"), b"hello").unwrap();

    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("leaked.fits"), b"nope").unwrap();
    std::os::unix::fs::symlink(outside.path(), dir.path().join("escape")).unwrap();
    std::os::unix::fs::symlink("/etc", dir.path().join("etc")).unwrap();

    let src = FolderMountSource::new(dir.path()).unwrap();
    let counted = ListCallCounter::new(Arc::new(src) as Arc<dyn MountSource>);

    assert!(
        counted.search_cheap("fts:fits").is_none(),
        "fts: must stay None"
    );

    let hits = counted.search_cheap("*.fits").expect("Folder Some");
    assert_eq!(
        counted.list_calls.load(Ordering::SeqCst),
        0,
        "Folder search_cheap must not call list()"
    );
    let paths: Vec<_> = hits.iter().map(|h| h.path.as_str()).collect();
    assert!(paths.contains(&"/a.fits"), "{paths:?}");
    assert!(paths.contains(&"/nested/b.fits"), "{paths:?}");
    assert!(!paths.contains(&"/readme.txt"), "{paths:?}");
    assert!(
        !paths.iter().any(|p| p.contains("leaked")),
        "must not recurse S_IFLNK dir: {paths:?}"
    );
    assert_eq!(hits.iter().find(|h| h.path == "/a.fits").unwrap().size, 4);

    let tsv = live_search_tsv(&counted, None, "*", sidecar_err());
    assert!(
        !tsv.contains("/etc/"),
        "symlink-to-/etc must be absent from TSV: {tsv}"
    );
    assert!(
        !tsv.contains("leaked.fits"),
        "escaped host tree must be absent from TSV: {tsv}"
    );
    assert!(tsv.contains("/a.fits\t"), "{tsv}");
    assert_eq!(
        counted.list_calls.load(Ordering::SeqCst),
        0,
        "live TSV must not call list()"
    );
}

/// Regression: Folder `*` truncates at DEFAULT_SEARCH_LIMIT (no fat list()).
#[test]
fn search_cheap_folder_limit_cap() {
    let dir = tempfile::tempdir().unwrap();
    let n = DEFAULT_SEARCH_LIMIT + 1;
    for i in 0..n {
        std::fs::write(dir.path().join(format!("n{i}.dat")), b"x").unwrap();
    }
    let src = FolderMountSource::new(dir.path()).unwrap();
    let counted = ListCallCounter::new(Arc::new(src) as Arc<dyn MountSource>);
    let hits = counted.search_cheap("*").expect("Folder Some");
    assert_eq!(
        counted.list_calls.load(Ordering::SeqCst),
        0,
        "limit walk must not call list()"
    );
    assert_eq!(
        hits.len(),
        DEFAULT_SEARCH_LIMIT,
        "dense folder * must cap at DEFAULT_SEARCH_LIMIT"
    );
}

/// Regression: Union merges every source (not `sources[0]`).
#[test]
fn search_cheap_union_merges_all_sources() {
    let dir = tempfile::tempdir().unwrap();
    let tar_path = dir.path().join("a.tar");
    write_fits_tar(
        &tar_path,
        &[
            ("a.fits", b"tar-a".as_slice()),
            ("only-tar.fits", b"from-tar".as_slice()),
        ],
    );
    let zip_path = dir.path().join("b.zip");
    write_zip(
        &zip_path,
        &[
            ("a.fits", b"zip-later".as_slice()),
            ("only-zip.fits", b"from-zip".as_slice()),
        ],
    );
    let tar = Arc::new(open_tar(&tar_path)) as Arc<dyn MountSource>;
    let zip = Arc::new(open_zip(&zip_path)) as Arc<dyn MountSource>;
    let union = UnionMountSource::new(vec![Arc::clone(&tar), Arc::clone(&zip)]);

    assert!(
        union.search_cheap("fts:fits").is_none(),
        "fts: must stay None"
    );

    let hits = union.search_cheap("*.fits").expect("Union Some");
    let paths: Vec<_> = hits.iter().map(|h| h.path.as_str()).collect();
    assert!(
        paths.contains(&"/only-tar.fits"),
        "must not forward sources[0] only: {paths:?}"
    );
    assert!(
        paths.contains(&"/only-zip.fits"),
        "later source unique missing: {paths:?}"
    );
    let tar_a = tar
        .search_cheap("*.fits")
        .unwrap()
        .into_iter()
        .find(|h| h.path == "/a.fits")
        .expect("tar a.fits");
    let zip_a = zip
        .search_cheap("*.fits")
        .unwrap()
        .into_iter()
        .find(|h| h.path == "/a.fits")
        .expect("zip a.fits");
    let a: Vec<_> = hits.iter().filter(|h| h.path == "/a.fits").collect();
    assert!(!a.is_empty(), "overlapping name dropped: {hits:?}");
    let later = a
        .iter()
        .find(|h| h.offsetheader == zip_a.offsetheader)
        .unwrap_or_else(|| panic!("later ZIP path+oh missing: {a:?}"));
    assert_eq!(
        later.size, zip_a.size,
        "later ZIP must win colliding key {:?}: {a:?}",
        zip_a.offsetheader
    );
    if tar_a.offsetheader == zip_a.offsetheader {
        assert_eq!(a.len(), 1, "same path+oh must collapse: {a:?}");
    }

    let early = Arc::new(FileInfoSpy {
        inner: CheapBase::two_offsetheader(),
        list_calls: AtomicUsize::new(0),
        lookup_calls: AtomicUsize::new(0),
    });
    let late = Arc::new(FileInfoSpy {
        inner: CheapBase {
            hits: vec![CheapSearchHit {
                path: "/a.fits".into(),
                name: "a.fits".into(),
                size: 99,
                mtime: 9.0,
                offsetheader: Some(0),
            }],
        },
        list_calls: AtomicUsize::new(0),
        lookup_calls: AtomicUsize::new(0),
    });
    let union = UnionMountSource::new(vec![
        Arc::clone(&early) as Arc<dyn MountSource>,
        Arc::clone(&late) as Arc<dyn MountSource>,
    ]);
    let hits = union.search_cheap("*.fits").expect("Union Some");
    let a: Vec<_> = hits.iter().filter(|h| h.path == "/a.fits").collect();
    assert_eq!(a.len(), 2, "keep both offsetheader rows: {hits:?}");
    let oh0 = a.iter().find(|h| h.offsetheader == Some(0)).unwrap();
    let oh512 = a.iter().find(|h| h.offsetheader == Some(512)).unwrap();
    assert_eq!(oh0.size, 99, "same path+oh later source wins");
    assert_eq!(oh512.size, 8, "distinct offsetheader must stay");
    assert_eq!(
        early.list_calls.load(Ordering::SeqCst) + late.list_calls.load(Ordering::SeqCst),
        0,
        "Union search_cheap must not call list()"
    );
    assert_eq!(
        early.lookup_calls.load(Ordering::SeqCst) + late.lookup_calls.load(Ordering::SeqCst),
        0,
        "FileInfo count 0: no lookup / no B-4"
    );
}

/// Regression: `Some([])` is a contributing catalog, not `None`.
#[test]
fn search_cheap_union_empty_catalog_contributes() {
    let empty = Arc::new(CheapBase::empty()) as Arc<dyn MountSource>;
    let fits = Arc::new(CheapBase::fits()) as Arc<dyn MountSource>;
    for (label, sources) in [
        (
            "empty then fits",
            vec![Arc::clone(&empty), Arc::clone(&fits)],
        ),
        (
            "fits then empty",
            vec![Arc::clone(&fits), Arc::clone(&empty)],
        ),
    ] {
        let union = UnionMountSource::new(sources);
        let hits = union
            .search_cheap("*.fits")
            .unwrap_or_else(|| panic!("{label}: empty catalog must contribute"));
        let paths: Vec<_> = hits.iter().map(|h| h.path.as_str()).collect();
        assert!(paths.contains(&"/a.fits"), "{label}: {paths:?}");
        assert!(paths.contains(&"/dir/b.fits"), "{label}: {paths:?}");
    }
    let both_empty = UnionMountSource::new(vec![Arc::clone(&empty), empty]);
    let hits = both_empty
        .search_cheap("*.fits")
        .expect("two empty catalogs still Some");
    assert!(hits.is_empty(), "two empties: {hits:?}");
}

/// Regression: Union truncates the merged catalog at DEFAULT_SEARCH_LIMIT.
#[test]
fn search_cheap_union_limit_cap() {
    let left_n = DEFAULT_SEARCH_LIMIT / 2;
    let right_n = DEFAULT_SEARCH_LIMIT + 1 - left_n;
    let left = Arc::new(FileInfoSpy {
        inner: CheapBase {
            hits: (0..left_n)
                .map(|i| hit(&format!("/l{i}.dat"), &format!("l{i}.dat"), 1, 1.0))
                .collect(),
        },
        list_calls: AtomicUsize::new(0),
        lookup_calls: AtomicUsize::new(0),
    });
    let right = Arc::new(FileInfoSpy {
        inner: CheapBase {
            hits: (0..right_n)
                .map(|i| hit(&format!("/r{i}.dat"), &format!("r{i}.dat"), 1, 1.0))
                .collect(),
        },
        list_calls: AtomicUsize::new(0),
        lookup_calls: AtomicUsize::new(0),
    });
    let union = UnionMountSource::new(vec![
        Arc::clone(&left) as Arc<dyn MountSource>,
        Arc::clone(&right) as Arc<dyn MountSource>,
    ]);
    let hits = union.search_cheap("*").expect("Union Some");
    assert_eq!(
        hits.len(),
        DEFAULT_SEARCH_LIMIT,
        "merged unique keys must cap at DEFAULT_SEARCH_LIMIT"
    );
    assert_eq!(
        left.list_calls.load(Ordering::SeqCst) + right.list_calls.load(Ordering::SeqCst),
        0,
        "limit merge must not call list()"
    );
    assert_eq!(
        left.lookup_calls.load(Ordering::SeqCst) + right.lookup_calls.load(Ordering::SeqCst),
        0,
        "FileInfo count 0: no lookup / no B-4"
    );
}

/// Regression: any source `None` (Folder-without-impl) → Union `None`.
#[test]
fn search_cheap_union_none_if_any_source_none() {
    let dir = tempfile::tempdir().unwrap();
    let zip_path = dir.path().join("a.zip");
    write_fits_zip(&zip_path);
    let zip = Arc::new(open_zip(&zip_path)) as Arc<dyn MountSource>;
    let none = Arc::new(NoneBase) as Arc<dyn MountSource>;
    let union = UnionMountSource::new(vec![zip, none]);
    assert!(
        union.search_cheap("*.fits").is_none(),
        "any source None must not drop to sources[0]"
    );
}

/// Regression: Folder (PR 7) + ZIP both `Some` → Union merge, not `None`.
#[test]
fn search_cheap_union_folder_and_zip_merges() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("host.fits"), b"host").unwrap();
    let zip_dir = tempfile::tempdir().unwrap();
    let zip_path = zip_dir.path().join("a.zip");
    write_fits_zip(&zip_path);
    let folder = Arc::new(FolderMountSource::new(dir.path()).unwrap()) as Arc<dyn MountSource>;
    let zip = Arc::new(open_zip(&zip_path)) as Arc<dyn MountSource>;
    let union = UnionMountSource::new(vec![folder, zip]);
    let hits = union.search_cheap("*.fits").expect("Folder+ZIP Some");
    let paths: Vec<_> = hits.iter().map(|h| h.path.as_str()).collect();
    assert!(paths.contains(&"/host.fits"), "{paths:?}");
    assert!(paths.contains(&"/a.fits"), "{paths:?}");
}

/// Regression: OCI locate is overlayfs across layers, not `layers[0]`.
/// Whiteout hides a lower file; opaque dir hides lower children; `.wh.*`
/// never appears in TSV. `fts:` stays None.
#[test]
fn search_cheap_oci_applies_whiteouts() {
    let dir = tempfile::tempdir().unwrap();
    let lower_path = dir.path().join("lower.tar");
    write_fits_tar(
        &lower_path,
        &[
            ("a.fits", b"hide-me".as_slice()),
            ("hello.fits", b"from-lower".as_slice()),
            ("dir/lower.fits", b"opaque-hidden".as_slice()),
            ("only-lower.fits", b"bottom-unique".as_slice()),
        ],
    );
    let upper_path = dir.path().join("upper.tar");
    write_fits_tar(
        &upper_path,
        &[
            (".wh.a.fits", b"".as_slice()),
            ("world.fits", b"from-upper".as_slice()),
            ("dir/.wh..wh..opq", b"".as_slice()),
            ("dir/upper.fits", b"from-upper-dir".as_slice()),
        ],
    );
    let lower = Arc::new(ListCallCounter::new(
        Arc::new(open_tar(&lower_path)) as Arc<dyn MountSource>
    ));
    let upper = Arc::new(ListCallCounter::new(
        Arc::new(open_tar(&upper_path)) as Arc<dyn MountSource>
    ));
    let oci = OciImageMountSource::new(vec![
        Arc::clone(&lower) as Arc<dyn MountSource>,
        Arc::clone(&upper) as Arc<dyn MountSource>,
    ]);

    assert!(
        oci.search_cheap("fts:fits").is_none(),
        "fts: must stay None"
    );

    let hits = oci.search_cheap("*.fits").expect("OCI Some");
    let paths: Vec<_> = hits.iter().map(|h| h.path.as_str()).collect();
    assert!(
        paths.contains(&"/world.fits"),
        "must not forward layers[0] only: {paths:?}"
    );
    assert!(
        paths.contains(&"/hello.fits") && paths.contains(&"/only-lower.fits"),
        "lower unique missing (not top-only): {paths:?}"
    );
    assert!(
        paths.contains(&"/dir/upper.fits"),
        "upper opaque-dir child missing: {paths:?}"
    );
    assert!(
        !paths.contains(&"/a.fits"),
        "whiteout must hide lower file: {paths:?}"
    );
    assert!(
        !paths.contains(&"/dir/lower.fits"),
        "opaque dir must hide lower children: {paths:?}"
    );
    assert!(
        paths
            .iter()
            .all(|p| !p.split('/').any(|c| c.starts_with(".wh."))),
        ".wh. leaked into hits: {paths:?}"
    );

    let tsv = live_search_tsv(&oci, None, "*", sidecar_err());
    let tsv_paths = tsv_paths(&tsv);
    assert!(
        tsv_paths
            .iter()
            .all(|p| !p.split('/').any(|c| c.starts_with(".wh."))),
        "no .wh. in TSV: {tsv}"
    );
    assert!(tsv_paths.contains(&"/world.fits"), "{tsv}");
    assert!(tsv_paths.contains(&"/hello.fits"), "{tsv}");
    assert!(
        !tsv_paths.contains(&"/a.fits"),
        "whiteout leaked into TSV: {tsv}"
    );
    assert!(
        !tsv_paths.contains(&"/dir/lower.fits"),
        "opaque child leaked into TSV: {tsv}"
    );
    assert_eq!(
        lower.list_calls.load(Ordering::SeqCst) + upper.list_calls.load(Ordering::SeqCst),
        0,
        "OCI search_cheap must not recurse overlay_list / list()"
    );
    assert_eq!(
        lower.dirent_calls.load(Ordering::SeqCst) + upper.dirent_calls.load(Ordering::SeqCst),
        0,
        "must not recurse overlay_list_dirents"
    );
    assert_eq!(
        lower.lookup_calls.load(Ordering::SeqCst) + upper.lookup_calls.load(Ordering::SeqCst),
        0,
        "FileInfo count 0: no lookup"
    );
}

/// Regression: any layer `None` → OCI `None` (do not drop to layers[0]).
#[test]
fn search_cheap_oci_none_if_any_layer_none() {
    let dir = tempfile::tempdir().unwrap();
    let zip_path = dir.path().join("a.zip");
    write_fits_zip(&zip_path);
    let zip = || Arc::new(open_zip(&zip_path)) as Arc<dyn MountSource>;
    let none = || Arc::new(NoneBase) as Arc<dyn MountSource>;
    let top_none = OciImageMountSource::new(vec![zip(), none()]);
    assert!(
        top_none.search_cheap("*.fits").is_none(),
        "top layer None must not drop to layers[0]"
    );
    let bottom_none = OciImageMountSource::new(vec![none(), zip()]);
    assert!(
        bottom_none.search_cheap("*.fits").is_none(),
        "bottom layer None must not drop to layers.last()"
    );
}

/// Regression: `Some([])` is a contributing catalog, not `None`.
#[test]
fn search_cheap_oci_empty_catalog_contributes() {
    let empty = Arc::new(CheapBase::empty()) as Arc<dyn MountSource>;
    let fits = Arc::new(CheapBase::fits()) as Arc<dyn MountSource>;
    let oci = OciImageMountSource::new(vec![empty, fits]);
    let hits = oci
        .search_cheap("*.fits")
        .expect("empty catalog contributes");
    let paths: Vec<_> = hits.iter().map(|h| h.path.as_str()).collect();
    assert!(paths.contains(&"/a.fits"), "{paths:?}");
    assert!(paths.contains(&"/dir/b.fits"), "{paths:?}");
}

/// Regression: overlapping path keeps the higher layer's size (not layers[0]).
#[test]
fn search_cheap_oci_higher_layer_wins_overlap() {
    let lower = Arc::new(ListCallCounter::new(
        Arc::new(CheapBase::fits()) as Arc<dyn MountSource>
    ));
    let upper = Arc::new(ListCallCounter::new(Arc::new(CheapBase {
        hits: vec![hit("/a.fits", "a.fits", 99, 9.0)],
    }) as Arc<dyn MountSource>));
    let oci = OciImageMountSource::new(vec![
        Arc::clone(&lower) as Arc<dyn MountSource>,
        Arc::clone(&upper) as Arc<dyn MountSource>,
    ]);
    let hits = oci.search_cheap("*.fits").expect("OCI Some");
    let a = hits.iter().find(|h| h.path == "/a.fits").expect("a.fits");
    assert_eq!(a.size, 99, "higher layer must win overlap: {hits:?}");
    assert!(
        hits.iter().any(|h| h.path == "/dir/b.fits"),
        "lower unique missing: {hits:?}"
    );
    assert_eq!(lower.list_calls.load(Ordering::SeqCst), 0);
    assert_eq!(lower.dirent_calls.load(Ordering::SeqCst), 0);
    assert_eq!(lower.lookup_calls.load(Ordering::SeqCst), 0);
    assert_eq!(upper.list_calls.load(Ordering::SeqCst), 0);
    assert_eq!(upper.dirent_calls.load(Ordering::SeqCst), 0);
    assert_eq!(upper.lookup_calls.load(Ordering::SeqCst), 0);
}

/// Regression: extra `.wh.*` scan `None` fail-closes (do not leak hidden names).
#[test]
fn search_cheap_oci_none_if_any_wh_scan() {
    struct WhScanNone(CheapBase);
    impl MountSource for WhScanNone {
        fn list(&self, path: &str) -> Option<ListResult> {
            self.0.list(path)
        }
        fn lookup(&self, path: &str, v: i32) -> Option<FileInfo> {
            self.0.lookup(path, v)
        }
        fn search_cheap(&self, pattern: &str) -> Option<Vec<CheapSearchHit>> {
            if pattern == ".wh.*" {
                return None;
            }
            self.0.search_cheap(pattern)
        }
        fn open(&self, fi: &FileInfo, b: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            self.0.open(fi, b)
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }
    let oci = OciImageMountSource::new(vec![
        Arc::new(CheapBase::fits()) as Arc<dyn MountSource>,
        Arc::new(WhScanNone(CheapBase::fits())) as Arc<dyn MountSource>,
    ]);
    assert!(
        oci.search_cheap("*.fits").is_none(),
        "`.wh.*` None must not leak hidden names"
    );
}

/// Regression: status_text uses list_dirents (counted list() stays 0).
#[test]
fn search_cheap_status_text_no_list() {
    let counted = Arc::new(ListCallCounter::new(
        Arc::new(CheapBase::fits()) as Arc<dyn MountSource>
    ));
    let ctrl = ControlFolderMountSource::new(
        Arc::clone(&counted) as Arc<dyn MountSource>,
        ControlFolderOptions::enabled(),
    );
    let path = format!("{CONTROL_DIR_PATH}/status");
    let fi = ctrl.lookup(&path, 0).expect("status");
    let mut r = ctrl.open(&fi, 0).unwrap();
    let mut body = String::new();
    std::io::Read::read_to_string(&mut r, &mut body).unwrap();
    assert_eq!(
        counted.list_calls.load(Ordering::SeqCst),
        0,
        "status_text must not call list()"
    );
    assert!(body.contains("root:"), "{body}");
}

/// Regression: AutoMount list_names_no_lazy uses list_dirents.
#[test]
fn search_cheap_automount_names_no_list() {
    let counted = Arc::new(ListCallCounter::new(
        Arc::new(CheapBase::fits()) as Arc<dyn MountSource>
    ));
    let _am = AutoMountLayer::new(
        Arc::clone(&counted) as Arc<dyn MountSource>,
        1,
        Arc::new(|_: &std::path::Path| Err(io::Error::other("no nested"))),
    );
    assert_eq!(
        counted.list_calls.load(Ordering::SeqCst),
        0,
        "eager scan list_names_no_lazy must not call list()"
    );
}

#[test]
fn search_cheap_format_tsv_helper() {
    let hits = vec![hit("/a.fits", "a.fits", 4, 1.0)];
    let tsv = format_cheap_hits_tsv(&hits);
    assert_eq!(tsv_paths(&tsv), vec!["/a.fits"]);
}
