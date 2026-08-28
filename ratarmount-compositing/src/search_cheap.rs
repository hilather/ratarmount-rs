//! V-1 live `search_cheap` + overlay last-wins + SearchFn tests.

use std::io::{self, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ratarmount_core::{
    format_cheap_hits_tsv, CheapDirent, CheapSearchHit, FileInfo, ListResult, MountSource,
};
use ratarmount_formats_zip::ZipMountSource;
use ratarmount_index::locate_pattern_matches;
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

use crate::control::{
    live_search_tsv, ControlFolderMountSource, ControlFolderOptions, CONTROL_DIR_PATH,
};
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
}

impl MountSource for ListCallCounter {
    fn list(&self, path: &str) -> Option<ListResult> {
        self.list_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.list(path)
    }
    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        self.inner.list_dirents(path)
    }
    fn lookup(&self, path: &str, v: i32) -> Option<FileInfo> {
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
    let file = std::fs::File::create(path).unwrap();
    let mut zw = ZipWriter::new(file);
    let opts = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);
    zw.start_file("a.fits", opts).unwrap();
    zw.write_all(b"fits").unwrap();
    zw.start_file("dir/b.fits", opts).unwrap();
    zw.write_all(b"fits2").unwrap();
    zw.start_file("readme.txt", opts).unwrap();
    zw.write_all(b"hello").unwrap();
    zw.finish().unwrap();
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

/// Regression: Union and OCI stay None (not layer-0 / `.wh.` names).
#[test]
fn search_cheap_union_oci_stay_none() {
    let zip_dir = tempfile::tempdir().unwrap();
    let zip_path = zip_dir.path().join("a.zip");
    write_fits_zip(&zip_path);
    let zip = Arc::new(open_zip(&zip_path)) as Arc<dyn MountSource>;
    let union = UnionMountSource::new(vec![Arc::clone(&zip)]);
    assert!(
        union.search_cheap("*.fits").is_none(),
        "Union must stay None, not layer-0"
    );

    let oci = OciImageMountSource::new(vec![Arc::clone(&zip)]);
    let oci_hits = oci.search_cheap("*.fits");
    assert!(
        oci_hits.is_none(),
        "OCI must stay None, not emit layer/`.wh.` hits: {oci_hits:?}"
    );
}

/// Regression: status_text uses list_dirents (counted list() stays 0).
#[test]
fn search_cheap_status_text_no_list() {
    let counted = Arc::new(ListCallCounter {
        inner: Arc::new(CheapBase::fits()) as Arc<dyn MountSource>,
        list_calls: AtomicUsize::new(0),
    });
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
    let counted = Arc::new(ListCallCounter {
        inner: Arc::new(CheapBase::fits()) as Arc<dyn MountSource>,
        list_calls: AtomicUsize::new(0),
    });
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
