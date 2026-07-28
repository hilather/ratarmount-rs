//! Open archives / folders into `Arc<dyn MountSource>`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ratarmount_compositing::{
    parse_recursive_extensions, AutoMountLayer, AutoMountOptions, FileVersionLayer,
    FolderMountSource, OpenNestedFn, PrefixMountSource, RecursiveExtSet, TransformMountSource,
    UnionMountOptions, UnionMountSource,
};
use ratarmount_compress::{
    body_looks_like_tar, check_for_split_file_in_folder, detect_compression, joined_base_name,
    looks_like_tar, materialize, materialize_joined_parts, name_suggests_compressed_tar,
    open_seekable_bzip2_with_threads, open_seekable_compress_z, open_seekable_lz4,
    open_seekable_lzip,
    open_seekable_lzma, open_seekable_lzo, open_seekable_xz, open_seekable_zlib,
    strip_compression_suffix, CompressionFormat, SeekableBody, SeekableZstd, SharedSeekableGzip,
};
use ratarmount_core::{MountSource, OpenOptions};
use ratarmount_formats_ar::{looks_like_ar, ArMountSource};
use ratarmount_formats_asar::{looks_like_asar, AsarMountSource};
use ratarmount_formats_cab::{looks_like_cab, CabError, CabMountSource};
use ratarmount_formats_cpio::{looks_like_cpio, CpioMountSource};
use ratarmount_formats_ext4::{looks_like_ext4, Ext4MountSource};
use ratarmount_formats_fat::{looks_like_fat, FatMountSource};
use ratarmount_formats_git::{looks_like_git, GitMountSource};
use ratarmount_formats_html::{looks_like_html, HtmlMountSource};
use ratarmount_formats_iso9660::{looks_like_iso, Iso9660MountSource};
use ratarmount_formats_libarchive::{looks_like_libarchive, LibarchiveMountSource};
use ratarmount_formats_ogg::{looks_like_ogg, OggMountSource};
use ratarmount_formats_pdf::{looks_like_pdf, PdfMountSource};
use ratarmount_formats_sevenzip::{looks_like_7z, SevenZipMountSource};
use ratarmount_formats_sqlar::{looks_like_sqlar, SqlarMountSource};
use ratarmount_formats_squashfs::{looks_like_squashfs, SquashFsMountSource};
use ratarmount_formats_tar::{SingleFileMountSource, SqliteIndexedTar};
use ratarmount_formats_warc::{looks_like_warc, WarcMountSource};
use ratarmount_formats_xar::{looks_like_xar, XarMountSource};
use ratarmount_formats_zip::{looks_like_zip, ZipMountSource};
use ratarmount_index::{resolve_index_location, IndexLocation};

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Archive format backends probed for uncompressed inputs.
///
/// Order of [`DEFAULT_FORMAT_PROBE_ORDER`] matches the historical fixed chain
/// (7z → zip → … → tar). [`ordered_format_backends`] prepends names from
/// [`OpenOptions::use_backends`] (Python `prioritizedBackends`: last flag wins).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum FormatBackend {
    SevenZip,
    Zip,
    Asar,
    Ar,
    Cpio,
    Iso,
    Warc,
    Xar,
    Cab,
    Sqlar,
    SquashFs,
    Ext4,
    Fat,
    Ogg,
    Pdf,
    Html,
    Libarchive,
    Tar,
}

/// Default probe order when `--use-backend` is empty (historical fixed chain).
const DEFAULT_FORMAT_PROBE_ORDER: &[FormatBackend] = &[
    FormatBackend::SevenZip,
    FormatBackend::Zip,
    FormatBackend::Asar,
    FormatBackend::Ar,
    FormatBackend::Cpio,
    FormatBackend::Iso,
    FormatBackend::Warc,
    FormatBackend::Xar,
    FormatBackend::Cab,
    FormatBackend::Sqlar,
    FormatBackend::SquashFs,
    FormatBackend::Ext4,
    FormatBackend::Fat,
    FormatBackend::Ogg,
    FormatBackend::Pdf,
    FormatBackend::Html,
    FormatBackend::Libarchive,
    FormatBackend::Tar,
];

/// Map a user/Python backend name to a format backend.
///
/// Unknown names return `None` (skipped with no error, like Python's warning path).
/// Compression-only names (`rapidgzip`, `indexed_bzip2`, …) map to `Tar`, matching
/// Python `mapToArchiveBackend` → `tarfile`.
fn parse_format_backend(name: &str) -> Option<FormatBackend> {
    let n = name.trim().to_ascii_lowercase();
    if n.is_empty() {
        return None;
    }
    Some(match n.as_str() {
        "tar" | "tarfile" | "sqliteindexedtar" => FormatBackend::Tar,
        // Compression backends that Python delegates to tarfile.
        "rapidgzip"
        | "indexed_gzip"
        | "indexed_bzip2"
        | "xz"
        | "lzma"
        | "zstd"
        | "lz4"
        | "lzip"
        | "lzo"
        | "lzop"
        | "zlib"
        | "deflate"
        | "compress"
        | "compress-z"
        | "gzip"
        | "bzip2" => FormatBackend::Tar,
        "zip" | "zipfile" => FormatBackend::Zip,
        "7z" | "sevenzip" | "py7zr" => FormatBackend::SevenZip,
        "libarchive" => FormatBackend::Libarchive,
        "squashfs" | "pysquashfsimage" => FormatBackend::SquashFs,
        "ext4" | "ext" => FormatBackend::Ext4,
        "fat" | "fatfs" | "vfat" => FormatBackend::Fat,
        "ar" => FormatBackend::Ar,
        "cpio" => FormatBackend::Cpio,
        "iso" | "iso9660" => FormatBackend::Iso,
        "warc" => FormatBackend::Warc,
        "xar" => FormatBackend::Xar,
        "cab" => FormatBackend::Cab,
        "asar" => FormatBackend::Asar,
        "sqlar" => FormatBackend::Sqlar,
        "ogg" | "ogv" | "oga" => FormatBackend::Ogg,
        "pdf" => FormatBackend::Pdf,
        "html" | "htm" => FormatBackend::Html,
        // RAR/RPM have no dedicated Rust backend; prefer libarchive when requested.
        "rar" | "rarfile" | "rpm" => FormatBackend::Libarchive,
        _ => return None,
    })
}

/// Build format probe order from `--use-backend` / `OpenOptions.use_backends`.
///
/// Matches Python `CLIHelpers`: flatten comma-separated values, then reverse so
/// the **last** name has highest priority (tried first). Unknown names are
/// ignored. Remaining defaults follow without duplicates.
fn ordered_format_backends(use_backends: &[String]) -> Vec<FormatBackend> {
    let mut ordered = Vec::with_capacity(DEFAULT_FORMAT_PROBE_ORDER.len() + use_backends.len());
    let mut seen = std::collections::HashSet::new();

    // Python: [b for s in use_backend for b in s.split(',')][::-1]
    let flattened: Vec<&str> = use_backends
        .iter()
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    for name in flattened.into_iter().rev() {
        if let Some(backend) = parse_format_backend(name) {
            if seen.insert(backend) {
                ordered.push(backend);
            }
        }
    }
    for &backend in DEFAULT_FORMAT_PROBE_ORDER {
        if seen.insert(backend) {
            ordered.push(backend);
        }
    }
    ordered
}

/// Try one format backend; `Ok(None)` means magic/extension check failed (try next).
fn try_open_format_backend(
    path: &Path,
    backend: FormatBackend,
    index_path: Option<&Path>,
    options: &OpenOptions,
    recreate: bool,
) -> Result<Option<Arc<dyn MountSource>>, String> {
    match backend {
        FormatBackend::SevenZip => {
            if !looks_like_7z(path) {
                return Ok(None);
            }
            Ok(Some(Arc::new(
                SevenZipMountSource::open(path, index_path, options, VERSION, recreate)
                    .map_err(|e| e.to_string())?,
            )))
        }
        FormatBackend::Zip => {
            if !looks_like_zip(path) {
                return Ok(None);
            }
            Ok(Some(Arc::new(
                ZipMountSource::open(path, index_path, options, VERSION, recreate)
                    .map_err(|e| e.to_string())?,
            )))
        }
        FormatBackend::Asar => {
            if !looks_like_asar(path) {
                return Ok(None);
            }
            Ok(Some(Arc::new(
                AsarMountSource::open(path, index_path, options, VERSION, recreate)
                    .map_err(|e| e.to_string())?,
            )))
        }
        FormatBackend::Ar => {
            if !looks_like_ar(path) {
                return Ok(None);
            }
            Ok(Some(Arc::new(
                ArMountSource::open(path, index_path, options, VERSION, recreate)
                    .map_err(|e| e.to_string())?,
            )))
        }
        FormatBackend::Cpio => {
            if !looks_like_cpio(path) {
                return Ok(None);
            }
            Ok(Some(Arc::new(
                CpioMountSource::open(path, index_path, options, VERSION, recreate)
                    .map_err(|e| e.to_string())?,
            )))
        }
        FormatBackend::Iso => {
            if !looks_like_iso(path) {
                return Ok(None);
            }
            Ok(Some(Arc::new(
                Iso9660MountSource::open(path, index_path, options, VERSION, recreate)
                    .map_err(|e| e.to_string())?,
            )))
        }
        FormatBackend::Warc => {
            if !looks_like_warc(path) {
                return Ok(None);
            }
            Ok(Some(Arc::new(
                WarcMountSource::open(path, index_path, options, VERSION, recreate)
                    .map_err(|e| e.to_string())?,
            )))
        }
        FormatBackend::Xar => {
            if !looks_like_xar(path) {
                return Ok(None);
            }
            Ok(Some(Arc::new(
                XarMountSource::open(path, index_path, options, VERSION, recreate)
                    .map_err(|e| e.to_string())?,
            )))
        }
        FormatBackend::Cab => {
            if !looks_like_cab(path) {
                return Ok(None);
            }
            match CabMountSource::open(path, index_path, options, VERSION, recreate) {
                Ok(s) => Ok(Some(Arc::new(s))),
                Err(CabError::UnsupportedCompression(_)) => Ok(Some(Arc::new(
                    LibarchiveMountSource::open(path, index_path, options, VERSION, recreate)
                        .map_err(|e| e.to_string())?,
                ))),
                Err(e) => Err(e.to_string()),
            }
        }
        FormatBackend::Sqlar => {
            if !looks_like_sqlar(path) {
                return Ok(None);
            }
            Ok(Some(Arc::new(
                SqlarMountSource::open(path, options).map_err(|e| e.to_string())?,
            )))
        }
        FormatBackend::SquashFs => {
            if !looks_like_squashfs(path) {
                return Ok(None);
            }
            Ok(Some(Arc::new(
                SquashFsMountSource::open(path).map_err(|e| e.to_string())?,
            )))
        }
        FormatBackend::Ext4 => {
            if !looks_like_ext4(path) {
                return Ok(None);
            }
            Ok(Some(Arc::new(
                Ext4MountSource::open(path).map_err(|e| e.to_string())?,
            )))
        }
        FormatBackend::Fat => {
            if !looks_like_fat(path) {
                return Ok(None);
            }
            Ok(Some(Arc::new(
                FatMountSource::open(path).map_err(|e| e.to_string())?,
            )))
        }
        FormatBackend::Ogg => {
            if !looks_like_ogg(path) {
                return Ok(None);
            }
            Ok(Some(Arc::new(
                OggMountSource::open(path, index_path, options, VERSION, recreate)
                    .map_err(|e| e.to_string())?,
            )))
        }
        FormatBackend::Pdf => {
            if !looks_like_pdf(path) {
                return Ok(None);
            }
            Ok(Some(Arc::new(
                PdfMountSource::open(path, index_path, options, VERSION, recreate)
                    .map_err(|e| e.to_string())?,
            )))
        }
        FormatBackend::Html => {
            if !looks_like_html(path) {
                return Ok(None);
            }
            Ok(Some(Arc::new(
                HtmlMountSource::open(path, index_path, options, VERSION, recreate)
                    .map_err(|e| e.to_string())?,
            )))
        }
        FormatBackend::Libarchive => {
            if !looks_like_libarchive(path) {
                return Ok(None);
            }
            Ok(Some(Arc::new(
                LibarchiveMountSource::open(path, index_path, options, VERSION, recreate)
                    .map_err(|e| e.to_string())?,
            )))
        }
        FormatBackend::Tar => {
            let by_ext = path
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("tar"));
            if !looks_like_tar(path).unwrap_or(false) && !by_ext {
                return Ok(None);
            }
            let mut mat = None;
            Ok(Some(Arc::new(open_tar(
                path, path, index_path, options, recreate, &mut mat,
            )?)))
        }
    }
}

/// Open an uncompressed path by probing formats in [`ordered_format_backends`] order.
fn open_uncompressed_path(
    path: &Path,
    index_path: Option<&Path>,
    options: &OpenOptions,
    recreate: bool,
) -> Result<Arc<dyn MountSource>, String> {
    for backend in ordered_format_backends(&options.use_backends) {
        if let Some(src) = try_open_format_backend(path, backend, index_path, options, recreate)? {
            return Ok(src);
        }
    }
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file")
        .to_string();
    let size = std::fs::metadata(path).map_err(|e| e.to_string())?.len();
    Ok(Arc::new(
        SingleFileMountSource::new(name, path.to_path_buf(), size, None)
            .map_err(|e| e.to_string())?,
    ))
}

#[cfg(test)]
mod split_open_tests {
    use super::*;
    use std::io::Read;
    use std::sync::Arc;

    #[test]
    fn ordered_format_backends_default_matches_historical() {
        let order = ordered_format_backends(&[]);
        assert_eq!(order, DEFAULT_FORMAT_PROBE_ORDER.to_vec());
        assert_eq!(order.first(), Some(&FormatBackend::SevenZip));
        assert_eq!(order.last(), Some(&FormatBackend::Tar));
    }

    #[test]
    fn ordered_format_backends_last_flag_highest_priority() {
        // Python: use_backend flatten then [::-1] → last wins.
        let order = ordered_format_backends(&[
            "zip".into(),
            "tar".into(),
        ]);
        assert_eq!(order[0], FormatBackend::Tar);
        assert_eq!(order[1], FormatBackend::Zip);
        // No duplicates; defaults fill the rest.
        assert_eq!(
            order.iter().filter(|&&b| b == FormatBackend::Zip).count(),
            1
        );
        assert_eq!(
            order.iter().filter(|&&b| b == FormatBackend::Tar).count(),
            1
        );
        assert_eq!(order.len(), DEFAULT_FORMAT_PROBE_ORDER.len());
    }

    #[test]
    fn ordered_format_backends_comma_and_aliases() {
        let order = ordered_format_backends(&["zipfile,sevenzip".into()]);
        // Flatten then reverse: sevenzip first, then zipfile.
        assert_eq!(order[0], FormatBackend::SevenZip);
        assert_eq!(order[1], FormatBackend::Zip);
        // Python aliases
        assert_eq!(parse_format_backend("py7zr"), Some(FormatBackend::SevenZip));
        assert_eq!(parse_format_backend("iso9660"), Some(FormatBackend::Iso));
        assert_eq!(parse_format_backend("rapidgzip"), Some(FormatBackend::Tar));
        assert_eq!(parse_format_backend("PySquashfsImage"), Some(FormatBackend::SquashFs));
        assert_eq!(parse_format_backend("unknown-backend-xyz"), None);
    }

    #[test]
    fn ordered_format_backends_unknown_skipped() {
        let order = ordered_format_backends(&["nope".into(), "libarchive".into()]);
        assert_eq!(order[0], FormatBackend::Libarchive);
        assert!(!order.is_empty());
    }

    #[test]
    fn open_joined_plain_file() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("foo.001"), b"foo").unwrap();
        std::fs::write(dir.path().join("foo.002"), b"bar").unwrap();
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let m = open_path(&dir.path().join("foo.001"), &opts, true).unwrap();
        let fi = m.lookup("/foo", 0).expect("joined name foo");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"foobar");
        // Opening .002 also joins the set
        let m2 = open_path(&dir.path().join("foo.002"), &opts, true).unwrap();
        let fi2 = m2.lookup("/foo", 0).expect("joined name");
        let mut r2 = m2.open(&fi2, 0).unwrap();
        buf.clear();
        r2.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"foobar");
    }

    #[test]
    fn open_python_fixture_single_file_split_tar() {
        let py = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let p001 = PathBuf::from(&py).join("tests/single-file-split.tar.001");
        if !p001.exists() {
            eprintln!("skip: missing fixture {p001:?}");
            return;
        }
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let m = open_path(&p001, &opts, true).unwrap();
        let fi = m.lookup("/bar", 0).expect("bar in joined tar");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert!(!buf.is_empty());
        let _ = Arc::strong_count(&m);
    }
}

pub fn open_nested_fn(options: OpenOptions) -> OpenNestedFn {
    Arc::new(move |path: &Path| {
        // Nested archives must not share the parent's index path.
        let mut opts = options.clone();
        opts.index_file_path = None;
        opts.index_in_memory = false;
        opts.clear_index_cache = true;
        // Always rebuild nested indexes next to the materialised file.
        let mut idx = path.as_os_str().to_os_string();
        idx.push(".index.sqlite");
        opts.index_file_path = Some(PathBuf::from(idx));
        open_path(path, &opts, true).map_err(std::io::Error::other)
    })
}

fn resolved_index(path: &Path, options: &OpenOptions, recreate: bool) -> IndexLocation {
    if options.index_in_memory {
        return IndexLocation::Memory;
    }
    let explicit = options
        .index_file_path
        .as_ref()
        .map(|p| p.to_string_lossy().into_owned());
    resolve_index_location(
        path,
        explicit.as_deref(),
        &options.index_folders,
        recreate || options.clear_index_cache,
    )
}

fn index_arg(loc: &IndexLocation) -> Option<&Path> {
    loc.as_path()
}

/// Open a multi-volume split set (Python JoinedFileFromFactory → open_mount_source).
///
/// Joins parts into a temp file, then reuses the normal open path. Index defaults
/// next to the first part (`foo.001.index.sqlite`) like Python.
fn open_split_set(
    parts: &[PathBuf],
    options: &OpenOptions,
    recreate: bool,
) -> Result<Arc<dyn MountSource>, String> {
    if parts.is_empty() {
        return Err("empty split set".into());
    }
    let first = &parts[0];
    let joined_name = joined_base_name(first);
    let (tmp, size) = materialize_joined_parts(parts).map_err(|e| e.to_string())?;
    let tmp_path = tmp.path().to_path_buf();

    let mut opts = options.clone();
    if opts.index_file_path.is_none() && !opts.index_in_memory {
        let mut idx = first.as_os_str().to_os_string();
        idx.push(".index.sqlite");
        opts.index_file_path = Some(PathBuf::from(idx));
    }

    let compression = detect_compression(&tmp_path).map_err(|e| e.to_string())?;
    let looks_archive = compression != CompressionFormat::None
        || looks_like_tar(&tmp_path).unwrap_or(false)
        || looks_like_zip(&tmp_path)
        || looks_like_7z(&tmp_path)
        || looks_like_ar(&tmp_path)
        || looks_like_cpio(&tmp_path);

    if !looks_archive {
        // Plain joined file → virtual name without split suffix (Python SingleFileMountSource).
        return Ok(Arc::new(
            SingleFileMountSource::new(joined_name, tmp_path, size, Some(tmp))
                .map_err(|e| e.to_string())?,
        ));
    }

    // Archive/compressed stream: open without re-running split detection; keep temp alive.
    let inner = open_path_impl(&tmp_path, &opts, recreate, false)?;
    Ok(Arc::new(KeepAliveMount { inner, _tmp: tmp }))
}

struct KeepAliveMount {
    inner: Arc<dyn MountSource>,
    _tmp: tempfile::NamedTempFile,
}

impl MountSource for KeepAliveMount {
    fn list(&self, path: &str) -> Option<ratarmount_core::ListResult> {
        self.inner.list(path)
    }
    fn list_mode(&self, path: &str) -> Option<ratarmount_core::ListModeResult> {
        self.inner.list_mode(path)
    }
    fn lookup(&self, path: &str, file_version: i32) -> Option<ratarmount_core::FileInfo> {
        self.inner.lookup(path, file_version)
    }
    fn open(
        &self,
        file_info: &ratarmount_core::FileInfo,
        buffering: i32,
    ) -> std::io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        self.inner.open(file_info, buffering)
    }
    fn read(
        &self,
        file_info: &ratarmount_core::FileInfo,
        size: usize,
        offset: u64,
    ) -> std::io::Result<Vec<u8>> {
        self.inner.read(file_info, size, offset)
    }
    fn is_immutable(&self) -> bool {
        self.inner.is_immutable()
    }
    fn exists(&self, path: &str) -> bool {
        self.inner.exists(path)
    }
    fn is_dir(&self, path: &str) -> bool {
        self.inner.is_dir(path)
    }
}

/// Open a single path (file archive or directory).
pub fn open_path(
    path: &Path,
    options: &OpenOptions,
    recreate: bool,
) -> Result<Arc<dyn MountSource>, String> {
    open_path_impl(path, options, recreate, true)
}

fn open_path_impl(
    path: &Path,
    options: &OpenOptions,
    recreate: bool,
    allow_split: bool,
) -> Result<Arc<dyn MountSource>, String> {
    if path.is_dir() {
        // Git: bare repos / `.git` dirs (HEAD+objects, no nested `.git`), or force via env.
        // Normal worktrees keep FolderMountSource so the live working tree is shown.
        let is_git_dir_or_bare = path.join("HEAD").is_file()
            && path.join("objects").is_dir()
            && !path.join(".git").exists();
        let force_git = std::env::var_os("RATARMOUNT_FORCE_GIT").is_some();
        if (is_git_dir_or_bare || force_git) && looks_like_git(path) {
            return GitMountSource::open(path, None)
                .map(|g| Arc::new(g) as Arc<dyn MountSource>)
                .map_err(|e| e.to_string());
        }
        return FolderMountSource::new(path)
            .map(|f| Arc::new(f) as Arc<dyn MountSource>)
            .map_err(|e| e.to_string());
    }
    if !path.exists() {
        return Err(format!("not found: {}", path.display()));
    }

    // Multi-volume split files (Python check_for_split_file_in_folder + JoinedFile).
    if allow_split {
        if let Some(split) = check_for_split_file_in_folder(path) {
            return open_split_set(&split.paths, options, recreate);
        }
    }

    let compression = detect_compression(path).map_err(|e| e.to_string())?;
    let index_loc = resolved_index(path, options, recreate);
    // Propagate memory flag so format open() does not fall back to a disk path.
    let mut options = options.clone();
    if index_loc.is_memory() {
        options.index_in_memory = true;
        options.index_file_path = None;
    } else if let Some(p) = index_loc.as_path() {
        options.index_file_path = Some(p.to_path_buf());
        options.index_in_memory = false;
    }
    let index_path = index_arg(&index_loc);

    let source: Arc<dyn MountSource> = match compression {
        // Outer compression still wins (detect_compression first). Format
        // backends are reordered via options.use_backends only for plain files.
        CompressionFormat::None => open_uncompressed_path(path, index_path, &options, recreate)?,
        CompressionFormat::Gzip => open_gzip(path, index_path, &options, recreate)?,
        CompressionFormat::Bzip2 => {
            let threads = options.threads_for("bzip2");
            open_seekable_codec(path, index_path, &options, recreate, "bzip2", || {
                open_seekable_bzip2_with_threads(path, threads)
            })?
        }
        CompressionFormat::Xz => {
            open_seekable_codec(path, index_path, &options, recreate, "xz", || {
                open_seekable_xz(path)
            })?
        }
        CompressionFormat::Zstd => {
            open_seekable_codec(path, index_path, &options, recreate, "zstd", || {
                SeekableZstd::open(path)
            })?
        }
        CompressionFormat::Lz4 => {
            open_seekable_codec(path, index_path, &options, recreate, "lz4", || {
                open_seekable_lz4(path)
            })?
        }
        CompressionFormat::Lzip => {
            open_seekable_codec(path, index_path, &options, recreate, "lzip", || {
                open_seekable_lzip(path)
            })?
        }
        CompressionFormat::Lzo => {
            open_seekable_codec(path, index_path, &options, recreate, "lzo", || {
                open_seekable_lzo(path)
            })?
        }
        CompressionFormat::CompressZ => {
            open_seekable_codec(path, index_path, &options, recreate, "compress-z", || {
                open_seekable_compress_z(path)
            })?
        }
        CompressionFormat::Lzma => {
            open_seekable_codec(path, index_path, &options, recreate, "lzma", || {
                open_seekable_lzma(path)
            })?
        }
        CompressionFormat::Zlib => {
            open_seekable_codec(path, index_path, &options, recreate, "zlib", || {
                open_seekable_zlib(path)
            })?
        }
    };

    Ok(source)
}

fn open_tar(
    archive_path: &Path,
    data_path: &Path,
    index_path: Option<&Path>,
    options: &OpenOptions,
    recreate: bool,
    materialised: &mut Option<tempfile::NamedTempFile>,
) -> Result<SqliteIndexedTar, String> {
    if let Some(ip) = index_path {
        if !recreate && !options.index_in_memory && ip.exists() {
            let meta_ok = std::fs::metadata(ip).map(|m| m.len() > 0).unwrap_or(false);
            if meta_ok {
                match SqliteIndexedTar::open_with_existing_index(
                    archive_path,
                    data_path,
                    ip,
                    options.clone(),
                    materialised,
                ) {
                    Ok(s) => return Ok(s),
                    Err(e) => eprintln!("info: could not load index ({e}); rebuilding"),
                }
            }
        }
    }
    SqliteIndexedTar::create_index(
        archive_path,
        data_path,
        index_path,
        options,
        VERSION,
        materialised,
    )
    .map_err(|e| e.to_string())
}

/// Open gzip: G3 Tier B seekable checkpoints for `.tar.gz` / `.tgz`; materialize for plain `.gz`.
fn open_gzip(
    path: &Path,
    index_path: Option<&Path>,
    options: &OpenOptions,
    recreate: bool,
) -> Result<Arc<dyn MountSource>, String> {
    let spacing = if options.gzip_seek_point_spacing == 0 {
        ratarmount_compress::DEFAULT_GZIP_SEEK_SPACING
    } else {
        options.gzip_seek_point_spacing
    };

    // Prefer seekable path for names that clearly indicate compressed TAR.
    if name_suggests_compressed_tar(path) {
        let gzip = SharedSeekableGzip::open(path, spacing).map_err(|e| e.to_string())?;
        eprintln!(
            "seekable gzip: {} ({} uncompressed bytes, {} checkpoints)",
            path.display(),
            gzip.size(),
            gzip.checkpoint_count()
        );
        return Ok(Arc::new(open_tar_gzip(
            path, gzip, index_path, options, recreate,
        )?));
    }

    // Plain `.gz` (or ambiguous): materialize once; detect secret TAR / EXT4 body if present.
    let (tmp, size) = materialize(path, CompressionFormat::Gzip).map_err(|e| e.to_string())?;
    let data_path = tmp.path().to_path_buf();
    let mut materialised = Some(tmp);
    if looks_like_tar(&data_path).unwrap_or(false) {
        return Ok(Arc::new(open_tar(
            path,
            &data_path,
            index_path,
            options,
            recreate,
            &mut materialised,
        )?));
    }
    if looks_like_ext4(&data_path) {
        let keep = materialised
            .take()
            .ok_or_else(|| "materialized gzip missing".to_string())?
            .into_temp_path()
            .keep()
            .map_err(|e| e.error.to_string())?;
        return Ok(Arc::new(
            Ext4MountSource::open(&keep).map_err(|e| e.to_string())?,
        ));
    }
    if looks_like_fat(&data_path) {
        let keep = materialised
            .take()
            .ok_or_else(|| "materialized gzip missing".to_string())?
            .into_temp_path()
            .keep()
            .map_err(|e| e.error.to_string())?;
        return Ok(Arc::new(
            FatMountSource::open(&keep).map_err(|e| e.to_string())?,
        ));
    }
    if let Some(src) =
        try_stencil_archives_on_path(&data_path, index_path, options, recreate, &mut materialised)?
    {
        return Ok(src);
    }
    let stripped =
        strip_compression_suffix(path.file_name().and_then(|s| s.to_str()).unwrap_or("file"));
    Ok(Arc::new(
        SingleFileMountSource::new(stripped, data_path, size, materialised.take())
            .map_err(|e| e.to_string())?,
    ))
}

/// After compression materialize: prefer pure stencil ISO/WARC/XAR/CAB before libarchive.
fn try_stencil_archives_on_path(
    data_path: &Path,
    index_path: Option<&Path>,
    options: &OpenOptions,
    recreate: bool,
    materialised: &mut Option<tempfile::NamedTempFile>,
) -> Result<Option<Arc<dyn MountSource>>, String> {
    let keep_path =
        |materialised: &mut Option<tempfile::NamedTempFile>| -> Result<PathBuf, String> {
            if let Some(tmp) = materialised.take() {
                tmp.into_temp_path().keep().map_err(|e| e.error.to_string())
            } else {
                Ok(data_path.to_path_buf())
            }
        };

    if looks_like_iso(data_path) {
        let keep = keep_path(materialised)?;
        return Ok(Some(Arc::new(
            Iso9660MountSource::open(&keep, index_path, options, VERSION, recreate)
                .map_err(|e| e.to_string())?,
        )));
    }
    if looks_like_warc(data_path) {
        let keep = keep_path(materialised)?;
        return Ok(Some(Arc::new(
            WarcMountSource::open(&keep, index_path, options, VERSION, recreate)
                .map_err(|e| e.to_string())?,
        )));
    }
    if looks_like_xar(data_path) {
        let keep = keep_path(materialised)?;
        return Ok(Some(Arc::new(
            XarMountSource::open(&keep, index_path, options, VERSION, recreate)
                .map_err(|e| e.to_string())?,
        )));
    }
    if looks_like_cab(data_path) {
        let keep = keep_path(materialised)?;
        match CabMountSource::open(&keep, index_path, options, VERSION, recreate) {
            Ok(s) => return Ok(Some(Arc::new(s))),
            Err(CabError::UnsupportedCompression(_)) => {
                return Ok(Some(Arc::new(
                    LibarchiveMountSource::open(&keep, index_path, options, VERSION, recreate)
                        .map_err(|e| e.to_string())?,
                )));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(None)
}

fn open_tar_gzip(
    archive_path: &Path,
    gzip: Arc<SharedSeekableGzip>,
    index_path: Option<&Path>,
    options: &OpenOptions,
    recreate: bool,
) -> Result<SqliteIndexedTar, String> {
    if let Some(ip) = index_path {
        if !recreate && !options.index_in_memory && ip.exists() {
            let meta_ok = std::fs::metadata(ip).map(|m| m.len() > 0).unwrap_or(false);
            if meta_ok {
                match SqliteIndexedTar::open_with_existing_index_gzip(
                    archive_path,
                    Arc::clone(&gzip),
                    ip,
                    options.clone(),
                ) {
                    Ok(s) => return Ok(s),
                    Err(e) => eprintln!("info: could not load index ({e}); rebuilding"),
                }
            }
        }
    }
    SqliteIndexedTar::create_index_gzip(archive_path, gzip, index_path, options, VERSION)
        .map_err(|e| e.to_string())
}

/// Open bzip2/xz/zstd via SeekableBody (RAM/temp decode; multi-frame zstd when applicable).
fn open_seekable_codec(
    path: &Path,
    index_path: Option<&Path>,
    options: &OpenOptions,
    recreate: bool,
    label: &str,
    open_body: impl FnOnce() -> Result<Arc<dyn SeekableBody>, ratarmount_compress::CompressError>,
) -> Result<Arc<dyn MountSource>, String> {
    let body = open_body().map_err(|e| e.to_string())?;
    eprintln!(
        "seekable {label}: {} ({} uncompressed bytes, {} checkpoints, kind={})",
        path.display(),
        body.size(),
        body.checkpoint_count(),
        body.kind()
    );

    let is_tar = name_suggests_compressed_tar(path) || body_looks_like_tar(&body).unwrap_or(false);

    if is_tar {
        return Ok(Arc::new(open_tar_body(
            path, body, index_path, options, recreate,
        )?));
    }

    // Non-TAR: prefer detecting EXT4 / libarchive on a materialized body.
    // Drop seekable body first so we don't hold two full copies.
    let format = match label {
        "bzip2" => CompressionFormat::Bzip2,
        "xz" => CompressionFormat::Xz,
        "zstd" => CompressionFormat::Zstd,
        "lz4" => CompressionFormat::Lz4,
        "lzip" => CompressionFormat::Lzip,
        "lzo" => CompressionFormat::Lzo,
        "compress-z" => CompressionFormat::CompressZ,
        "lzma" => CompressionFormat::Lzma,
        "zlib" => CompressionFormat::Zlib,
        _ => CompressionFormat::Zstd,
    };
    drop(body);
    let (tmp, size) = materialize(path, format).map_err(|e| e.to_string())?;
    let data_path = tmp.path().to_path_buf();
    if looks_like_ext4(&data_path) {
        let keep = tmp
            .into_temp_path()
            .keep()
            .map_err(|e| e.error.to_string())?;
        return Ok(Arc::new(
            Ext4MountSource::open(&keep).map_err(|e| e.to_string())?,
        ));
    }
    if looks_like_fat(&data_path) {
        let keep = tmp
            .into_temp_path()
            .keep()
            .map_err(|e| e.error.to_string())?;
        return Ok(Arc::new(
            FatMountSource::open(&keep).map_err(|e| e.to_string())?,
        ));
    }
    let mut materialised = Some(tmp);
    if let Some(src) =
        try_stencil_archives_on_path(&data_path, index_path, options, recreate, &mut materialised)?
    {
        return Ok(src);
    }
    if looks_like_libarchive(&data_path) {
        let keep = materialised
            .take()
            .ok_or_else(|| "materialized body missing".to_string())?
            .into_temp_path()
            .keep()
            .map_err(|e| e.error.to_string())?;
        return Ok(Arc::new(
            LibarchiveMountSource::open(&keep, index_path, options, VERSION, recreate)
                .map_err(|e| e.to_string())?,
        ));
    }
    let stripped =
        strip_compression_suffix(path.file_name().and_then(|s| s.to_str()).unwrap_or("file"));
    Ok(Arc::new(
        SingleFileMountSource::new(stripped, data_path, size, materialised.take())
            .map_err(|e| e.to_string())?,
    ))
}

fn open_tar_body(
    archive_path: &Path,
    body: Arc<dyn SeekableBody>,
    index_path: Option<&Path>,
    options: &OpenOptions,
    recreate: bool,
) -> Result<SqliteIndexedTar, String> {
    if let Some(ip) = index_path {
        if !recreate && !options.index_in_memory && ip.exists() {
            let meta_ok = std::fs::metadata(ip).map(|m| m.len() > 0).unwrap_or(false);
            if meta_ok {
                match SqliteIndexedTar::open_with_existing_index_body(
                    archive_path,
                    Arc::clone(&body),
                    ip,
                    options.clone(),
                ) {
                    Ok(s) => return Ok(s),
                    Err(e) => eprintln!("info: could not load index ({e}); rebuilding"),
                }
            }
        }
    }
    SqliteIndexedTar::create_index_body(archive_path, body, index_path, options, VERSION)
        .map_err(|e| e.to_string())
}

/// Holds remote downloads for process lifetime (deleted on drop).
pub struct MountBundle {
    pub source: Arc<dyn MountSource>,
    /// Fetched HTTP bodies etc. must outlive `source`.
    _remotes: Vec<ratarmount_remote::RemoteLocal>,
}

/// Extra compositing options beyond [`OpenOptions`].
#[derive(Clone, Debug, Default)]
pub struct CompositingOptions {
    pub recursive: bool,
    /// When true with recursive, mount nested archives on first access.
    pub lazy: bool,
    pub file_versions: bool,
    pub prefix: Option<String>,
    /// Mount `foo.tar` at `foo/` instead of `foo.tar/`.
    pub strip_recursive_extension: bool,
    /// Regex `(pattern, replacement)` for nested mount points.
    pub transform_recursive: Option<(String, String)>,
    /// Python `--transform` member path rewrite.
    pub transform: Option<(String, String)>,
    /// Python `--disable-union-mount`: each source under its basename.
    pub disable_union_mount: bool,
    /// Python `--recursive-extensions` selection string.
    pub recursive_extensions: Option<String>,
    /// Union folder-cache knobs (Python `--union-mount-cache-*`).
    pub union_cache: UnionMountOptions,
}

/// Build final mount source from one or more inputs (local paths or URLs).
#[allow(dead_code)]
pub fn build_mount_source(
    paths: &[PathBuf],
    options: &OpenOptions,
    recreate: bool,
    recursive: bool,
) -> Result<MountBundle, String> {
    build_mount_source_ex(
        paths,
        options,
        recreate,
        CompositingOptions {
            recursive,
            lazy: false,
            file_versions: true,
            prefix: None,
            strip_recursive_extension: false,
            transform_recursive: None,
            transform: None,
            disable_union_mount: false,
            recursive_extensions: None,
            union_cache: UnionMountOptions::default(),
        },
    )
}

/// Build with full compositing knobs (versions, prefix, lazy).
pub fn build_mount_source_ex(
    paths: &[PathBuf],
    options: &OpenOptions,
    recreate: bool,
    comp: CompositingOptions,
) -> Result<MountBundle, String> {
    if paths.is_empty() {
        return Err("no input paths".into());
    }
    let ext_set: RecursiveExtSet = comp
        .recursive_extensions
        .as_deref()
        .map(parse_recursive_extensions)
        .unwrap_or_default();
    let mut sources = Vec::new();
    let mut remotes = Vec::new();
    for p in paths {
        let input = p.to_string_lossy();
        let local_path = if ratarmount_remote::is_remote_url(&input) {
            let remote = ratarmount_remote::resolve_to_local(&input).map_err(|e| e.to_string())?;
            let path = remote.path().to_path_buf();
            remotes.push(remote);
            path
        } else {
            p.clone()
        };

        // Do not force a default index path here — `open_path` resolves via folders / :memory:.
        let mut opts = options.clone();
        if opts.read_only_index {
            opts.write_index = false;
            opts.clear_index_cache = false;
        }
        let mut src = open_path(&local_path, &opts, recreate && !opts.read_only_index)?;
        if let Some((ref pat, ref rep)) = comp.transform {
            src = Arc::new(TransformMountSource::new(pat, rep, src)?);
        }
        if comp.recursive {
            let opener = open_nested_fn(opts.clone());
            // Negative depth (Python -1) → deep default handled inside AutoMountLayer (0 → 32).
            let depth = match opts.recursion_depth.unwrap_or(0) {
                d if d < 0 => 0,
                d => d as u32,
            };
            src = Arc::new(AutoMountLayer::new_with_options(
                src,
                depth,
                opener,
                AutoMountOptions {
                    lazy: comp.lazy,
                    strip_recursive_extension: comp.strip_recursive_extension,
                    transform: comp.transform_recursive.clone(),
                    recursive_extensions: ext_set.clone(),
                },
            ));
        }
        if comp.disable_union_mount && paths.len() > 1 {
            let name = local_path
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("source");
            // strip common archive extension for folder name
            let folder = strip_source_name(name);
            src = Arc::new(PrefixMountSource::new(&folder, src));
        }
        sources.push(src);
    }
    let mut source = if sources.len() == 1 {
        sources.pop().unwrap()
    } else {
        Arc::new(UnionMountSource::new_with_options(
            sources,
            comp.union_cache.clone(),
        ))
    };
    if comp.file_versions {
        source = Arc::new(FileVersionLayer::new(source));
    }
    if let Some(ref p) = comp.prefix {
        if !p.is_empty() {
            source = Arc::new(PrefixMountSource::new(p, source));
        }
    }
    Ok(MountBundle {
        source,
        _remotes: remotes,
    })
}

fn strip_source_name(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    for suf in [
        ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".tar", ".tgz", ".zip", ".7z", ".rar",
    ] {
        if lower.ends_with(suf) && name.len() > suf.len() {
            return name[..name.len() - suf.len()].to_string();
        }
    }
    name.to_string()
}
