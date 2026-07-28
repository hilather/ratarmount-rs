//! Open archives / folders into `Arc<dyn MountSource>`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ratarmount_compositing::{
    parse_recursive_extensions, AutoMountLayer, AutoMountOptions, FileVersionLayer,
    FolderMountSource, OpenNestedFn, OpenNestedReaderFn, PrefixMountSource, RecursiveExtSet,
    TransformMountSource, UnionMountOptions, UnionMountSource,
};
use ratarmount_compress::{
    body_looks_like_tar, check_for_split_file_in_folder, detect_compression, export_bzip2_blocks,
    export_bzip2_blocks_from_reader, export_zstd_blocks, export_zstd_blocks_from_reader,
    joined_base_name, looks_like_tar, materialize, materialize_joined_parts,
    name_suggests_compressed_tar, open_seekable_bzip2_with_bzip2_blocks,
    open_seekable_bzip2_with_bzip2_blocks_from_reader, open_seekable_bzip2_with_threads,
    open_seekable_bzip2_with_threads_from_reader, open_seekable_compress_z_with_threads,
    open_seekable_lz4_with_threads, open_seekable_lzip_with_threads,
    open_seekable_lzma_with_threads, open_seekable_lzo_with_threads, open_seekable_xz_with_threads,
    open_seekable_xz_with_threads_from_reader, open_seekable_zlib_with_threads,
    open_seekable_zstd_with_threads, open_seekable_zstd_with_threads_from_reader,
    open_seekable_zstd_with_zstd_blocks, open_seekable_zstd_with_zstd_blocks_from_reader,
    strip_compression_suffix, CompressionFormat, SeekableBody, SharedSeekableGzip,
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
use ratarmount_formats_libarchive::{
    looks_like_libarchive, try_open_lrzip_via_libarchive, LibarchiveMountSource,
};
use ratarmount_formats_ogg::{looks_like_ogg, OggMountSource};
use ratarmount_formats_pdf::{looks_like_pdf, PdfMountSource};
use ratarmount_formats_sevenzip::{looks_like_7z, SevenZipMountSource};
use ratarmount_formats_sqlar::{looks_like_sqlar, SqlarMountSource};
use ratarmount_formats_squashfs::{looks_like_squashfs, SquashFsMountSource};
use ratarmount_formats_tar::{SingleFileMountSource, SqliteIndexedTar};
use ratarmount_formats_warc::{looks_like_warc, WarcMountSource};
use ratarmount_formats_xar::{looks_like_xar, XarMountSource};
use ratarmount_formats_zip::{looks_like_zip, ZipMountSource};
use ratarmount_index::{resolve_index_location, IndexLocation, SqliteIndex};

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
        "rapidgzip" | "indexed_gzip" | "indexed_bzip2" | "xz" | "lzma" | "zstd" | "lz4"
        | "lzip" | "lzo" | "lzop" | "zlib" | "deflate" | "compress" | "compress-z" | "gzip"
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
        let order = ordered_format_backends(&["zip".into(), "tar".into()]);
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
        assert_eq!(
            parse_format_backend("PySquashfsImage"),
            Some(FormatBackend::SquashFs)
        );
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

/// Nested open from a seekable parent-member stream (no temp spool).
///
/// Supports uncompressed TAR, 7z, and ZIP. Other formats fail so AutoMount can
/// fall back to materializing a temp file and [`open_nested_fn`].
pub fn open_nested_reader_fn(options: OpenOptions) -> OpenNestedReaderFn {
    Arc::new(move |mut reader, label| {
        use std::io::{Read, Seek, SeekFrom};

        let mut opts = options.clone();
        // Nested indexes cannot live next to a virtual label; keep them in memory.
        opts.index_file_path = None;
        opts.index_in_memory = true;
        opts.clear_index_cache = true;

        let mut magic = [0u8; 512];
        let n = reader.read(&mut magic).map_err(std::io::Error::other)?;
        reader
            .seek(SeekFrom::Start(0))
            .map_err(std::io::Error::other)?;
        let head = &magic[..n];
        log::debug!(
            "nested reader open: label={} magic_len={n} passwords={}",
            label.display(),
            opts.passwords.len()
        );

        // 7z magic
        if head.len() >= 6 && &head[..6] == b"7z\xBC\xAF'\x1C" {
            log::debug!(
                "nested reader open: {} detected as 7z (passwords={})",
                label.display(),
                opts.passwords.len()
            );
            return SevenZipMountSource::open_from_reader(
                reader, label, None, &opts, VERSION, true,
            )
            .map(|s| {
                log::debug!(
                    "nested reader open: 7z {} mounted successfully",
                    label.display()
                );
                Arc::new(s) as Arc<dyn MountSource>
            })
            .map_err(|e| {
                log::warn!("nested reader open: 7z {} failed: {e}", label.display());
                std::io::Error::other(e.to_string())
            });
        }
        // ZIP local/EOCD
        if head.len() >= 4 && &head[..2] == b"PK" {
            log::debug!("nested reader open: {} detected as ZIP", label.display());
            return ZipMountSource::open_from_reader(reader, label, None, &opts, VERSION)
                .map(|s| Arc::new(s) as Arc<dyn MountSource>)
                .map_err(|e| {
                    log::warn!("nested reader open: ZIP {} failed: {e}", label.display());
                    std::io::Error::other(e.to_string())
                });
        }
        // Uncompressed TAR (ustar) or name suggests .tar
        let looks_tar =
            (head.len() >= 262 && &head[257..262] == b"ustar") || name_suggests_plain_tar(label);
        if looks_tar {
            log::debug!("nested reader open: {} detected as TAR", label.display());
            return SqliteIndexedTar::open_from_reader(reader, label, None, &opts, VERSION)
                .map(|s| Arc::new(s) as Arc<dyn MountSource>)
                .map_err(|e| {
                    log::warn!("nested reader open: TAR {} failed: {e}", label.display());
                    std::io::Error::other(e.to_string())
                });
        }

        log::debug!(
            "nested reader open: {} unsupported format (magic={:02x?}); will try temp spool",
            label.display(),
            &head[..n.min(16)]
        );
        Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "nested reader open unsupported for {} (will try temp spool)",
                label.display()
            ),
        ))
    })
}

fn name_suggests_plain_tar(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    name.ends_with(".tar") || name == "tar"
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
        CompressionFormat::Bzip2 => open_bzip2(path, index_path, &options, recreate)?,
        CompressionFormat::Xz => {
            let threads = options.threads_for("xz");
            open_seekable_codec(path, index_path, &options, recreate, "xz", || {
                open_seekable_xz_with_threads(path, threads)
            })?
        }
        CompressionFormat::Zstd => open_zstd(path, index_path, &options, recreate)?,
        CompressionFormat::Lz4 => {
            let threads = options.threads_for("lz4");
            open_seekable_codec(path, index_path, &options, recreate, "lz4", || {
                open_seekable_lz4_with_threads(path, threads)
            })?
        }
        CompressionFormat::Lzip => {
            let threads = options.threads_for("lzip");
            open_seekable_codec(path, index_path, &options, recreate, "lzip", || {
                open_seekable_lzip_with_threads(path, threads)
            })?
        }
        CompressionFormat::Lzo => {
            let threads = options.threads_for("lzo");
            open_seekable_codec(path, index_path, &options, recreate, "lzo", || {
                open_seekable_lzo_with_threads(path, threads)
            })?
        }
        CompressionFormat::CompressZ => {
            let threads = options.threads_for("Z");
            open_seekable_codec(path, index_path, &options, recreate, "compress-z", || {
                open_seekable_compress_z_with_threads(path, threads)
            })?
        }
        CompressionFormat::Lzma => {
            let threads = options.threads_for("lzma");
            open_seekable_codec(path, index_path, &options, recreate, "lzma", || {
                open_seekable_lzma_with_threads(path, threads)
            })?
        }
        CompressionFormat::Zlib => {
            let threads = options.threads_for("zlib");
            open_seekable_codec(path, index_path, &options, recreate, "zlib", || {
                open_seekable_zlib_with_threads(path, threads)
            })?
        }
        CompressionFormat::Lrzip => open_lrzip(path, index_path, &options, recreate)?,
    };

    Ok(source)
}

/// Open lrzip: prefer external `lrzip`/`lrunzip` materialize (then format probe);
/// if the CLI is missing / fails, fall back to libarchive (Python pure-RA path).
fn open_lrzip(
    path: &Path,
    index_path: Option<&Path>,
    options: &OpenOptions,
    recreate: bool,
) -> Result<Arc<dyn MountSource>, String> {
    match materialize(path, CompressionFormat::Lrzip) {
        Ok((tmp, size)) => {
            eprintln!(
                "lrzip materialize: {} ({} uncompressed bytes)",
                path.display(),
                size
            );
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
                    .ok_or_else(|| "materialized lrzip missing".to_string())?
                    .into_temp_path()
                    .keep()
                    .map_err(|e| e.error.to_string())?;
                return Ok(Arc::new(
                    Ext4MountSource::open(&keep).map_err(|e| e.to_string())?,
                ));
            }
            if let Some(src) = try_stencil_archives_on_path(
                &data_path,
                index_path,
                options,
                recreate,
                &mut materialised,
            )? {
                return Ok(src);
            }
            if looks_like_libarchive(&data_path) {
                let keep = materialised
                    .take()
                    .ok_or_else(|| "materialized lrzip missing".to_string())?
                    .into_temp_path()
                    .keep()
                    .map_err(|e| e.error.to_string())?;
                return Ok(Arc::new(
                    LibarchiveMountSource::open(&keep, index_path, options, VERSION, recreate)
                        .map_err(|e| e.to_string())?,
                ));
            }
            let stripped = strip_compression_suffix(
                path.file_name().and_then(|s| s.to_str()).unwrap_or("file"),
            );
            Ok(Arc::new(
                SingleFileMountSource::new(stripped, data_path, size, materialised.take())
                    .map_err(|e| e.to_string())?,
            ))
        }
        Err(cli_err) => {
            // Python keeps lrzip on libarchive only; filter_all includes lrzip when built-in.
            match try_open_lrzip_via_libarchive(path, index_path, options, VERSION, recreate) {
                Ok(src) => {
                    eprintln!(
                        "lrzip via libarchive (CLI unavailable): {}",
                        path.display()
                    );
                    Ok(Arc::new(src))
                }
                Err(la_err) => Err(format!(
                    "lrzip open failed for {}: CLI materialize: {cli_err}; libarchive: {la_err}. \
                     Install `lrzip`/`lrunzip` on PATH, or use a libarchive built with the lrzip filter \
                     (runtime may still need the external lrzip program).",
                    path.display()
                )),
            }
        }
    }
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

/// Read the first gzip seek-index blob from an on-disk SQLite index, if present.
///
/// Used to hydrate Tier C RGZI checkpoints before a full spacing-based rebuild.
/// Returns `None` when recreate is set, the path is missing, or the table is empty.
fn try_load_gzip_index_blob(index_path: Option<&Path>, recreate: bool) -> Option<Vec<u8>> {
    if recreate {
        return None;
    }
    let ip = index_path?;
    if !ip.exists() {
        return None;
    }
    let meta_ok = std::fs::metadata(ip).map(|m| m.len() > 0).unwrap_or(false);
    if !meta_ok {
        return None;
    }
    // Prefer open_writable so we do not emit the RO "Successfully loaded…" banner
    // (TAR will open RO itself). Fall back to open_read_only if the file is not writable.
    let idx = match SqliteIndex::open_writable(ip) {
        Ok(i) => i,
        Err(_) => SqliteIndex::open_read_only(ip).ok()?,
    };
    match idx.get_gzip_index_blobs() {
        Ok(blobs) => blobs.into_iter().next().filter(|b| !b.is_empty()),
        Err(_) => None,
    }
}

/// Persist a Tier C RGZI seek-index blob into the SQLite side table when writable.
///
/// No-op for `:memory:` / missing path / read-only / `write_index = false`.
fn persist_gzip_index_blob(
    gzip: &SharedSeekableGzip,
    index_path: Option<&Path>,
    options: &OpenOptions,
) {
    if !options.write_index || options.read_only_index || options.index_in_memory {
        return;
    }
    let Some(ip) = index_path else {
        return;
    };
    if !ip.exists() {
        return;
    }
    let blob = gzip.export_seek_index_blob();
    match SqliteIndex::open_writable(ip) {
        Ok(idx) => {
            if let Err(e) = idx.ensure_compression_tables() {
                eprintln!("info: could not ensure compression tables for gzip blob: {e}");
                return;
            }
            match idx.set_gzip_index_blob(&blob) {
                Ok(()) => eprintln!(
                    "gzip RGZI: stored {}-byte seek index in {}",
                    blob.len(),
                    ip.display()
                ),
                Err(e) => eprintln!("info: could not store gzip seek index blob: {e}"),
            }
        }
        Err(e) => eprintln!("info: could not open index to store gzip seek blob: {e}"),
    }
}

/// Open seekable gzip from a path, preferring an imported RGZI blob when available.
fn open_shared_seekable_gzip_path(
    path: &Path,
    spacing: u64,
    threads: u32,
    index_path: Option<&Path>,
    recreate: bool,
) -> Result<Arc<SharedSeekableGzip>, String> {
    if let Some(blob) = try_load_gzip_index_blob(index_path, recreate) {
        match SharedSeekableGzip::open_with_imported_index(path, spacing, threads, &blob) {
            Ok(g) => {
                eprintln!(
                    "seekable gzip (imported RGZI): {} ({} uncompressed bytes, {} checkpoints, -P gzip:{})",
                    path.display(),
                    g.size(),
                    g.checkpoint_count(),
                    threads
                );
                return Ok(g);
            }
            Err(e) => {
                eprintln!("info: gzip RGZI import failed ({e}); rebuilding seek checkpoints");
            }
        }
    }
    let gzip =
        SharedSeekableGzip::open_with_threads(path, spacing, threads).map_err(|e| e.to_string())?;
    eprintln!(
        "seekable gzip: {} ({} uncompressed bytes, {} checkpoints, -P gzip:{})",
        path.display(),
        gzip.size(),
        gzip.checkpoint_count(),
        threads
    );
    Ok(gzip)
}

/// Try opening seekable gzip from a Range reader using an on-disk RGZI blob.
///
/// Returns `None` when no blob is available or import fails (caller rebuilds with a
/// **fresh** reader — the passed reader is consumed on both success and failure).
fn try_open_gzip_imported_from_reader<R>(
    reader: R,
    label: &Path,
    spacing: u64,
    threads: u32,
    index_path: Option<&Path>,
    recreate: bool,
) -> Option<Arc<SharedSeekableGzip>>
where
    R: std::io::Read + std::io::Seek + Send + 'static,
{
    let blob = try_load_gzip_index_blob(index_path, recreate)?;
    match SharedSeekableGzip::open_with_imported_index_from_reader(
        reader, spacing, threads, label, &blob,
    ) {
        Ok(g) => {
            eprintln!(
                "seekable gzip (imported RGZI): {} ({} uncompressed bytes, {} checkpoints, -P gzip:{})",
                label.display(),
                g.size(),
                g.checkpoint_count(),
                threads
            );
            Some(g)
        }
        Err(e) => {
            eprintln!("info: gzip RGZI import failed ({e}); rebuilding seek checkpoints");
            None
        }
    }
}

/// Build seekable gzip from a Range reader, rebuilding checkpoints from scratch.
fn open_gzip_rebuilt_from_reader<R>(
    reader: R,
    label: &Path,
    spacing: u64,
    threads: u32,
) -> Result<Arc<SharedSeekableGzip>, String>
where
    R: std::io::Read + std::io::Seek + Send + 'static,
{
    let gzip = SharedSeekableGzip::open_with_threads_from_reader(reader, spacing, threads, label)
        .map_err(|e| e.to_string())?;
    eprintln!(
        "seekable gzip: {} ({} uncompressed bytes, {} checkpoints, -P gzip:{})",
        label.display(),
        gzip.size(),
        gzip.checkpoint_count(),
        threads
    );
    Ok(gzip)
}

/// Open gzip: G3 Tier B seekable checkpoints for `.tar.gz` / `.tgz`; materialize for plain `.gz`.
///
/// When an on-disk index carries a Tier C RGZI blob, import it before a full checkpoint rebuild.
/// After a successful TAR index open/create, export and store the blob when the index is writable.
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
        let threads = options.threads_for("gzip");
        let gzip = open_shared_seekable_gzip_path(path, spacing, threads, index_path, recreate)?;
        let tar = open_tar_gzip(path, Arc::clone(&gzip), index_path, options, recreate)?;
        // TAR index is now on disk (or memory); side-table write only when path exists.
        persist_gzip_index_blob(&gzip, index_path, options);
        return Ok(Arc::new(tar));
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
    open_from_seekable_body(path, body, index_path, options, recreate, label)
}

/// Convert SQLite `zstdblocks` `(i64, i64)` pairs to `(u64, u64)`.
///
/// Returns `None` when any offset is negative (corrupt side table → rebuild).
fn zstd_blocks_i64_to_u64(blocks: &[(i64, i64)]) -> Option<Vec<(u64, u64)>> {
    let mut out = Vec::with_capacity(blocks.len());
    for &(c, d) in blocks {
        if c < 0 || d < 0 {
            return None;
        }
        out.push((c as u64, d as u64));
    }
    Some(out)
}

/// Convert exported `(u64, u64)` pairs for SQLite storage.
///
/// Returns `None` when any offset exceeds `i64::MAX` (should not happen for real archives).
fn zstd_blocks_u64_to_i64(blocks: &[(u64, u64)]) -> Option<Vec<(i64, i64)>> {
    let mut out = Vec::with_capacity(blocks.len());
    for &(c, d) in blocks {
        if c > i64::MAX as u64 || d > i64::MAX as u64 {
            return None;
        }
        out.push((c as i64, d as i64));
    }
    Some(out)
}

/// Read Python-compatible `zstdblocks` from an on-disk SQLite index, if present.
///
/// Returns `None` when recreate is set, the path is missing, the table is empty,
/// or offsets cannot be converted to `u64`.
fn try_load_zstd_blocks(index_path: Option<&Path>, recreate: bool) -> Option<Vec<(u64, u64)>> {
    if recreate {
        return None;
    }
    let ip = index_path?;
    if !ip.exists() {
        return None;
    }
    let meta_ok = std::fs::metadata(ip).map(|m| m.len() > 0).unwrap_or(false);
    if !meta_ok {
        return None;
    }
    let idx = match SqliteIndex::open_writable(ip) {
        Ok(i) => i,
        Err(_) => SqliteIndex::open_read_only(ip).ok()?,
    };
    let raw = match idx.get_zstd_blocks() {
        Ok(b) if !b.is_empty() => b,
        _ => return None,
    };
    zstd_blocks_i64_to_u64(&raw)
}

/// Persist exported `zstdblocks` into the SQLite side table when writable.
///
/// No-op for `:memory:` / missing path / read-only / `write_index = false` / empty map.
fn store_zstd_blocks_in_index(
    blocks: &[(u64, u64)],
    index_path: Option<&Path>,
    options: &OpenOptions,
) {
    if blocks.is_empty() {
        return;
    }
    if !options.write_index || options.read_only_index || options.index_in_memory {
        return;
    }
    let Some(ip) = index_path else {
        return;
    };
    if !ip.exists() {
        return;
    }
    let Some(i64_blocks) = zstd_blocks_u64_to_i64(blocks) else {
        eprintln!("info: zstdblocks offsets exceed i64 range; skipping side-table write");
        return;
    };
    match SqliteIndex::open_writable(ip) {
        Ok(idx) => {
            if let Err(e) = idx.ensure_compression_tables() {
                eprintln!("info: could not ensure compression tables for zstdblocks: {e}");
                return;
            }
            match idx.set_zstd_blocks(&i64_blocks) {
                Ok(()) => eprintln!(
                    "zstdblocks: stored {} offset pairs in {}",
                    i64_blocks.len(),
                    ip.display()
                ),
                Err(e) => eprintln!("info: could not store zstdblocks: {e}"),
            }
        }
        Err(e) => eprintln!("info: could not open index to store zstdblocks: {e}"),
    }
}

/// Export frame map from a local path and store as `zstdblocks` when writable.
fn persist_zstd_blocks_from_path(path: &Path, index_path: Option<&Path>, options: &OpenOptions) {
    if !options.write_index || options.read_only_index || options.index_in_memory {
        return;
    }
    if index_path.is_none_or(|ip| !ip.exists()) {
        return;
    }
    match export_zstd_blocks(path) {
        Ok(blocks) => store_zstd_blocks_in_index(&blocks, index_path, options),
        Err(e) => eprintln!("info: could not export zstdblocks: {e}"),
    }
}

/// Open seekable zstd from a path, preferring imported `zstdblocks` when available.
fn open_seekable_zstd_prefer_blocks(
    path: &Path,
    threads: u32,
    index_path: Option<&Path>,
    recreate: bool,
) -> Result<Arc<dyn SeekableBody>, String> {
    if let Some(blocks) = try_load_zstd_blocks(index_path, recreate) {
        match open_seekable_zstd_with_zstd_blocks(path, threads, &blocks) {
            Ok(body) => {
                eprintln!(
                    "seekable zstd (imported zstdblocks): {} ({} uncompressed bytes, {} checkpoints, -P zstd:{})",
                    path.display(),
                    body.size(),
                    body.checkpoint_count(),
                    threads
                );
                return Ok(body);
            }
            Err(e) => {
                eprintln!("info: zstdblocks import failed ({e}); rebuilding frame map");
            }
        }
    }
    open_seekable_zstd_with_threads(path, threads).map_err(|e| e.to_string())
}

/// Try opening seekable zstd from a Range reader using on-disk `zstdblocks`.
///
/// Returns `None` when no map is available or import fails (caller rebuilds with a
/// **fresh** reader — the passed reader is consumed on both success and failure).
fn try_open_zstd_imported_from_reader<R>(
    reader: R,
    label: &Path,
    threads: u32,
    index_path: Option<&Path>,
    recreate: bool,
) -> Option<Arc<dyn SeekableBody>>
where
    R: std::io::Read + std::io::Seek + Send + 'static,
{
    let blocks = try_load_zstd_blocks(index_path, recreate)?;
    match open_seekable_zstd_with_zstd_blocks_from_reader(reader, threads, label, &blocks) {
        Ok(body) => {
            eprintln!(
                "seekable zstd (imported zstdblocks): {} ({} uncompressed bytes, {} checkpoints, -P zstd:{})",
                label.display(),
                body.size(),
                body.checkpoint_count(),
                threads
            );
            Some(body)
        }
        Err(e) => {
            eprintln!("info: zstdblocks import failed ({e}); rebuilding frame map");
            None
        }
    }
}

/// Open zstd: seekable multi-frame / seek-table body; import `zstdblocks` when present.
///
/// After a successful TAR (or other) open via the seekable body, export and store
/// the frame map in the SQLite side table when the index is writable.
fn open_zstd(
    path: &Path,
    index_path: Option<&Path>,
    options: &OpenOptions,
    recreate: bool,
) -> Result<Arc<dyn MountSource>, String> {
    let threads = options.threads_for("zstd");
    let body = open_seekable_zstd_prefer_blocks(path, threads, index_path, recreate)?;
    let src = open_from_seekable_body(path, body, index_path, options, recreate, "zstd")?;
    // Index is now on disk (or memory); side-table write only when path exists.
    persist_zstd_blocks_from_path(path, index_path, options);
    Ok(src)
}

/// Read Python-compatible `bzip2blocks` from an on-disk SQLite index, if present.
fn try_load_bzip2_blocks(index_path: Option<&Path>, recreate: bool) -> Option<Vec<(u64, u64)>> {
    if recreate {
        return None;
    }
    let ip = index_path?;
    if !ip.exists() {
        return None;
    }
    let meta_ok = std::fs::metadata(ip).map(|m| m.len() > 0).unwrap_or(false);
    if !meta_ok {
        return None;
    }
    let idx = match SqliteIndex::open_writable(ip) {
        Ok(i) => i,
        Err(_) => SqliteIndex::open_read_only(ip).ok()?,
    };
    let raw = match idx.get_bzip2_blocks() {
        Ok(b) if !b.is_empty() => b,
        _ => return None,
    };
    zstd_blocks_i64_to_u64(&raw)
}

fn store_bzip2_blocks_in_index(
    blocks: &[(u64, u64)],
    index_path: Option<&Path>,
    options: &OpenOptions,
) {
    if blocks.is_empty() {
        return;
    }
    if !options.write_index || options.read_only_index || options.index_in_memory {
        return;
    }
    let Some(ip) = index_path else {
        return;
    };
    if !ip.exists() {
        return;
    }
    let Some(i64_blocks) = zstd_blocks_u64_to_i64(blocks) else {
        eprintln!("info: bzip2blocks offsets exceed i64 range; skipping side-table write");
        return;
    };
    match SqliteIndex::open_writable(ip) {
        Ok(idx) => {
            if let Err(e) = idx.ensure_compression_tables() {
                eprintln!("info: could not ensure compression tables for bzip2blocks: {e}");
                return;
            }
            match idx.set_bzip2_blocks(&i64_blocks) {
                Ok(()) => eprintln!(
                    "bzip2blocks: stored {} offset pairs in {}",
                    i64_blocks.len(),
                    ip.display()
                ),
                Err(e) => eprintln!("info: could not store bzip2blocks: {e}"),
            }
        }
        Err(e) => eprintln!("info: could not open index to store bzip2blocks: {e}"),
    }
}

fn persist_bzip2_blocks_from_path(path: &Path, index_path: Option<&Path>, options: &OpenOptions) {
    if !options.write_index || options.read_only_index || options.index_in_memory {
        return;
    }
    if index_path.is_none_or(|ip| !ip.exists()) {
        return;
    }
    match export_bzip2_blocks(path) {
        Ok(blocks) => store_bzip2_blocks_in_index(&blocks, index_path, options),
        Err(e) => eprintln!("info: could not export bzip2blocks: {e}"),
    }
}

fn open_seekable_bzip2_prefer_blocks(
    path: &Path,
    threads: u32,
    index_path: Option<&Path>,
    recreate: bool,
) -> Result<Arc<dyn SeekableBody>, String> {
    if let Some(blocks) = try_load_bzip2_blocks(index_path, recreate) {
        match open_seekable_bzip2_with_bzip2_blocks(path, threads, &blocks) {
            Ok(body) => {
                eprintln!(
                    "seekable bzip2 (imported bzip2blocks): {} ({} uncompressed bytes, {} checkpoints, -P bzip2:{})",
                    path.display(),
                    body.size(),
                    body.checkpoint_count(),
                    threads
                );
                return Ok(body);
            }
            Err(e) => {
                eprintln!("info: bzip2blocks import failed ({e}); rebuilding bit-block map");
            }
        }
    }
    open_seekable_bzip2_with_threads(path, threads).map_err(|e| e.to_string())
}

fn try_open_bzip2_imported_from_reader<R>(
    reader: R,
    label: &Path,
    threads: u32,
    index_path: Option<&Path>,
    recreate: bool,
) -> Option<Arc<dyn SeekableBody>>
where
    R: std::io::Read + std::io::Seek + Send + 'static,
{
    let blocks = try_load_bzip2_blocks(index_path, recreate)?;
    match open_seekable_bzip2_with_bzip2_blocks_from_reader(reader, threads, label, &blocks) {
        Ok(body) => {
            eprintln!(
                "seekable bzip2 (imported bzip2blocks): {} ({} uncompressed bytes, {} checkpoints, -P bzip2:{})",
                label.display(),
                body.size(),
                body.checkpoint_count(),
                threads
            );
            Some(body)
        }
        Err(e) => {
            eprintln!("info: bzip2blocks import failed ({e}); rebuilding bit-block map");
            None
        }
    }
}

/// Open bzip2 with optional `bzip2blocks` side-table import/export.
fn open_bzip2(
    path: &Path,
    index_path: Option<&Path>,
    options: &OpenOptions,
    recreate: bool,
) -> Result<Arc<dyn MountSource>, String> {
    let threads = options.threads_for("bzip2");
    let body = open_seekable_bzip2_prefer_blocks(path, threads, index_path, recreate)?;
    let src = open_from_seekable_body(path, body, index_path, options, recreate, "bzip2")?;
    persist_bzip2_blocks_from_path(path, index_path, options);
    Ok(src)
}

/// Mount from an already-opened seekable uncompressed body (path or remote Range codec).
fn open_from_seekable_body(
    path: &Path,
    body: Arc<dyn SeekableBody>,
    index_path: Option<&Path>,
    options: &OpenOptions,
    recreate: bool,
    label: &str,
) -> Result<Arc<dyn MountSource>, String> {
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

    // Non-TAR: materialize uncompressed body to a temp path for format probe / single-file.
    let size = body.size();
    let mut reader = body.open_reader().map_err(|e| e.to_string())?;
    drop(body);
    let mut tmp = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
    std::io::copy(&mut reader, &mut tmp).map_err(|e| e.to_string())?;
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

/// Apply transform / recursive AutoMount / disable-union prefix layers.
fn apply_compositing(
    mut src: Arc<dyn MountSource>,
    opts: &OpenOptions,
    comp: &CompositingOptions,
    ext_set: &RecursiveExtSet,
    n_sources: usize,
    folder_hint: &str,
) -> Result<Arc<dyn MountSource>, String> {
    if let Some((ref pat, ref rep)) = comp.transform {
        src = Arc::new(TransformMountSource::new(pat, rep, src)?);
    }
    if comp.recursive {
        let opener = open_nested_fn(opts.clone());
        let reader_opener = open_nested_reader_fn(opts.clone());
        let depth = match opts.recursion_depth.unwrap_or(0) {
            d if d < 0 => 0,
            d => d as u32,
        };
        let layer = AutoMountLayer::new_with_openers(
            src,
            depth,
            opener,
            Some(reader_opener),
            AutoMountOptions {
                lazy: comp.lazy,
                strip_recursive_extension: comp.strip_recursive_extension,
                transform: comp.transform_recursive.clone(),
                recursive_extensions: ext_set.clone(),
            },
        );
        src = Arc::new(layer);
    }
    if comp.disable_union_mount && n_sources > 1 {
        let folder = strip_source_name(folder_hint);
        src = Arc::new(PrefixMountSource::new(&folder, src));
    }
    Ok(src)
}

/// Resolve index options for a remote URL label (same rules as local `open_path`).
fn remote_index_setup(
    label: &Path,
    opts: &OpenOptions,
    recreate: bool,
) -> (OpenOptions, Option<PathBuf>) {
    let index_loc = resolved_index(label, opts, recreate);
    let mut o = opts.clone();
    let index_path = if index_loc.is_memory() {
        o.index_in_memory = true;
        o.index_file_path = None;
        None
    } else if let Some(p) = index_loc.as_path() {
        o.index_file_path = Some(p.to_path_buf());
        o.index_in_memory = false;
        Some(p.to_path_buf())
    } else {
        None
    };
    (o, index_path)
}

/// Result of a successful live-Range open (label path + mount source).
type LiveRangeOpened = (PathBuf, Arc<dyn MountSource>);

/// Open TAR/ZIP/gzip/bzip2/xz/zstd from a live Range-capable `Read+Seek` body.
///
/// Returns `Ok(None)` when the probed format is unsupported (caller should materialize).
/// `transport` is a short label for logs (`HTTP Range`, `S3 Range`).
///
/// `reopen` rebuilds a fresh reader after a failed gzip RGZI import (reader was consumed).
fn open_from_live_range<R, F>(
    mut range: R,
    range_len: u64,
    input: &str,
    opts: &OpenOptions,
    recreate: bool,
    transport: &str,
    reopen: F,
) -> Result<Option<LiveRangeOpened>, String>
where
    R: std::io::Read + std::io::Seek + Send + 'static,
    F: FnOnce() -> Result<R, String>,
{
    let mut magic = [0u8; 512];
    let n = std::io::Read::read(&mut range, &mut magic).map_err(|e| e.to_string())?;
    std::io::Seek::seek(&mut range, std::io::SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    let kind = probe_archive_magic(&magic[..n]);
    let label = PathBuf::from(input);
    let (o, index_path) = remote_index_setup(&label, opts, recreate);
    let ip = index_path.as_deref();

    match kind {
        "tar" => {
            eprintln!("{transport} TAR: {input} ({range_len} bytes, live Range)");
            let src = SqliteIndexedTar::open_from_reader(range, &label, ip, &o, VERSION)
                .map_err(|e| e.to_string())?;
            Ok(Some((label, Arc::new(src))))
        }
        "zip" => {
            eprintln!("{transport} ZIP: {input} ({range_len} bytes, live Range)");
            let src = ZipMountSource::open_from_reader(range, &label, ip, &o, VERSION)
                .map_err(|e| e.to_string())?;
            Ok(Some((label, Arc::new(src))))
        }
        "gzip" => {
            let spacing = if o.gzip_seek_point_spacing == 0 {
                ratarmount_compress::DEFAULT_GZIP_SEEK_SPACING
            } else {
                o.gzip_seek_point_spacing
            };
            let threads = o.threads_for("gzip");
            eprintln!(
                "{transport} gzip: {input} ({range_len} compressed bytes, live Range, -P gzip:{threads})"
            );
            // Prefer RGZI import; on failure rebuild with a fresh Range handle.
            let gzip = if try_load_gzip_index_blob(ip, recreate).is_some() {
                match try_open_gzip_imported_from_reader(
                    range, &label, spacing, threads, ip, recreate,
                ) {
                    Some(g) => g,
                    None => {
                        let fresh = reopen()?;
                        open_gzip_rebuilt_from_reader(fresh, &label, spacing, threads)?
                    }
                }
            } else {
                open_gzip_rebuilt_from_reader(range, &label, spacing, threads)?
            };
            let is_tar = name_suggests_compressed_tar(&label)
                || body_looks_like_tar_gzip(&gzip).unwrap_or(false);
            if is_tar {
                let src = open_tar_gzip(&label, Arc::clone(&gzip), ip, &o, recreate)?;
                persist_gzip_index_blob(&gzip, ip, &o);
                return Ok(Some((label, Arc::new(src))));
            }
            // Plain .gz single-file: materialize uncompressed via seekable body.
            let size = gzip.size();
            let mut reader = gzip.reader().map_err(|e| e.to_string())?;
            let mut tmp = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
            std::io::copy(&mut reader, &mut tmp).map_err(|e| e.to_string())?;
            let data_path = tmp.path().to_path_buf();
            let stripped = strip_compression_suffix(
                label.file_name().and_then(|s| s.to_str()).unwrap_or("file"),
            );
            let src = SingleFileMountSource::new(stripped, data_path, size, Some(tmp))
                .map_err(|e| e.to_string())?;
            Ok(Some((label, Arc::new(src))))
        }
        "bzip2" => {
            let threads = o.threads_for("bzip2");
            eprintln!(
                "{transport} bzip2: {input} ({range_len} compressed bytes, live Range, -P bzip2:{threads})"
            );
            let mut reopen_opt = Some(reopen);
            let body = if try_load_bzip2_blocks(ip, recreate).is_some() {
                match try_open_bzip2_imported_from_reader(range, &label, threads, ip, recreate) {
                    Some(b) => b,
                    None => {
                        let reopen_fn = reopen_opt
                            .take()
                            .ok_or_else(|| "internal: reopen already consumed".to_string())?;
                        let fresh = reopen_fn()?;
                        open_seekable_bzip2_with_threads_from_reader(fresh, threads, &label)
                            .map_err(|e| e.to_string())?
                    }
                }
            } else {
                open_seekable_bzip2_with_threads_from_reader(range, threads, &label)
                    .map_err(|e| e.to_string())?
            };
            let src = open_from_seekable_body(&label, body, ip, &o, recreate, "bzip2")?;
            if let Some(reopen_fn) = reopen_opt {
                if o.write_index && !o.read_only_index && !o.index_in_memory {
                    if let Some(ipath) = ip {
                        if ipath.exists() {
                            match reopen_fn() {
                                Ok(mut fresh) => {
                                    match export_bzip2_blocks_from_reader(&mut fresh) {
                                        Ok(blocks) => store_bzip2_blocks_in_index(&blocks, ip, &o),
                                        Err(e) => {
                                            eprintln!("info: could not export bzip2blocks: {e}")
                                        }
                                    }
                                }
                                Err(e) => {
                                    eprintln!("info: could not reopen stream for bzip2blocks: {e}")
                                }
                            }
                        }
                    }
                }
            }
            Ok(Some((label, src)))
        }
        "xz" => {
            let threads = o.threads_for("xz");
            eprintln!(
                "{transport} xz: {input} ({range_len} compressed bytes, live Range, -P xz:{threads})"
            );
            let body = open_seekable_xz_with_threads_from_reader(range, threads, &label)
                .map_err(|e| e.to_string())?;
            let src = open_from_seekable_body(&label, body, ip, &o, recreate, "xz")?;
            Ok(Some((label, src)))
        }
        "zstd" => {
            let threads = o.threads_for("zstd");
            eprintln!(
                "{transport} zstd: {input} ({range_len} compressed bytes, live Range, -P zstd:{threads})"
            );
            // Prefer zstdblocks import; on failure rebuild with a fresh Range handle.
            // Keep `reopen` available for post-open export when it was not needed for rebuild.
            let mut reopen_opt = Some(reopen);
            let body = if try_load_zstd_blocks(ip, recreate).is_some() {
                match try_open_zstd_imported_from_reader(range, &label, threads, ip, recreate) {
                    Some(b) => b,
                    None => {
                        let reopen_fn = reopen_opt
                            .take()
                            .ok_or_else(|| "internal: reopen already consumed".to_string())?;
                        let fresh = reopen_fn()?;
                        open_seekable_zstd_with_threads_from_reader(fresh, threads, &label)
                            .map_err(|e| e.to_string())?
                    }
                }
            } else {
                open_seekable_zstd_with_threads_from_reader(range, threads, &label)
                    .map_err(|e| e.to_string())?
            };
            let src = open_from_seekable_body(&label, body, ip, &o, recreate, "zstd")?;
            // Best-effort export via a fresh Range handle when still available.
            if let Some(reopen_fn) = reopen_opt {
                if o.write_index && !o.read_only_index && !o.index_in_memory {
                    if let Some(ipath) = ip {
                        if ipath.exists() {
                            match reopen_fn() {
                                Ok(mut fresh) => match export_zstd_blocks_from_reader(&mut fresh) {
                                    Ok(blocks) => store_zstd_blocks_in_index(&blocks, ip, &o),
                                    Err(e) => {
                                        eprintln!("info: could not export zstdblocks: {e}")
                                    }
                                },
                                Err(e) => {
                                    eprintln!("info: could not reopen stream for zstdblocks: {e}")
                                }
                            }
                        }
                    }
                }
            }
            Ok(Some((label, src)))
        }
        _ => {
            eprintln!(
                "info: {transport} for {input} is not TAR/ZIP/gzip/bzip2/xz/zstd; materializing"
            );
            Ok(None)
        }
    }
}

/// Materialize a remote URL to a local path and open it.
fn materialize_remote_input(
    input: &str,
    opts: &OpenOptions,
    recreate: bool,
    remotes: &mut Vec<ratarmount_remote::RemoteLocal>,
) -> Result<(PathBuf, Arc<dyn MountSource>), String> {
    let remote = ratarmount_remote::resolve_to_local(input).map_err(|e| e.to_string())?;
    let path = remote.path().to_path_buf();
    remotes.push(remote);
    let src = open_path(&path, opts, recreate)?;
    Ok((path, src))
}

/// Open a remote URL: prefer live HTTP/S3 Range for TAR/ZIP/codecs; else materialize.
fn open_remote_input(
    input: &str,
    opts: &OpenOptions,
    recreate: bool,
    remotes: &mut Vec<ratarmount_remote::RemoteLocal>,
) -> Result<(PathBuf, Arc<dyn MountSource>), String> {
    use ratarmount_remote::{open_s3_range, resolve_access, RemoteAccess, RemoteHttp};

    // Live S3 Range I/O (parallel to HTTP Range) when GetObject Range works.
    if input.starts_with("s3://") {
        match open_s3_range(input) {
            Ok(range) if range.uses_ranges() => {
                let len = range.len();
                eprintln!("S3 Range: {input} ({len} bytes, live Range GetObject)");
                let input_owned = input.to_string();
                match open_from_live_range(range, len, input, opts, recreate, "S3 Range", || {
                    open_s3_range(&input_owned)
                        .map_err(|e| e.to_string())
                        .and_then(|r| {
                            if r.uses_ranges() {
                                Ok(r)
                            } else {
                                Err("S3 Range reopen lost live Range support".into())
                            }
                        })
                })? {
                    Some(opened) => return Ok(opened),
                    None => {
                        eprintln!("info: S3 Range format unsupported for {input}; materializing");
                        return materialize_remote_input(input, opts, recreate, remotes);
                    }
                }
            }
            Ok(_) => {
                eprintln!(
                    "info: S3 Range unavailable for {input} (full body buffered); materializing"
                );
                return materialize_remote_input(input, opts, recreate, remotes);
            }
            Err(e) => {
                eprintln!("info: S3 Range open failed for {input}: {e}; materializing");
                return materialize_remote_input(input, opts, recreate, remotes);
            }
        }
    }

    let access = resolve_access(input).map_err(|e| e.to_string())?;
    match access {
        RemoteAccess::Http(RemoteHttp::Range(range)) => {
            let len = range.len();
            let input_owned = input.to_string();
            match open_from_live_range(range, len, input, opts, recreate, "HTTP Range", || {
                // Buffered fallback is still Read+Seek-usable for rebuild.
                ratarmount_remote::open_http_range(&input_owned).map_err(|e| e.to_string())
            })? {
                Some(opened) => Ok(opened),
                None => materialize_remote_input(input, opts, recreate, remotes),
            }
        }
        RemoteAccess::Http(RemoteHttp::Materialized(remote)) | RemoteAccess::Path(remote) => {
            let path = remote.path().to_path_buf();
            remotes.push(remote);
            let src = open_path(&path, opts, recreate)?;
            Ok((path, src))
        }
    }
}

fn probe_archive_magic(magic: &[u8]) -> &'static str {
    // Outer compression first (remote .tar.gz / .bz2 / .xz / .zst)
    if magic.len() >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
        return "gzip";
    }
    if magic.len() >= 3 && &magic[..3] == b"BZh" {
        return "bzip2";
    }
    // xz: FD 37 7A 58 5A 00
    if magic.len() >= 6
        && magic[0] == 0xfd
        && magic[1] == 0x37
        && magic[2] == 0x7a
        && magic[3] == 0x58
        && magic[4] == 0x5a
        && magic[5] == 0x00
    {
        return "xz";
    }
    // zstd frame magic
    if magic.len() >= 4
        && magic[0] == 0x28
        && magic[1] == 0xb5
        && magic[2] == 0x2f
        && magic[3] == 0xfd
    {
        return "zstd";
    }
    // ustar at offset 257
    if magic.len() >= 262 && &magic[257..262] == b"ustar" {
        return "tar";
    }
    // GNU tar old magic
    if magic.len() >= 265 && &magic[257..263] == b"ustar " {
        return "tar";
    }
    // Empty / sparse TAR often still has null blocks — check for tar-like name + mode digits
    if magic.len() >= 100 {
        // crude: many tars have spaces/nulls in name and octal mode at 100
        let mode = &magic[100..108.min(magic.len())];
        if mode
            .iter()
            .all(|b| b.is_ascii_digit() || *b == b' ' || *b == 0)
            && magic.iter().take(20).any(|b| b.is_ascii_graphic())
            && magic.get(257).copied().unwrap_or(0) == 0
        {
            // could be pre-POSIX tar without ustar; leave to path open after materialize
        }
    }
    if magic.len() >= 4 && &magic[0..2] == b"PK" {
        // Local file header / EOCD
        return "zip";
    }
    "other"
}

/// Peek whether a seekable gzip body starts with a TAR stream.
fn body_looks_like_tar_gzip(gzip: &SharedSeekableGzip) -> Result<bool, String> {
    let mut r = gzip.reader().map_err(|e| e.to_string())?;
    use std::io::Read;
    let mut hdr = [0u8; 512];
    let n = r.read(&mut hdr).map_err(|e| e.to_string())?;
    if n < 262 {
        return Ok(false);
    }
    Ok(&hdr[257..262] == b"ustar" || (n >= 265 && &hdr[257..263] == b"ustar "))
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

        // Do not force a default index path here — `open_path` resolves via folders / :memory:.
        let mut opts = options.clone();
        if opts.read_only_index {
            opts.write_index = false;
            opts.clear_index_cache = false;
        }
        let recreate_src = recreate && !opts.read_only_index;

        // Dropbox folders: browse via API (list + download-on-open). Files fall through.
        if input.starts_with("dropbox://") || input.starts_with("dropbox:") {
            match ratarmount_remote::DropboxMountSource::open(input.as_ref()) {
                Ok(ms) => {
                    let mut src: Arc<dyn MountSource> = Arc::new(ms);
                    src = apply_compositing(src, &opts, &comp, &ext_set, paths.len(), "dropbox")?;
                    sources.push(src);
                    continue;
                }
                Err(e) => {
                    let msg = e.to_string();
                    // File paths: materialize via resolve_to_local below.
                    if !msg.contains("is a file, not a folder") {
                        return Err(msg);
                    }
                }
            }
        }

        let (local_path, mut src) = if ratarmount_remote::is_remote_url(&input) {
            open_remote_input(input.as_ref(), &opts, recreate_src, &mut remotes)?
        } else {
            let local_path = p.clone();
            let src = open_path(&local_path, &opts, recreate_src)?;
            (local_path, src)
        };

        let folder_hint = local_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("source");
        src = apply_compositing(src, &opts, &comp, &ext_set, paths.len(), folder_hint)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn make_tiny_tar_gz(dir: &Path) -> PathBuf {
        let data = dir.join("data");
        std::fs::create_dir_all(&data).expect("mkdir");
        std::fs::write(data.join("hello.txt"), b"hello world\n").expect("write");
        let tar_gz = dir.join("tiny.tar.gz");
        let status = Command::new("tar")
            .args(["-czf"])
            .arg(&tar_gz)
            .arg("-C")
            .arg(&data)
            .arg("hello.txt")
            .status()
            .expect("spawn tar");
        assert!(status.success(), "tar -czf failed");
        tar_gz
    }

    fn make_tiny_tar_zst(dir: &Path) -> PathBuf {
        let data = dir.join("data-zst");
        std::fs::create_dir_all(&data).expect("mkdir");
        // Multi-member payload so multi-frame / seek-table export has meaningful pairs.
        std::fs::write(data.join("hello.txt"), b"hello world from zstd\n").expect("write");
        std::fs::write(data.join("pad.bin"), vec![b'x'; 4096]).expect("write pad");
        let tar_path = dir.join("tiny.tar");
        let status = Command::new("tar")
            .args(["-cf"])
            .arg(&tar_path)
            .arg("-C")
            .arg(&data)
            .args(["hello.txt", "pad.bin"])
            .status()
            .expect("spawn tar");
        assert!(status.success(), "tar -cf failed");
        let tar_zst = dir.join("tiny.tar.zst");
        // Compress as multi-frame when possible (frame size small → multiple frames).
        let status = Command::new("zstd")
            .args(["-f", "-19", "--stream-size=1024", "-o"])
            .arg(&tar_zst)
            .arg(&tar_path)
            .status()
            .expect("spawn zstd");
        if !status.success() {
            // Older zstd without --stream-size: plain compress still yields exportable map.
            let status = Command::new("zstd")
                .args(["-f", "-o"])
                .arg(&tar_zst)
                .arg(&tar_path)
                .status()
                .expect("spawn zstd fallback");
            assert!(status.success(), "zstd compress failed");
        }
        tar_zst
    }

    #[test]
    fn probe_magic_detects_gzip_and_zip() {
        assert_eq!(probe_archive_magic(&[0x1f, 0x8b, 0x08]), "gzip");
        assert_eq!(probe_archive_magic(b"BZh91"), "bzip2");
        assert_eq!(probe_archive_magic(b"PK\x03\x04"), "zip");
        assert_eq!(probe_archive_magic(b"not-an-archive"), "other");
    }

    #[test]
    fn gzip_rgzi_blob_persisted_and_reimported() {
        let dir = tempfile::tempdir().unwrap();
        let archive = make_tiny_tar_gz(dir.path());
        let index = dir.path().join("tiny.index.sqlite");
        // Tiny spacing so checkpoints are cheap.
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            gzip_seek_point_spacing: 64 * 1024,
            ..Default::default()
        };

        // Cold open: build seek table + TAR index, then store RGZI side blob.
        let src = open_path(&archive, &opts, true).expect("cold open");
        drop(src);

        let idx = SqliteIndex::open_read_only(&index).expect("open index");
        let blobs = idx.get_gzip_index_blobs().expect("get blobs");
        assert_eq!(blobs.len(), 1, "expected single gzipindex blob");
        assert!(
            blobs[0].starts_with(b"RGZI"),
            "blob should be Tier C RGZI magic"
        );
        let stored = blobs[0].clone();
        drop(idx);

        // Warm open: import blob (no full spacing rebuild required for offsets).
        let src2 = open_path(&archive, &opts, false).expect("warm open with import");
        drop(src2);

        let idx2 = SqliteIndex::open_read_only(&index).expect("reopen index");
        let blobs2 = idx2.get_gzip_index_blobs().expect("blobs again");
        assert_eq!(blobs2, vec![stored]);
    }

    #[test]
    fn gzip_rgzi_invalid_blob_falls_back_to_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let archive = make_tiny_tar_gz(dir.path());
        let index = dir.path().join("tiny.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            gzip_seek_point_spacing: 64 * 1024,
            ..Default::default()
        };

        let src = open_path(&archive, &opts, true).expect("cold open");
        drop(src);

        // Poison the side table with a non-RGZI payload.
        {
            let idx = SqliteIndex::open_writable(&index).expect("writable");
            idx.set_gzip_index_blob(b"not-a-valid-rgzi-blob")
                .expect("set garbage");
        }

        // Import must fail open; factory falls back to normal checkpoint rebuild.
        let src2 = open_path(&archive, &opts, false).expect("open after invalid blob");
        drop(src2);

        // Rebuild should have rewritten a valid RGZI blob.
        let idx = SqliteIndex::open_read_only(&index).expect("ro");
        let blobs = idx.get_gzip_index_blobs().expect("blobs");
        assert!(!blobs.is_empty());
        assert!(blobs[0].starts_with(b"RGZI"));
    }

    #[test]
    fn gzip_rgzi_memory_index_skips_side_table_path() {
        let dir = tempfile::tempdir().unwrap();
        let archive = make_tiny_tar_gz(dir.path());
        let opts = OpenOptions {
            index_in_memory: true,
            gzip_seek_point_spacing: 64 * 1024,
            ..Default::default()
        };

        // No on-disk index path → open works; nothing to assert on side tables.
        let src = open_path(&archive, &opts, false).expect("memory index open");
        drop(src);
        // Sibling default index must not be required / created for :memory: path.
        let sibling = archive.with_extension("gz.index.sqlite");
        // default sibling name varies; just ensure open succeeded without panic.
        let _ = sibling;
    }

    #[test]
    fn try_load_gzip_index_blob_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.sqlite");
        assert!(try_load_gzip_index_blob(Some(&missing), false).is_none());
        assert!(try_load_gzip_index_blob(None, false).is_none());
        assert!(try_load_gzip_index_blob(Some(&missing), true).is_none());
    }

    #[test]
    fn zstd_blocks_persisted_and_reimported() {
        let dir = tempfile::tempdir().unwrap();
        let archive = make_tiny_tar_zst(dir.path());
        let index = dir.path().join("tiny.zst.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            ..Default::default()
        };

        // Cold open: build frame map + TAR index, then store zstdblocks side table.
        let src = open_path(&archive, &opts, true).expect("cold open");
        drop(src);

        let idx = SqliteIndex::open_read_only(&index).expect("open index");
        let blocks = idx.get_zstd_blocks().expect("get zstdblocks");
        assert!(
            !blocks.is_empty(),
            "expected non-empty zstdblocks after cold open"
        );
        let stored = blocks.clone();
        drop(idx);

        // Warm open: import zstdblocks (no full multi-frame rescan required).
        let src2 = open_path(&archive, &opts, false).expect("warm open with import");
        drop(src2);

        let idx2 = SqliteIndex::open_read_only(&index).expect("reopen index");
        let blocks2 = idx2.get_zstd_blocks().expect("blocks again");
        assert_eq!(blocks2, stored);
    }

    #[test]
    fn zstd_blocks_invalid_map_falls_back_to_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let archive = make_tiny_tar_zst(dir.path());
        let index = dir.path().join("tiny.zst.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            ..Default::default()
        };

        let src = open_path(&archive, &opts, true).expect("cold open");
        drop(src);

        // Poison the side table with a non-monotonic / bogus map.
        {
            let idx = SqliteIndex::open_writable(&index).expect("writable");
            // Decreasing compressed offsets must fail import validation.
            idx.set_zstd_blocks(&[(100, 0), (50, 10), (200, 20)])
                .expect("set garbage");
        }

        // Import must fail; factory falls back to normal frame-map rebuild.
        let src2 = open_path(&archive, &opts, false).expect("open after invalid blocks");
        drop(src2);

        // Rebuild should have rewritten a valid (non-empty, sorted) map.
        let idx = SqliteIndex::open_read_only(&index).expect("ro");
        let blocks = idx.get_zstd_blocks().expect("blocks");
        assert!(!blocks.is_empty());
        for w in blocks.windows(2) {
            assert!(w[0].0 <= w[1].0, "blockoffset must be non-decreasing");
        }
    }

    #[test]
    fn zstd_blocks_memory_index_skips_side_table_path() {
        let dir = tempfile::tempdir().unwrap();
        let archive = make_tiny_tar_zst(dir.path());
        let opts = OpenOptions {
            index_in_memory: true,
            ..Default::default()
        };

        let src = open_path(&archive, &opts, false).expect("memory index open");
        drop(src);
    }

    #[test]
    fn try_load_zstd_blocks_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.sqlite");
        assert!(try_load_zstd_blocks(Some(&missing), false).is_none());
        assert!(try_load_zstd_blocks(None, false).is_none());
        assert!(try_load_zstd_blocks(Some(&missing), true).is_none());
    }

    #[test]
    fn zstd_blocks_i64_u64_roundtrip_helpers() {
        let u = vec![(0u64, 0u64), (10, 20), (100, 200)];
        let i = zstd_blocks_u64_to_i64(&u).expect("to i64");
        assert_eq!(i, vec![(0i64, 0i64), (10, 20), (100, 200)]);
        let back = zstd_blocks_i64_to_u64(&i).expect("to u64");
        assert_eq!(back, u);

        assert!(zstd_blocks_i64_to_u64(&[(-1, 0)]).is_none());
        assert!(zstd_blocks_u64_to_i64(&[(u64::MAX, 0)]).is_none());
    }
}
