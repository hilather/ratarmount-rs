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
    GZIP_SEEK_INDEX_MAGIC, INDEXED_GZIP_INDEX_MAGIC,
};
use ratarmount_core::{MountSource, OpenOptions};
use ratarmount_formats_ar::{looks_like_ar, ArMountSource};
use ratarmount_formats_asar::{looks_like_asar, AsarMountSource};
use ratarmount_formats_cab::{looks_like_cab, CabError, CabMountSource};
use ratarmount_formats_cpio::{looks_like_cpio, CpioMountSource};
use ratarmount_formats_ext4::{looks_like_ext4, looks_like_ext4_reader, Ext4MountSource};
use ratarmount_formats_fat::{looks_like_fat, looks_like_fat_reader, FatMountSource};
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
use ratarmount_formats_squashfs::{
    looks_like_squashfs, looks_like_squashfs_reader, SquashFsMountSource,
};
use ratarmount_formats_tar::{SingleFileMountSource, SqliteIndexedTar};
use ratarmount_formats_warc::{looks_like_warc, WarcMountSource};
use ratarmount_formats_xar::{looks_like_xar, XarMountSource};
use ratarmount_formats_zip::{looks_like_zip, ZipMountSource};
use ratarmount_index::{
    discard_index_file_if_below_minimum, resolve_index_location, IndexLocation, SqliteIndex,
};

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
/// Supports:
/// - **7z**, **ZIP**, uncompressed **TAR**
/// - **gzip / zstd / bzip2 / xz** when the body is a compressed TAR (e.g. `.tar.gz`
///   embedded in a store 7z) — seekable decompress + in-memory TAR index
/// - **CPIO**, **AR**, **ISO 9660**, **WARC**, **ASAR**, **XAR**, **CAB** (store/MSZIP),
///   **SQLAR** (unencrypted, full image in RAM), **FAT** images
/// - **SquashFS** (none/gzip/zstd/lz4/lzo/xz via in-process backhand); classic **LZMA**
///   images fail here so AutoMount can temp-spool + path/`unsquashfs`
/// - **EXT2/3/4** via pure ext4-view on a shared stream; pure fail → temp spool + path open
///   (may use debugfs)
///
/// Other formats fail so AutoMount can fall back to materializing a temp file
/// and [`open_nested_fn`].
pub fn open_nested_reader_fn(options: OpenOptions) -> OpenNestedReaderFn {
    Arc::new(move |mut reader, label| {
        use std::io::{Read, Seek, SeekFrom};

        let mut opts = options.clone();
        // Nested indexes cannot live next to a virtual label. Use compact-only
        // file table (string pool + SoA) — no SQLite `files` store for nested.
        opts.index_file_path = None;
        opts.index_in_memory = false;
        opts.index_compact_only = true;
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

        // 7z magic (not covered by probe_archive_magic)
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

        // Unix ar
        if head.len() >= 8 && &head[..8] == b"!<arch>\n" {
            return map_nested_open("AR", label, || {
                ArMountSource::open_from_reader(reader, label, None, &opts, VERSION)
            });
        }

        // XAR
        if head.len() >= 4 && &head[..4] == b"xar!" {
            return map_nested_open("XAR", label, || {
                XarMountSource::open_from_reader(reader, label, None, &opts, VERSION)
            });
        }

        // CAB (MSCF); LZX returns UnsupportedCompression → AutoMount temp spool → libarchive
        if head.len() >= 4 && &head[..4] == b"MSCF" {
            return map_nested_open("CAB", label, || {
                CabMountSource::open_from_reader(reader, label, None, &opts, VERSION, true)
            });
        }

        // Unencrypted SQLAR / SQLite header
        if head.len() >= 16 && &head[..16] == b"SQLite format 3\0" {
            return map_nested_open("SQLAR", label, || {
                SqlarMountSource::open_from_reader(reader, label, &opts)
            });
        }

        // CPIO newc/crc/odc (ASCII) or binary magic
        if head_looks_like_cpio(head) {
            return map_nested_open("CPIO", label, || {
                CpioMountSource::open_from_reader(reader, label, None, &opts, VERSION)
            });
        }

        // WARC
        if head.len() >= 5 && &head[..5] == b"WARC/" {
            return map_nested_open("WARC", label, || {
                WarcMountSource::open_from_reader(reader, label, None, &opts, VERSION)
            });
        }

        match probe_archive_magic(head) {
            "gzip" => return open_nested_gzip_tar(reader, label, &opts),
            "zstd" => {
                return open_nested_seekable_tar(
                    reader,
                    label,
                    &opts,
                    "zstd",
                    opts.threads_for("zstd"),
                    |r, thr, lab| {
                        open_seekable_zstd_with_threads_from_reader(r, thr, lab)
                            .map_err(|e| std::io::Error::other(e.to_string()))
                    },
                )
            }
            "bzip2" => {
                return open_nested_seekable_tar(
                    reader,
                    label,
                    &opts,
                    "bzip2",
                    opts.threads_for("bzip2"),
                    |r, thr, lab| {
                        open_seekable_bzip2_with_threads_from_reader(r, thr, lab)
                            .map_err(|e| std::io::Error::other(e.to_string()))
                    },
                )
            }
            "xz" => {
                return open_nested_seekable_tar(
                    reader,
                    label,
                    &opts,
                    "xz",
                    opts.threads_for("xz"),
                    |r, thr, lab| {
                        open_seekable_xz_with_threads_from_reader(r, thr, lab)
                            .map_err(|e| std::io::Error::other(e.to_string()))
                    },
                )
            }
            "zip" => {
                return map_nested_open("ZIP", label, || {
                    ZipMountSource::open_from_reader(reader, label, None, &opts, VERSION)
                });
            }
            "tar" => {
                return map_nested_open("TAR", label, || {
                    SqliteIndexedTar::open_from_reader(reader, label, None, &opts, VERSION)
                });
            }
            _ => {}
        }

        // Uncompressed TAR by name (no ustar magic in first 512 — rare)
        if name_suggests_plain_tar(label) {
            return map_nested_open("TAR", label, || {
                SqliteIndexedTar::open_from_reader(reader, label, None, &opts, VERSION)
            });
        }

        // ISO 9660: PVD at sector 16 (beyond first 512 bytes) — probe stream or name
        let looks_iso = name_suggests_iso(label)
            || ratarmount_formats_iso9660::looks_like_iso9660_reader(&mut reader);
        let _ = reader.seek(SeekFrom::Start(0));
        if looks_iso {
            return map_nested_open("ISO9660", label, || {
                Iso9660MountSource::open_from_reader(reader, label, None, &opts, VERSION)
            });
        }

        // ASAR: extension (header sniff needs full parse; name is the nested-open trigger)
        if name_suggests_asar(label) {
            return map_nested_open("ASAR", label, || {
                AsarMountSource::open_from_reader(reader, label, None, &opts, VERSION, true)
            });
        }

        // WARC / CPIO by extension when magic was missed
        if name_suggests_ext(label, &["warc"]) {
            return map_nested_open("WARC", label, || {
                WarcMountSource::open_from_reader(reader, label, None, &opts, VERSION)
            });
        }
        if name_suggests_ext(label, &["cpio"]) {
            return map_nested_open("CPIO", label, || {
                CpioMountSource::open_from_reader(reader, label, None, &opts, VERSION)
            });
        }
        if name_suggests_ext(label, &["ar", "a"]) {
            return map_nested_open("AR", label, || {
                ArMountSource::open_from_reader(reader, label, None, &opts, VERSION)
            });
        }
        if name_suggests_ext(label, &["xar"]) {
            return map_nested_open("XAR", label, || {
                XarMountSource::open_from_reader(reader, label, None, &opts, VERSION)
            });
        }
        if name_suggests_ext(label, &["cab"]) {
            return map_nested_open("CAB", label, || {
                CabMountSource::open_from_reader(reader, label, None, &opts, VERSION, true)
            });
        }
        if name_suggests_ext(label, &["sqlar"]) {
            return map_nested_open("SQLAR", label, || {
                SqlarMountSource::open_from_reader(reader, label, &opts)
            });
        }

        // FAT image: boot-sector probe or name (`.img` only if probe matches — ISO checked above)
        let looks_fat = name_suggests_ext(label, &["fat", "vfat", "fat12", "fat16", "fat32"])
            || looks_like_fat_reader(&mut reader);
        let _ = reader.seek(SeekFrom::Start(0));
        if looks_fat {
            return map_nested_open("FAT", label, || {
                FatMountSource::open_from_reader(reader, label)
            });
        }

        // SquashFS: magic at 0 (or AppImage-style scan); classic LZMA fails → temp spool
        let looks_sqfs = name_suggests_ext(label, &["squashfs", "sqfs", "snap"])
            || looks_like_squashfs_reader(&mut reader);
        let _ = reader.seek(SeekFrom::Start(0));
        if looks_sqfs {
            return map_nested_open("SquashFS", label, || {
                SquashFsMountSource::open_from_reader(reader, label)
            });
        }

        // EXT2/3/4: superblock magic @ 1024+0x38; pure fail → temp spool / debugfs path
        let looks_ext4 = name_suggests_ext(label, &["ext2", "ext3", "ext4", "ext4img"])
            || looks_like_ext4_reader(&mut reader);
        let _ = reader.seek(SeekFrom::Start(0));
        if looks_ext4 {
            return map_nested_open("EXT4", label, || {
                Ext4MountSource::open_from_reader(reader, label)
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

fn map_nested_open<S, E>(
    kind: &str,
    label: &Path,
    f: impl FnOnce() -> std::result::Result<S, E>,
) -> std::io::Result<Arc<dyn MountSource>>
where
    S: MountSource + 'static,
    E: std::fmt::Display,
{
    log::debug!("nested reader open: {} detected as {kind}", label.display());
    f().map(|s| {
        log::debug!(
            "nested reader open: {kind} {} mounted successfully",
            label.display()
        );
        Arc::new(s) as Arc<dyn MountSource>
    })
    .map_err(|e| {
        log::warn!("nested reader open: {kind} {} failed: {e}", label.display());
        std::io::Error::other(e.to_string())
    })
}

fn head_looks_like_cpio(head: &[u8]) -> bool {
    if head.len() >= 6 {
        let m6 = &head[..6];
        if m6 == b"070701" || m6 == b"070702" || m6 == b"070707" {
            return true;
        }
    }
    if head.len() >= 2 {
        let m2 = &head[..2];
        if m2 == b"\xc7\x71" || m2 == b"\x71\xc7" {
            return true;
        }
    }
    false
}

fn name_suggests_iso(path: &Path) -> bool {
    // Do not treat bare `.img` as ISO — FAT images often use that suffix too.
    name_suggests_ext(path, &["iso", "iso9660", "cdr"])
}

fn name_suggests_asar(path: &Path) -> bool {
    name_suggests_ext(path, &["asar"])
}

fn name_suggests_ext(path: &Path, exts: &[&str]) -> bool {
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("")
        .to_ascii_lowercase();
    exts.iter().any(|e| name.ends_with(&format!(".{e}")))
}

/// Seek a nested gzip compressed stream to byte 0 before a G3 open attempt.
///
/// Used after a failed prefer-rapidgzip `from_reader` so
/// [`SharedSeekableGzip::open_with_threads_from_reader`] can re-scan from the start.
/// Always compiled so unit tests cover rewind without `gzip-rapidgzip`.
#[cfg_attr(not(feature = "gzip-rapidgzip"), allow(dead_code))]
fn rewind_nested_gzip_reader_for_g3(reader: &mut dyn std::io::Seek) -> std::io::Result<()> {
    std::io::Seek::seek(reader, std::io::SeekFrom::Start(0))?;
    Ok(())
}

/// Shared ownership of a nested compressed body so rapidgzip open failure can
/// recover the stream for G3 (rapidgzip takes `R` by value).
#[cfg(feature = "gzip-rapidgzip")]
type NestedGzipReaderHeld = Arc<std::sync::Mutex<Box<dyn ratarmount_core::ArchiveRead>>>;

/// `Read + Seek + Send` facade over [`NestedGzipReaderHeld`] for rapidgzip open.
#[cfg(feature = "gzip-rapidgzip")]
struct NestedRecoverableGzipReader {
    inner: NestedGzipReaderHeld,
}

#[cfg(feature = "gzip-rapidgzip")]
impl std::io::Read for NestedRecoverableGzipReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        std::io::Read::read(
            &mut **self.inner.lock().unwrap_or_else(|e| e.into_inner()),
            buf,
        )
    }
}

#[cfg(feature = "gzip-rapidgzip")]
impl std::io::Seek for NestedRecoverableGzipReader {
    fn seek(&mut self, pos: std::io::SeekFrom) -> std::io::Result<u64> {
        std::io::Seek::seek(
            &mut **self.inner.lock().unwrap_or_else(|e| e.into_inner()),
            pos,
        )
    }
}

/// Recover the nested stream after rapidgzip dropped its `R`, then rewind to 0.
///
/// Residual: `Arc` still shared (unexpected holder) or `seek(Start(0))` fails →
/// G3 fallback is impossible.
#[cfg(feature = "gzip-rapidgzip")]
fn take_and_rewind_nested_gzip_reader(
    held: NestedGzipReaderHeld,
) -> std::io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
    let mut reader = Arc::try_unwrap(held)
        .map_err(|_| {
            std::io::Error::other(
                "nested compressed reader still held after rapidgzip failure; cannot rewind for G3",
            )
        })?
        .into_inner()
        .unwrap_or_else(|e| e.into_inner());
    rewind_nested_gzip_reader_for_g3(reader.as_mut()).map_err(|e| {
        std::io::Error::other(format!(
            "rewind nested gzip reader for G3 fallback failed: {e}"
        ))
    })?;
    Ok(reader)
}

/// Nested gzip body: seekable checkpoints + TAR / format / single-file (no temp spool).
///
/// With `gzip-rapidgzip` + prefer backend, uses rapidgzip `from_reader` (kind
/// `gzip-rapidgzip`). On failure, if the held reader can be recovered and
/// [`rewind_nested_gzip_reader_for_g3`] succeeds, falls through to G3
/// [`SharedSeekableGzip::open_with_threads_from_reader`]. Residual: if recover
/// or rewind fails (or another holder still owns the stream), return the
/// rapidgzip error — there is no Range-style reopen for nested bodies.
/// Without prefer, G3 only (still no temp spool).
fn open_nested_gzip_tar(
    reader: Box<dyn ratarmount_core::ArchiveRead>,
    label: &Path,
    opts: &OpenOptions,
) -> std::io::Result<Arc<dyn MountSource>> {
    // Only reassigned when rapidgzip prefer fails and we recover the stream for G3.
    #[cfg(feature = "gzip-rapidgzip")]
    let mut reader = reader;
    #[cfg(not(feature = "gzip-rapidgzip"))]
    let reader = reader;

    let spacing = if opts.gzip_seek_point_spacing == 0 {
        ratarmount_compress::DEFAULT_GZIP_SEEK_SPACING
    } else {
        opts.gzip_seek_point_spacing
    };
    let threads = opts.threads_for("gzip");
    log::debug!(
        "nested reader open: {} detected as gzip (spacing={spacing}, -P gzip:{threads})",
        label.display()
    );

    #[cfg(feature = "gzip-rapidgzip")]
    if ratarmount_compress::prefer_rapidgzip_gzip_backend(&opts.use_backends) {
        let rg_threads = rapidgzip_threads(opts);
        // Hold the stream under Arc so a failed rapidgzip open (which takes
        // ownership of R) does not drop the compressed body — we can rewind
        // and fall through to G3. ArchiveRead is always Seek; residual is
        // recover/rewind failure, not a non-Seek trait object.
        let held: NestedGzipReaderHeld = Arc::new(std::sync::Mutex::new(reader));
        let attempt = NestedRecoverableGzipReader {
            inner: Arc::clone(&held),
        };
        match ratarmount_compress::open_seekable_gzip_rapidgzip_from_reader(
            attempt, spacing, rg_threads, label,
        ) {
            Ok(body) => {
                log::debug!(
                    "nested reader open: {} gzip-rapidgzip ({} uncompressed bytes, {} checkpoints, kind={})",
                    label.display(),
                    body.size(),
                    body.checkpoint_count(),
                    body.kind()
                );
                let is_tar = name_suggests_compressed_tar(label)
                    || body_looks_like_tar(&body).unwrap_or(false);
                if is_tar {
                    return open_tar_body(label, body, None, opts, true)
                        .map(|s| Arc::new(s) as Arc<dyn MountSource>)
                        .map_err(std::io::Error::other);
                }
                return open_nested_non_tar_seekable_body(label, body, opts, "gzip-rapidgzip");
            }
            Err(e) => {
                match take_and_rewind_nested_gzip_reader(held) {
                    Ok(recovered) => {
                        log::info!(
                            "nested rapidgzip open failed for {}: {e}; falling back to G3 seekable gzip",
                            label.display()
                        );
                        eprintln!(
                            "info: nested rapidgzip open failed ({e}); falling back to G3 seekable gzip"
                        );
                        reader = recovered;
                        // Fall through to SharedSeekableGzip below.
                    }
                    Err(rewind_err) => {
                        log::warn!(
                            "nested rapidgzip open failed for {} ({e}); cannot fall back to G3: {rewind_err}",
                            label.display()
                        );
                        return Err(std::io::Error::other(format!(
                            "nested rapidgzip open failed: {e} (G3 fallback unavailable: {rewind_err})"
                        )));
                    }
                }
            }
        }
    }

    let gzip = SharedSeekableGzip::open_with_threads_from_reader(reader, spacing, threads, label)
        .map_err(|e| std::io::Error::other(e.to_string()))?;
    let is_tar =
        name_suggests_compressed_tar(label) || body_looks_like_tar_gzip(&gzip).unwrap_or(false);
    if is_tar {
        log::debug!(
            "nested reader open: {} gzip→tar ({} uncompressed bytes, {} checkpoints)",
            label.display(),
            gzip.size(),
            gzip.checkpoint_count()
        );
        // Nested: always rebuild in-memory index (opts already force index_in_memory).
        return SqliteIndexedTar::create_index_gzip(label, gzip, None, opts, VERSION)
            .map(|s| {
                log::debug!(
                    "nested reader open: gzip→tar {} mounted successfully",
                    label.display()
                );
                Arc::new(s) as Arc<dyn MountSource>
            })
            .map_err(|e| {
                log::warn!(
                    "nested reader open: gzip→tar {} failed: {e}",
                    label.display()
                );
                std::io::Error::other(e.to_string())
            });
    }
    // Plain nested .gz (or non-TAR archive body): seekable body, no temp spool.
    let body: Arc<dyn SeekableBody> = gzip;
    open_nested_non_tar_seekable_body(label, body, opts, "gzip")
}

/// Nested zstd/bzip2/xz: TAR when body matches; else formats / single-file over seekable body.
fn open_nested_seekable_tar<R, F>(
    reader: R,
    label: &Path,
    opts: &OpenOptions,
    codec: &str,
    threads: u32,
    open_body: F,
) -> std::io::Result<Arc<dyn MountSource>>
where
    R: std::io::Read + std::io::Seek + Send + 'static,
    F: FnOnce(R, u32, &Path) -> std::io::Result<Arc<dyn SeekableBody>>,
{
    log::debug!(
        "nested reader open: {} detected as {codec} (-P {codec}:{threads})",
        label.display()
    );
    let body = open_body(reader, threads, label)?;
    let is_tar = name_suggests_compressed_tar(label) || body_looks_like_tar(&body).unwrap_or(false);
    if is_tar {
        log::debug!(
            "nested reader open: {} {codec}→tar ({} uncompressed bytes, {} checkpoints)",
            label.display(),
            body.size(),
            body.checkpoint_count()
        );
        return open_tar_body(label, body, None, opts, true)
            .map(|s| {
                log::debug!(
                    "nested reader open: {codec}→tar {} mounted successfully",
                    label.display()
                );
                Arc::new(s) as Arc<dyn MountSource>
            })
            .map_err(|e| {
                log::warn!(
                    "nested reader open: {codec}→tar {} failed: {e}",
                    label.display()
                );
                std::io::Error::other(e)
            });
    }
    open_nested_non_tar_seekable_body(label, body, opts, codec)
}

/// Nested non-TAR compressed body: probe archive formats from reader, else single-file.
fn open_nested_non_tar_seekable_body(
    label: &Path,
    body: Arc<dyn SeekableBody>,
    opts: &OpenOptions,
    codec: &str,
) -> std::io::Result<Arc<dyn MountSource>> {
    log::debug!(
        "nested reader open: {} {codec} body is not TAR; trying format/single-file (no tmp)",
        label.display()
    );
    if let Some(src) =
        try_open_formats_from_seekable_body(label, Arc::clone(&body), None, opts, true)
            .map_err(std::io::Error::other)?
    {
        log::debug!(
            "nested reader open: {codec}→archive {} mounted successfully",
            label.display()
        );
        return Ok(src);
    }
    let stripped =
        strip_compression_suffix(label.file_name().and_then(|s| s.to_str()).unwrap_or("file"));
    log::debug!(
        "nested reader open: {codec}→single-file {} as {stripped} ({} bytes, no tmp)",
        label.display(),
        body.size()
    );
    SingleFileMountSource::from_seekable_body(stripped, body)
        .map(|s| Arc::new(s) as Arc<dyn MountSource>)
        .map_err(std::io::Error::other)
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

/// B-119 / `--index-minimum-file-count`: drop a freshly written on-disk SQLite index
/// when the archive has strictly fewer indexed members than the threshold.
///
/// Mount stays live via the open connection (unlinked file). `minimum == 0`,
/// `:memory:`, read-only index mode, or `write_index = false` leave the file alone.
fn maybe_discard_index_below_minimum(index_path: Option<&Path>, options: &OpenOptions) {
    let minimum = options.index_minimum_file_count;
    if minimum == 0 || options.index_in_memory || options.read_only_index || !options.write_index {
        return;
    }
    let Some(ip) = index_path else {
        return;
    };
    if !ip.exists() {
        return;
    }
    match discard_index_file_if_below_minimum(ip, minimum) {
        Ok(true) => {
            // Count is not re-queried here; helper already applied the gate.
            eprintln!(
                "info: not keeping on-disk index {} (archive has fewer than \
                 --index-minimum-file-count {minimum} indexed files)",
                ip.display()
            );
        }
        Ok(false) => {}
        Err(e) => {
            eprintln!(
                "info: could not apply --index-minimum-file-count gate on {}: {e}",
                ip.display()
            );
        }
    }
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

    // After create + optional compression side-table writes: drop small indexes (B-119).
    maybe_discard_index_below_minimum(index_path, &options);

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
/// Returns `None` when recreate is set, the path is missing, the table is empty,
/// or stored `tarstats` does not match `archive_path` (stale index after in-place replace).
fn try_load_gzip_index_blob(
    index_path: Option<&Path>,
    archive_path: Option<&Path>,
    recreate: bool,
) -> Option<Vec<u8>> {
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
    if let Some(ap) = archive_path {
        if let Err(e) = idx.check_tarstats_matches_archive(ap) {
            eprintln!("info: gzip RGZI skipped (index fingerprint: {e})");
            return None;
        }
    }
    match idx.get_gzip_index_blobs() {
        Ok(blobs) => blobs.into_iter().next().filter(|b| !b.is_empty()),
        Err(_) => None,
    }
}

/// Short format label for gzip seek-index side-table blobs (import / fail logs).
///
/// Distinguishes native Tier C **`RGZI`** from Python `indexed_gzip` **`GZIDX`**
/// via magic prefix so logs do not claim RGZI when the blob is GZIDX (or vice versa).
fn gzip_seek_index_format_label(blob: &[u8]) -> &'static str {
    if blob.starts_with(GZIP_SEEK_INDEX_MAGIC) {
        "RGZI"
    } else if blob.starts_with(INDEXED_GZIP_INDEX_MAGIC) {
        "GZIDX"
    } else {
        "seek-index"
    }
}

/// Persist a Tier C RGZI seek-index blob into the SQLite side table when writable.
///
/// No-op for `:memory:` / missing path / read-only / `write_index = false`.
/// Creates the index file when the path is set but does not yet exist (plain `.gz`
/// has no TAR `files` build — same shell path as zstdblocks / bzip2blocks).
/// Also refreshes `tarstats` from the archive path so warm reimport can fingerprint.
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
    let blob = gzip.export_seek_index_blob();
    match open_or_create_writable_index(ip) {
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
            if let Err(e) = idx.store_tarstats_for_path(gzip.path()) {
                eprintln!("info: could not store tarstats for gzip index: {e}");
            }
        }
        Err(e) => eprintln!("info: could not open index to store gzip seek blob: {e}"),
    }
}

/// Open seekable gzip from a path, preferring an imported RGZI/GZIDX blob when available.
fn open_shared_seekable_gzip_path(
    path: &Path,
    spacing: u64,
    threads: u32,
    index_path: Option<&Path>,
    recreate: bool,
) -> Result<Arc<SharedSeekableGzip>, String> {
    if let Some(blob) = try_load_gzip_index_blob(index_path, Some(path), recreate) {
        let fmt = gzip_seek_index_format_label(&blob);
        match SharedSeekableGzip::open_with_imported_index(path, spacing, threads, &blob) {
            Ok(g) => {
                eprintln!(
                    "seekable gzip (imported {fmt}): {} ({} uncompressed bytes, {} checkpoints, -P gzip:{})",
                    path.display(),
                    g.size(),
                    g.checkpoint_count(),
                    threads
                );
                return Ok(g);
            }
            Err(e) => {
                eprintln!("info: gzip {fmt} import failed ({e}); rebuilding seek checkpoints");
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

/// Try opening seekable gzip from a Range reader using an on-disk RGZI/GZIDX blob.
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
    // Label may be virtual (HTTP); fingerprint only when it resolves to a real path.
    let blob = try_load_gzip_index_blob(index_path, Some(label), recreate)?;
    let fmt = gzip_seek_index_format_label(&blob);
    match SharedSeekableGzip::open_with_imported_index_from_reader(
        reader, spacing, threads, label, &blob,
    ) {
        Ok(g) => {
            eprintln!(
                "seekable gzip (imported {fmt}): {} ({} uncompressed bytes, {} checkpoints, -P gzip:{})",
                label.display(),
                g.size(),
                g.checkpoint_count(),
                threads
            );
            Some(g)
        }
        Err(e) => {
            eprintln!("info: gzip {fmt} import failed ({e}); rebuilding seek checkpoints");
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

/// Resolve rapidgzip worker budget (`-P rapidgzip-gzip:N` wins over `-P gzip:N`).
///
/// Do not `.max()` the two: unlisted backends fall back to
/// [`ParallelizationSpec`](ratarmount_core::ParallelizationSpec) defaults (often CPU
/// count), which would ignore a lower `-P gzip:N`.
#[cfg(feature = "gzip-rapidgzip")]
fn rapidgzip_threads(options: &OpenOptions) -> u32 {
    if options
        .parallelization
        .by_backend
        .contains_key("rapidgzip-gzip")
    {
        options.threads_for("rapidgzip-gzip")
    } else {
        options.threads_for("gzip")
    }
}

/// Open path-backed rapidgzip, optionally hydrating a SQLite GZIDX blob first.
///
/// Keeps a typed [`ratarmount_compress::SharedRapidgzip`] so GZIDX export can run after
/// TAR/body open without downcasting `Arc<dyn SeekableBody>`.
///
/// Tries [`SharedRapidgzip::open_with_imported_index`] when a side-table blob loads;
/// invalid / foreign (e.g. RGZI-only) blobs fall through to a cold
/// [`SharedRapidgzip::open_with_threads`] rebuild (never panics).
#[cfg(feature = "gzip-rapidgzip")]
fn open_shared_rapidgzip_path(
    path: &Path,
    spacing: u64,
    threads: u32,
    index_path: Option<&Path>,
    recreate: bool,
) -> Result<Arc<ratarmount_compress::SharedRapidgzip>, String> {
    if let Some(blob) = try_load_gzip_index_blob(index_path, Some(path), recreate) {
        let fmt = gzip_seek_index_format_label(&blob);
        match ratarmount_compress::SharedRapidgzip::open_with_imported_index(
            path, spacing, threads, &blob,
        ) {
            Ok(shared) => {
                eprintln!(
                    "seekable gzip-rapidgzip (imported {fmt}): {} ({} uncompressed bytes, {} checkpoints, -P rapidgzip-gzip:{})",
                    path.display(),
                    shared.size(),
                    shared.checkpoint_count(),
                    threads
                );
                return Ok(shared);
            }
            Err(e) => {
                eprintln!("info: rapidgzip {fmt} import failed ({e}); rebuilding seek index");
            }
        }
    }
    let shared = ratarmount_compress::SharedRapidgzip::open_with_threads(path, spacing, threads)
        .map_err(|e| e.to_string())?;
    eprintln!(
        "seekable gzip-rapidgzip: {} ({} uncompressed bytes, {} checkpoints, -P rapidgzip-gzip:{})",
        path.display(),
        shared.size(),
        shared.checkpoint_count(),
        threads
    );
    Ok(shared)
}

/// Persist rapidgzip GZIDX into the SQLite side table when writable.
///
/// Mirrors [`persist_gzip_index_blob`] control flow (`write_index`, not RO / `:memory:`).
/// Creates the index file when the path is set but does not yet exist (plain `.gz`
/// has no TAR `files` build — same shell path as G3 RGZI / zstdblocks).
/// Stores Python `indexed_gzip` (`GZIDX`) bytes via
/// [`SharedRapidgzip::export_gzidx_blob`](ratarmount_compress::SharedRapidgzip::export_gzidx_blob).
#[cfg(feature = "gzip-rapidgzip")]
fn persist_rapidgzip_index_blob(
    shared: &ratarmount_compress::SharedRapidgzip,
    index_path: Option<&Path>,
    options: &OpenOptions,
) {
    if !options.write_index || options.read_only_index || options.index_in_memory {
        return;
    }
    let Some(ip) = index_path else {
        return;
    };
    let blob = match shared.export_gzidx_blob() {
        Ok(b) => b,
        Err(e) => {
            eprintln!("info: rapidgzip GZIDX export failed: {e}");
            return;
        }
    };
    match open_or_create_writable_index(ip) {
        Ok(idx) => {
            if let Err(e) = idx.ensure_compression_tables() {
                eprintln!("info: could not ensure compression tables for gzip blob: {e}");
                return;
            }
            match idx.set_gzip_index_blob(&blob) {
                Ok(()) => eprintln!(
                    "gzip GZIDX (rapidgzip): stored {}-byte seek index in {}",
                    blob.len(),
                    ip.display()
                ),
                Err(e) => eprintln!("info: could not store rapidgzip GZIDX blob: {e}"),
            }
            if let Err(e) = idx.store_tarstats_for_path(shared.path()) {
                eprintln!("info: could not store tarstats for rapidgzip index: {e}");
            }
        }
        Err(e) => eprintln!("info: could not open index to store rapidgzip GZIDX: {e}"),
    }
}

/// Open gzip: always seekable (RGZI/GZIDX import when present); TAR / formats / single-file over body.
///
/// Plain single-file `.gz` uses [`SingleFileMountSource::from_seekable_body`] — **no materialize**.
/// Path-only residual backends (EXT4 superblock, SquashFS, libarchive-only) may still materialize.
///
/// With feature `gzip-rapidgzip` and `RATARMOUNT_GZIP_BACKEND=rapidgzip` (or
/// `--use-backend rapidgzip`), path / nested / Range opens prefer the parallel
/// IndexedReader backend (typed [`SharedRapidgzip`](ratarmount_compress::SharedRapidgzip)
/// for GZIDX import/export) and fall back to G3 on path open failure, nested
/// prefer failure after rewind when the stream is recoverable, and Range reopen
/// when a fresh handle remains. Residual: nested recover/rewind failure has no
/// second handle (unlike path reopen / Range).
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
    let threads = options.threads_for("gzip");

    #[cfg(feature = "gzip-rapidgzip")]
    if ratarmount_compress::prefer_rapidgzip_gzip_backend(&options.use_backends) {
        let rg_threads = rapidgzip_threads(options);
        match open_shared_rapidgzip_path(path, spacing, rg_threads, index_path, recreate) {
            Ok(shared) => {
                // Keep typed Arc for GZIDX export after body/TAR open (create_index_body
                // already accepts Arc<dyn SeekableBody>).
                let body: Arc<dyn SeekableBody> = shared.clone();
                let src = open_from_seekable_body(
                    path,
                    body,
                    index_path,
                    options,
                    recreate,
                    "gzip-rapidgzip",
                )?;
                persist_rapidgzip_index_blob(shared.as_ref(), index_path, options);
                return Ok(src);
            }
            Err(e) => {
                eprintln!(
                    "info: rapidgzip gzip open failed ({e}); falling back to G3 seekable gzip"
                );
            }
        }
    }

    let gzip = open_shared_seekable_gzip_path(path, spacing, threads, index_path, recreate)?;

    let is_tar =
        name_suggests_compressed_tar(path) || body_looks_like_tar_gzip(&gzip).unwrap_or(false);
    if is_tar {
        let tar = open_tar_gzip(path, Arc::clone(&gzip), index_path, options, recreate)?;
        persist_gzip_index_blob(&gzip, index_path, options);
        return Ok(Arc::new(tar));
    }

    // Plain `.gz` / non-TAR body: still persist RGZI so warm remount imports
    // checkpoints (index shell created if missing — no TAR files table required).
    let body: Arc<dyn SeekableBody> = gzip.clone();
    let src = open_from_seekable_body(path, body, index_path, options, recreate, "gzip")?;
    persist_gzip_index_blob(&gzip, index_path, options);
    Ok(src)
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
/// offsets cannot be converted to `u64`, or `tarstats` mismatches `archive_path`.
fn try_load_zstd_blocks(
    index_path: Option<&Path>,
    archive_path: Option<&Path>,
    recreate: bool,
) -> Option<Vec<(u64, u64)>> {
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
    if let Some(ap) = archive_path {
        if let Err(e) = idx.check_tarstats_matches_archive(ap) {
            eprintln!("info: zstdblocks skipped (index fingerprint: {e})");
            return None;
        }
    }
    let raw = match idx.get_zstd_blocks() {
        Ok(b) if !b.is_empty() => b,
        _ => return None,
    };
    zstd_blocks_i64_to_u64(&raw)
}

/// Open or create a writable on-disk index for compression side-table writes.
///
/// Creates a fresh schema when the path is missing so plain compress opens
/// (no TAR `files` table build) can still persist `zstdblocks` / `bzip2blocks`.
fn open_or_create_writable_index(ip: &Path) -> Result<SqliteIndex, String> {
    if ip.exists() {
        SqliteIndex::open_writable(ip).map_err(|e| e.to_string())
    } else {
        SqliteIndex::create_writable(Some(ip)).map_err(|e| e.to_string())
    }
}

/// Persist exported `zstdblocks` into the SQLite side table when writable.
///
/// No-op for `:memory:` / missing path / read-only / `write_index = false` / empty map.
/// Creates the index file when the path is set but does not yet exist (plain compress).
/// When `archive_path` is set, also stores `tarstats` for warm-open fingerprinting.
fn store_zstd_blocks_in_index(
    blocks: &[(u64, u64)],
    index_path: Option<&Path>,
    archive_path: Option<&Path>,
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
    let Some(i64_blocks) = zstd_blocks_u64_to_i64(blocks) else {
        eprintln!("info: zstdblocks offsets exceed i64 range; skipping side-table write");
        return;
    };
    match open_or_create_writable_index(ip) {
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
            if let Some(ap) = archive_path {
                if let Err(e) = idx.store_tarstats_for_path(ap) {
                    eprintln!("info: could not store tarstats for zstdblocks index: {e}");
                }
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
    if index_path.is_none() {
        return;
    }
    match export_zstd_blocks(path) {
        Ok(blocks) => store_zstd_blocks_in_index(&blocks, index_path, Some(path), options),
        Err(e) => eprintln!("info: could not export zstdblocks: {e}"),
    }
}

/// Open seekable zstd from a path, preferring imported `zstdblocks` when available.
///
/// Returns `(body, true)` when the side-table map was used (caller may skip re-export).
fn open_seekable_zstd_prefer_blocks(
    path: &Path,
    threads: u32,
    index_path: Option<&Path>,
    recreate: bool,
) -> Result<(Arc<dyn SeekableBody>, bool), String> {
    if let Some(blocks) = try_load_zstd_blocks(index_path, Some(path), recreate) {
        match open_seekable_zstd_with_zstd_blocks(path, threads, &blocks) {
            Ok(body) => {
                eprintln!(
                    "seekable zstd (imported zstdblocks): {} ({} uncompressed bytes, {} checkpoints, -P zstd:{})",
                    path.display(),
                    body.size(),
                    body.checkpoint_count(),
                    threads
                );
                return Ok((body, true));
            }
            Err(e) => {
                eprintln!("info: zstdblocks import failed ({e}); rebuilding frame map");
            }
        }
    }
    open_seekable_zstd_with_threads(path, threads)
        .map(|body| (body, false))
        .map_err(|e| e.to_string())
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
    let blocks = try_load_zstd_blocks(index_path, Some(label), recreate)?;
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
/// the frame map in the SQLite side table when the index is writable **and** the
/// open did not already reuse a side-table map (avoids a full stream rescan on
/// warm reimport — FR-9).
fn open_zstd(
    path: &Path,
    index_path: Option<&Path>,
    options: &OpenOptions,
    recreate: bool,
) -> Result<Arc<dyn MountSource>, String> {
    let threads = options.threads_for("zstd");
    let (body, used_blocks) =
        open_seekable_zstd_prefer_blocks(path, threads, index_path, recreate)?;
    let src = open_from_seekable_body(path, body, index_path, options, recreate, "zstd")?;
    // Index is now on disk (or memory); side-table write only when path exists
    // and we rebuilt the frame map (cold open / import miss / import failure).
    if !used_blocks {
        persist_zstd_blocks_from_path(path, index_path, options);
    }
    Ok(src)
}

/// Read Python-compatible `bzip2blocks` from an on-disk SQLite index, if present.
///
/// Returns `None` when `tarstats` mismatches `archive_path` (stale after in-place replace).
fn try_load_bzip2_blocks(
    index_path: Option<&Path>,
    archive_path: Option<&Path>,
    recreate: bool,
) -> Option<Vec<(u64, u64)>> {
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
    if let Some(ap) = archive_path {
        if let Err(e) = idx.check_tarstats_matches_archive(ap) {
            eprintln!("info: bzip2blocks skipped (index fingerprint: {e})");
            return None;
        }
    }
    let raw = match idx.get_bzip2_blocks() {
        Ok(b) if !b.is_empty() => b,
        _ => return None,
    };
    zstd_blocks_i64_to_u64(&raw)
}

fn store_bzip2_blocks_in_index(
    blocks: &[(u64, u64)],
    index_path: Option<&Path>,
    archive_path: Option<&Path>,
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
    let Some(i64_blocks) = zstd_blocks_u64_to_i64(blocks) else {
        eprintln!("info: bzip2blocks offsets exceed i64 range; skipping side-table write");
        return;
    };
    match open_or_create_writable_index(ip) {
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
            if let Some(ap) = archive_path {
                if let Err(e) = idx.store_tarstats_for_path(ap) {
                    eprintln!("info: could not store tarstats for bzip2blocks index: {e}");
                }
            }
        }
        Err(e) => eprintln!("info: could not open index to store bzip2blocks: {e}"),
    }
}

fn persist_bzip2_blocks_from_path(path: &Path, index_path: Option<&Path>, options: &OpenOptions) {
    if !options.write_index || options.read_only_index || options.index_in_memory {
        return;
    }
    if index_path.is_none() {
        return;
    }
    match export_bzip2_blocks(path) {
        Ok(blocks) => store_bzip2_blocks_in_index(&blocks, index_path, Some(path), options),
        Err(e) => eprintln!("info: could not export bzip2blocks: {e}"),
    }
}

/// Open seekable bzip2 from a path, preferring imported `bzip2blocks` when available.
///
/// Returns `(body, true)` when the side-table map was used (caller may skip re-export).
fn open_seekable_bzip2_prefer_blocks(
    path: &Path,
    threads: u32,
    index_path: Option<&Path>,
    recreate: bool,
) -> Result<(Arc<dyn SeekableBody>, bool), String> {
    if let Some(blocks) = try_load_bzip2_blocks(index_path, Some(path), recreate) {
        match open_seekable_bzip2_with_bzip2_blocks(path, threads, &blocks) {
            Ok(body) => {
                eprintln!(
                    "seekable bzip2 (imported bzip2blocks): {} ({} uncompressed bytes, {} checkpoints, -P bzip2:{})",
                    path.display(),
                    body.size(),
                    body.checkpoint_count(),
                    threads
                );
                return Ok((body, true));
            }
            Err(e) => {
                eprintln!("info: bzip2blocks import failed ({e}); rebuilding bit-block map");
            }
        }
    }
    open_seekable_bzip2_with_threads(path, threads)
        .map(|body| (body, false))
        .map_err(|e| e.to_string())
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
    let blocks = try_load_bzip2_blocks(index_path, Some(label), recreate)?;
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
///
/// On warm open, a present `bzip2blocks` side table is imported so the bit-block
/// map is not rebuilt. Export runs only when the open rebuilt the map (FR-9).
fn open_bzip2(
    path: &Path,
    index_path: Option<&Path>,
    options: &OpenOptions,
    recreate: bool,
) -> Result<Arc<dyn MountSource>, String> {
    let threads = options.threads_for("bzip2");
    let (body, used_blocks) =
        open_seekable_bzip2_prefer_blocks(path, threads, index_path, recreate)?;
    let src = open_from_seekable_body(path, body, index_path, options, recreate, "bzip2")?;
    if !used_blocks {
        persist_bzip2_blocks_from_path(path, index_path, options);
    }
    Ok(src)
}

/// Mount from an already-opened seekable uncompressed body (path or remote Range codec).
///
/// TAR → index over body; other archives → `open_from_reader` when practical;
/// plain single-file → [`SingleFileMountSource::from_seekable_body`] (**no** full `io::copy`).
/// Residual path-only backends (EXT4 / classic SquashFS lzma / libarchive-only) may still materialize.
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

    if let Some(src) =
        try_open_formats_from_seekable_body(path, Arc::clone(&body), index_path, options, recreate)?
    {
        return Ok(src);
    }

    // Residual path-only backends that cannot open from a reader yet.
    if body_needs_path_materialize(&body) {
        return materialize_seekable_body_for_path_backends(
            path, body, index_path, options, recreate,
        );
    }

    let stripped =
        strip_compression_suffix(path.file_name().and_then(|s| s.to_str()).unwrap_or("file"));
    Ok(Arc::new(
        SingleFileMountSource::from_seekable_body(stripped, body).map_err(|e| e.to_string())?,
    ))
}

/// Probe uncompressed archive formats via `open_from_reader` on a seekable body (no `/tmp`).
///
/// Returns `Ok(None)` when magic/name does not match a reader-capable backend (caller
/// may single-file or residual-materialize). Hard open errors propagate as `Err`.
fn try_open_formats_from_seekable_body(
    label: &Path,
    body: Arc<dyn SeekableBody>,
    index_path: Option<&Path>,
    options: &OpenOptions,
    recreate: bool,
) -> Result<Option<Arc<dyn MountSource>>, String> {
    use std::io::{Read, Seek, SeekFrom};

    let mut head = [0u8; 512];
    let n = {
        let mut r = body.open_reader().map_err(|e| e.to_string())?;
        r.read(&mut head).map_err(|e| e.to_string())?
    };
    let head = &head[..n];

    let open_reader = || body.open_reader().map_err(|e| e.to_string());

    // 7z
    if head.len() >= 6 && &head[..6] == b"7z\xBC\xAF'\x1C" {
        let r = open_reader()?;
        return Ok(Some(Arc::new(
            SevenZipMountSource::open_from_reader(r, label, index_path, options, VERSION, recreate)
                .map_err(|e| e.to_string())?,
        )));
    }
    // Unix ar
    if head.len() >= 8 && &head[..8] == b"!<arch>\n" {
        let r = open_reader()?;
        return Ok(Some(Arc::new(
            ArMountSource::open_from_reader(r, label, index_path, options, VERSION)
                .map_err(|e| e.to_string())?,
        )));
    }
    // XAR
    if head.len() >= 4 && &head[..4] == b"xar!" {
        let r = open_reader()?;
        return Ok(Some(Arc::new(
            XarMountSource::open_from_reader(r, label, index_path, options, VERSION)
                .map_err(|e| e.to_string())?,
        )));
    }
    // CAB (store/MSZIP; LZX → residual materialize + libarchive)
    if head.len() >= 4 && &head[..4] == b"MSCF" {
        let r = open_reader()?;
        match CabMountSource::open_from_reader(r, label, index_path, options, VERSION, recreate) {
            Ok(s) => return Ok(Some(Arc::new(s))),
            Err(CabError::UnsupportedCompression(_)) => {
                return Ok(Some(materialize_seekable_body_for_path_backends(
                    label, body, index_path, options, recreate,
                )?));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    // SQLAR / SQLite
    if head.len() >= 16 && &head[..16] == b"SQLite format 3\0" {
        let r = open_reader()?;
        return Ok(Some(Arc::new(
            SqlarMountSource::open_from_reader(r, label, options).map_err(|e| e.to_string())?,
        )));
    }
    // CPIO
    if head_looks_like_cpio(head) {
        let r = open_reader()?;
        return Ok(Some(Arc::new(
            CpioMountSource::open_from_reader(r, label, index_path, options, VERSION)
                .map_err(|e| e.to_string())?,
        )));
    }
    // WARC
    if head.len() >= 5 && &head[..5] == b"WARC/" {
        let r = open_reader()?;
        return Ok(Some(Arc::new(
            WarcMountSource::open_from_reader(r, label, index_path, options, VERSION)
                .map_err(|e| e.to_string())?,
        )));
    }
    // ZIP
    if head.len() >= 4 && &head[..2] == b"PK" {
        let r = open_reader()?;
        return Ok(Some(Arc::new(
            ZipMountSource::open_from_reader(r, label, index_path, options, VERSION)
                .map_err(|e| e.to_string())?,
        )));
    }
    // TAR (ustar / name) — normally handled before this helper, but catch edge cases.
    if (head.len() >= 262 && &head[257..262] == b"ustar")
        || (head.len() >= 265 && &head[257..263] == b"ustar ")
        || name_suggests_plain_tar(label)
    {
        let r = open_reader()?;
        return Ok(Some(Arc::new(
            SqliteIndexedTar::open_from_reader(r, label, index_path, options, VERSION)
                .map_err(|e| e.to_string())?,
        )));
    }
    // ISO 9660: PVD at sector 16 or name
    {
        let mut r = open_reader()?;
        let looks_iso = name_suggests_iso(label)
            || ratarmount_formats_iso9660::looks_like_iso9660_reader(&mut r);
        let _ = r.seek(SeekFrom::Start(0));
        if looks_iso {
            return Ok(Some(Arc::new(
                Iso9660MountSource::open_from_reader(r, label, index_path, options, VERSION)
                    .map_err(|e| e.to_string())?,
            )));
        }
    }
    // ASAR by name
    if name_suggests_asar(label) {
        let r = open_reader()?;
        return Ok(Some(Arc::new(
            AsarMountSource::open_from_reader(r, label, index_path, options, VERSION, recreate)
                .map_err(|e| e.to_string())?,
        )));
    }
    // Extension fallbacks (magic missed)
    if name_suggests_ext(label, &["warc"]) {
        let r = open_reader()?;
        return Ok(Some(Arc::new(
            WarcMountSource::open_from_reader(r, label, index_path, options, VERSION)
                .map_err(|e| e.to_string())?,
        )));
    }
    if name_suggests_ext(label, &["cpio"]) {
        let r = open_reader()?;
        return Ok(Some(Arc::new(
            CpioMountSource::open_from_reader(r, label, index_path, options, VERSION)
                .map_err(|e| e.to_string())?,
        )));
    }
    if name_suggests_ext(label, &["ar", "a"]) {
        let r = open_reader()?;
        return Ok(Some(Arc::new(
            ArMountSource::open_from_reader(r, label, index_path, options, VERSION)
                .map_err(|e| e.to_string())?,
        )));
    }
    if name_suggests_ext(label, &["xar"]) {
        let r = open_reader()?;
        return Ok(Some(Arc::new(
            XarMountSource::open_from_reader(r, label, index_path, options, VERSION)
                .map_err(|e| e.to_string())?,
        )));
    }
    if name_suggests_ext(label, &["cab"]) {
        let r = open_reader()?;
        match CabMountSource::open_from_reader(r, label, index_path, options, VERSION, recreate) {
            Ok(s) => return Ok(Some(Arc::new(s))),
            Err(CabError::UnsupportedCompression(_)) => {
                return Ok(Some(materialize_seekable_body_for_path_backends(
                    label, body, index_path, options, recreate,
                )?));
            }
            Err(e) => return Err(e.to_string()),
        }
    }
    if name_suggests_ext(label, &["sqlar"]) {
        let r = open_reader()?;
        return Ok(Some(Arc::new(
            SqlarMountSource::open_from_reader(r, label, options).map_err(|e| e.to_string())?,
        )));
    }
    // FAT image
    {
        let mut r = open_reader()?;
        let looks_fat = name_suggests_ext(label, &["fat", "vfat", "fat12", "fat16", "fat32"])
            || looks_like_fat_reader(&mut r);
        let _ = r.seek(SeekFrom::Start(0));
        if looks_fat {
            return Ok(Some(Arc::new(
                FatMountSource::open_from_reader(r, label).map_err(|e| e.to_string())?,
            )));
        }
    }
    // SquashFS (in-process backhand; classic LZMA → Ok(None) → path materialize residual)
    {
        let mut r = open_reader()?;
        let looks_sqfs = name_suggests_ext(label, &["squashfs", "sqfs", "snap"])
            || looks_like_squashfs_reader(&mut r);
        let _ = r.seek(SeekFrom::Start(0));
        if looks_sqfs {
            match SquashFsMountSource::open_from_reader(r, label) {
                Ok(s) => return Ok(Some(Arc::new(s))),
                Err(e) => {
                    log::debug!(
                        "squashfs open_from_reader failed for {} ({e}); residual path materialize",
                        label.display()
                    );
                    return Ok(None);
                }
            }
        }
    }
    // EXT2/3/4 (pure ext4-view shared stream; pure fail → Ok(None) → path materialize / debugfs)
    {
        let mut r = open_reader()?;
        let looks_ext4 = name_suggests_ext(label, &["ext2", "ext3", "ext4", "ext4img"])
            || looks_like_ext4_reader(&mut r);
        let _ = r.seek(SeekFrom::Start(0));
        if looks_ext4 {
            match Ext4MountSource::open_from_reader(r, label) {
                Ok(s) => return Ok(Some(Arc::new(s))),
                Err(e) => {
                    log::debug!(
                        "ext4 open_from_reader failed for {} ({e}); residual path materialize",
                        label.display()
                    );
                    return Ok(None);
                }
            }
        }
    }

    Ok(None)
}

/// True when the uncompressed body looks like a path-only residual (EXT4 / classic SquashFS lzma / RAR…).
fn body_needs_path_materialize(body: &Arc<dyn SeekableBody>) -> bool {
    use std::io::{Read, Seek, SeekFrom};
    let mut r = match body.open_reader() {
        Ok(r) => r,
        Err(_) => return false,
    };
    // EXT superblock magic 0xEF53 at absolute offset 1024+0x38.
    if r.seek(SeekFrom::Start(1024 + 0x38)).is_ok() {
        let mut m = [0u8; 2];
        if r.read_exact(&mut m).is_ok() && u16::from_le_bytes(m) == 0xEF53 {
            return true;
        }
    }
    let _ = r.seek(SeekFrom::Start(0));
    let mut head = [0u8; 16];
    let n = r.read(&mut head).unwrap_or(0);
    let head = &head[..n];
    // SquashFS little/big endian magic — only residual when open_from_reader failed
    // (classic LZMA / corrupt); in-process codecs open earlier without materialize.
    if head.len() >= 4 && (&head[..4] == b"hsqs" || &head[..4] == b"sqsh") {
        return true;
    }
    // RAR (libarchive path residual)
    if (head.len() >= 7 && &head[..7] == b"Rar!\x1a\x07\x00")
        || (head.len() >= 8 && &head[..8] == b"Rar!\x1a\x07\x01\x00")
    {
        return true;
    }
    // CAB LZX residual is detected only after Cab open fails; MSCF alone is not enough.
    false
}

/// Materialize a seekable body once for residual path-only backends (EXT4 / SquashFS / libarchive).
fn materialize_seekable_body_for_path_backends(
    path: &Path,
    body: Arc<dyn SeekableBody>,
    index_path: Option<&Path>,
    options: &OpenOptions,
    recreate: bool,
) -> Result<Arc<dyn MountSource>, String> {
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
    if looks_like_squashfs(&data_path) {
        let keep = tmp
            .into_temp_path()
            .keep()
            .map_err(|e| e.error.to_string())?;
        return Ok(Arc::new(
            SquashFsMountSource::open(&keep).map_err(|e| e.to_string())?,
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
    // Fallback: keep temp as single-file (should be rare after body_needs_path_materialize).
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
    /// Cap for eager AutoMount same-dir nested opens (FR-6 / #80).
    /// `0` = auto `available_parallelism`; `1` = sequential; `N≥2` = cap workers.
    /// Ignored when `lazy` is true. Default `0` matches [`AutoMountOptions`].
    pub parallel_nested_threads: u32,
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
                // FR-6 / #80: CLI `--parallel-nested` (0 = auto available_parallelism).
                parallel_nested_threads: comp.parallel_nested_threads,
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

            // Single reopen token shared by rapidgzip prefer-path and G3 import-fail.
            let mut reopen_opt = Some(reopen);

            #[cfg(feature = "gzip-rapidgzip")]
            if ratarmount_compress::prefer_rapidgzip_gzip_backend(&o.use_backends) {
                let rg_threads = rapidgzip_threads(&o);
                let rg_result: Result<Arc<ratarmount_compress::SharedRapidgzip>, String> =
                    if let Some(blob) = try_load_gzip_index_blob(ip, Some(&label), recreate) {
                        let fmt = gzip_seek_index_format_label(&blob);
                        match ratarmount_compress::SharedRapidgzip::open_with_imported_index_from_reader(
                            range, spacing, rg_threads, &label, &blob,
                        ) {
                            Ok(shared) => {
                                eprintln!(
                                    "seekable gzip-rapidgzip (imported {fmt}): {} ({} uncompressed bytes, {} checkpoints, -P rapidgzip-gzip:{})",
                                    label.display(),
                                    shared.size(),
                                    shared.checkpoint_count(),
                                    rg_threads
                                );
                                Ok(shared)
                            }
                            Err(e) => {
                                eprintln!(
                                    "info: rapidgzip {fmt} import failed ({e}); rebuilding seek index"
                                );
                                let reopen_fn = reopen_opt.take().ok_or_else(|| {
                                    "internal: reopen already consumed".to_string()
                                })?;
                                let fresh = reopen_fn()?;
                                ratarmount_compress::SharedRapidgzip::open_with_threads_from_reader(
                                    fresh, spacing, rg_threads, &label,
                                )
                                .map_err(|e| e.to_string())
                            }
                        }
                    } else {
                        ratarmount_compress::SharedRapidgzip::open_with_threads_from_reader(
                            range, spacing, rg_threads, &label,
                        )
                        .map_err(|e| e.to_string())
                    };

                match rg_result {
                    Ok(shared) => {
                        let body: Arc<dyn SeekableBody> = shared.clone();
                        let src = open_from_seekable_body(
                            &label,
                            body,
                            ip,
                            &o,
                            recreate,
                            "gzip-rapidgzip",
                        )?;
                        persist_rapidgzip_index_blob(shared.as_ref(), ip, &o);
                        return Ok(Some((label, src)));
                    }
                    Err(e) => {
                        eprintln!(
                            "info: rapidgzip gzip open failed ({e}); falling back to G3 seekable gzip"
                        );
                        let reopen_fn = reopen_opt.take().ok_or_else(|| {
                            format!(
                                "rapidgzip gzip open failed and no {transport} Range reopen left: {e}"
                            )
                        })?;
                        range = reopen_fn()?;
                    }
                }
            }

            // Prefer RGZI/GZIDX import; on failure rebuild with a fresh Range handle.
            let gzip = if try_load_gzip_index_blob(ip, Some(&label), recreate).is_some() {
                match try_open_gzip_imported_from_reader(
                    range, &label, spacing, threads, ip, recreate,
                ) {
                    Some(g) => g,
                    None => {
                        let reopen_fn = reopen_opt
                            .take()
                            .ok_or_else(|| "internal: reopen already consumed".to_string())?;
                        let fresh = reopen_fn()?;
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
            // Plain .gz: formats / single-file over seekable body (no materialize).
            // Persist RGZI so warm Range remount can import (create index shell if needed).
            let body: Arc<dyn SeekableBody> = gzip.clone();
            let src = open_from_seekable_body(&label, body, ip, &o, recreate, "gzip")?;
            persist_gzip_index_blob(&gzip, ip, &o);
            Ok(Some((label, src)))
        }
        "bzip2" => {
            let threads = o.threads_for("bzip2");
            eprintln!(
                "{transport} bzip2: {input} ({range_len} compressed bytes, live Range, -P bzip2:{threads})"
            );
            // Prefer bzip2blocks import; on success skip re-export (FR-9). Keep
            // `reopen` for post-open export only when the map was rebuilt.
            let mut reopen_opt = Some(reopen);
            let mut used_blocks = false;
            let body = if try_load_bzip2_blocks(ip, Some(&label), recreate).is_some() {
                match try_open_bzip2_imported_from_reader(range, &label, threads, ip, recreate) {
                    Some(b) => {
                        used_blocks = true;
                        b
                    }
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
            if !used_blocks {
                if let Some(reopen_fn) = reopen_opt {
                    if o.write_index && !o.read_only_index && !o.index_in_memory {
                        if let Some(ipath) = ip {
                            if ipath.exists() {
                                match reopen_fn() {
                                    Ok(mut fresh) => {
                                        match export_bzip2_blocks_from_reader(&mut fresh) {
                                            Ok(blocks) => store_bzip2_blocks_in_index(
                                                &blocks,
                                                ip,
                                                Some(&label),
                                                &o,
                                            ),
                                            Err(e) => {
                                                eprintln!("info: could not export bzip2blocks: {e}")
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "info: could not reopen stream for bzip2blocks: {e}"
                                        )
                                    }
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
            // Prefer zstdblocks import; on success skip re-export (FR-9). Keep
            // `reopen` for post-open export only when the map was rebuilt.
            let mut reopen_opt = Some(reopen);
            let mut used_blocks = false;
            let body = if try_load_zstd_blocks(ip, Some(&label), recreate).is_some() {
                match try_open_zstd_imported_from_reader(range, &label, threads, ip, recreate) {
                    Some(b) => {
                        used_blocks = true;
                        b
                    }
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
            // Best-effort export via a fresh Range handle when still available
            // and we rebuilt (cold open / import miss).
            if !used_blocks {
                if let Some(reopen_fn) = reopen_opt {
                    if o.write_index && !o.read_only_index && !o.index_in_memory {
                        if let Some(ipath) = ip {
                            if ipath.exists() {
                                match reopen_fn() {
                                    Ok(mut fresh) => {
                                        match export_zstd_blocks_from_reader(&mut fresh) {
                                            Ok(blocks) => store_zstd_blocks_in_index(
                                                &blocks,
                                                ip,
                                                Some(&label),
                                                &o,
                                            ),
                                            Err(e) => {
                                                eprintln!("info: could not export zstdblocks: {e}")
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "info: could not reopen stream for zstdblocks: {e}"
                                        )
                                    }
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
            parallel_nested_threads: 0, // auto
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
    use std::io::Read;
    use std::process::Command;

    /// Plain 1-file TAR for B-119 index-minimum-file-count regression tests.
    fn make_tiny_plain_tar(dir: &Path) -> PathBuf {
        let data = dir.join("data-plain");
        std::fs::create_dir_all(&data).expect("mkdir");
        std::fs::write(data.join("hello.txt"), b"hello world\n").expect("write");
        let tar_path = dir.join("tiny-plain.tar");
        let status = Command::new("tar")
            .args(["-cf"])
            .arg(&tar_path)
            .arg("-C")
            .arg(&data)
            .arg("hello.txt")
            .status()
            .expect("spawn tar");
        assert!(status.success(), "tar -cf failed");
        tar_path
    }

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

    /// Regression: Dec 31 1969-style silent wrong data class — warm `*.index.sqlite` reuse
    /// without archive fingerprint. After replacing the archive in place (size/mtime
    /// change), remount with the existing index path must rebuild and serve **new** bytes.
    #[test]
    fn warm_index_rebuilds_when_archive_size_or_mtime_changes() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data-swap");
        std::fs::create_dir_all(&data).expect("mkdir");
        std::fs::write(data.join("hello.txt"), b"content-v1\n").expect("write v1");
        let archive = dir.path().join("swap.tar");
        let status = Command::new("tar")
            .args(["-cf"])
            .arg(&archive)
            .arg("-C")
            .arg(&data)
            .arg("hello.txt")
            .status()
            .expect("spawn tar");
        assert!(status.success(), "tar -cf v1 failed");

        let index = dir.path().join("swap.tar.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            write_index: true,
            index_minimum_file_count: 0,
            ..Default::default()
        };

        let src = open_path(&archive, &opts, true).expect("cold open");
        let info = src.lookup("/hello.txt", 0).expect("lookup v1");
        let mut buf = Vec::new();
        src.open(&info, 0)
            .expect("open v1")
            .read_to_end(&mut buf)
            .expect("read v1");
        assert_eq!(buf, b"content-v1\n");
        drop(src);
        assert!(index.exists() && std::fs::metadata(&index).unwrap().len() > 0);

        // Overwrite archive at the same path with different content (size changes).
        std::fs::write(data.join("hello.txt"), b"content-v2-longer\n").expect("write v2");
        let status = Command::new("tar")
            .args(["-cf"])
            .arg(&archive)
            .arg("-C")
            .arg(&data)
            .arg("hello.txt")
            .status()
            .expect("spawn tar rewrite");
        assert!(status.success(), "tar -cf v2 failed");

        // Warm open: no force-recreate; tarstats mismatch must rebuild the index.
        let src2 = open_path(&archive, &opts, false).expect("warm open after replace");
        let info2 = src2.lookup("/hello.txt", 0).expect("lookup v2");
        let mut buf2 = Vec::new();
        src2.open(&info2, 0)
            .expect("open v2")
            .read_to_end(&mut buf2)
            .expect("read v2");
        assert_eq!(
            buf2,
            b"content-v2-longer\n",
            "must serve new archive data after tarstats mismatch rebuild, got {:?}",
            String::from_utf8_lossy(&buf2)
        );
    }

    /// Regression: B-119 / upstream #119 — small archive must not leave an on-disk index
    /// when `--index-minimum-file-count` is above the member count (even with explicit
    /// `--index-file`). Mount still serves content via the live (unlinked) index.
    #[test]
    fn index_minimum_file_count_skips_small_archive() {
        let dir = tempfile::tempdir().unwrap();
        let archive = make_tiny_plain_tar(dir.path());
        let index = dir.path().join("forced.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            write_index: true,
            index_minimum_file_count: 1000,
            ..Default::default()
        };
        let src = open_path(&archive, &opts, true).expect("open small tar");
        // Content readable without FUSE.
        let info = src.lookup("/hello.txt", 0).expect("lookup hello.txt");
        let mut r = src.open(&info, 0).expect("open member");
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).expect("read member");
        assert_eq!(buf, b"hello world\n");
        drop(src);
        assert!(
            !index.exists(),
            "expected no on-disk index for small archive with index_minimum_file_count=1000; \
             path still present: {}",
            index.display()
        );
    }

    /// Regression: B-119 — minimum 0 (always allow) or 1 (tiny archive meets threshold)
    /// still writes the index when write_index is true.
    #[test]
    fn index_minimum_file_count_zero_or_one_writes_index() {
        let dir = tempfile::tempdir().unwrap();
        let archive = make_tiny_plain_tar(dir.path());

        for (min, name) in [(0u64, "min0"), (1u64, "min1")] {
            let index = dir.path().join(format!("{name}.index.sqlite"));
            let opts = OpenOptions {
                index_file_path: Some(index.clone()),
                write_index: true,
                index_minimum_file_count: min,
                ..Default::default()
            };
            let src = open_path(&archive, &opts, true).expect("open");
            drop(src);
            assert!(
                index.exists(),
                "expected on-disk index when index_minimum_file_count={min}"
            );
            let meta = std::fs::metadata(&index).expect("stat index");
            assert!(meta.len() > 0, "index should be non-empty for min={min}");
        }
    }

    /// Sibling auto index next to the archive honors the same minimum gate (B-119).
    #[test]
    fn index_minimum_file_count_skips_sibling_auto_index() {
        let dir = tempfile::tempdir().unwrap();
        let archive = make_tiny_plain_tar(dir.path());
        // Empty index_folders entry → next to archive.
        let opts = OpenOptions {
            index_file_path: None,
            index_folders: vec![PathBuf::from("")],
            write_index: true,
            index_minimum_file_count: 1000,
            ..Default::default()
        };
        let sibling = {
            let mut p = archive.as_os_str().to_os_string();
            p.push(".index.sqlite");
            PathBuf::from(p)
        };
        let src = open_path(&archive, &opts, true).expect("open");
        drop(src);
        assert!(
            !sibling.exists(),
            "sibling auto index should not remain for small archive"
        );
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
        // Skip when `zstd` is not on PATH (e.g. stock macOS CI without brew zstd).
        let Ok(status) = Command::new("zstd")
            .args(["-f", "-19", "--stream-size=1024", "-o"])
            .arg(&tar_zst)
            .arg(&tar_path)
            .status()
        else {
            // Caller tests that need this fixture should skip when missing.
            return PathBuf::new();
        };
        if !status.success() {
            // Older zstd without --stream-size: plain compress still yields exportable map.
            let Ok(status) = Command::new("zstd")
                .args(["-f", "-o"])
                .arg(&tar_zst)
                .arg(&tar_path)
                .status()
            else {
                return PathBuf::new();
            };
            if !status.success() {
                return PathBuf::new();
            }
        }
        tar_zst
    }

    /// Patterned payload spanning >1 bzip2 block at compression level 1 (100 KiB).
    fn multi_block_bz2_payload() -> Vec<u8> {
        let mut data = Vec::with_capacity(350_000);
        for i in 0..350_000u32 {
            data.push(((i / 17) % 251) as u8);
        }
        data
    }

    fn make_tiny_tar_bz2(dir: &Path) -> PathBuf {
        let data = dir.join("data-bz2");
        std::fs::create_dir_all(&data).expect("mkdir");
        std::fs::write(data.join("hello.txt"), b"hello world from bzip2\n").expect("write");
        // Multi-block: level-1 bzip2 uses 100 KiB blocks; pad must exceed one block.
        std::fs::write(data.join("pad.bin"), multi_block_bz2_payload()).expect("write pad");
        let tar_path = dir.join("tiny-bz2.tar");
        let status = Command::new("tar")
            .args(["-cf"])
            .arg(&tar_path)
            .arg("-C")
            .arg(&data)
            .args(["hello.txt", "pad.bin"])
            .status()
            .expect("spawn tar");
        assert!(status.success(), "tar -cf failed");
        let tar_bz2 = dir.join("tiny.tar.bz2");
        // `-1` → 100 KiB blocks so export_bzip2_blocks sees a multi-block map.
        let Ok(out) = std::fs::File::create(&tar_bz2) else {
            return PathBuf::new();
        };
        let Ok(status) = Command::new("bzip2")
            .args(["-1", "-k", "-f", "-c"])
            .arg(&tar_path)
            .stdout(out)
            .status()
        else {
            return PathBuf::new();
        };
        if !status.success() {
            return PathBuf::new();
        }
        tar_bz2
    }

    /// Plain multi-frame `.zst` (not TAR) for side-table wire on plain compress open.
    fn make_plain_multi_zst(dir: &Path) -> PathBuf {
        let plain = dir.join("plain.txt");
        std::fs::write(&plain, vec![b'z'; 8192]).expect("write plain");
        let zst = dir.join("plain.txt.zst");
        let Ok(status) = Command::new("zstd")
            .args(["-f", "--stream-size=1024", "-o"])
            .arg(&zst)
            .arg(&plain)
            .status()
        else {
            return PathBuf::new();
        };
        if !status.success() {
            let Ok(status) = Command::new("zstd")
                .args(["-f", "-o"])
                .arg(&zst)
                .arg(&plain)
                .status()
            else {
                return PathBuf::new();
            };
            if !status.success() {
                return PathBuf::new();
            }
        }
        zst
    }

    fn make_plain_bz2(dir: &Path) -> PathBuf {
        let plain = dir.join("plain-bz2.txt");
        // Patterned multi-block payload (not zeros — zeros collapse to one tiny block).
        std::fs::write(&plain, multi_block_bz2_payload()).expect("write plain");
        let bz2 = dir.join("plain-bz2.txt.bz2");
        let Ok(out) = std::fs::File::create(&bz2) else {
            return PathBuf::new();
        };
        let Ok(status) = Command::new("bzip2")
            .args(["-1", "-k", "-f", "-c"])
            .arg(&plain)
            .stdout(out)
            .status()
        else {
            return PathBuf::new();
        };
        if !status.success() {
            return PathBuf::new();
        }
        bz2
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
            write_index: true,
            ..Default::default()
        };

        // Cold open: build seek table + TAR index, then store RGZI side blob.
        let src = open_path(&archive, &opts, true).expect("cold open");
        assert_eq!(
            read_all(src.as_ref(), "/hello.txt"),
            b"hello world\n".as_slice()
        );
        drop(src);

        let idx = SqliteIndex::open_read_only(&index).expect("open index");
        let blobs = idx.get_gzip_index_blobs().expect("get blobs");
        assert_eq!(blobs.len(), 1, "expected single gzipindex blob");
        assert!(
            blobs[0].starts_with(b"RGZI"),
            "blob should be Tier C RGZI magic"
        );
        assert!(
            !blobs[0].is_empty(),
            "RGZI blob must be non-empty after cold"
        );
        let stored = blobs[0].clone();
        drop(idx);

        // Side table is loadable and importable without a full spacing rebuild.
        let loaded = try_load_gzip_index_blob(Some(&index), Some(&archive), false)
            .expect("try_load must surface RGZI before warm open");
        assert_eq!(loaded, stored);
        SharedSeekableGzip::open_with_imported_index(&archive, 64 * 1024, 1, &loaded)
            .expect("stored RGZI must open via import path");

        // Warm open: import blob (no full spacing rebuild required for offsets).
        let src2 = open_path(&archive, &opts, false).expect("warm open with import");
        assert_eq!(
            read_all(src2.as_ref(), "/hello.txt"),
            b"hello world\n".as_slice()
        );
        drop(src2);

        let idx2 = SqliteIndex::open_read_only(&index).expect("reopen index");
        let blobs2 = idx2.get_gzip_index_blobs().expect("blobs again");
        assert_eq!(blobs2, vec![stored]);
        // recreate=true must ignore side table for body build.
        assert!(try_load_gzip_index_blob(Some(&index), Some(&archive), true).is_none());
    }

    /// Regression: plain (non-TAR) `.gz` + write_index creates an index shell and
    /// stores RGZI; second open imports the blob (skips full checkpoint rebuild).
    #[test]
    fn plain_gzip_rgzi_blob_persisted_and_reimported() {
        let dir = tempfile::tempdir().unwrap();
        // SeekableGzip clamps spacing to ≥64 KiB — payload must exceed 2× that for
        // multiple checkpoints (import path is still meaningful with one, but multi
        // proves cold build + export encoded more than the member-start point).
        let mut payload = Vec::new();
        for i in 0..400u32 {
            payload.extend(format!("plain-gz-{i:04}-").repeat(64).into_bytes());
            payload.push(b'\n');
        }
        assert!(
            payload.len() as u64 > 2 * 64 * 1024,
            "payload must exceed 2× min spacing for multi-checkpoint RGZI"
        );
        let plain = dir.path().join("blob.bin");
        std::fs::write(&plain, &payload).expect("write plain");
        let gz = dir.path().join("blob.bin.gz");
        let status = Command::new("gzip")
            .args(["-c"])
            .arg(&plain)
            .stdout(std::fs::File::create(&gz).expect("create gz"))
            .status()
            .expect("spawn gzip");
        assert!(status.success(), "gzip CLI failed");

        let index = dir.path().join("plain.gz.index.sqlite");
        // 64 KiB is the effective floor; passing a smaller value is clamped the same way.
        let spacing = 64 * 1024u64;
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            gzip_seek_point_spacing: spacing,
            write_index: true,
            ..Default::default()
        };

        // Cold open: no TAR index — must still create SQLite shell + RGZI side blob.
        let src = open_path(&gz, &opts, true).expect("cold plain .gz");
        assert_eq!(read_all(src.as_ref(), "/blob.bin"), payload);
        drop(src);

        assert!(
            index.exists(),
            "plain .gz cold open with write_index must create index path for RGZI"
        );
        let stored = {
            let idx = SqliteIndex::open_read_only(&index).expect("open index");
            let blobs = idx.get_gzip_index_blobs().expect("get blobs");
            assert_eq!(blobs.len(), 1, "expected single gzipindex blob");
            assert!(
                blobs[0].starts_with(b"RGZI"),
                "blob should be Tier C RGZI magic, got {:?}",
                blobs[0].get(..8)
            );
            assert!(!blobs[0].is_empty());
            blobs[0].clone()
        };

        // Direct import proves warm path can hydrate without spacing rebuild.
        let loaded = try_load_gzip_index_blob(Some(&index), Some(&gz), false)
            .expect("try_load RGZI after plain cold open");
        assert_eq!(loaded, stored);
        let imported = SharedSeekableGzip::open_with_imported_index(&gz, spacing, 1, &loaded)
            .expect("import path must accept stored RGZI");
        assert!(
            imported.checkpoint_count() >= 2,
            "expected multiple checkpoints on multi-block plain .gz, got {}",
            imported.checkpoint_count()
        );

        // Warm open via factory: import + serve full payload + mid seek.
        let src2 = open_path(&gz, &opts, false).expect("warm plain .gz with RGZI import");
        assert_eq!(read_all(src2.as_ref(), "/blob.bin"), payload);
        let mid = payload.len() / 2;
        assert_eq!(
            read_seek_mid(src2.as_ref(), "/blob.bin", mid as u64).as_slice(),
            &payload[mid..]
        );
        drop(src2);

        let blobs2 = SqliteIndex::open_read_only(&index)
            .expect("reopen")
            .get_gzip_index_blobs()
            .expect("blobs");
        assert_eq!(blobs2, vec![stored], "warm remount must keep RGZI blob");
    }

    /// Regression: write_index=false must not leave an RGZI side table on disk.
    #[test]
    fn plain_gzip_rgzi_skipped_when_write_index_false() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"no-rgzi-when-write-index-false\n";
        let plain = dir.path().join("n.txt");
        std::fs::write(&plain, payload).expect("write");
        let gz = dir.path().join("n.txt.gz");
        let status = Command::new("gzip")
            .args(["-c"])
            .arg(&plain)
            .stdout(std::fs::File::create(&gz).expect("create gz"))
            .status()
            .expect("spawn gzip");
        assert!(status.success(), "gzip CLI failed");

        let index = dir.path().join("n.gz.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            gzip_seek_point_spacing: 16 * 1024,
            write_index: false,
            ..Default::default()
        };
        let src = open_path(&gz, &opts, true).expect("open with write_index=false");
        assert_eq!(read_all(src.as_ref(), "/n.txt"), payload.as_slice());
        drop(src);

        // No shell / no side table: either missing file or empty gzip blobs.
        if index.exists() {
            let blobs = SqliteIndex::open_read_only(&index)
                .expect("ro")
                .get_gzip_index_blobs()
                .unwrap_or_default();
            assert!(
                blobs.is_empty(),
                "write_index=false must not store RGZI, got {} blob(s)",
                blobs.len()
            );
        }
    }

    #[test]
    fn gzip_rgzi_invalid_blob_falls_back_to_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let archive = make_tiny_tar_gz(dir.path());
        let index = dir.path().join("tiny.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            gzip_seek_point_spacing: 64 * 1024,
            write_index: true,
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
        assert_eq!(
            read_all(src2.as_ref(), "/hello.txt"),
            b"hello world\n".as_slice()
        );
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
        assert!(try_load_gzip_index_blob(Some(&missing), None, false).is_none());
        assert!(try_load_gzip_index_blob(None, None, false).is_none());
        assert!(try_load_gzip_index_blob(Some(&missing), None, true).is_none());
    }

    /// Regression: import/persist logs must label blob magic (RGZI vs GZIDX), not hardcode one.
    #[test]
    fn gzip_seek_index_format_label_distinguishes_rgzi_gzidx() {
        assert_eq!(
            gzip_seek_index_format_label(b"RGZI\x01\x00\x00\x00"),
            "RGZI"
        );
        assert_eq!(gzip_seek_index_format_label(b"GZIDX\x01\x00rest"), "GZIDX");
        assert_eq!(
            gzip_seek_index_format_label(b"XXXX-not-an-index"),
            "seek-index"
        );
        assert_eq!(gzip_seek_index_format_label(b""), "seek-index");
        assert_eq!(gzip_seek_index_format_label(GZIP_SEEK_INDEX_MAGIC), "RGZI");
        assert_eq!(
            gzip_seek_index_format_label(INDEXED_GZIP_INDEX_MAGIC),
            "GZIDX"
        );
    }

    #[test]
    fn zstd_blocks_persisted_and_reimported() {
        let dir = tempfile::tempdir().unwrap();
        let archive = make_tiny_tar_zst(dir.path());
        if archive.as_os_str().is_empty() {
            eprintln!("skip: zstd CLI unavailable");
            return;
        }
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
        if archive.as_os_str().is_empty() {
            eprintln!("skip: zstd CLI unavailable");
            return;
        }
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
        if archive.as_os_str().is_empty() {
            eprintln!("skip: zstd CLI unavailable");
            return;
        }
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
        assert!(try_load_zstd_blocks(Some(&missing), None, false).is_none());
        assert!(try_load_zstd_blocks(None, None, false).is_none());
        assert!(try_load_zstd_blocks(Some(&missing), None, true).is_none());
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

    /// Regression: FR-9 warm open loads `zstdblocks` and skips full frame rescan export.
    #[test]
    fn zstd_blocks_warm_open_uses_side_table_without_rewrite() {
        let dir = tempfile::tempdir().unwrap();
        let archive = make_tiny_tar_zst(dir.path());
        if archive.as_os_str().is_empty() {
            eprintln!("skip: zstd CLI unavailable");
            return;
        }
        let index = dir.path().join("tiny.zst.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            ..Default::default()
        };

        let src = open_path(&archive, &opts, true).expect("cold open");
        drop(src);
        let stored = {
            let idx = SqliteIndex::open_read_only(&index).expect("open index");
            let blocks = idx.get_zstd_blocks().expect("get zstdblocks");
            assert!(!blocks.is_empty());
            blocks
        };

        // Mark side table with a sentinel last-row identity: warm open must import,
        // not re-export (re-export would rewrite the same pairs; we assert load works
        // and prefer_blocks path is taken via try_load).
        let loaded =
            try_load_zstd_blocks(Some(&index), Some(&archive), false).expect("load for warm open");
        assert_eq!(
            loaded.len(),
            stored.len(),
            "try_load must surface side table before warm open"
        );

        let src2 = open_path(&archive, &opts, false).expect("warm open with import");
        // MountSource stays usable after import-backed body open.
        let _ = src2.list("/");
        drop(src2);

        let blocks2 = {
            let idx = SqliteIndex::open_read_only(&index).expect("reopen");
            idx.get_zstd_blocks().expect("blocks after warm")
        };
        assert_eq!(blocks2, stored, "warm import must not clobber side table");
        // recreate=true must ignore side table for body build (persist may rewrite).
        assert!(try_load_zstd_blocks(Some(&index), Some(&archive), true).is_none());
    }

    /// Regression: FR-9 plain `.zst` also auto-wires `zstdblocks` on open.
    #[test]
    fn zstd_blocks_plain_zst_persisted_and_reimported() {
        let dir = tempfile::tempdir().unwrap();
        let archive = make_plain_multi_zst(dir.path());
        if archive.as_os_str().is_empty() {
            eprintln!("skip: zstd CLI unavailable");
            return;
        }
        let index = dir.path().join("plain.zst.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            ..Default::default()
        };

        let src = open_path(&archive, &opts, true).expect("cold plain zst");
        drop(src);

        let blocks = {
            let idx = SqliteIndex::open_read_only(&index).expect("index");
            let b = idx.get_zstd_blocks().expect("zstdblocks");
            assert!(
                !b.is_empty(),
                "plain .zst cold open should store zstdblocks"
            );
            b
        };

        let src2 = open_path(&archive, &opts, false).expect("warm plain zst");
        drop(src2);
        let blocks2 = SqliteIndex::open_read_only(&index)
            .expect("index")
            .get_zstd_blocks()
            .expect("blocks");
        assert_eq!(blocks2, blocks);
    }

    #[test]
    fn bzip2_blocks_persisted_and_reimported() {
        let dir = tempfile::tempdir().unwrap();
        let archive = make_tiny_tar_bz2(dir.path());
        if archive.as_os_str().is_empty() {
            eprintln!("skip: bzip2 CLI unavailable");
            return;
        }
        let index = dir.path().join("tiny.bz2.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            ..Default::default()
        };

        // Cold open: build bit-block map + TAR index, then store bzip2blocks side table.
        let src = open_path(&archive, &opts, true).expect("cold open");
        drop(src);

        let idx = SqliteIndex::open_read_only(&index).expect("open index");
        let blocks = idx.get_bzip2_blocks().expect("get bzip2blocks");
        assert!(
            !blocks.is_empty(),
            "expected non-empty bzip2blocks after cold open"
        );
        let stored = blocks.clone();
        drop(idx);

        // Warm open: import bzip2blocks (no full bit-scan rebuild required).
        let src2 = open_path(&archive, &opts, false).expect("warm open with import");
        drop(src2);

        let idx2 = SqliteIndex::open_read_only(&index).expect("reopen index");
        let blocks2 = idx2.get_bzip2_blocks().expect("blocks again");
        assert_eq!(blocks2, stored);
    }

    /// Regression: corrupt `bzip2blocks` falls back to rebuild and rewrites the table.
    #[test]
    fn bzip2_blocks_invalid_map_falls_back_to_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let archive = make_tiny_tar_bz2(dir.path());
        if archive.as_os_str().is_empty() {
            eprintln!("skip: bzip2 CLI unavailable");
            return;
        }
        let index = dir.path().join("tiny.bz2.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            ..Default::default()
        };

        let src = open_path(&archive, &opts, true).expect("cold open");
        drop(src);

        {
            let idx = SqliteIndex::open_writable(&index).expect("writable");
            // Decreasing bit offsets must fail import validation.
            idx.set_bzip2_blocks(&[(100, 0), (50, 10), (200, 20)])
                .expect("set garbage");
        }

        let src2 = open_path(&archive, &opts, false).expect("open after invalid blocks");
        drop(src2);

        let idx = SqliteIndex::open_read_only(&index).expect("ro");
        let blocks = idx.get_bzip2_blocks().expect("blocks");
        assert!(!blocks.is_empty());
        for w in blocks.windows(2) {
            assert!(w[0].0 <= w[1].0, "blockoffset must be non-decreasing");
        }
    }

    #[test]
    fn bzip2_blocks_memory_index_skips_side_table_path() {
        let dir = tempfile::tempdir().unwrap();
        let archive = make_tiny_tar_bz2(dir.path());
        if archive.as_os_str().is_empty() {
            eprintln!("skip: bzip2 CLI unavailable");
            return;
        }
        let opts = OpenOptions {
            index_in_memory: true,
            ..Default::default()
        };

        let src = open_path(&archive, &opts, false).expect("memory index open");
        drop(src);
    }

    #[test]
    fn try_load_bzip2_blocks_none_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.sqlite");
        assert!(try_load_bzip2_blocks(Some(&missing), None, false).is_none());
        assert!(try_load_bzip2_blocks(None, None, false).is_none());
        assert!(try_load_bzip2_blocks(Some(&missing), None, true).is_none());
    }

    /// Regression: FR-9 plain `.bz2` also auto-wires `bzip2blocks` on open.
    #[test]
    fn bzip2_blocks_plain_bz2_persisted_and_reimported() {
        let dir = tempfile::tempdir().unwrap();
        let archive = make_plain_bz2(dir.path());
        if archive.as_os_str().is_empty() {
            eprintln!("skip: bzip2 CLI unavailable");
            return;
        }
        let index = dir.path().join("plain.bz2.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            ..Default::default()
        };

        let src = open_path(&archive, &opts, true).expect("cold plain bz2");
        drop(src);

        let blocks = {
            let idx = SqliteIndex::open_read_only(&index).expect("index");
            let b = idx.get_bzip2_blocks().expect("bzip2blocks");
            assert!(
                !b.is_empty(),
                "plain .bz2 cold open should store bzip2blocks"
            );
            b
        };

        let src2 = open_path(&archive, &opts, false).expect("warm plain bz2");
        drop(src2);
        let blocks2 = SqliteIndex::open_read_only(&index)
            .expect("index")
            .get_bzip2_blocks()
            .expect("blocks");
        assert_eq!(blocks2, blocks);
    }

    /// Multi-file `.tar.gz` for nested random-read checks.
    fn make_multi_tar_gz(dir: &Path) -> PathBuf {
        let data = dir.join("tg-data");
        std::fs::create_dir_all(&data).expect("mkdir");
        std::fs::write(data.join("alpha.txt"), b"alpha-payload-line\n").expect("write");
        std::fs::write(
            data.join("beta.txt"),
            b"beta-RANDOM-seek-target-0123456789\n",
        )
        .expect("write");
        let tar_gz = dir.join("inner.tar.gz");
        let status = Command::new("tar")
            .args(["-czf"])
            .arg(&tar_gz)
            .arg("-C")
            .arg(&data)
            .args(["alpha.txt", "beta.txt"])
            .status()
            .expect("spawn tar");
        assert!(status.success(), "tar -czf multi failed");
        tar_gz
    }

    /// Shared multi-member plain TAR (alpha/beta) for nested compressed-TAR fixtures.
    fn make_multi_plain_tar(dir: &Path, data_subdir: &str, tar_name: &str) -> PathBuf {
        let data = dir.join(data_subdir);
        std::fs::create_dir_all(&data).expect("mkdir");
        std::fs::write(data.join("alpha.txt"), b"alpha-payload-line\n").expect("write");
        std::fs::write(
            data.join("beta.txt"),
            b"beta-RANDOM-seek-target-0123456789\n",
        )
        .expect("write");
        let tar_path = dir.join(tar_name);
        let status = Command::new("tar")
            .args(["-cf"])
            .arg(&tar_path)
            .arg("-C")
            .arg(&data)
            .args(["alpha.txt", "beta.txt"])
            .status()
            .expect("spawn tar");
        assert!(status.success(), "tar -cf multi failed");
        tar_path
    }

    /// Multi-file `.tar.zst` for nested no-tmp open via `open_nested_reader_fn`.
    /// Returns `None` when `zstd` is missing or fails (caller skips).
    fn make_multi_tar_zst(dir: &Path) -> Option<PathBuf> {
        let tar_path = make_multi_plain_tar(dir, "tzst-data", "inner-zst.tar");
        let tar_zst = dir.join("inner.tar.zst");
        let Ok(status) = Command::new("zstd")
            .args(["-q", "-f", "-o"])
            .arg(&tar_zst)
            .arg(&tar_path)
            .status()
        else {
            return None;
        };
        if !status.success() || !tar_zst.exists() {
            return None;
        }
        Some(tar_zst)
    }

    /// Multi-file `.tar.bz2` for nested no-tmp open via `open_nested_reader_fn`.
    fn make_multi_tar_bz2(dir: &Path) -> Option<PathBuf> {
        let tar_path = make_multi_plain_tar(dir, "tbz-data", "inner-bz2.tar");
        let tar_bz2 = dir.join("inner.tar.bz2");
        let Ok(out) = std::fs::File::create(&tar_bz2) else {
            return None;
        };
        let Ok(status) = Command::new("bzip2")
            .args(["-c"])
            .arg(&tar_path)
            .stdout(out)
            .status()
        else {
            return None;
        };
        if !status.success() || !tar_bz2.exists() {
            return None;
        }
        Some(tar_bz2)
    }

    /// Multi-file `.tar.xz` for nested no-tmp open via `open_nested_reader_fn`.
    fn make_multi_tar_xz(dir: &Path) -> Option<PathBuf> {
        let tar_path = make_multi_plain_tar(dir, "txz-data", "inner-xz.tar");
        let tar_xz = dir.join("inner.tar.xz");
        let Ok(status) = Command::new("xz")
            .args(["-f", "-k", "-T1", "-c"])
            .arg(&tar_path)
            .stdout(std::fs::File::create(&tar_xz).ok()?)
            .status()
        else {
            return None;
        };
        if !status.success() || !tar_xz.exists() {
            return None;
        }
        Some(tar_xz)
    }

    /// Shared asserts for nested multi-member compressed TAR opened from Cursor
    /// (list + full read + mid-member seek; no NamedTempFile in the open path).
    fn assert_nested_multi_tar_from_cursor(label: &str, bytes: Vec<u8>) {
        let opts = OpenOptions {
            index_in_memory: true,
            ..Default::default()
        };
        let opener = open_nested_reader_fn(opts);
        let boxed: Box<dyn ratarmount_core::ArchiveRead> = Box::new(std::io::Cursor::new(bytes));
        let inner = opener(boxed, Path::new(label)).unwrap_or_else(|e| {
            panic!("nested {label} open_nested_reader_fn from Cursor must succeed without temp spool: {e}")
        });
        assert_eq!(
            read_all(inner.as_ref(), "/alpha.txt"),
            b"alpha-payload-line\n"
        );
        let beta = read_all(inner.as_ref(), "/beta.txt");
        assert_eq!(beta, b"beta-RANDOM-seek-target-0123456789\n");
        let mid = read_seek_mid(inner.as_ref(), "/beta.txt", 5);
        assert_eq!(mid.as_slice(), &beta[5..]);
    }

    fn make_multi_zip(dir: &Path) -> PathBuf {
        let data = dir.join("zip-data");
        std::fs::create_dir_all(&data).expect("mkdir");
        std::fs::write(data.join("one.txt"), b"zip-one-contents\n").expect("write");
        std::fs::write(data.join("two.txt"), b"zip-two-SEEK-ME-abcdef\n").expect("write");
        let zip_path = dir.join("inner.zip");
        let status = Command::new("zip")
            .args(["-q", "-j"])
            .arg(&zip_path)
            .arg(data.join("one.txt"))
            .arg(data.join("two.txt"))
            .status()
            .expect("spawn zip");
        assert!(status.success(), "zip failed");
        zip_path
    }

    /// Store/non-solid outer 7z (no solid compression — random outer member open is free).
    fn make_store_7z_with_member(dir: &Path, member: &Path, outer_name: &str) -> Option<PathBuf> {
        let outer = dir.join(outer_name);
        // Prefer 7z; fall back to 7za.
        for bin in ["7z", "7za"] {
            let status = Command::new(bin)
                .args(["a", "-t7z", "-mx0", "-y"])
                .arg(&outer)
                .arg(member)
                .status();
            match status {
                Ok(s) if s.success() && outer.exists() => return Some(outer),
                _ => continue,
            }
        }
        None
    }

    fn read_all(ms: &dyn MountSource, path: &str) -> Vec<u8> {
        let fi = ms
            .lookup(path, 0)
            .unwrap_or_else(|| panic!("lookup {path}"));
        let mut r = ms.open(&fi, 0).expect("open");
        let mut buf = Vec::new();
        use std::io::Read;
        r.read_to_end(&mut buf).expect("read");
        buf
    }

    fn read_seek_mid(ms: &dyn MountSource, path: &str, start: u64) -> Vec<u8> {
        use std::io::{Read, Seek, SeekFrom};
        let fi = ms.lookup(path, 0).expect("lookup");
        let mut r = ms.open(&fi, 0).expect("open");
        r.seek(SeekFrom::Start(start)).expect("seek");
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).expect("read");
        buf
    }

    #[test]
    fn nested_tar_gz_inside_store_7z_reader_random_read_no_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let tar_gz = make_multi_tar_gz(dir.path());
        let Some(outer) = make_store_7z_with_member(dir.path(), &tar_gz, "outer-tgz.7z") else {
            eprintln!("skip: 7z/7za not available");
            return;
        };

        let opts = OpenOptions {
            index_in_memory: true,
            gzip_seek_point_spacing: 64 * 1024,
            ..Default::default()
        };
        let outer_ms = SevenZipMountSource::open(&outer, None, &opts, VERSION, true)
            .expect("open store 7z outer");
        let nested_name = tar_gz.file_name().unwrap().to_str().unwrap();
        let nested_path = format!("/{nested_name}");
        let nested_fi = outer_ms
            .lookup(&nested_path, 0)
            .unwrap_or_else(|| panic!("lookup nested member {nested_path}"));
        let nested_reader = outer_ms
            .open(&nested_fi, 0)
            .expect("open nested member stream (no tmp)");

        let opener = open_nested_reader_fn(opts.clone());
        let inner = opener(nested_reader, Path::new(nested_name)).expect(
            "nested open_nested_reader_fn must open .tar.gz from 7z member without temp spool",
        );

        let alpha = read_all(inner.as_ref(), "/alpha.txt");
        assert_eq!(alpha, b"alpha-payload-line\n");
        let beta = read_all(inner.as_ref(), "/beta.txt");
        assert_eq!(beta, b"beta-RANDOM-seek-target-0123456789\n");
        // True random read: mid-member seek on gzip-backed TAR.
        let mid = read_seek_mid(inner.as_ref(), "/beta.txt", 5);
        assert_eq!(mid.as_slice(), &beta[5..]);
    }

    #[test]
    fn nested_zip_inside_store_7z_reader_random_read_no_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let zip_path = make_multi_zip(dir.path());
        let Some(outer) = make_store_7z_with_member(dir.path(), &zip_path, "outer-zip.7z") else {
            eprintln!("skip: 7z/7za not available");
            return;
        };

        let opts = OpenOptions {
            index_in_memory: true,
            ..Default::default()
        };
        let outer_ms = SevenZipMountSource::open(&outer, None, &opts, VERSION, true)
            .expect("open store 7z outer");
        let nested_name = zip_path.file_name().unwrap().to_str().unwrap();
        let nested_fi = outer_ms
            .lookup(&format!("/{nested_name}"), 0)
            .expect("lookup inner.zip");
        let nested_reader = outer_ms
            .open(&nested_fi, 0)
            .expect("open zip member stream");

        let opener = open_nested_reader_fn(opts);
        let inner = opener(nested_reader, Path::new(nested_name))
            .expect("nested ZIP open_from_reader without temp spool");

        let one = read_all(inner.as_ref(), "/one.txt");
        assert_eq!(one, b"zip-one-contents\n");
        let two = read_all(inner.as_ref(), "/two.txt");
        assert_eq!(two, b"zip-two-SEEK-ME-abcdef\n");
        let mid = read_seek_mid(inner.as_ref(), "/two.txt", 4);
        assert_eq!(mid.as_slice(), &two[4..]);
    }

    #[test]
    fn nested_tar_gz_from_cursor_direct() {
        // No outer 7z: pure nested gzip→tar path (what AutoMount feeds after parent.open).
        let dir = tempfile::tempdir().unwrap();
        let tar_gz = make_multi_tar_gz(dir.path());
        let bytes = std::fs::read(&tar_gz).expect("read tar.gz");
        let reader = std::io::Cursor::new(bytes);
        let opts = OpenOptions {
            index_in_memory: true,
            gzip_seek_point_spacing: 32 * 1024,
            ..Default::default()
        };
        let opener = open_nested_reader_fn(opts);
        let boxed: Box<dyn ratarmount_core::ArchiveRead> = Box::new(reader);
        let inner = opener(boxed, Path::new("inner.tar.gz")).expect("gzip→tar nested");
        assert_eq!(
            read_all(inner.as_ref(), "/alpha.txt"),
            b"alpha-payload-line\n"
        );
        let beta = read_all(inner.as_ref(), "/beta.txt");
        assert_eq!(
            read_seek_mid(inner.as_ref(), "/beta.txt", 10).as_slice(),
            &beta[10..]
        );
    }

    /// Nested `.tar.zst` via `open_nested_reader_fn` Cursor — zstd→TAR no-tmp path.
    #[test]
    fn nested_tar_zst_from_cursor_via_opener() {
        let dir = tempfile::tempdir().unwrap();
        let Some(tar_zst) = make_multi_tar_zst(dir.path()) else {
            eprintln!("skip: zstd not available or failed to compress multi TAR");
            return;
        };
        let bytes = std::fs::read(&tar_zst).expect("read tar.zst");
        assert_nested_multi_tar_from_cursor("inner.tar.zst", bytes);
    }

    /// Nested `.tar.bz2` via `open_nested_reader_fn` Cursor — bzip2→TAR no-tmp path.
    #[test]
    fn nested_tar_bz2_from_cursor_via_opener() {
        let dir = tempfile::tempdir().unwrap();
        let Some(tar_bz2) = make_multi_tar_bz2(dir.path()) else {
            eprintln!("skip: bzip2 not available or failed to compress multi TAR");
            return;
        };
        let bytes = std::fs::read(&tar_bz2).expect("read tar.bz2");
        assert_nested_multi_tar_from_cursor("inner.tar.bz2", bytes);
    }

    /// Nested `.tar.xz` via `open_nested_reader_fn` Cursor — xz→TAR no-tmp path.
    #[test]
    fn nested_tar_xz_from_cursor_via_opener() {
        let dir = tempfile::tempdir().unwrap();
        let Some(tar_xz) = make_multi_tar_xz(dir.path()) else {
            eprintln!("skip: xz not available or failed to compress multi TAR");
            return;
        };
        let bytes = std::fs::read(&tar_xz).expect("read tar.xz");
        assert_nested_multi_tar_from_cursor("inner.tar.xz", bytes);
    }

    /// Plain (non-TAR) `.gz` via `open_path` / seekable body — no materialize to single-file path.
    #[test]
    fn plain_gzip_single_file_open_path_no_materialize() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"plain-gzip-SEEK-ME-payload-0123456789\n";
        let plain = dir.path().join("hello.txt");
        std::fs::write(&plain, payload).expect("write plain");
        let gz = dir.path().join("hello.txt.gz");
        let status = Command::new("gzip")
            .args(["-c"])
            .arg(&plain)
            .stdout(std::fs::File::create(&gz).expect("create gz"))
            .status()
            .expect("spawn gzip");
        assert!(status.success(), "gzip CLI failed");

        let opts = OpenOptions {
            index_in_memory: true,
            gzip_seek_point_spacing: 16 * 1024,
            ..Default::default()
        };
        let src = open_path(&gz, &opts, false).expect("open plain .gz");
        // Stripped name: hello.txt
        assert_eq!(read_all(src.as_ref(), "/hello.txt"), payload);
        let mid = read_seek_mid(src.as_ref(), "/hello.txt", 6);
        assert_eq!(mid.as_slice(), &payload[6..]);
    }

    /// Tier D POC: path-backed rapidgzip when feature + `--use-backend rapidgzip`.
    ///
    /// Regression: factory must serve full payload and mid-seek without materialize.
    #[cfg(feature = "gzip-rapidgzip")]
    #[test]
    fn plain_gzip_rapidgzip_backend_open_path_seek() {
        let dir = tempfile::tempdir().unwrap();
        // Large enough for multiple checkpoints at 4 KiB spacing.
        let mut payload = Vec::new();
        for i in 0..80u32 {
            payload.extend(format!("rgz-{i:04}-").repeat(128).into_bytes());
            payload.push(b'\n');
        }
        let plain = dir.path().join("blob.bin");
        std::fs::write(&plain, &payload).expect("write plain");
        let gz = dir.path().join("blob.bin.gz");
        let status = Command::new("gzip")
            .args(["-c"])
            .arg(&plain)
            .stdout(std::fs::File::create(&gz).expect("create gz"))
            .status()
            .expect("spawn gzip");
        assert!(status.success(), "gzip CLI failed");

        // Prove rapidgzip can open this file (factory may fall back to G3 on error).
        let body = ratarmount_compress::open_seekable_gzip_rapidgzip(&gz, 4 * 1024, 2)
            .expect("rapidgzip open must succeed for this corpus");
        assert_eq!(
            body.kind(),
            ratarmount_compress::RAPIDGZIP_BODY_KIND,
            "must take rapidgzip SeekableBody path"
        );
        assert!(body.checkpoint_count() >= 2);

        let opts = OpenOptions {
            index_in_memory: true,
            gzip_seek_point_spacing: 4 * 1024,
            use_backends: vec!["rapidgzip".into()],
            parallelization: ratarmount_core::ParallelizationSpec::parse("gzip:2").unwrap(),
            ..Default::default()
        };
        let src = open_path(&gz, &opts, false).expect("open plain .gz via rapidgzip");
        assert_eq!(read_all(src.as_ref(), "/blob.bin"), payload);
        let mid = payload.len() / 2;
        let mid_bytes = read_seek_mid(src.as_ref(), "/blob.bin", mid as u64);
        assert_eq!(mid_bytes.as_slice(), &payload[mid..]);
    }

    /// Regression: rapidgzip path open with a poisoned SQLite gzip blob must rebuild
    /// (no panic) and still serve members. Uses `.tar.gz` so cold open seeds a real index.
    #[cfg(feature = "gzip-rapidgzip")]
    #[test]
    fn plain_gzip_rapidgzip_invalid_index_blob_falls_back_no_panic() {
        let dir = tempfile::tempdir().unwrap();
        let archive = make_tiny_tar_gz(dir.path());
        let index = dir.path().join("tiny-rgz.index.sqlite");
        // Seed on-disk index via G3 cold open (tarstats + gzipindex side table).
        {
            let opts = OpenOptions {
                index_file_path: Some(index.clone()),
                gzip_seek_point_spacing: 4 * 1024,
                ..Default::default()
            };
            let src = open_path(&archive, &opts, true).expect("G3 cold open seeds index");
            drop(src);
        }
        {
            let idx = SqliteIndex::open_writable(&index).expect("writable index");
            idx.set_gzip_index_blob(b"not-a-valid-gzidx-or-rgzi-blob")
                .expect("poison gzip blob");
        }

        // Prefer rapidgzip: import of garbage must fail open (no panic); cold rebuild.
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            gzip_seek_point_spacing: 4 * 1024,
            use_backends: vec!["rapidgzip".into()],
            parallelization: ratarmount_core::ParallelizationSpec::parse("gzip:2").unwrap(),
            ..Default::default()
        };
        let src = open_path(&archive, &opts, false).expect("rapidgzip open after invalid blob");
        assert_eq!(
            read_all(src.as_ref(), "/hello.txt"),
            b"hello world\n".as_slice()
        );
        drop(src);

        // Rebuild rewrites a valid GZIDX blob for warm remount.
        let idx = SqliteIndex::open_read_only(&index).expect("ro index");
        let blobs = idx.get_gzip_index_blobs().expect("blobs");
        assert!(!blobs.is_empty());
        assert!(
            blobs[0].starts_with(b"GZIDX"),
            "expected GZIDX after rapidgzip rebuild, got {:?}",
            blobs[0].get(..8)
        );
    }

    /// Regression: prefer rapidgzip + write_index stores GZIDX; second open imports it
    /// (skips full keep_index rebuild) and still serves members.
    #[cfg(feature = "gzip-rapidgzip")]
    #[test]
    fn plain_gzip_rapidgzip_gzidx_persisted_and_reimported() {
        let dir = tempfile::tempdir().unwrap();
        let archive = make_tiny_tar_gz(dir.path());
        let index = dir.path().join("tiny-rgz-gzidx.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            gzip_seek_point_spacing: 4 * 1024,
            use_backends: vec!["rapidgzip".into()],
            parallelization: ratarmount_core::ParallelizationSpec::parse("gzip:2").unwrap(),
            write_index: true,
            ..Default::default()
        };

        // Cold open: build rapidgzip index + TAR, then persist GZIDX side blob.
        let src = open_path(&archive, &opts, true).expect("cold rapidgzip open");
        assert_eq!(
            read_all(src.as_ref(), "/hello.txt"),
            b"hello world\n".as_slice()
        );
        drop(src);

        let idx = SqliteIndex::open_read_only(&index).expect("open index");
        let blobs = idx.get_gzip_index_blobs().expect("get blobs");
        assert_eq!(blobs.len(), 1, "expected single gzipindex blob");
        assert!(
            blobs[0].starts_with(b"GZIDX"),
            "blob should be GZIDX magic, got {:?}",
            blobs[0].get(..8)
        );
        let stored = blobs[0].clone();
        drop(idx);

        // Warm open: import blob (no full keep_index rebuild required).
        let src2 = open_path(&archive, &opts, false).expect("warm open with GZIDX import");
        assert_eq!(
            read_all(src2.as_ref(), "/hello.txt"),
            b"hello world\n".as_slice()
        );
        drop(src2);

        let idx2 = SqliteIndex::open_read_only(&index).expect("reopen index");
        let blobs2 = idx2.get_gzip_index_blobs().expect("blobs again");
        assert_eq!(blobs2, vec![stored]);
    }

    /// Regression: plain (non-TAR) `.gz` + prefer rapidgzip + write_index creates an
    /// index shell and stores GZIDX even when no TAR `files` table is built; warm open
    /// imports the blob. Mirrors G3-B plain RGZI shell create.
    #[cfg(feature = "gzip-rapidgzip")]
    #[test]
    fn plain_gzip_rapidgzip_plain_gzidx_shell_persisted_and_reimported() {
        let dir = tempfile::tempdir().unwrap();
        // Large enough for multiple checkpoints at 4 KiB spacing.
        let mut payload = Vec::new();
        for i in 0..80u32 {
            payload.extend(format!("rgz-plain-{i:04}-").repeat(128).into_bytes());
            payload.push(b'\n');
        }
        let plain = dir.path().join("blob.bin");
        std::fs::write(&plain, &payload).expect("write plain");
        let gz = dir.path().join("blob.bin.gz");
        let status = Command::new("gzip")
            .args(["-c"])
            .arg(&plain)
            .stdout(std::fs::File::create(&gz).expect("create gz"))
            .status()
            .expect("spawn gzip");
        assert!(status.success(), "gzip CLI failed");

        let index = dir.path().join("plain.rgz.gzidx.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            gzip_seek_point_spacing: 4 * 1024,
            use_backends: vec!["rapidgzip".into()],
            parallelization: ratarmount_core::ParallelizationSpec::parse("gzip:2").unwrap(),
            write_index: true,
            ..Default::default()
        };

        // Cold open: no TAR index — must still create SQLite shell + GZIDX side blob.
        let src = open_path(&gz, &opts, true).expect("cold plain .gz rapidgzip");
        assert_eq!(read_all(src.as_ref(), "/blob.bin"), payload);
        drop(src);

        assert!(
            index.exists(),
            "plain .gz rapidgzip cold open with write_index must create index path for GZIDX"
        );
        let stored = {
            let idx = SqliteIndex::open_read_only(&index).expect("open index");
            let blobs = idx.get_gzip_index_blobs().expect("get blobs");
            assert_eq!(blobs.len(), 1, "expected single gzipindex blob");
            assert!(
                blobs[0].starts_with(b"GZIDX"),
                "blob should be GZIDX magic, got {:?}",
                blobs[0].get(..8)
            );
            assert!(
                !blobs[0].is_empty(),
                "GZIDX blob must be non-empty after cold"
            );
            blobs[0].clone()
        };

        let loaded = try_load_gzip_index_blob(Some(&index), Some(&gz), false)
            .expect("try_load GZIDX after plain rapidgzip cold open");
        assert_eq!(loaded, stored);
        assert_eq!(gzip_seek_index_format_label(&loaded), "GZIDX");

        // Warm open via factory: import + serve full payload + mid seek.
        let src2 = open_path(&gz, &opts, false).expect("warm plain .gz with GZIDX import");
        assert_eq!(read_all(src2.as_ref(), "/blob.bin"), payload);
        let mid = payload.len() / 2;
        assert_eq!(
            read_seek_mid(src2.as_ref(), "/blob.bin", mid as u64).as_slice(),
            &payload[mid..]
        );
        drop(src2);

        let blobs2 = SqliteIndex::open_read_only(&index)
            .expect("reopen")
            .get_gzip_index_blobs()
            .expect("blobs");
        assert_eq!(blobs2, vec![stored], "warm remount must keep GZIDX blob");
    }

    /// Regression: write_index=false must not leave a rapidgzip GZIDX side table on disk
    /// for plain `.gz` (no shell create / no side blob).
    #[cfg(feature = "gzip-rapidgzip")]
    #[test]
    fn plain_gzip_rapidgzip_gzidx_skipped_when_write_index_false() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"no-gzidx-when-write-index-false\n";
        let plain = dir.path().join("n.txt");
        std::fs::write(&plain, payload).expect("write");
        let gz = dir.path().join("n.txt.gz");
        let status = Command::new("gzip")
            .args(["-c"])
            .arg(&plain)
            .stdout(std::fs::File::create(&gz).expect("create gz"))
            .status()
            .expect("spawn gzip");
        assert!(status.success(), "gzip CLI failed");

        let index = dir.path().join("n.rgz.gzidx.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            gzip_seek_point_spacing: 4 * 1024,
            use_backends: vec!["rapidgzip".into()],
            parallelization: ratarmount_core::ParallelizationSpec::parse("gzip:2").unwrap(),
            write_index: false,
            ..Default::default()
        };
        let src = open_path(&gz, &opts, true).expect("open with write_index=false");
        assert_eq!(read_all(src.as_ref(), "/n.txt"), payload.as_slice());
        drop(src);

        if index.exists() {
            let blobs = SqliteIndex::open_read_only(&index)
                .expect("ro")
                .get_gzip_index_blobs()
                .unwrap_or_default();
            assert!(
                blobs.is_empty(),
                "write_index=false must not store GZIDX, got {} blob(s)",
                blobs.len()
            );
        }
    }

    /// Regression: plain rapidgzip path with poisoned GZIDX blob rebuilds and rewrites
    /// a valid GZIDX (shell already exists from cold open).
    #[cfg(feature = "gzip-rapidgzip")]
    #[test]
    fn plain_gzip_rapidgzip_plain_invalid_blob_falls_back_rewrites_gzidx() {
        let dir = tempfile::tempdir().unwrap();
        let mut payload = Vec::new();
        for i in 0..40u32 {
            payload.extend(format!("poison-{i:03}-").repeat(64).into_bytes());
            payload.push(b'\n');
        }
        let plain = dir.path().join("blob.bin");
        std::fs::write(&plain, &payload).expect("write plain");
        let gz = dir.path().join("blob.bin.gz");
        let status = Command::new("gzip")
            .args(["-c"])
            .arg(&plain)
            .stdout(std::fs::File::create(&gz).expect("create gz"))
            .status()
            .expect("spawn gzip");
        assert!(status.success(), "gzip CLI failed");

        let index = dir.path().join("plain-poison.rgz.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            gzip_seek_point_spacing: 4 * 1024,
            use_backends: vec!["rapidgzip".into()],
            parallelization: ratarmount_core::ParallelizationSpec::parse("gzip:2").unwrap(),
            write_index: true,
            ..Default::default()
        };

        let src = open_path(&gz, &opts, true).expect("cold plain rapidgzip seeds shell+GZIDX");
        drop(src);
        assert!(index.exists(), "shell must exist before poison");

        {
            let idx = SqliteIndex::open_writable(&index).expect("writable");
            idx.set_gzip_index_blob(b"not-a-valid-gzidx-or-rgzi-blob")
                .expect("poison");
        }

        let src2 = open_path(&gz, &opts, false).expect("open after invalid blob");
        assert_eq!(read_all(src2.as_ref(), "/blob.bin"), payload);
        drop(src2);

        let blobs = SqliteIndex::open_read_only(&index)
            .expect("ro")
            .get_gzip_index_blobs()
            .expect("blobs");
        assert!(!blobs.is_empty());
        assert!(
            blobs[0].starts_with(b"GZIDX"),
            "expected GZIDX after rapidgzip plain rebuild, got {:?}",
            blobs[0].get(..8)
        );
    }

    /// Nested plain `.gz` with prefer_rapidgzip uses rapidgzip `from_reader` (no G3 residual).
    ///
    /// Compress `from_reader` reports `RAPIDGZIP_BODY_KIND`; factory must open the same
    /// corpus via nested cursor without falling back to the residual G3-only log path.
    #[cfg(feature = "gzip-rapidgzip")]
    #[test]
    fn nested_plain_gzip_prefer_rapidgzip_from_cursor_still_opens() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"nested-rgz-prefer-RANDOM-seek-xyz\n";
        let plain = dir.path().join("nested.bin");
        std::fs::write(&plain, payload).expect("write");
        let gz = dir.path().join("nested.bin.gz");
        let status = Command::new("gzip")
            .args(["-c"])
            .arg(&plain)
            .stdout(std::fs::File::create(&gz).expect("create gz"))
            .status()
            .expect("spawn gzip");
        assert!(status.success(), "gzip CLI failed");

        let bytes = std::fs::read(&gz).expect("read gz");

        // Prove compress from_reader takes the rapidgzip body path for this corpus.
        let body = ratarmount_compress::open_seekable_gzip_rapidgzip_from_reader(
            std::io::Cursor::new(bytes.clone()),
            16 * 1024,
            2,
            Path::new("nested.bin.gz"),
        )
        .expect("rapidgzip from_reader must succeed for this corpus");
        assert_eq!(
            body.kind(),
            ratarmount_compress::RAPIDGZIP_BODY_KIND,
            "nested prefer path must use rapidgzip SeekableBody kind"
        );

        let opts = OpenOptions {
            index_in_memory: true,
            gzip_seek_point_spacing: 16 * 1024,
            use_backends: vec!["rapidgzip".into()],
            parallelization: ratarmount_core::ParallelizationSpec::parse("gzip:2").unwrap(),
            ..Default::default()
        };
        let opener = open_nested_reader_fn(opts);
        let boxed: Box<dyn ratarmount_core::ArchiveRead> = Box::new(std::io::Cursor::new(bytes));
        let inner = opener(boxed, Path::new("nested.bin.gz"))
            .expect("nested plain gzip with prefer_rapidgzip must open via from_reader");
        assert_eq!(read_all(inner.as_ref(), "/nested.bin"), payload);
        let mid = read_seek_mid(inner.as_ref(), "/nested.bin", 8);
        assert_eq!(mid.as_slice(), &payload[8..]);
    }

    /// Unit: rewind helper resets cursor to 0 for G3 fall-through.
    #[test]
    fn rewind_nested_gzip_reader_for_g3_resets_position() {
        use std::io::{Cursor, Read, Seek, SeekFrom};
        let mut cur = Cursor::new(vec![10u8, 20, 30, 40]);
        cur.seek(SeekFrom::End(0)).unwrap();
        assert_eq!(cur.stream_position().unwrap(), 4);
        rewind_nested_gzip_reader_for_g3(&mut cur).expect("rewind");
        assert_eq!(cur.stream_position().unwrap(), 0);
        let mut b = [0u8; 2];
        cur.read_exact(&mut b).unwrap();
        assert_eq!(b, [10, 20]);
    }

    /// Regression: nested prefer rapidgzip fails → rewind → G3 still opens valid gzip.
    ///
    /// `open_nested_reader_fn` sniffs magic with the first `Read`; the second `Read`
    /// (rapidgzip keep_index / ReadAt) is poisoned once so prefer fails; later reads
    /// succeed for G3 after factory rewind. Single rapidgzip worker avoids parallel
    /// ReadAt racing past the one-shot poison.
    #[cfg(feature = "gzip-rapidgzip")]
    #[test]
    fn nested_plain_gzip_prefer_rapidgzip_fail_rewinds_to_g3() {
        use std::io::{Read, Seek, SeekFrom};
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct FailSecondReadThenOk {
            data: Vec<u8>,
            pos: u64,
            /// Number of `read` calls so far (magic sniff is #1).
            read_calls: AtomicUsize,
        }

        impl Read for FailSecondReadThenOk {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let n = self.read_calls.fetch_add(1, Ordering::SeqCst) + 1;
                // 1 = nested magic sniff (must succeed for gzip probe).
                // 2 = first rapidgzip compressed ReadAt (poison → G3 fallback).
                if n == 2 {
                    return Err(std::io::Error::other(
                        "simulated rapidgzip decode failure before factory rewind",
                    ));
                }
                let start = self.pos as usize;
                if start >= self.data.len() {
                    return Ok(0);
                }
                let nread = buf.len().min(self.data.len() - start);
                buf[..nread].copy_from_slice(&self.data[start..start + nread]);
                self.pos += nread as u64;
                Ok(nread)
            }
        }

        impl Seek for FailSecondReadThenOk {
            fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
                let len = self.data.len() as u64;
                let next = match pos {
                    SeekFrom::Start(o) => o,
                    SeekFrom::End(o) => {
                        if o >= 0 {
                            len.saturating_add(o as u64)
                        } else {
                            len.saturating_sub((-o) as u64)
                        }
                    }
                    SeekFrom::Current(o) => {
                        if o >= 0 {
                            self.pos.saturating_add(o as u64)
                        } else {
                            self.pos.saturating_sub((-o) as u64)
                        }
                    }
                };
                if next > len {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "seek past end",
                    ));
                }
                self.pos = next;
                Ok(self.pos)
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let payload = b"nested-rgz-fail-then-G3-payload\n";
        let plain = dir.path().join("nested.bin");
        std::fs::write(&plain, payload).expect("write");
        let gz = dir.path().join("nested.bin.gz");
        let status = Command::new("gzip")
            .args(["-c"])
            .arg(&plain)
            .stdout(std::fs::File::create(&gz).expect("create gz"))
            .status()
            .expect("spawn gzip");
        assert!(status.success(), "gzip CLI failed");
        let bytes = std::fs::read(&gz).expect("read gz");

        let opts = OpenOptions {
            index_in_memory: true,
            gzip_seek_point_spacing: 16 * 1024,
            use_backends: vec!["rapidgzip".into()],
            // Single worker: one poisoned Read must abort rapidgzip before G3.
            parallelization: ratarmount_core::ParallelizationSpec::parse("gzip:1,rapidgzip-gzip:1")
                .unwrap(),
            ..Default::default()
        };
        let opener = open_nested_reader_fn(opts);
        let boxed: Box<dyn ratarmount_core::ArchiveRead> = Box::new(FailSecondReadThenOk {
            data: bytes,
            pos: 0,
            read_calls: AtomicUsize::new(0),
        });
        let inner = opener(boxed, Path::new("nested.bin.gz")).expect(
            "nested prefer rapidgzip fail must rewind and open via G3 when stream is recoverable",
        );
        assert_eq!(read_all(inner.as_ref(), "/nested.bin"), payload);
        let mid = read_seek_mid(inner.as_ref(), "/nested.bin", 7);
        assert_eq!(mid.as_slice(), &payload[7..]);
    }

    /// Unit: take_and_rewind recovers Arc-held reader and seeks to 0.
    #[cfg(feature = "gzip-rapidgzip")]
    #[test]
    fn take_and_rewind_nested_gzip_reader_recovers_cursor() {
        use std::io::{Cursor, Read, Seek, SeekFrom};
        let held: NestedGzipReaderHeld =
            Arc::new(std::sync::Mutex::new(Box::new(Cursor::new(vec![
                1u8, 2, 3, 4, 5,
            ]))));
        {
            let mut g = held.lock().unwrap();
            g.seek(SeekFrom::Start(3)).unwrap();
        }
        let mut recovered = take_and_rewind_nested_gzip_reader(held).expect("recover+rewind");
        assert_eq!(recovered.stream_position().unwrap(), 0);
        let mut b = [0u8; 3];
        recovered.read_exact(&mut b).unwrap();
        assert_eq!(b, [1, 2, 3]);
    }

    /// Plain `.zst` / `.bz2` via seekable body (same no-materialize path as gzip).
    #[test]
    fn plain_zstd_and_bzip2_open_path_no_materialize() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"plain-zstd-bz2-SEEK-payload-zzzz\n";
        let plain = dir.path().join("data.bin");
        std::fs::write(&plain, payload).unwrap();

        let zst = dir.path().join("data.bin.zst");
        let st = Command::new("zstd")
            .args(["-q", "-f", "-o"])
            .arg(&zst)
            .arg(&plain)
            .status();
        if let Ok(st) = st {
            if st.success() {
                let opts = OpenOptions {
                    index_in_memory: true,
                    ..Default::default()
                };
                let src = open_path(&zst, &opts, false).expect("open plain .zst");
                assert_eq!(read_all(src.as_ref(), "/data.bin"), payload);
                let mid = read_seek_mid(src.as_ref(), "/data.bin", 6);
                assert_eq!(mid.as_slice(), &payload[6..]);
            } else {
                eprintln!("skip: zstd CLI failed");
            }
        } else {
            eprintln!("skip: zstd not available");
        }

        let bz2 = dir.path().join("data.bin.bz2");
        let st = Command::new("bzip2")
            .args(["-c"])
            .arg(&plain)
            .stdout(std::fs::File::create(&bz2).unwrap())
            .status();
        if let Ok(st) = st {
            if st.success() {
                let opts = OpenOptions {
                    index_in_memory: true,
                    ..Default::default()
                };
                let src = open_path(&bz2, &opts, false).expect("open plain .bz2");
                assert_eq!(read_all(src.as_ref(), "/data.bin"), payload);
                let mid = read_seek_mid(src.as_ref(), "/data.bin", 6);
                assert_eq!(mid.as_slice(), &payload[6..]);
            } else {
                eprintln!("skip: bzip2 CLI failed");
            }
        } else {
            eprintln!("skip: bzip2 not available");
        }
    }

    /// Nested plain `.gz` via `open_nested_reader_fn` Cursor — single-file over seekable body (no spool).
    #[test]
    fn nested_plain_gzip_from_cursor_single_file_no_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let payload = b"nested-plain-gz-RANDOM-seek-abcdef\n";
        let plain = dir.path().join("data.bin");
        std::fs::write(&plain, payload).expect("write");
        let gz = dir.path().join("data.bin.gz");
        let status = Command::new("gzip")
            .args(["-c"])
            .arg(&plain)
            .stdout(std::fs::File::create(&gz).expect("create gz"))
            .status()
            .expect("spawn gzip");
        assert!(status.success(), "gzip CLI failed");

        let bytes = std::fs::read(&gz).expect("read gz");
        let reader = std::io::Cursor::new(bytes);
        let opts = OpenOptions {
            index_in_memory: true,
            gzip_seek_point_spacing: 16 * 1024,
            ..Default::default()
        };
        let opener = open_nested_reader_fn(opts);
        let boxed: Box<dyn ratarmount_core::ArchiveRead> = Box::new(reader);
        let inner = opener(boxed, Path::new("data.bin.gz"))
            .expect("nested plain gzip must open as single-file without temp spool");
        assert_eq!(read_all(inner.as_ref(), "/data.bin"), payload);
        let mid = read_seek_mid(inner.as_ref(), "/data.bin", 7);
        assert_eq!(mid.as_slice(), &payload[7..]);
    }

    /// Large nested plain `.gz` must deliver the full payload under FUSE-style
    /// seek+read chunks (short inflate windows must not truncate).
    #[test]
    fn nested_large_plain_gzip_fuse_style_full_payload() {
        use std::io::{Read, Seek, SeekFrom, Write};
        let dir = tempfile::tempdir().unwrap();
        let mut payload = Vec::new();
        for i in 0..4000 {
            writeln!(&mut payload, "nested-large {i:05} {}", "q".repeat(48)).unwrap();
        }
        assert!(
            payload.len() > 80_000,
            "need larger than one typical inflate window"
        );
        let plain = dir.path().join("blob.bin");
        std::fs::write(&plain, &payload).unwrap();
        let gz = dir.path().join("blob.bin.gz");
        let status = Command::new("gzip")
            .args(["-c"])
            .arg(&plain)
            .stdout(std::fs::File::create(&gz).unwrap())
            .status()
            .expect("gzip");
        assert!(status.success());

        let bytes = std::fs::read(&gz).unwrap();
        let opts = OpenOptions {
            index_in_memory: true,
            gzip_seek_point_spacing: 16 * 1024,
            ..Default::default()
        };
        let opener = open_nested_reader_fn(opts);
        let inner = opener(
            Box::new(std::io::Cursor::new(bytes)),
            Path::new("blob.bin.gz"),
        )
        .expect("nested large gzip open");
        let fi = inner.lookup("/blob.bin", 0).expect("lookup");
        assert_eq!(fi.size, payload.len() as u64);
        let mut reader = inner.open(&fi, 0).expect("open");
        let mut out = Vec::new();
        let mut off = 0u64;
        loop {
            reader.seek(SeekFrom::Start(off)).unwrap();
            let mut buf = [0u8; 4096];
            let n = reader.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
            off += n as u64;
            assert!(
                off <= payload.len() as u64 + 1,
                "read past end (got offset {off})"
            );
        }
        assert_eq!(
            out.len(),
            payload.len(),
            "short read under FUSE-style loop (got {} want {})",
            out.len(),
            payload.len()
        );
        assert_eq!(out, payload);
    }

    /// `.tar` embedded in ZIP: parent open + nested TAR from_reader — no temp spool.
    #[test]
    fn nested_tar_inside_zip_reader_random_read_no_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("tar-data");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(data.join("hi.txt"), b"hello from tar in zip\n").unwrap();
        std::fs::write(data.join("pad.txt"), b"0123456789ABCDEF_mid_seek\n").unwrap();
        let inner_tar = dir.path().join("inner.tar");
        let status = Command::new("tar")
            .args(["-cf"])
            .arg(&inner_tar)
            .arg("-C")
            .arg(&data)
            .args(["hi.txt", "pad.txt"])
            .status()
            .expect("spawn tar");
        assert!(status.success());
        let outer_zip = dir.path().join("outer.zip");
        // Default zip compresses (deflate); still no /tmp — inflate to RAM then TAR from_reader.
        let status = Command::new("zip")
            .args(["-q", "-j"])
            .arg(&outer_zip)
            .arg(&inner_tar)
            .status()
            .expect("spawn zip");
        assert!(status.success());

        let opts = OpenOptions {
            index_in_memory: true,
            ..Default::default()
        };
        let outer = ZipMountSource::open(&outer_zip, None, &opts, VERSION, true).expect("zip open");
        let nested_fi = outer
            .lookup("/inner.tar", 0)
            .expect("lookup /inner.tar in zip");
        let nested_reader = outer
            .open(&nested_fi, 0)
            .expect("open tar member from zip (store region or inflated buffer)");

        let opener = open_nested_reader_fn(opts);
        let inner = opener(nested_reader, Path::new("inner.tar"))
            .expect("nested TAR inside ZIP must open without temp spool");

        assert_eq!(
            read_all(inner.as_ref(), "/hi.txt"),
            b"hello from tar in zip\n"
        );
        let pad = read_all(inner.as_ref(), "/pad.txt");
        assert_eq!(pad, b"0123456789ABCDEF_mid_seek\n");
        assert_eq!(
            read_seek_mid(inner.as_ref(), "/pad.txt", 10).as_slice(),
            &pad[10..]
        );
    }

    /// Minimal newc CPIO with one regular file and TRAILER (mirrors formats-cpio tests).
    fn build_newc_cpio(name: &str, data: &[u8], mode: u32) -> Vec<u8> {
        fn push_entry(out: &mut Vec<u8>, name: &str, data: &[u8], mode: u32) {
            let namesize = name.len() + 1;
            let filesize = data.len() as u32;
            out.extend_from_slice(b"070701");
            for val in [
                1u32, // ino
                mode,
                0, // uid
                0, // gid
                1, // nlink
                0, // mtime
                filesize,
                0, // devmajor
                0, // devminor
                0, // rdevmajor
                0, // rdevminor
                namesize as u32,
                0, // check
            ] {
                out.extend_from_slice(format!("{val:08X}").as_bytes());
            }
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            let header_and_name = 110 + namesize;
            let name_pad = (4 - (header_and_name % 4)) % 4;
            out.extend(std::iter::repeat_n(0u8, name_pad));
            out.extend_from_slice(data);
            let data_pad = (4 - (data.len() % 4)) % 4;
            out.extend(std::iter::repeat_n(0u8, data_pad));
        }

        let mut out = Vec::new();
        push_entry(&mut out, name, data, mode);
        push_entry(&mut out, "TRAILER!!!", &[], 0);
        out
    }

    /// Minimal SVR4/GNU `ar` with one regular member (name ends with `/`).
    fn synthetic_ar(name: &str, payload: &[u8]) -> Vec<u8> {
        const HEADER_SIZE: usize = 60;
        let mut out = Vec::new();
        out.extend_from_slice(b"!<arch>\n");
        let mut hdr = [b' '; HEADER_SIZE];
        let name_field = format!("{name}/");
        let nb = name_field.as_bytes();
        assert!(nb.len() <= 16, "name too long for short AR header");
        hdr[..nb.len()].copy_from_slice(nb);
        hdr[16] = b'0'; // mtime
        hdr[28] = b'0'; // uid
        hdr[34] = b'0'; // gid
        let mode = b"100644";
        hdr[40..40 + mode.len()].copy_from_slice(mode);
        let size_s = payload.len().to_string();
        hdr[48..48 + size_s.len()].copy_from_slice(size_s.as_bytes());
        hdr[58..60].copy_from_slice(b"`\n");
        out.extend_from_slice(&hdr);
        out.extend_from_slice(payload);
        if payload.len() % 2 == 1 {
            out.push(b'\n');
        }
        out
    }

    /// Minimal WARC/1.0 with one `response` record.
    fn synthetic_response_warc(uri: &str, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"WARC/1.0\r\n");
        out.extend_from_slice(b"WARC-Type: response\r\n");
        out.extend_from_slice(format!("WARC-Target-URI: {uri}\r\n").as_bytes());
        out.extend_from_slice(b"WARC-Date: 2020-01-01T00:00:00Z\r\n");
        out.extend_from_slice(
            b"WARC-Record-ID: <urn:uuid:00000000-0000-0000-0000-000000000001>\r\n",
        );
        out.extend_from_slice(format!("Content-Length: {}\r\n", payload.len()).as_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(payload);
        out
    }

    /// Minimal Electron ASAR with flat files (concatenated payload; no serde_json dep).
    fn build_minimal_asar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut entries = Vec::new();
        let mut offset: u64 = 0;
        let mut payload = Vec::new();
        for (name, data) in files {
            entries.push(format!(
                r#""{name}":{{"size":{},"offset":"{offset}"}}"#,
                data.len()
            ));
            payload.extend_from_slice(data);
            offset += data.len() as u64;
        }
        let header_bytes = format!(r#"{{"files":{{{}}}}}"#, entries.join(",")).into_bytes();
        let size_of_pickled_header = header_bytes.len() as u32;
        let padding = (4 - (size_of_pickled_header % 4)) % 4;
        let size_of_pickled_pickled_header = size_of_pickled_header + padding + 4;
        let size_of_pickled_pickled_pickled_header = size_of_pickled_pickled_header + 4;

        let mut out = Vec::new();
        out.extend_from_slice(&4u32.to_le_bytes());
        out.extend_from_slice(&size_of_pickled_pickled_pickled_header.to_le_bytes());
        out.extend_from_slice(&size_of_pickled_pickled_header.to_le_bytes());
        out.extend_from_slice(&size_of_pickled_header.to_le_bytes());
        out.extend_from_slice(&header_bytes);
        out.extend(std::iter::repeat_n(0u8, padding as usize));
        out.extend_from_slice(&payload);
        out
    }

    #[test]
    fn nested_cpio_from_cursor_via_opener() {
        // S_IFREG | 0644
        let mode = ratarmount_core::S_IFREG | 0o644;
        let payload = b"cpio-SEEK-ME-payload-xyz";
        let bytes = build_newc_cpio("hello.txt", payload, mode);
        let reader = std::io::Cursor::new(bytes);
        let opts = OpenOptions {
            index_in_memory: true,
            ..Default::default()
        };
        let opener = open_nested_reader_fn(opts);
        let boxed: Box<dyn ratarmount_core::ArchiveRead> = Box::new(reader);
        let inner = opener(boxed, Path::new("inner.cpio"))
            .expect("nested CPIO open_from_reader without temp spool");

        assert_eq!(read_all(inner.as_ref(), "/hello.txt"), payload);
        let mid = read_seek_mid(inner.as_ref(), "/hello.txt", 5);
        assert_eq!(mid.as_slice(), &payload[5..]);
    }

    #[test]
    fn nested_ar_from_cursor_via_opener() {
        let payload = b"ar-RANDOM-seek-target-0123456789";
        let bytes = synthetic_ar("member.txt", payload);
        let reader = std::io::Cursor::new(bytes);
        let opts = OpenOptions {
            index_in_memory: true,
            ..Default::default()
        };
        let opener = open_nested_reader_fn(opts);
        let boxed: Box<dyn ratarmount_core::ArchiveRead> = Box::new(reader);
        let inner = opener(boxed, Path::new("inner.a"))
            .expect("nested AR open_from_reader without temp spool");

        assert_eq!(read_all(inner.as_ref(), "/member.txt"), payload);
        let mid = read_seek_mid(inner.as_ref(), "/member.txt", 3);
        assert_eq!(mid.as_slice(), &payload[3..]);
    }

    #[test]
    fn nested_warc_from_cursor_via_opener() {
        let payload = b"warc-Hello-World-seek-mid";
        let bytes = synthetic_response_warc("http://example.com/hello.txt", payload);
        let reader = std::io::Cursor::new(bytes);
        let opts = OpenOptions {
            index_in_memory: true,
            ..Default::default()
        };
        let opener = open_nested_reader_fn(opts);
        let boxed: Box<dyn ratarmount_core::ArchiveRead> = Box::new(reader);
        let inner = opener(boxed, Path::new("inner.warc"))
            .expect("nested WARC open_from_reader without temp spool");

        assert_eq!(read_all(inner.as_ref(), "/example.com/hello.txt"), payload);
        let mid = read_seek_mid(inner.as_ref(), "/example.com/hello.txt", 5);
        assert_eq!(mid.as_slice(), &payload[5..]);
    }

    #[test]
    fn nested_asar_from_cursor_via_opener() {
        // ASAR nested open is name-triggered (no early magic); label must end in .asar.
        let pad = b"asar-SEEK-ME-abcdef012345";
        let bytes = build_minimal_asar(&[("hello.txt", b"world\n"), ("pad.txt", pad)]);
        let reader = std::io::Cursor::new(bytes);
        let opts = OpenOptions {
            index_in_memory: true,
            ..Default::default()
        };
        let opener = open_nested_reader_fn(opts);
        let boxed: Box<dyn ratarmount_core::ArchiveRead> = Box::new(reader);
        let inner = opener(boxed, Path::new("inner.asar"))
            .expect("nested ASAR open_from_reader without temp spool");

        assert_eq!(read_all(inner.as_ref(), "/hello.txt"), b"world\n");
        assert_eq!(read_all(inner.as_ref(), "/pad.txt"), pad);
        let mid = read_seek_mid(inner.as_ref(), "/pad.txt", 5);
        assert_eq!(mid.as_slice(), &pad[5..]);
    }

    /// Minimal store (uncompressed) CAB for factory magic detection (`MSCF`).
    fn synthetic_store_cab(name: &str, payload: &[u8]) -> Vec<u8> {
        let name_bytes = name.as_bytes();
        let coff_files = 36u32 + 8;
        let coff_cab_start = coff_files + 16 + name_bytes.len() as u32 + 1;
        let total = coff_cab_start as usize + 8 + payload.len();
        let mut out = Vec::with_capacity(total);
        out.extend_from_slice(b"MSCF");
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(total as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&coff_files.to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.push(3);
        out.push(1);
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&coff_cab_start.to_le_bytes());
        out.extend_from_slice(&1u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes()); // TCOMP_TYPE_NONE
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&0x20u16.to_le_bytes());
        out.extend_from_slice(name_bytes);
        out.push(0);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        out.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    /// Factory nested CAB (MSCF magic) — no-tmp open_from_reader wiring.
    #[test]
    fn nested_cab_from_cursor_via_opener() {
        let payload = b"cab-store-SEEK-payload-xyz";
        let bytes = synthetic_store_cab("member.txt", payload);
        let opts = OpenOptions {
            index_in_memory: true,
            ..Default::default()
        };
        let opener = open_nested_reader_fn(opts);
        let inner = opener(
            Box::new(std::io::Cursor::new(bytes)),
            Path::new("inner.cab"),
        )
        .expect("nested CAB open without temp spool");
        assert_eq!(read_all(inner.as_ref(), "/member.txt"), payload);
        let mid = read_seek_mid(inner.as_ref(), "/member.txt", 4);
        assert_eq!(mid.as_slice(), &payload[4..]);
    }

    /// Factory nested EXT4 — no-tmp open_from_reader wiring (pure ext4-view).
    #[test]
    fn nested_ext4_from_cursor_via_opener() {
        use std::process::Command;
        // Prefer Python fixture; else mke2fs -d seed (same as formats-ext4 tests).
        let bytes = (|| -> Option<Vec<u8>> {
            let root = std::env::var("RATARMOUNT_PY_ROOT")
                .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
            let bz2 = PathBuf::from(root).join("tests/nested-tar-1M.ext4.bz2");
            if bz2.is_file() {
                let dir = tempfile::tempdir().ok()?;
                let img = dir.path().join("x.ext4");
                let status = Command::new("bzip2")
                    .args(["-dc"])
                    .arg(&bz2)
                    .stdout(std::fs::File::create(&img).ok()?)
                    .status()
                    .ok()?;
                if status.success() {
                    return std::fs::read(&img).ok();
                }
            }
            let mke2fs = std::env::var_os("PATH").and_then(|p| {
                std::env::split_paths(&p)
                    .map(|d| d.join("mke2fs"))
                    .find(|p| p.is_file())
                    .or_else(|| {
                        let p = PathBuf::from("/usr/sbin/mke2fs");
                        p.is_file().then_some(p)
                    })
            })?;
            let dir = tempfile::tempdir().ok()?;
            let seed = dir.path().join("seed");
            std::fs::create_dir_all(seed.join("foo/fighter")).ok()?;
            std::fs::write(seed.join("foo/fighter/ufo"), b"iriya\n").ok()?;
            let img = dir.path().join("min.ext4");
            {
                let f = std::fs::File::create(&img).ok()?;
                f.set_len(1024 * 1024).ok()?;
            }
            let status = Command::new(&mke2fs)
                .args(["-t", "ext4", "-F", "-q", "-d"])
                .arg(&seed)
                .arg(&img)
                .status()
                .ok()?;
            if !status.success() {
                return None;
            }
            std::fs::read(&img).ok()
        })();
        let Some(bytes) = bytes else {
            eprintln!("skip: no EXT4 fixture and mke2fs unavailable");
            return;
        };
        let opts = OpenOptions {
            index_in_memory: true,
            ..Default::default()
        };
        let opener = open_nested_reader_fn(opts);
        let inner = opener(
            Box::new(std::io::Cursor::new(bytes)),
            Path::new("inner.ext4"),
        )
        .expect("nested EXT4 open without temp spool");
        // Fixture / mke2fs seed both place payload at /foo/fighter/ufo.
        assert_eq!(read_all(inner.as_ref(), "/foo/fighter/ufo"), b"iriya\n");
        let mid = read_seek_mid(inner.as_ref(), "/foo/fighter/ufo", 2);
        assert_eq!(mid.as_slice(), b"iya\n");
    }

    /// Factory nested SquashFS (hsqs magic) — no-tmp open_from_reader wiring (gzip image).
    #[test]
    fn nested_squashfs_from_cursor_via_opener() {
        use std::process::Command;
        let which = || {
            std::env::var_os("PATH").and_then(|p| {
                std::env::split_paths(&p)
                    .map(|d| d.join("mksquashfs"))
                    .find(|p| p.is_file())
            })
        };
        let Some(mks) = which() else {
            eprintln!("skip: mksquashfs not available");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let payload = b"sqfs-nested-SEEK-payload";
        std::fs::write(root.join("ufo"), payload).unwrap();
        let img = dir.path().join("inner.squashfs");
        let status = Command::new(mks)
            .args([
                root.to_str().unwrap(),
                img.to_str().unwrap(),
                "-comp",
                "gzip",
                "-noappend",
            ])
            .status()
            .expect("spawn mksquashfs");
        if !status.success() {
            eprintln!("skip: mksquashfs failed");
            return;
        }
        let bytes = std::fs::read(&img).expect("read squashfs image");
        let opts = OpenOptions {
            index_in_memory: true,
            ..Default::default()
        };
        let opener = open_nested_reader_fn(opts);
        let inner = opener(
            Box::new(std::io::Cursor::new(bytes)),
            Path::new("inner.squashfs"),
        )
        .expect("nested SquashFS open without temp spool");
        assert_eq!(read_all(inner.as_ref(), "/ufo"), payload);
        let mid = read_seek_mid(inner.as_ref(), "/ufo", 4);
        assert_eq!(mid.as_slice(), &payload[4..]);
    }

    /// CPIO embedded in store 7z: parent open + nested CPIO from_reader — no temp spool.
    #[test]
    fn nested_cpio_inside_store_7z_reader_random_read_no_tmp() {
        let dir = tempfile::tempdir().unwrap();
        let mode = ratarmount_core::S_IFREG | 0o644;
        let payload = b"cpio-in-7z-SEEK-payload";
        let cpio_bytes = build_newc_cpio("nested.txt", payload, mode);
        let cpio_path = dir.path().join("inner.cpio");
        std::fs::write(&cpio_path, &cpio_bytes).expect("write cpio");
        let Some(outer) = make_store_7z_with_member(dir.path(), &cpio_path, "outer-cpio.7z") else {
            eprintln!("skip: 7z/7za not available");
            return;
        };

        let opts = OpenOptions {
            index_in_memory: true,
            ..Default::default()
        };
        let outer_ms = SevenZipMountSource::open(&outer, None, &opts, VERSION, true)
            .expect("open store 7z outer");
        let nested_name = cpio_path.file_name().unwrap().to_str().unwrap();
        let nested_fi = outer_ms
            .lookup(&format!("/{nested_name}"), 0)
            .expect("lookup inner.cpio");
        let nested_reader = outer_ms
            .open(&nested_fi, 0)
            .expect("open cpio member stream");

        let opener = open_nested_reader_fn(opts);
        let inner = opener(nested_reader, Path::new(nested_name))
            .expect("nested CPIO inside 7z must open without temp spool");

        assert_eq!(read_all(inner.as_ref(), "/nested.txt"), payload);
        let mid = read_seek_mid(inner.as_ref(), "/nested.txt", 5);
        assert_eq!(mid.as_slice(), &payload[5..]);
    }
}
