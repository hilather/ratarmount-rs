//! Open archives / folders into `Arc<dyn MountSource>`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use ratarmount_compress::{
    body_looks_like_tar, detect_compression, looks_like_tar, materialize,
    name_suggests_compressed_tar, open_seekable_bzip2, open_seekable_compress_z,
    open_seekable_lz4, open_seekable_lzip, open_seekable_lzma, open_seekable_lzo,
    open_seekable_xz, open_seekable_zlib, strip_compression_suffix, CompressionFormat,
    SeekableBody, SeekableZstd, SharedSeekableGzip,
};
use ratarmount_compositing::{
    parse_recursive_extensions, AutoMountLayer, AutoMountOptions, FileVersionLayer,
    FolderMountSource, OpenNestedFn, PrefixMountSource, RecursiveExtSet, TransformMountSource,
    UnionMountOptions, UnionMountSource,
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

/// Open a single path (file archive or directory).
pub fn open_path(
    path: &Path,
    options: &OpenOptions,
    recreate: bool,
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
        CompressionFormat::None => {
            if looks_like_7z(path) {
                Arc::new(
                    SevenZipMountSource::open(path, index_path, &options, VERSION, recreate)
                        .map_err(|e| e.to_string())?,
                )
            } else if looks_like_zip(path) {
                Arc::new(
                    ZipMountSource::open(path, index_path, &options, VERSION, recreate)
                        .map_err(|e| e.to_string())?,
                )
            } else if looks_like_asar(path) {
                Arc::new(
                    AsarMountSource::open(path, index_path, &options, VERSION, recreate)
                        .map_err(|e| e.to_string())?,
                )
            } else if looks_like_ar(path) {
                Arc::new(
                    ArMountSource::open(path, index_path, &options, VERSION, recreate)
                        .map_err(|e| e.to_string())?,
                )
            } else if looks_like_cpio(path) {
                Arc::new(
                    CpioMountSource::open(path, index_path, &options, VERSION, recreate)
                        .map_err(|e| e.to_string())?,
                )
            } else if looks_like_iso(path) {
                Arc::new(
                    Iso9660MountSource::open(path, index_path, &options, VERSION, recreate)
                        .map_err(|e| e.to_string())?,
                )
            } else if looks_like_warc(path) {
                Arc::new(
                    WarcMountSource::open(path, index_path, &options, VERSION, recreate)
                        .map_err(|e| e.to_string())?,
                )
            } else if looks_like_xar(path) {
                Arc::new(
                    XarMountSource::open(path, index_path, &options, VERSION, recreate)
                        .map_err(|e| e.to_string())?,
                )
            } else if looks_like_cab(path) {
                match CabMountSource::open(path, index_path, &options, VERSION, recreate) {
                    Ok(s) => Arc::new(s),
                    Err(CabError::UnsupportedCompression(_)) => Arc::new(
                        LibarchiveMountSource::open(
                            path,
                            index_path,
                            &options,
                            VERSION,
                            recreate,
                        )
                        .map_err(|e| e.to_string())?,
                    ),
                    Err(e) => return Err(e.to_string()),
                }
            } else if looks_like_sqlar(path) {
                Arc::new(
                    SqlarMountSource::open(path, &options).map_err(|e| e.to_string())?,
                )
            } else if looks_like_squashfs(path) {
                Arc::new(SquashFsMountSource::open(path).map_err(|e| e.to_string())?)
            } else if looks_like_ext4(path) {
                Arc::new(Ext4MountSource::open(path).map_err(|e| e.to_string())?)
            } else if looks_like_fat(path) {
                Arc::new(FatMountSource::open(path).map_err(|e| e.to_string())?)
            } else if looks_like_ogg(path) {
                Arc::new(
                    OggMountSource::open(path, index_path, &options, VERSION, recreate)
                        .map_err(|e| e.to_string())?,
                )
            } else if looks_like_pdf(path) {
                Arc::new(
                    PdfMountSource::open(path, index_path, &options, VERSION, recreate)
                        .map_err(|e| e.to_string())?,
                )
            } else if looks_like_html(path) {
                Arc::new(
                    HtmlMountSource::open(path, index_path, &options, VERSION, recreate)
                        .map_err(|e| e.to_string())?,
                )
            } else if looks_like_libarchive(path) {
                Arc::new(
                    LibarchiveMountSource::open(path, index_path, &options, VERSION, recreate)
                        .map_err(|e| e.to_string())?,
                )
            } else if looks_like_tar(path).unwrap_or(false)
                || path
                    .extension()
                    .and_then(|e| e.to_str())
                    .is_some_and(|e| e.eq_ignore_ascii_case("tar"))
            {
                let mut mat = None;
                Arc::new(open_tar(
                    path,
                    path,
                    index_path,
                    &options,
                    recreate,
                    &mut mat,
                )?)
            } else {
                let name = path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("file")
                    .to_string();
                let size = std::fs::metadata(path).map_err(|e| e.to_string())?.len();
                Arc::new(
                    SingleFileMountSource::new(name, path.to_path_buf(), size, None)
                        .map_err(|e| e.to_string())?,
                )
            }
        }
        CompressionFormat::Gzip => {
            open_gzip(path, index_path, &options, recreate)?
        }
        CompressionFormat::Bzip2 => {
            open_seekable_codec(path, index_path, &options, recreate, "bzip2", || {
                open_seekable_bzip2(path)
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
            let meta_ok = std::fs::metadata(ip)
                .map(|m| m.len() > 0)
                .unwrap_or(false);
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
            path,
            gzip,
            index_path,
            options,
            recreate,
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
    if let Some(src) = try_stencil_archives_on_path(
        &data_path,
        index_path,
        options,
        recreate,
        &mut materialised,
    )? {
        return Ok(src);
    }
    let stripped = strip_compression_suffix(
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("file"),
    );
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
    let keep_path = |materialised: &mut Option<tempfile::NamedTempFile>| -> Result<PathBuf, String> {
        if let Some(tmp) = materialised.take() {
            tmp.into_temp_path()
                .keep()
                .map_err(|e| e.error.to_string())
                .map(PathBuf::from)
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
            let meta_ok = std::fs::metadata(ip)
                .map(|m| m.len() > 0)
                .unwrap_or(false);
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

    let is_tar =
        name_suggests_compressed_tar(path) || body_looks_like_tar(&body).unwrap_or(false);

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
            .ok_or_else(|| "materialized body missing".to_string())?
            .into_temp_path()
            .keep()
            .map_err(|e| e.error.to_string())?;
        return Ok(Arc::new(
            LibarchiveMountSource::open(&keep, index_path, options, VERSION, recreate)
                .map_err(|e| e.to_string())?,
        ));
    }
    let stripped = strip_compression_suffix(
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("file"),
    );
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
            let meta_ok = std::fs::metadata(ip)
                .map(|m| m.len() > 0)
                .unwrap_or(false);
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
            src = Arc::new(
                TransformMountSource::new(pat, rep, src)
                    .map_err(|e| e)?,
            );
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
    for suf in [".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst", ".tar", ".tgz", ".zip", ".7z", ".rar"] {
        if lower.ends_with(suf) && name.len() > suf.len() {
            return name[..name.len() - suf.len()].to_string();
        }
    }
    name.to_string()
}
