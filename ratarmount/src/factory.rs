//! Open archives / folders into `Arc<dyn MountSource>`.

use std::path::Path;
use std::sync::Arc;

use ratarmount_compress::{
    detect_compression, looks_like_tar, materialize, name_suggests_compressed_tar,
    strip_compression_suffix, CompressionFormat,
};
use ratarmount_compositing::{AutoMountLayer, FolderMountSource, OpenNestedFn, UnionMountSource};
use ratarmount_core::{MountSource, OpenOptions};
use ratarmount_formats_ar::{looks_like_ar, ArMountSource};
use ratarmount_formats_cpio::{looks_like_cpio_newc, CpioMountSource};
use ratarmount_formats_libarchive::{looks_like_libarchive, LibarchiveMountSource};
use ratarmount_formats_sevenzip::{looks_like_7z, SevenZipMountSource};
use ratarmount_formats_tar::{default_index_path, SingleFileMountSource, SqliteIndexedTar};
use ratarmount_formats_zip::{looks_like_zip, ZipMountSource};

const VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn open_nested_fn(options: OpenOptions) -> OpenNestedFn {
    Arc::new(move |path: &Path| {
        // Nested archives must not share the parent's index path.
        let mut opts = options.clone();
        opts.index_file_path = None;
        opts.clear_index_cache = true;
        // Always rebuild nested in-memory-adjacent temp indexes next to the materialised file.
        let mut idx = path.as_os_str().to_os_string();
        idx.push(".index.sqlite");
        opts.index_file_path = Some(std::path::PathBuf::from(idx));
        open_path(path, &opts, true).map_err(std::io::Error::other)
    })
}

/// Open a single path (file archive or directory).
pub fn open_path(
    path: &Path,
    options: &OpenOptions,
    recreate: bool,
) -> Result<Arc<dyn MountSource>, String> {
    if path.is_dir() {
        return FolderMountSource::new(path)
            .map(|f| Arc::new(f) as Arc<dyn MountSource>)
            .map_err(|e| e.to_string());
    }
    if !path.exists() {
        return Err(format!("not found: {}", path.display()));
    }

    let compression = detect_compression(path).map_err(|e| e.to_string())?;
    let index_path = options
        .index_file_path
        .clone()
        .unwrap_or_else(|| default_index_path(path));

    let source: Arc<dyn MountSource> = match compression {
        CompressionFormat::None => {
            if looks_like_7z(path) {
                // Prefer custom random-access SevenZip backend over libarchive.
                Arc::new(
                    SevenZipMountSource::open(path, Some(&index_path), options, VERSION, recreate)
                        .map_err(|e| e.to_string())?,
                )
            } else if looks_like_zip(path) {
                Arc::new(
                    ZipMountSource::open(path, Some(&index_path), options, VERSION, recreate)
                        .map_err(|e| e.to_string())?,
                )
            } else if looks_like_ar(path) {
                Arc::new(
                    ArMountSource::open(path, Some(&index_path), options, VERSION, recreate)
                        .map_err(|e| e.to_string())?,
                )
            } else if looks_like_cpio_newc(path) {
                Arc::new(
                    CpioMountSource::open(path, Some(&index_path), options, VERSION, recreate)
                        .map_err(|e| e.to_string())?,
                )
            } else if looks_like_libarchive(path) {
                Arc::new(
                    LibarchiveMountSource::open(path, Some(&index_path), options, VERSION, recreate)
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
                    &index_path,
                    options,
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
        format @ (CompressionFormat::Gzip
        | CompressionFormat::Bzip2
        | CompressionFormat::Xz
        | CompressionFormat::Zstd) => {
            let (tmp, size) = materialize(path, format).map_err(|e| e.to_string())?;
            let data_path = tmp.path().to_path_buf();
            let mut materialised = Some(tmp);
            let is_tar =
                looks_like_tar(&data_path).unwrap_or(false) || name_suggests_compressed_tar(path);
            if is_tar {
                Arc::new(open_tar(
                    path,
                    &data_path,
                    &index_path,
                    options,
                    recreate,
                    &mut materialised,
                )?)
            } else if looks_like_libarchive(&data_path) {
                // e.g. .iso.bz2 → decompress then libarchive
                // Keep materialised alive by renaming into a durable path next to index
                let body = materialised
                    .take()
                    .ok_or_else(|| "missing materialised body".to_string())?;
                let keep = body
                    .into_temp_path()
                    .keep()
                    .map_err(|e| e.error.to_string())?;
                // Leak keep path for process lifetime (archive needs file on disk)
                let keep_path = keep;
                Arc::new(
                    LibarchiveMountSource::open(
                        &keep_path,
                        Some(&index_path),
                        options,
                        VERSION,
                        recreate,
                    )
                    .map_err(|e| e.to_string())?,
                )
            } else {
                let stripped = strip_compression_suffix(
                    path.file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("file"),
                );
                Arc::new(
                    SingleFileMountSource::new(
                        stripped,
                        data_path,
                        size,
                        materialised.take(),
                    )
                    .map_err(|e| e.to_string())?,
                )
            }
        }
    };

    Ok(source)
}

fn open_tar(
    archive_path: &Path,
    data_path: &Path,
    index_path: &Path,
    options: &OpenOptions,
    recreate: bool,
    materialised: &mut Option<tempfile::NamedTempFile>,
) -> Result<SqliteIndexedTar, String> {
    if !recreate && index_path.exists() {
        let meta_ok = std::fs::metadata(index_path)
            .map(|m| m.len() > 0)
            .unwrap_or(false);
        if meta_ok {
            match SqliteIndexedTar::open_with_existing_index(
                archive_path,
                data_path,
                index_path,
                options.clone(),
                materialised,
            ) {
                Ok(s) => return Ok(s),
                Err(e) => eprintln!("info: could not load index ({e}); rebuilding"),
            }
        }
    }
    SqliteIndexedTar::create_index(
        archive_path,
        data_path,
        Some(index_path),
        options,
        VERSION,
        materialised,
    )
    .map_err(|e| e.to_string())
}

/// Holds remote downloads for process lifetime (deleted on drop).
pub struct MountBundle {
    pub source: Arc<dyn MountSource>,
    /// Fetched HTTP bodies etc. must outlive `source`.
    _remotes: Vec<ratarmount_remote::RemoteLocal>,
}

/// Build final mount source from one or more inputs (local paths or URLs).
pub fn build_mount_source(
    paths: &[std::path::PathBuf],
    options: &OpenOptions,
    recreate: bool,
    recursive: bool,
) -> Result<MountBundle, String> {
    if paths.is_empty() {
        return Err("no input paths".into());
    }
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

        // Per-path index next to archive (or in temp for remotes: next to fetched body)
        let mut opts = options.clone();
        if opts.index_file_path.is_none() && local_path.is_file() {
            opts.index_file_path = Some(default_index_path(&local_path));
        }
        let mut src = open_path(&local_path, &opts, recreate)?;
        if recursive {
            let opener = open_nested_fn(opts.clone());
            let depth = opts.recursion_depth.unwrap_or(0).max(0) as u32;
            src = Arc::new(AutoMountLayer::new(src, depth, opener));
        }
        sources.push(src);
    }
    let source = if sources.len() == 1 {
        sources.pop().unwrap()
    } else {
        Arc::new(UnionMountSource::new(sources))
    };
    Ok(MountBundle {
        source,
        _remotes: remotes,
    })
}
