//! Custom 7z MountSource with real pack offsets (`backendName=SevenZipMountSource`).
//!
//! Port of Python `ratarmountcore.mountsource.formats.sevenzip` + `sevenzip.py`
//! (hilather/ratarmount PR #1).
//!
//! # Nested archives (AutoMount / `open_from_reader`)
//!
//! Parent [`MountSource::open`] always returns a **seekable** body (`Read + Seek`)
//! so nested 7z can open without a host temp spool when the outer member stream
//! is fed into [`SevenZipMountSource::open_from_reader`].
//!
//! | Outer member packing | `open()` body | Nested open without temp |
//! |----------------------|---------------|---------------------------|
//! | **Store / Copy** (non-solid) | [`SharedArchiveView`] over shared archive IO | Yes — zero-copy stencil |
//! | **Encrypted COPY** | [`decode::PackSourceReader`] over [`decode::AesPackSource`] | Yes — range decrypt, not a ciphertext stencil |
//! | **Pure LZMA2 / AES+LZMA2** (small folder ≤ 4 MiB unpack) | `Cursor` of the member slice | Yes — fully buffered seekable |
//! | **Pure LZMA2 / AES+LZMA2** (large folder) | [`decode::Lzma2MemberReader`] live cursor + chunk resume | Yes — sequential is linear; random resumes at dict reset |
//! | **Native BCJ/Delta+LZMA2** (large folder) | [`decode::Lzma2MemberReader`] sequential-from-0 + LRU | Yes — no dict-reset resume (BCJ IP is decoder-relative) |
//! | BCJ2 / multi-pack / Deflate / BZip2 solid | `Cursor` after full-folder decompress | Yes for fixture sizes; multi-GB may hold a large unpack buffer |
//!
//! **Residual / not free:** BCJ2 / multi-pack solids still materialize the folder
//! (or member) into RAM. Encrypted folders need a password before `open`.
//! Store-in-store and solid-in-store nested fixtures both avoid writing the
//! outer member to a temp file when AutoMount uses the reader path.

mod decode;
mod parse;

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use log::{debug, info, warn};
use ratarmount_core::{
    normpath, CheapDirent, CheapSearchHit, FileInfo, ListModeResult, ListResult, MountSource,
    OpenOptions, UserData,
};
use ratarmount_index::{
    compute_hashes_limited, normalize_algorithm, FileRowSoa, IndexError, SqliteIndex,
};
use thiserror::Error;

use decode::{
    content_filter_label, lzma2_folder_can_use_decoder, lzma2_folder_uses_progressive,
    make_pack_source, Lzma2MemberReader, PackSource, PackSourceReader, SeekPackSource,
    SharedArchiveIo, SharedArchiveView, SharedLzma2Decoder, DEFAULT_MAX_CACHED_CHUNKS,
};

pub use parse::{looks_like_7z, SevenZipArchiveInfo, SevenZipError, SevenZipFileEntry};

pub const BACKEND_NAME: &str = "SevenZipMountSource";

/// Below [`decode::SMALL_FOLDER_FULL_CACHE`], solid LZMA2 / AES+LZMA2 /
/// BCJ+LZMA2 members materialize into a `Cursor`. Larger folders use
/// [`Lzma2MemberReader`] with a live sequential cursor (non-solid folders
/// also retain the 0..N prefix so nested header-at-end parse is not a
/// second full restart). BCJ/Delta chains never independent-chunk resume.

#[derive(Debug, Error)]
pub enum SzError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Seven(#[from] SevenZipError),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, SzError>;

/// Mount source for 7z archives with pack-offset random access.
pub struct SevenZipMountSource {
    /// Host path or virtual label (URL / nested name).
    #[allow(dead_code)]
    archive_path: PathBuf,
    archive: SevenZipArchiveInfo,
    index: SqliteIndex,
    /// Shared seekable archive bytes (file or nested reader — no temp required).
    archive_io: SharedArchiveIo,
    /// folder_index → fully decompressed folder bytes (small/medium folders).
    folder_cache: Mutex<HashMap<usize, Vec<u8>>>,
    /// folder_index → packed stream bytes (shared across solid members).
    packed_cache: Mutex<HashMap<usize, Vec<u8>>>,
    /// folder_index → shared pure-LZMA2 progressive decoder (large solid folders).
    lzma2_decoders: Mutex<HashMap<usize, SharedLzma2Decoder>>,
    /// Sorted (pack_offset, unpack_offset) → file index (binary search).
    entry_by_offsets: EntryOffsetTable,
    password: Option<String>,
    /// Encrypted archive mounted without a valid password: list/stat only.
    content_locked: bool,
    /// Opened via durable blob that included 7z structure (no header re-parse).
    from_durable_structure: bool,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl SevenZipMountSource {
    /// True when the nested compact-only file table is used (no SQLite `files` store).
    pub fn index_is_compact_only(&self) -> bool {
        self.index.is_compact_only()
    }

    /// Open 7z using an imported durable nested index (skip cold file-table rebuild).
    ///
    /// When the blob includes [`DurableNestedBlob::sevenzip`] structure sidecars, the
    /// 7z header is **not** re-parsed — only the seekable body is attached. Legacy blobs
    /// without structure fall back to header parse + file-table import.
    pub fn open_from_reader_with_durable<R>(
        mut reader: R,
        archive_label: impl AsRef<Path>,
        blob: &ratarmount_index::DurableNestedBlob,
        options: &OpenOptions,
    ) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        use ratarmount_index::NESTED_FORMAT_SEVENZIP;
        if blob.format != NESTED_FORMAT_SEVENZIP {
            return Err(SzError::Msg(format!(
                "durable nested blob format {} is not 7z",
                blob.format
            )));
        }
        let archive_path = archive_label.as_ref().to_path_buf();
        reader.seek(SeekFrom::Start(0))?;

        let (mut archive, from_structure) = if let Some(ref sz) = blob.sevenzip {
            match archive_info_from_durable(sz) {
                Ok(a) => (a, true),
                Err(e) => {
                    eprintln!(
                        "info: nested durable 7z structure import failed ({e}); re-parsing header"
                    );
                    let a = parse::parse_7z_archive(&mut reader, |folder, packed| {
                        decode::decompress_folder(folder, packed, None)
                            .map_err(|err| parse::SevenZipError::Msg(err.to_string()))
                    })?;
                    reader.seek(SeekFrom::Start(0))?;
                    (a, false)
                }
            }
        } else {
            let a = parse::parse_7z_archive(&mut reader, |folder, packed| {
                decode::decompress_folder(folder, packed, None)
                    .map_err(|e| parse::SevenZipError::Msg(e.to_string()))
            })?;
            reader.seek(SeekFrom::Start(0))?;
            (a, false)
        };

        reader.seek(SeekFrom::Start(0))?;
        let archive_io: SharedArchiveIo = Arc::new(Mutex::new(Box::new(reader)));

        let (password, content_locked) =
            Self::resolve_password_for_archive(&archive_io, &archive, options)?;

        let index = SqliteIndex::create_compact_from_nested_blob(blob)?;
        // Re-share entry path Arcs with the compact string pool.
        for entry in &mut archive.files {
            if let Some(pooled) = index.lookup_pooled_string(entry.path.as_ref()) {
                entry.path = pooled;
            }
        }
        let entry_by_offsets = entry_offset_map(&archive);
        if from_structure {
            eprintln!(
                "nested durable index: imported 7z file table + structure for {} ({} rows, no header re-parse)",
                archive_path.display(),
                index.file_count().unwrap_or(0)
            );
        } else {
            eprintln!(
                "nested durable index: imported 7z file table for {} ({} rows; structure re-parsed)",
                archive_path.display(),
                index.file_count().unwrap_or(0)
            );
        }
        Ok(Self {
            archive_path,
            archive,
            index,
            archive_io,
            folder_cache: Mutex::new(HashMap::new()),
            packed_cache: Mutex::new(HashMap::new()),
            lzma2_decoders: Mutex::new(HashMap::new()),
            entry_by_offsets,
            password,
            content_locked,
            from_durable_structure: from_structure,
            options: options.clone(),
        })
    }

    /// Export compact nested durable blob including 7z structure sidecars.
    pub fn export_nested_durable(
        &self,
        fingerprint: ratarmount_index::NestedBodyFingerprint,
    ) -> Result<Vec<u8>> {
        use ratarmount_index::NESTED_FORMAT_SEVENZIP;
        let structure = durable_from_archive_info(&self.archive);
        self.index
            .export_nested_blob_with_sidecars(
                NESTED_FORMAT_SEVENZIP,
                fingerprint,
                vec![],
                Some(structure),
            )
            .map_err(Into::into)
    }

    /// True when this mount imported 7z structure from a durable blob (no header parse).
    pub fn opened_from_durable_structure(&self) -> bool {
        self.from_durable_structure
    }

    /// True when entry `path` Arc is the same allocation as the compact index pool.
    pub fn entry_path_shares_pool(&self, entry_index: usize) -> bool {
        let Some(entry) = self.archive.files.get(entry_index) else {
            return false;
        };
        let Some(pooled) = self.index.lookup_pooled_string(entry.path.as_ref()) else {
            return false;
        };
        std::sync::Arc::ptr_eq(&entry.path, &pooled)
    }

    #[cfg(test)]
    fn entry_offset_table_is_sorted(&self) -> bool {
        self.entry_by_offsets.entry_offset_table_is_sorted()
    }

    pub fn open(
        archive_path: impl AsRef<Path>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
        recreate: bool,
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        let file = File::open(&archive_path)?;
        Self::open_from_reader(
            file,
            &archive_path,
            index_path,
            options,
            product_version,
            recreate,
        )
    }

    /// Open a 7z archive from any seekable reader (nested AutoMount without temp spool).
    ///
    /// `archive_label` is used for logs / index metadata (may be a nested member name).
    /// Prefer `index_path: None` or `options.index_in_memory` for nested mounts.
    pub fn open_from_reader<R>(
        reader: R,
        archive_label: impl AsRef<Path>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
        recreate: bool,
    ) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        let archive_path = archive_label.as_ref().to_path_buf();
        debug!(
            "7z open_from_reader: label={} passwords={} index_in_memory={} recreate={}",
            archive_path.display(),
            options.passwords.len(),
            options.index_in_memory,
            recreate
        );
        let index_path_buf: Option<PathBuf> = if options.index_in_memory {
            None
        } else {
            index_path.map(|p| p.to_path_buf()).or_else(|| {
                // Only invent a sibling index path when the label is a real file.
                if archive_path.is_file() {
                    let mut s = archive_path.as_os_str().to_os_string();
                    s.push(".index.sqlite");
                    Some(PathBuf::from(s))
                } else {
                    None
                }
            })
        };

        if let Some(ref ip) = index_path_buf {
            if !recreate && ip.exists() && archive_path.is_file() {
                // Existing index path only valid when we can re-open by path.
                match Self::open_existing_path(&archive_path, ip, options) {
                    Ok(s) => {
                        debug!(
                            "7z open_from_reader: reloaded existing index {} content_locked={}",
                            ip.display(),
                            s.content_locked
                        );
                        return Ok(s);
                    }
                    Err(e) => {
                        debug!(
                            "7z open_from_reader: existing index {} unusable ({e}); rebuilding",
                            ip.display()
                        );
                    }
                }
            }
        }

        Self::create_index_from_reader(
            reader,
            &archive_path,
            index_path_buf.as_deref(),
            options,
            product_version,
        )
    }

    fn open_existing_path(
        archive_path: &Path,
        index_path: &Path,
        options: &OpenOptions,
    ) -> Result<Self> {
        // Index + fingerprint first (same order as TAR/ZIP): reject a sibling
        // index for a replaced archive before paying for header parse.
        let index = SqliteIndex::open_read_only(index_path)?;
        index.check_backend_name(BACKEND_NAME)?;
        // Reject sibling indexes for a replaced archive (size/mtime/edge hash).
        // Missing tarstats still Ok (legacy indexes).
        index.check_tarstats_matches_archive(archive_path)?;

        let mut file = File::open(archive_path)?;
        let archive = parse::parse_7z_archive(&mut file, |folder, packed| {
            decode::decompress_folder(folder, packed, None)
                .map_err(|e| parse::SevenZipError::Msg(e.to_string()))
        })?;
        file.seek(SeekFrom::Start(0))?;
        let archive_io: SharedArchiveIo = Arc::new(Mutex::new(Box::new(file)));
        let (password, content_locked) =
            Self::resolve_password_for_archive(&archive_io, &archive, options)?;
        let entry_by_offsets = entry_offset_map(&archive);
        Ok(Self {
            archive_path: archive_path.to_path_buf(),
            archive,
            index,
            archive_io,
            folder_cache: Mutex::new(HashMap::new()),
            packed_cache: Mutex::new(HashMap::new()),
            lzma2_decoders: Mutex::new(HashMap::new()),
            entry_by_offsets,
            password,
            content_locked,
            from_durable_structure: false,
            options: options.clone(),
        })
    }

    fn create_index_from_reader<R>(
        mut reader: R,
        archive_path: &Path,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
    ) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        println!(
            "Creating offset dictionary for {} ...",
            archive_path.display()
        );
        let t0 = Instant::now();

        // Parse once (encoded-header decompress uses no password typically).
        let mut archive = parse::parse_7z_archive(&mut reader, |folder, packed| {
            decode::decompress_folder(folder, packed, None)
                .map_err(|e| parse::SevenZipError::Msg(e.to_string()))
        })?;

        reader.seek(SeekFrom::Start(0))?;
        let archive_io: SharedArchiveIo = Arc::new(Mutex::new(Box::new(reader)));

        let encrypted = archive.folders.iter().any(|f| f.is_encrypted());
        let n_folders = archive.folders.len();
        let n_files = archive.files.len();
        debug!(
            "7z {}: parsed archive folders={n_folders} files={n_files} encrypted={encrypted}",
            archive_path.display()
        );
        let (password, content_locked) =
            Self::resolve_password_for_archive(&archive_io, &archive, options)?;
        if encrypted && content_locked {
            warn!(
                "7z {}: contents are encrypted; mounting metadata only \
                 (listing works; reading members fails until --password is provided). \
                 Nested encrypted archives need the *inner* password \
                 (e.g. nested-encrypted-inner.7z uses `innerpw`).",
                archive_path.display()
            );
            // Also print so users without RUST_LOG still see the hint on mount.
            eprintln!(
                "warning: 7z archive contents are encrypted; mounting metadata only \
                 (listing works; reading members fails until --password is provided). \
                 Nested encrypted archives need the *inner* password \
                 (e.g. nested-encrypted-inner.7z uses `innerpw`)."
            );
        }

        let index = SqliteIndex::create_writable_for_open(index_path, options)?;
        index.set_build_hooks(options.index_build.clone());
        index.begin_write()?;

        let mut batch = FileRowSoa::with_capacity(512);
        let mut generated = std::collections::BTreeSet::new();

        for (entry_index, entry) in archive.files.iter().enumerate() {
            let mut full = entry.path.trim_end_matches('/').to_string();
            if full.is_empty() && entry.is_dir {
                continue;
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
            if name.is_empty() {
                continue;
            }
            ensure_parent_dirs(&mut batch, &path, &mut generated, entry.mtime);

            let mut mode = entry.mode;
            let ifmt = mode & ratarmount_core::S_IFMT;
            if entry.is_dir && ifmt != ratarmount_core::S_IFDIR {
                mode = (mode & 0o777) | ratarmount_core::S_IFDIR;
            } else if !entry.is_dir && ifmt == 0 {
                mode = (mode & 0o777) | ratarmount_core::S_IFREG;
            }

            let mut linkname = String::new();
            let mut size = entry.size as i64;
            if ifmt == ratarmount_core::S_IFLNK
                || (mode & ratarmount_core::S_IFMT) == ratarmount_core::S_IFLNK
            {
                // Read symlink target at index time (skip when content-locked).
                if !content_locked {
                    if let Some(fi) = entry.folder_index {
                        if let Ok(bytes) = read_member_bytes_io(
                            &archive_io,
                            &archive,
                            entry,
                            &archive.folders[fi],
                            password.as_deref(),
                        ) {
                            linkname = String::from_utf8_lossy(&bytes).into_owned();
                        }
                    }
                }
                size = 0;
            }

            let header_offset = if entry.folder_index.is_some() {
                entry.pack_offset as i64
            } else {
                ((1u64 << 62) + entry_index as u64) as i64
            };
            let data_offset = entry.unpack_offset as i64;

            batch.push(
                &path,
                &name,
                header_offset,
                data_offset,
                size,
                entry.mtime,
                mode as i64,
                0,
                &linkname,
                0,
                0,
                false,
                false,
                false,
                0,
            );
            if batch.len() >= 512 {
                index.insert_files_batch_soa(&batch)?;
                batch.clear();
            }
        }
        if !batch.is_empty() {
            index.insert_files_batch_soa(&batch)?;
            batch.clear();
        }

        // Share entry paths with the compact index string pool (Arc identity).
        for entry in &mut archive.files {
            if let Some(pooled) = index.intern_during_build(entry.path.as_ref()) {
                entry.path = pooled;
            }
        }

        // Content hashes (`--hashes` / OpenOptions.hashes) → user.hash.* xattrs.
        // Skip when encrypted content is locked (no password); otherwise best-effort
        // per member (decompress via pack offsets, store under offsetheader=pack_offset).
        if !options.hashes.is_empty() {
            if content_locked {
                warn!(
                    "skipping content hashes for encrypted 7z without password ({})",
                    archive_path.display()
                );
            } else {
                fill_member_content_hashes(
                    &index,
                    &archive_io,
                    &archive,
                    password.as_deref(),
                    &options.hashes,
                )?;
            }
        }

        index.store_versions(product_version)?;
        index.store_metadata_key_value("backendName", BACKEND_NAME)?;
        store_stats(&index, archive_path)?;
        index.commit_write()?;

        let secs = t0.elapsed().as_secs_f64();
        println!(
            "Creating offset dictionary for {} took {secs:.2}s",
            archive_path.display()
        );
        info!(
            "7z {}: index ready in {secs:.2}s files={n_files} folders={n_folders} \
             encrypted={encrypted} content_locked={content_locked} has_password={}",
            archive_path.display(),
            password.is_some()
        );

        let index = index.into_read_only()?;
        let entry_by_offsets = entry_offset_map(&archive);
        Ok(Self {
            archive_path: archive_path.to_path_buf(),
            archive,
            index,
            archive_io,
            folder_cache: Mutex::new(HashMap::new()),
            packed_cache: Mutex::new(HashMap::new()),
            lzma2_decoders: Mutex::new(HashMap::new()),
            entry_by_offsets,
            password,
            content_locked,
            from_durable_structure: false,
            options: options.clone(),
        })
    }

    /// Password trial / content_locked for a parsed or imported archive graph.
    fn resolve_password_for_archive(
        archive_io: &SharedArchiveIo,
        archive: &SevenZipArchiveInfo,
        options: &OpenOptions,
    ) -> Result<(Option<String>, bool)> {
        let encrypted = archive.folders.iter().any(|f| f.is_encrypted());
        if !encrypted {
            return Ok((options.passwords.first().cloned(), false));
        }
        for folder in &archive.folders {
            if folder.is_encrypted() && !folder.is_supported_for_open(true) {
                return Err(SzError::Seven(SevenZipError::Msg(format!(
                    "Unsupported encrypted 7z coder chain: {:?}",
                    folder
                        .coders
                        .iter()
                        .map(|c| format!("{:02x?}", c.method))
                        .collect::<Vec<_>>()
                ))));
            }
        }
        if options.passwords.is_empty() {
            return Ok((None, true));
        }
        let mut chosen = None;
        let mut last_err = None;
        let Some(entry) = archive
            .files
            .iter()
            .find(|e| e.folder_index.is_some() && e.size > 0 && !e.is_dir)
        else {
            return Err(SzError::Seven(SevenZipError::Msg(
                "encrypted 7z has no non-empty file to trial the password against".into(),
            )));
        };
        let fi = entry.folder_index.unwrap();
        let folder = &archive.folders[fi];
        for pw in options.passwords.iter() {
            match Self::try_decrypt_entry_io(archive_io, archive, entry, folder, pw) {
                Ok(()) => {
                    chosen = Some(pw.clone());
                    break;
                }
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            }
        }
        if chosen.is_none() {
            return Err(SzError::Seven(last_err.unwrap_or_else(|| {
                SevenZipError::Msg(
                    "Could not decrypt 7z archive with the provided password(s)".into(),
                )
            })));
        }
        Ok((chosen, false))
    }

    fn try_decrypt_entry_io(
        archive_io: &SharedArchiveIo,
        archive: &SevenZipArchiveInfo,
        entry: &SevenZipFileEntry,
        folder: &parse::Folder,
        password: &str,
    ) -> std::result::Result<(), SevenZipError> {
        let sizes = pack_stream_sizes(archive, entry);
        // File CRC + member-only progressive decode: a multi-GB AES+LZMA2 solid
        // must not unpack the whole folder at mount. Full-folder trial remains
        // when the only digest is folder.has_crc (or the decoder cannot be used).
        if let Some(want) = entry.crc {
            if lzma2_folder_can_use_decoder(folder) && sizes.is_none() {
                let pack =
                    SeekPackSource::new(Arc::clone(archive_io), entry.pack_offset, entry.pack_size);
                let (content_folder, content_pack) =
                    make_pack_source(folder, Box::new(pack), Some(password))?;
                let mut decoder = decode::Lzma2RandomAccessDecoder::from_pack(
                    &content_folder,
                    content_pack,
                    DEFAULT_MAX_CACHED_CHUNKS,
                )?;
                let member = decoder.read_range(entry.unpack_offset, entry.size as usize)?;
                if (member.len() as u64) < entry.size {
                    return Err(SevenZipError::Msg(
                        "password trial produced short data".into(),
                    ));
                }
                let got = parse::crc32_for_password_trial(&member);
                if got != want {
                    return Err(SevenZipError::Msg(format!(
                        "password trial file CRC mismatch (got {got:#010x}, want {want:#010x})"
                    )));
                }
                return Ok(());
            }
        }

        let pack = SeekPackSource::new(Arc::clone(archive_io), entry.pack_offset, entry.pack_size);
        let data = decode::decompress_folder_source(
            folder,
            Box::new(pack),
            Some(password),
            sizes.as_deref(),
        )?;
        let need = folder.get_unpack_size().max(entry.size);
        if (data.len() as u64) < need && data.len() < entry.size as usize {
            return Err(SevenZipError::Msg(
                "password trial produced short data".into(),
            ));
        }
        // Length alone is not enough: AES with a wrong key can still yield a
        // full-size buffer (store/Copy folders). Prefer folder CRC, then the
        // file-level Substreams CRC (p7zip often omits folder CRC).
        if folder.has_crc {
            let slice = if (data.len() as u64) >= folder.get_unpack_size() {
                &data[..folder.get_unpack_size() as usize]
            } else {
                &data[..]
            };
            let got = parse::crc32_for_password_trial(slice);
            if got != folder.crc {
                return Err(SevenZipError::Msg(format!(
                    "password trial CRC mismatch (got {got:#010x}, want {:#010x})",
                    folder.crc
                )));
            }
            return Ok(());
        }
        if let Some(want) = entry.crc {
            let end = (entry.unpack_offset + entry.size) as usize;
            if end > data.len() {
                return Err(SevenZipError::Msg(
                    "password trial member slice out of range".into(),
                ));
            }
            let member = &data[entry.unpack_offset as usize..end];
            let got = parse::crc32_for_password_trial(member);
            if got != want {
                return Err(SevenZipError::Msg(format!(
                    "password trial file CRC mismatch (got {got:#010x}, want {want:#010x})"
                )));
            }
            return Ok(());
        }
        let copy_only = folder.is_copy_only()
            || folder.content_coders().is_empty()
            || folder
                .content_coders()
                .iter()
                .all(|c| c.method.as_slice() == parse::METHOD_COPY);
        if copy_only {
            // Store+AES without any CRC: garbage is full-size and non-zero.
            return Err(SevenZipError::Msg(
                "password trial cannot verify store+AES without a CRC".into(),
            ));
        }
        Ok(())
    }

    fn pack_stream_sizes_for(&self, entry: &SevenZipFileEntry) -> Option<Vec<u64>> {
        pack_stream_sizes(&self.archive, entry)
    }

    /// True when `folder_index` has at most one non-empty file (non-solid member).
    fn folder_is_single_member(&self, folder_index: usize) -> bool {
        self.archive
            .files
            .iter()
            .filter(|e| e.folder_index == Some(folder_index) && !e.is_dir && !e.is_empty_stream)
            .count()
            <= 1
    }

    /// Largest fully unpacked folder currently in `folder_cache` (0 if empty).
    #[cfg(test)]
    fn test_folder_cache_max_len(&self) -> usize {
        self.folder_cache
            .lock()
            .unwrap()
            .values()
            .map(|v| v.len())
            .max()
            .unwrap_or(0)
    }

    #[cfg(test)]
    fn test_last_resume_unpacked(&self, file_info: &FileInfo) -> Option<u64> {
        let entry = self.find_entry(file_info).ok()?;
        let fi = entry.folder_index?;
        let cache = self.lzma2_decoders.lock().ok()?;
        let decoder = cache.get(&fi)?;
        decoder.lock().ok().map(|d| d.last_resume_unpacked())
    }

    /// Open of this `FileInfo` returns a progressive (expensive-seek) body.
    fn member_open_is_progressive(&self, file_info: &FileInfo) -> bool {
        let Ok(entry) = self.find_entry(file_info) else {
            return false;
        };
        let Some(fi) = entry.folder_index else {
            return false;
        };
        let folder = &self.archive.folders[fi];
        lzma2_folder_uses_progressive(folder, folder.get_unpack_size())
            && self.pack_stream_sizes_for(entry).is_none()
    }

    fn find_entry(&self, file_info: &FileInfo) -> Result<&SevenZipFileEntry> {
        let ud = file_info.userdata.iter().rev().find_map(|u| match u {
            UserData::Tar(t) => Some(t),
            _ => None,
        });
        let ud = ud.ok_or_else(|| {
            debug!(
                "7z {}: find_entry missing Tar userdata (size={} mode={:#x} userdata={:?})",
                self.archive_path.display(),
                file_info.size,
                file_info.mode,
                file_info.userdata
            );
            SzError::Msg("missing userdata".into())
        })?;
        let pack_offset = ud.offsetheader.unwrap_or(0);
        let unpack_offset = ud.offset;

        if let Some(idx) = self.entry_by_offsets.get(pack_offset, unpack_offset) {
            if let Some(entry) = self.archive.files.get(idx) {
                let is_link =
                    (file_info.mode & ratarmount_core::S_IFMT) == ratarmount_core::S_IFLNK;
                if entry.size == file_info.size || (is_link && file_info.size == 0) {
                    return Ok(entry);
                }
                debug!(
                    "7z {}: offset map hit idx={idx} but size mismatch entry={} fi={} path={}",
                    self.archive_path.display(),
                    entry.size,
                    file_info.size,
                    entry.path
                );
            }
        }

        for entry in &self.archive.files {
            if entry.is_dir || entry.is_empty_stream {
                continue;
            }
            if entry.pack_offset == pack_offset && entry.unpack_offset == unpack_offset {
                let is_link =
                    (file_info.mode & ratarmount_core::S_IFMT) == ratarmount_core::S_IFLNK;
                if entry.size == file_info.size || (is_link && file_info.size == 0) {
                    return Ok(entry);
                }
            }
        }
        debug!(
            "7z {}: find_entry failed pack={pack_offset} unpack={unpack_offset} size={} \
             (map has {} entries)",
            self.archive_path.display(),
            file_info.size,
            self.entry_by_offsets.len()
        );
        Err(SzError::Msg(format!(
            "Could not locate 7z member pack={pack_offset} unpack={unpack_offset} size={}",
            file_info.size
        )))
    }

    fn read_packed_for_folder(
        &self,
        folder_index: usize,
        entry: &SevenZipFileEntry,
    ) -> Result<Vec<u8>> {
        {
            let cache = self.packed_cache.lock().unwrap();
            if let Some(data) = cache.get(&folder_index) {
                return Ok(data.clone());
            }
        }
        let pack = SeekPackSource::new(
            Arc::clone(&self.archive_io),
            entry.pack_offset,
            entry.pack_size,
        );
        let packed = decode::PackSource::as_bytes(&pack).map_err(SzError::Seven)?;
        let mut cache = self.packed_cache.lock().unwrap();
        if cache.len() >= 8 {
            if let Some(k) = cache.keys().next().copied() {
                cache.remove(&k);
            }
        }
        cache.insert(folder_index, packed.clone());
        Ok(packed)
    }

    fn get_folder_bytes(&self, entry: &SevenZipFileEntry) -> Result<Vec<u8>> {
        let fi = entry
            .folder_index
            .ok_or_else(|| SzError::Msg("entry has no folder".into()))?;
        {
            let cache = self.folder_cache.lock().unwrap();
            if let Some(data) = cache.get(&fi) {
                return Ok(data.clone());
            }
        }
        let folder = &self.archive.folders[fi];
        if folder.is_encrypted() && (self.content_locked || self.password.is_none()) {
            warn!(
                "7z {}: get_folder_bytes denied for encrypted folder {fi} (content_locked={})",
                self.archive_path.display(),
                self.content_locked
            );
            return Err(SzError::Msg(
                "password required to open encrypted 7z member; pass --password / --password-file"
                    .into(),
            ));
        }
        // Pure LZMA2: prefer chunk-indexed decode so random member opens do not
        // force full solid-folder materialization when we only need a slice later.
        let packed = self.read_packed_for_folder(fi, entry)?;
        let sizes = self.pack_stream_sizes_for(entry);
        let data = if folder.coders.len() == 1
            && folder.coders[0].method.as_slice() == parse::METHOD_LZMA2
            && !folder.is_encrypted()
            && sizes.is_none()
        {
            let mut decoder = decode::Lzma2RandomAccessDecoder::new(folder, packed, 128)
                .map_err(SzError::Seven)?;
            decoder
                .read_range(0, decoder.unpack_size() as usize)
                .map_err(SzError::Seven)?
        } else {
            decode::decompress_folder_source(
                folder,
                Box::new(decode::BytesPackSource::new(packed)),
                self.password.as_deref(),
                sizes.as_deref(),
            )?
        };
        let mut cache = self.folder_cache.lock().unwrap();
        if cache.len() >= 4 {
            if let Some(k) = cache.keys().next().copied() {
                cache.remove(&k);
            }
        }
        cache.insert(fi, data.clone());
        Ok(data)
    }

    /// Open an LZMA2 / AES+LZMA2 / native BCJ|Delta+LZMA2 member via the
    /// chunk-indexed decoder (no full-folder slice).
    fn open_lzma2_member(&self, entry: &SevenZipFileEntry) -> Result<Vec<u8>> {
        let decoder = self.get_lzma2_decoder(entry)?;
        let mut g = decoder
            .lock()
            .map_err(|_| SzError::Msg("7z LZMA2 decoder lock poisoned".into()))?;
        g.read_range(entry.unpack_offset, entry.size as usize)
            .map_err(SzError::Seven)
    }

    /// Shared LZMA2 progressive decoder for a solid folder (creates on first use).
    ///
    /// Uses [`make_pack_source`] + a sliding packed window. Never slurps the pack
    /// via `as_bytes` / `packed_cache`.
    fn get_lzma2_decoder(&self, entry: &SevenZipFileEntry) -> Result<SharedLzma2Decoder> {
        let fi = entry
            .folder_index
            .ok_or_else(|| SzError::Msg("entry has no folder".into()))?;
        {
            let cache = self.lzma2_decoders.lock().unwrap();
            if let Some(d) = cache.get(&fi) {
                return Ok(Arc::clone(d));
            }
        }
        let folder = &self.archive.folders[fi];
        let pack = SeekPackSource::new(
            Arc::clone(&self.archive_io),
            entry.pack_offset,
            entry.pack_size,
        );
        let (content_folder, content_pack) =
            make_pack_source(folder, Box::new(pack), self.password.as_deref())
                .map_err(SzError::Seven)?;
        let mut decoder = decode::Lzma2RandomAccessDecoder::from_pack(
            &content_folder,
            content_pack,
            DEFAULT_MAX_CACHED_CHUNKS,
        )
        .map_err(SzError::Seven)?;
        // Non-solid / single-unpack-stream folders keep the 0..N prefix so a
        // header-at-end parse does not force a second full restart on first read.
        decoder.set_retain_from_zero(self.folder_is_single_member(fi));
        let shared: SharedLzma2Decoder = Arc::new(Mutex::new(decoder));
        let mut cache = self.lzma2_decoders.lock().unwrap();
        // Another open may have won the race; prefer the existing entry.
        Ok(Arc::clone(
            cache.entry(fi).or_insert_with(|| Arc::clone(&shared)),
        ))
    }

    /// Seekable solid LZMA2 / AES+LZMA2 / native BCJ|Delta+LZMA2 member body
    /// for nested AutoMount / random access.
    fn open_lzma2_member_reader(&self, entry: &SevenZipFileEntry) -> Result<Lzma2MemberReader> {
        let decoder = self.get_lzma2_decoder(entry)?;
        Ok(Lzma2MemberReader::new(
            decoder,
            entry.unpack_offset,
            entry.size,
        ))
    }
}

/// Sorted `(pack_offset, unpack_offset) → file-table index` for open lookup.
///
/// Replaces `HashMap<(u64, u64), usize>` so huge member counts pay a compact
/// `Vec` + binary search instead of hash-table buckets. Folder / coder graphs
/// stay on [`SevenZipArchiveInfo`] and are not cloned into this table.
/// Size / path remain on [`SevenZipFileEntry`] (already allocated at parse).
#[derive(Debug)]
struct EntryOffsetTable {
    keys: Vec<(u64, u64)>,
    idxs: Vec<usize>,
}

impl EntryOffsetTable {
    fn from_unsorted_pairs(pairs: impl IntoIterator<Item = ((u64, u64), usize)>) -> Self {
        let mut items: Vec<((u64, u64), usize)> = pairs.into_iter().collect();
        // Stable sort: last insert wins on duplicate keys (HashMap parity).
        items.sort_by_key(|(k, _)| *k);
        let mut keys = Vec::with_capacity(items.len());
        let mut idxs = Vec::with_capacity(items.len());
        for (k, i) in items {
            if keys.last() == Some(&k) {
                *idxs.last_mut().unwrap() = i;
            } else {
                keys.push(k);
                idxs.push(i);
            }
        }
        Self { keys, idxs }
    }

    fn get(&self, pack: u64, unpack: u64) -> Option<usize> {
        self.keys
            .binary_search(&(pack, unpack))
            .ok()
            .map(|i| self.idxs[i])
    }

    fn len(&self) -> usize {
        self.keys.len()
    }

    #[cfg(test)]
    fn entry_offset_table_is_sorted(&self) -> bool {
        self.keys.windows(2).all(|w| w[0] <= w[1]) && self.keys.len() == self.idxs.len()
    }
}

fn entry_offset_map(archive: &SevenZipArchiveInfo) -> EntryOffsetTable {
    EntryOffsetTable::from_unsorted_pairs(archive.files.iter().enumerate().filter_map(|(i, e)| {
        if e.is_dir || e.is_empty_stream {
            None
        } else {
            Some(((e.pack_offset, e.unpack_offset), i))
        }
    }))
}

/// Serialize live archive graph into a durable nested blob sidecar.
fn durable_from_archive_info(
    archive: &SevenZipArchiveInfo,
) -> ratarmount_index::DurableSevenZipArchive {
    use ratarmount_index::{
        DurableSevenZipArchive, DurableSevenZipCoder, DurableSevenZipFileEntry,
        DurableSevenZipFolder, DurableSevenZipPackInfo,
    };
    DurableSevenZipArchive {
        after_header: archive.after_header,
        pack_pos_base: archive.pack_pos_base,
        folders: archive
            .folders
            .iter()
            .map(|f| DurableSevenZipFolder {
                coders: f
                    .coders
                    .iter()
                    .map(|c| DurableSevenZipCoder {
                        method: c.method.clone(),
                        num_in_streams: c.num_in_streams,
                        num_out_streams: c.num_out_streams,
                        properties: c.properties.clone(),
                    })
                    .collect(),
                bind_pairs: f.bind_pairs.clone(),
                packed_indices: f.packed_indices.clone(),
                unpack_sizes: f.unpack_sizes.clone(),
                has_crc: f.has_crc,
                crc: f.crc,
            })
            .collect(),
        pack_info: archive.pack_info.as_ref().map(|p| DurableSevenZipPackInfo {
            pack_pos: p.pack_pos,
            pack_sizes: p.pack_sizes.clone(),
            crcs: p.crcs.clone(),
        }),
        files: archive
            .files
            .iter()
            .map(|e| DurableSevenZipFileEntry {
                path: e.path.to_string(),
                size: e.size,
                mtime: e.mtime,
                mode: e.mode,
                is_dir: e.is_dir,
                is_empty_stream: e.is_empty_stream,
                is_empty_file: e.is_empty_file,
                folder_index: e.folder_index,
                unpack_offset: e.unpack_offset,
                pack_offset: e.pack_offset,
                pack_size: e.pack_size,
                pack_stream_index: e.pack_stream_index,
            })
            .collect(),
        solid: archive.solid,
    }
}

/// Rebuild archive graph from durable structure (warm open without header parse).
fn archive_info_from_durable(
    d: &ratarmount_index::DurableSevenZipArchive,
) -> Result<SevenZipArchiveInfo> {
    use parse::{Coder, Folder, PackInfo, SevenZipFileEntry};
    if d.files.is_empty() && d.folders.is_empty() {
        return Err(SzError::Msg(
            "durable 7z structure is empty (cannot import)".into(),
        ));
    }
    let folders: Vec<Folder> = d
        .folders
        .iter()
        .map(|f| Folder {
            coders: f
                .coders
                .iter()
                .map(|c| Coder {
                    method: c.method.clone(),
                    num_in_streams: c.num_in_streams,
                    num_out_streams: c.num_out_streams,
                    properties: c.properties.clone(),
                })
                .collect(),
            bind_pairs: f.bind_pairs.clone(),
            packed_indices: f.packed_indices.clone(),
            unpack_sizes: f.unpack_sizes.clone(),
            has_crc: f.has_crc,
            crc: f.crc,
        })
        .collect();
    let pack_info = d.pack_info.as_ref().map(|p| PackInfo {
        pack_pos: p.pack_pos,
        pack_sizes: p.pack_sizes.clone(),
        crcs: p.crcs.clone(),
    });
    let files: Vec<SevenZipFileEntry> = d
        .files
        .iter()
        .map(|e| SevenZipFileEntry {
            path: std::sync::Arc::from(e.path.as_str()),
            size: e.size,
            mtime: e.mtime,
            mode: e.mode,
            is_dir: e.is_dir,
            is_empty_stream: e.is_empty_stream,
            is_empty_file: e.is_empty_file,
            folder_index: e.folder_index,
            unpack_offset: e.unpack_offset,
            pack_offset: e.pack_offset,
            pack_size: e.pack_size,
            pack_stream_index: e.pack_stream_index,
            crc: None,
        })
        .collect();
    // Validate folder indices reference existing folders.
    for e in &files {
        if let Some(fi) = e.folder_index {
            if fi >= folders.len() {
                return Err(SzError::Msg(format!(
                    "durable 7z structure: folder_index {fi} out of range ({})",
                    folders.len()
                )));
            }
        }
    }
    Ok(SevenZipArchiveInfo {
        after_header: d.after_header,
        pack_pos_base: d.pack_pos_base,
        folders,
        pack_info,
        files,
        solid: d.solid,
    })
}

fn pack_stream_sizes(archive: &SevenZipArchiveInfo, entry: &SevenZipFileEntry) -> Option<Vec<u64>> {
    let pack_info = archive.pack_info.as_ref()?;
    let fi = entry.folder_index?;
    let folder = archive.folders.get(fi)?;
    let count = if folder.packed_indices.is_empty() {
        1
    } else {
        folder.packed_indices.len()
    };
    if count <= 1 {
        return None;
    }
    let start = entry.pack_stream_index;
    let end = start + count;
    if end > pack_info.pack_sizes.len() {
        return None;
    }
    Some(pack_info.pack_sizes[start..end].to_vec())
}

fn read_member_bytes_io(
    archive_io: &SharedArchiveIo,
    archive: &SevenZipArchiveInfo,
    entry: &SevenZipFileEntry,
    folder: &parse::Folder,
    password: Option<&str>,
) -> Result<Vec<u8>> {
    if folder.is_copy_only() && !folder.is_encrypted() {
        let pack = SeekPackSource::new(
            Arc::clone(archive_io),
            entry.pack_offset + entry.unpack_offset,
            entry.size,
        );
        return pack.as_bytes().map_err(SzError::Seven);
    }
    let pack = SeekPackSource::new(Arc::clone(archive_io), entry.pack_offset, entry.pack_size);
    let packed = pack.as_bytes().map_err(SzError::Seven)?;
    let sizes = pack_stream_sizes(archive, entry);
    let data = decode::decompress_folder_source(
        folder,
        Box::new(decode::BytesPackSource::new(packed)),
        password,
        sizes.as_deref(),
    )?;
    let end = (entry.unpack_offset + entry.size) as usize;
    if end > data.len() {
        return Err(SzError::Msg("member slice exceeds folder".into()));
    }
    Ok(data[entry.unpack_offset as usize..end].to_vec())
}

fn ensure_parent_dirs(
    batch: &mut FileRowSoa,
    path: &str,
    generated: &mut std::collections::BTreeSet<String>,
    mtime: f64,
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
        batch.push(
            &parent,
            part,
            0,
            0,
            0,
            mtime,
            (ratarmount_core::S_IFDIR | 0o755) as i64,
            0,
            "",
            0,
            0,
            false,
            false,
            true,
            0,
        );
    }
}

fn store_stats(index: &SqliteIndex, path: &Path) -> Result<()> {
    // Real on-disk archives: full fingerprint (size/mtime + edge/full SHA-256)
    // via shared index helper so warm reopen fails closed after in-place replace.
    if path.is_file() && index.store_tarstats_for_path(path).is_ok() {
        return Ok(());
    }
    // Nested / virtual labels have no host metadata — synthetic size-only stats.
    index.store_metadata_key_value("tarstats", "{\"st_size\":0,\"st_mtime\":0}")?;
    Ok(())
}

/// Hash regular-file members into index xattrs (`user.hash.<algo>`).
///
/// Unlike path-backed TAR `fill_content_hashes`, 7z payloads are not raw at
/// `offset` — members must be decoded (Copy stencil or folder decompress).
/// Uses the same `offsetheader` (= pack offset) as the files row / Python.
fn fill_member_content_hashes(
    index: &SqliteIndex,
    archive_io: &SharedArchiveIo,
    archive: &SevenZipArchiveInfo,
    password: Option<&str>,
    algorithms: &[String],
) -> Result<()> {
    let mut algos: Vec<String> = Vec::new();
    for raw in algorithms {
        let Some(name) = normalize_algorithm(raw) else {
            if !raw.trim().is_empty() {
                warn!("Unsupported hash algorithm: {raw}");
            }
            continue;
        };
        if !algos.iter().any(|a| a == name) {
            algos.push(name.to_string());
        }
    }
    if algos.is_empty() {
        return Ok(());
    }

    let mut pending: Vec<(i64, String, Vec<u8>)> = Vec::new();

    for (entry_index, entry) in archive.files.iter().enumerate() {
        if entry.is_dir || entry.is_empty_stream || entry.size == 0 {
            continue;
        }
        let mut mode = entry.mode;
        let ifmt = mode & ratarmount_core::S_IFMT;
        if ifmt == ratarmount_core::S_IFDIR || ifmt == ratarmount_core::S_IFLNK {
            continue;
        }
        if ifmt == 0 {
            mode = (mode & 0o777) | ratarmount_core::S_IFREG;
        }
        if (mode & ratarmount_core::S_IFMT) != ratarmount_core::S_IFREG {
            continue;
        }
        let Some(fi) = entry.folder_index else {
            continue;
        };
        let folder = match archive.folders.get(fi) {
            Some(f) => f,
            None => continue,
        };
        if folder.is_encrypted() && password.is_none() {
            continue;
        }
        let allow_enc = !folder.is_encrypted() || password.is_some();
        if !folder.is_supported_for_open(allow_enc) {
            warn!(
                "skipping content hash for unsupported 7z codecs: {}",
                entry.path
            );
            continue;
        }

        let header_offset = if entry.folder_index.is_some() {
            entry.pack_offset as i64
        } else {
            ((1u64 << 62) + entry_index as u64) as i64
        };

        let bytes = match read_member_bytes_io(archive_io, archive, entry, folder, password) {
            Ok(b) => b,
            Err(e) => {
                warn!(
                    "Failed to read 7z member {} for content hash: {e}",
                    entry.path
                );
                continue;
            }
        };
        let digests = match compute_hashes_limited(&mut Cursor::new(&bytes), entry.size, &algos) {
            Ok(d) => d,
            Err(e) => {
                warn!(
                    "Failed to hash 7z member {} (offsetheader={header_offset}): {e}",
                    entry.path
                );
                continue;
            }
        };
        for (name, hex) in digests {
            pending.push((header_offset, format!("user.hash.{name}"), hex.into_bytes()));
        }
        if pending.len() >= 256 {
            index.insert_xattrs_batch(&pending)?;
            pending.clear();
        }
    }
    if !pending.is_empty() {
        index.insert_xattrs_batch(&pending)?;
    }
    Ok(())
}

/// `offsetheader` used as the xattrs table key (Python interop / pack offset).
fn sz_offsetheader(file_info: &FileInfo) -> Option<i64> {
    file_info.userdata.iter().rev().find_map(|u| match u {
        UserData::Tar(t) => t.offsetheader.map(|v| v as i64),
        _ => None,
    })
}

impl MountSource for SevenZipMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        self.index.list(path).ok().flatten().map(ListResult::Infos)
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        self.index
            .list_mode(path)
            .ok()
            .flatten()
            .map(ListModeResult::Modes)
    }

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        self.index.list_dirents(path).ok().flatten().map(|rows| {
            rows.into_iter()
                .map(|d| CheapDirent {
                    name: d.name,
                    mode: d.mode,
                    size: d.size,
                })
                .collect()
        })
    }

    fn search_cheap(&self, pattern: &str) -> Option<Vec<CheapSearchHit>> {
        if pattern.starts_with("fts:") {
            return None;
        }
        self.index.search_cheap(pattern).ok()
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        self.index.lookup(path, file_version).ok().flatten()
    }

    fn open(
        &self,
        file_info: &FileInfo,
        _buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        debug!(
            "7z {}: open request size={} mode={:#x} content_locked={} has_password={}",
            self.archive_path.display(),
            file_info.size,
            file_info.mode,
            self.content_locked,
            self.password.is_some()
        );
        if file_info.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "is a directory",
            ));
        }
        if file_info.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFLNK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot read symlink contents",
            ));
        }
        if file_info.size == 0 {
            debug!(
                "7z {}: open empty member (size=0)",
                self.archive_path.display()
            );
            return Ok(Box::new(Cursor::new(Vec::new())));
        }

        let entry = self.find_entry(file_info).map_err(|e| {
            warn!(
                "7z {}: open find_entry failed: {e}",
                self.archive_path.display()
            );
            io::Error::other(e.to_string())
        })?;
        let fi = entry.folder_index.ok_or_else(|| {
            warn!(
                "7z {}: entry {} has no folder_index",
                self.archive_path.display(),
                entry.path
            );
            io::Error::other("no folder")
        })?;
        let folder = &self.archive.folders[fi];
        debug!(
            "7z {}: open path={} pack={} unpack={} size={} folder_idx={} copy_only={} encrypted={}",
            self.archive_path.display(),
            entry.path,
            entry.pack_offset,
            entry.unpack_offset,
            entry.size,
            fi,
            folder.is_copy_only(),
            folder.is_encrypted()
        );

        if folder.is_encrypted() && (self.content_locked || self.password.is_none()) {
            // PermissionDenied → FUSE EACCES (not generic EIO) so users know a password is needed.
            warn!(
                "7z {}: open {} denied — encrypted content locked (metadata-only); \
                 pass --password / --password-file (nested archives need the *inner* password)",
                self.archive_path.display(),
                entry.path
            );
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "password required to open encrypted 7z member; pass --password / --password-file",
            ));
        }

        let allow_enc = !folder.is_encrypted() || self.password.is_some();
        if !folder.is_supported_for_open(allow_enc) {
            let methods: Vec<_> = folder
                .coders
                .iter()
                .map(|c| format!("{:02x?}", c.method))
                .collect();
            warn!(
                "7z {}: open {} unsupported codecs {:?}",
                self.archive_path.display(),
                entry.path,
                methods
            );
            return Err(io::Error::other(format!(
                "Unsupported 7z codecs for {} ({methods:?})",
                entry.path
            )));
        }

        // Store / Copy: true random access via shared seekable view (path or nested).
        if folder.is_copy_only() && !folder.is_encrypted() {
            let offset = entry.pack_offset + entry.unpack_offset;
            debug!(
                "7z {}: open {} via SharedArchiveView base={offset} len={}",
                self.archive_path.display(),
                entry.path,
                entry.size
            );
            let view = SharedArchiveView::new(Arc::clone(&self.archive_io), offset, entry.size);
            return Ok(Box::new(view));
        }

        let content_coders = folder.content_coders();
        let encrypted_copy = folder.is_encrypted()
            && (content_coders.is_empty()
                || content_coders
                    .iter()
                    .all(|c| c.method.as_slice() == parse::METHOD_COPY));
        if encrypted_copy {
            let pack = SeekPackSource::new(
                Arc::clone(&self.archive_io),
                entry.pack_offset,
                entry.pack_size,
            );
            let (_content, content_pack) =
                make_pack_source(folder, Box::new(pack), self.password.as_deref()).map_err(
                    |e| {
                        warn!(
                            "7z {}: encrypted COPY make_pack_source failed for {}: {e}",
                            self.archive_path.display(),
                            entry.path
                        );
                        io::Error::other(e.to_string())
                    },
                )?;
            debug!(
                "7z {}: open {} via PackSourceReader (encrypted COPY, aes=true)",
                self.archive_path.display(),
                entry.path
            );
            let reader = PackSourceReader::new(content_pack, entry.unpack_offset, entry.size);
            return Ok(Box::new(reader));
        }

        // LZMA2 / AES+LZMA2 / native BCJ|Delta+LZMA2: small folders → Cursor;
        // large → Lzma2MemberReader with a live sequential cursor. AES is
        // input-side (independent-chunk resume OK). BCJ/Delta disable dict-reset
        // resume.
        let sizes = self.pack_stream_sizes_for(entry);
        if lzma2_folder_can_use_decoder(folder) && sizes.is_none() {
            let folder_unpack = folder.get_unpack_size();
            let has_aes = folder.is_encrypted();
            let filter = content_filter_label(content_coders);
            if lzma2_folder_uses_progressive(folder, folder_unpack) {
                debug!(
                    "7z {}: open {} via Lzma2MemberReader (folder_unpack={folder_unpack}, aes={has_aes}, filter={filter})",
                    self.archive_path.display(),
                    entry.path
                );
                let reader = self.open_lzma2_member_reader(entry).map_err(|e| {
                    warn!(
                        "7z {}: Lzma2MemberReader open failed for {}: {e}",
                        self.archive_path.display(),
                        entry.path
                    );
                    io::Error::other(e.to_string())
                })?;
                return Ok(Box::new(reader));
            }
            debug!(
                "7z {}: open {} via LZMA2 full-member Cursor (folder_unpack={folder_unpack}, aes={has_aes}, filter={filter})",
                self.archive_path.display(),
                entry.path
            );
            let data = self.open_lzma2_member(entry).map_err(|e| {
                warn!(
                    "7z {}: LZMA2 member decode failed for {}: {e}",
                    self.archive_path.display(),
                    entry.path
                );
                io::Error::other(e.to_string())
            })?;
            return Ok(Box::new(Cursor::new(data)));
        }

        // BCJ2 / multi-pack / Deflate / BZip2: full-folder decompress + slice (cached).
        // Pack is read via SeekPackSource (shared archive IO — nested-safe).
        debug!(
            "7z {}: open {} via full-folder decompress + slice",
            self.archive_path.display(),
            entry.path
        );
        let folder_data = self.get_folder_bytes(entry).map_err(|e| {
            warn!(
                "7z {}: get_folder_bytes failed for {}: {e}",
                self.archive_path.display(),
                entry.path
            );
            io::Error::other(e.to_string())
        })?;
        let start = entry.unpack_offset as usize;
        let end = start + entry.size as usize;
        if end > folder_data.len() {
            warn!(
                "7z {}: member slice [{start}:{end}] exceeds folder len {}",
                self.archive_path.display(),
                folder_data.len()
            );
            return Err(io::Error::other(format!(
                "Member slice [{start}:{end}] exceeds folder {}",
                folder_data.len()
            )));
        }
        Ok(Box::new(Cursor::new(folder_data[start..end].to_vec())))
    }

    fn is_immutable(&self) -> bool {
        true
    }

    fn member_seek_is_cheap(&self, file_info: &FileInfo) -> bool {
        !self.member_open_is_progressive(file_info)
    }

    /// Xattr keys stored in the SQLite index (Python `user.hash.<algo>` content hashes).
    fn list_xattr(&self, file_info: &FileInfo) -> Vec<String> {
        let Some(oh) = sz_offsetheader(file_info) else {
            return Vec::new();
        };
        self.index.list_xattr_keys(oh).unwrap_or_default()
    }

    /// One xattr value from the index (e.g. hex digest for `user.hash.sha256`).
    fn get_xattr(&self, file_info: &FileInfo, key: &str) -> Option<Vec<u8>> {
        let oh = sz_offsetheader(file_info)?;
        self.index.get_xattr(oh, key).ok().flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratarmount_index::hash_hex;

    fn py_fixture(name: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        PathBuf::from(root).join("tests").join(name)
    }

    fn synthetic_offset_entry(
        path: &str,
        pack: u64,
        unpack: u64,
        is_dir: bool,
        is_empty_stream: bool,
    ) -> SevenZipFileEntry {
        SevenZipFileEntry {
            path: path.into(),
            size: if is_dir || is_empty_stream { 0 } else { 8 },
            mtime: 0.0,
            mode: if is_dir { 0o040755 } else { 0o100644 },
            is_dir,
            is_empty_stream,
            is_empty_file: is_empty_stream,
            folder_index: if is_dir || is_empty_stream {
                None
            } else {
                Some(0)
            },
            unpack_offset: unpack,
            pack_offset: pack,
            pack_size: 8,
            pack_stream_index: 0,
            crc: None,
        }
    }

    /// Unit: shipped offset table is sorted binary-search (not HashMap-only).
    #[test]
    fn entry_offset_table_finds_unsorted_inserts_and_rejects_missing() {
        // Unsorted insert order (high pack first) plus dirs/empty streams that
        // must not appear in the table. Last of a duplicate key wins.
        let mut files = vec![
            synthetic_offset_entry("dir", 0, 0, true, false),
            synthetic_offset_entry("empty", 1, 0, false, true),
        ];
        let mut expected: Vec<((u64, u64), usize)> = Vec::new();
        // 80 members, reverse pack order so construction is unsorted.
        for n in (0u64..80).rev() {
            let pack = n.wrapping_mul(4099).wrapping_add(17);
            let unpack = (79 - n).wrapping_mul(8);
            let path = format!("m{n:02}");
            files.push(synthetic_offset_entry(&path, pack, unpack, false, false));
            expected.push(((pack, unpack), files.len() - 1));
        }
        // Duplicate key: last insert overwrites (HashMap parity).
        files.push(synthetic_offset_entry(
            "dup-first",
            999_999,
            7,
            false,
            false,
        ));
        let dup_first_idx = files.len() - 1;
        files.push(synthetic_offset_entry("dup-last", 999_999, 7, false, false));
        let dup_last_idx = files.len() - 1;

        let archive = SevenZipArchiveInfo {
            after_header: 32,
            pack_pos_base: 32,
            folders: vec![],
            pack_info: None,
            files,
            solid: false,
        };
        let table = entry_offset_map(&archive);
        assert!(
            table.entry_offset_table_is_sorted(),
            "shipped EntryOffsetTable keys must be sorted for binary search"
        );
        assert_eq!(
            table.len(),
            expected.len() + 1,
            "dirs/empty skipped; dup collapsed"
        );
        for (key, idx) in &expected {
            assert_eq!(
                table.get(key.0, key.1),
                Some(*idx),
                "get({key:?}) must return file index {idx}"
            );
        }
        assert_eq!(
            table.get(999_999, 7),
            Some(dup_last_idx),
            "duplicate key must keep last insert, not {dup_first_idx}"
        );
        assert_eq!(table.get(u64::MAX, 0), None);
        assert_eq!(table.get(0, u64::MAX), None);
        assert_eq!(table.get(1, 2), None);
        // Direct constructor (same type as production), shuffled pairs.
        let shuffled = {
            let mut p = expected.clone();
            p.reverse();
            p.push(((3, 1), 1234));
            p.push(((3, 0), 99));
            p
        };
        let from_pairs = EntryOffsetTable::from_unsorted_pairs(shuffled);
        assert!(from_pairs.entry_offset_table_is_sorted());
        assert_eq!(from_pairs.get(3, 1), Some(1234));
        assert_eq!(from_pairs.get(3, 0), Some(99));
        assert_eq!(from_pairs.get(4, 0), None);
        for (key, idx) in &expected {
            assert_eq!(from_pairs.get(key.0, key.1), Some(*idx));
        }
    }

    /// Regression: multi-member 7z list + random open via sorted offset table.
    #[test]
    fn regression_multi_member_list_and_random_open_via_offset_table() {
        let dir = tempfile::tempdir().unwrap();
        let sevenz = ["7z", "7za"]
            .into_iter()
            .find(|c| std::process::Command::new(c).arg("--help").output().is_ok());
        let Some(sevenz) = sevenz else {
            eprintln!("skip: 7z/7za unavailable for multi-member offset-table fixture");
            return;
        };

        const N: usize = 32;
        let mut expected: Vec<(String, Vec<u8>)> = Vec::with_capacity(N);
        for i in 0..N {
            let name = format!("f{i:02}.txt");
            let body = format!("member-{i}-payload\n").into_bytes();
            std::fs::write(dir.path().join(&name), &body).unwrap();
            expected.push((format!("/{name}"), body));
        }
        let archive = dir.path().join("multi-offset.7z");
        let mut cmd = std::process::Command::new(sevenz);
        cmd.args(["a", "-t7z", "-m0=Copy", "-ms=off"])
            .arg(&archive)
            .current_dir(dir.path());
        for i in 0..N {
            cmd.arg(format!("f{i:02}.txt"));
        }
        let out = cmd.output().expect("run 7z");
        if !out.status.success() || !archive.exists() {
            eprintln!(
                "skip: 7z create failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }

        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let m = SevenZipMountSource::open(&archive, None, &opts, "0.1.0", true)
            .expect("open multi-member 7z");
        assert!(
            m.entry_offset_table_is_sorted(),
            "live mount offset table must stay sorted"
        );
        assert!(
            m.entry_by_offsets.len() >= N,
            "offset table must index all store members, got {}",
            m.entry_by_offsets.len()
        );

        let dirents = m.list_dirents("/").expect("cheap list_dirents");
        assert_eq!(dirents.len(), N, "list_dirents must cover all members");
        for (path, body) in &expected {
            let base = path.trim_start_matches('/');
            let d = dirents
                .iter()
                .find(|e| e.name == base || e.name == *path)
                .unwrap_or_else(|| panic!("dirent missing {base}"));
            assert_eq!(d.size, body.len() as u64, "dirent size {base}");
        }

        let names: Vec<String> = match m.list("/") {
            Some(ListResult::Infos(infos)) => infos.keys().cloned().collect(),
            other => panic!("expected Infos list, got {other:?}"),
        };
        for (path, _) in &expected {
            let base = path.trim_start_matches('/');
            assert!(
                names
                    .iter()
                    .any(|n| n == base || n == path || n.ends_with(base)),
                "list(\"/\") missing {base}, have {names:?}"
            );
        }

        let sample = [0usize, 1, N / 2, N - 2, N - 1];
        for &i in &sample {
            let (path, body) = &expected[i];
            let fi = m.lookup(path, 0).unwrap_or_else(|| {
                panic!("lookup {path}");
            });
            let mut r = m
                .open(&fi, 0)
                .unwrap_or_else(|e| panic!("open {path}: {e}"));
            let mut got = Vec::new();
            r.read_to_end(&mut got).unwrap();
            assert_eq!(&got, body, "random open {path} must match stored bytes");
        }
    }

    #[test]
    fn store_copy_two_files() {
        let path = py_fixture("store-copy-two-files.7z");
        if !path.exists() {
            eprintln!("skip missing {}", path.display());
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("i.sqlite");
        let opts = OpenOptions::default();
        let m = SevenZipMountSource::open(&path, Some(&idx), &opts, "0.1.0", true).unwrap();
        let fi = m.lookup("/a.txt", 0).expect("a.txt");
        let mut r = m.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert!(!s.is_empty());
        let fi2 = m.lookup("/b.txt", 0).expect("b.txt");
        assert!(fi2.size > 0);
        assert!(
            m.member_seek_is_cheap(&fi2),
            "store/copy members are cheap to seek"
        );
    }

    #[test]
    fn regression_lzma2_progressive_helper_and_store_not_progressive() {
        use crate::parse::{
            Folder, METHOD_AES, METHOD_BCJ, METHOD_BCJ2, METHOD_COPY, METHOD_LZMA2,
        };
        let small = Folder {
            coders: vec![parse::Coder {
                method: METHOD_LZMA2.to_vec(),
                num_in_streams: 1,
                num_out_streams: 1,
                properties: Some(vec![22]),
            }],
            bind_pairs: vec![],
            packed_indices: vec![],
            unpack_sizes: vec![1024],
            has_crc: false,
            crc: 0,
        };
        assert!(!lzma2_folder_uses_progressive(&small, 1024));
        let large_unpack = decode::SMALL_FOLDER_FULL_CACHE + 1;
        assert!(lzma2_folder_uses_progressive(&small, large_unpack));

        let copy = Folder {
            coders: vec![parse::Coder {
                method: METHOD_COPY.to_vec(),
                num_in_streams: 1,
                num_out_streams: 1,
                properties: None,
            }],
            bind_pairs: vec![],
            packed_indices: vec![],
            unpack_sizes: vec![large_unpack],
            has_crc: false,
            crc: 0,
        };
        assert!(!lzma2_folder_uses_progressive(&copy, large_unpack));
        assert!(!lzma2_folder_can_use_decoder(&copy));

        let aes_lzma2 = Folder {
            coders: vec![
                parse::Coder {
                    method: METHOD_AES.to_vec(),
                    num_in_streams: 1,
                    num_out_streams: 1,
                    properties: None,
                },
                parse::Coder {
                    method: METHOD_LZMA2.to_vec(),
                    num_in_streams: 1,
                    num_out_streams: 1,
                    properties: Some(vec![22]),
                },
            ],
            bind_pairs: vec![],
            packed_indices: vec![],
            unpack_sizes: vec![16, large_unpack],
            has_crc: false,
            crc: 0,
        };
        assert!(lzma2_folder_uses_progressive(&aes_lzma2, large_unpack));

        let bcj_lzma2 = Folder {
            coders: vec![
                parse::Coder {
                    method: METHOD_BCJ.to_vec(),
                    num_in_streams: 1,
                    num_out_streams: 1,
                    properties: None,
                },
                parse::Coder {
                    method: METHOD_LZMA2.to_vec(),
                    num_in_streams: 1,
                    num_out_streams: 1,
                    properties: Some(vec![22]),
                },
            ],
            bind_pairs: vec![],
            packed_indices: vec![],
            unpack_sizes: vec![large_unpack],
            has_crc: false,
            crc: 0,
        };
        assert!(lzma2_folder_uses_progressive(&bcj_lzma2, large_unpack));

        let bcj2 = Folder {
            coders: vec![parse::Coder {
                method: METHOD_BCJ2.to_vec(),
                num_in_streams: 4,
                num_out_streams: 1,
                properties: None,
            }],
            bind_pairs: vec![],
            packed_indices: vec![0, 1, 2, 3],
            unpack_sizes: vec![large_unpack],
            has_crc: false,
            crc: 0,
        };
        assert!(!lzma2_folder_uses_progressive(&bcj2, large_unpack));
        assert!(!lzma2_folder_can_use_decoder(&bcj2));
    }

    #[test]
    fn lzma2_two_files() {
        let path = py_fixture("lzma2-two-files-and-medium.7z");
        if !path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("i.sqlite");
        let m =
            SevenZipMountSource::open(&path, Some(&idx), &OpenOptions::default(), "0.1.0", true)
                .unwrap();
        let fi = m.lookup("/a.txt", 0).expect("a.txt");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf.len(), fi.size as usize);
        // Random mid-member read should match full open (LZMA2 chunk path).
        let med = m.lookup("/medium.bin", 0).expect("medium");
        assert_eq!(med.size, 2097152);
        let mut r = m.open(&med, 0).unwrap();
        let mut full = Vec::new();
        r.read_to_end(&mut full).unwrap();
        assert_eq!(full.len(), 2097152);
        // Second open uses packed cache + chunk index.
        let mut r2 = m.open(&med, 0).unwrap();
        let mut again = Vec::new();
        r2.read_to_end(&mut again).unwrap();
        assert_eq!(full, again);
        let mut r = m.open(&med, 0).unwrap();
        let mut one = [0u8; 1];
        r.read_exact(&mut one).unwrap();
    }

    /// Shipped path open: encrypted 7z with correct password returns member bytes.
    #[test]
    fn encrypted_hello() {
        let dir = tempfile::tempdir().unwrap();
        let (path, expected) = match ensure_encrypted_hello_fixture(dir.path()) {
            Some(v) => v,
            None => {
                eprintln!("skip: no encrypted-hello.7z fixture and cannot create with 7z CLI");
                return;
            }
        };
        let idx = dir.path().join("i.sqlite");
        let opts = OpenOptions {
            passwords: vec!["secret".into()],
            ..OpenOptions::default()
        };
        let m = SevenZipMountSource::open(&path, Some(&idx), &opts, "0.1.0", true)
            .expect("open encrypted with password");
        let fi = m.lookup("/secret.txt", 0).expect("secret.txt list/lookup");
        let mut r = m.open(&fi, 0).expect("open member with password");
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(
            got, expected,
            "password path must return exact member bytes on shipped open"
        );
    }

    /// Shipped path: no password → metadata list/stat OK; member open = PermissionDenied (EACCES).
    #[test]
    fn encrypted_metadata_only_without_password() {
        let dir = tempfile::tempdir().unwrap();
        let (path, expected) = match ensure_encrypted_hello_fixture(dir.path()) {
            Some(v) => v,
            None => {
                eprintln!("skip: no encrypted-hello.7z fixture and cannot create with 7z CLI");
                return;
            }
        };
        let idx = dir.path().join("i.sqlite");
        let m =
            SevenZipMountSource::open(&path, Some(&idx), &OpenOptions::default(), "0.1.0", true)
                .expect("metadata-only mount must succeed without password");
        let fi = m
            .lookup("/secret.txt", 0)
            .expect("list/stat works without password");
        assert_eq!(fi.size, expected.len() as u64);
        // List root must include the member (metadata-only).
        match m.list("/") {
            Some(ListResult::Infos(infos)) => {
                assert!(
                    infos.keys().any(|k| k.contains("secret")),
                    "list must show encrypted member names"
                );
            }
            other => panic!("expected Infos list, got {other:?}"),
        }
        let err = match m.open(&fi, 0) {
            Ok(_) => panic!("open must fail when content-locked"),
            Err(e) => e,
        };
        assert_eq!(
            err.kind(),
            io::ErrorKind::PermissionDenied,
            "content-locked open must be PermissionDenied (FUSE EACCES), got {err}"
        );
        let msg = err.to_string().to_ascii_lowercase();
        assert!(
            msg.contains("password"),
            "error should mention password: {msg}"
        );
    }

    /// Nested reader path: encrypted body without password is content-locked (PermissionDenied).
    #[test]
    fn encrypted_open_from_reader_metadata_only_and_password() {
        let dir = tempfile::tempdir().unwrap();
        let (path, expected) = match ensure_encrypted_hello_fixture(dir.path()) {
            Some(v) => v,
            None => {
                eprintln!("skip: no encrypted fixture");
                return;
            }
        };
        let bytes = std::fs::read(&path).unwrap();
        let opts_locked = OpenOptions {
            index_compact_only: true,
            ..OpenOptions::default()
        };
        let locked = SevenZipMountSource::open_from_reader(
            Cursor::new(bytes.clone()),
            Path::new("nested://encrypted.7z"),
            None,
            &opts_locked,
            "0.1.0",
            true,
        )
        .expect("nested metadata-only open_from_reader");
        let fi = locked.lookup("/secret.txt", 0).expect("lookup nested");
        let err = match locked.open(&fi, 0) {
            Ok(_) => panic!("nested content-locked open must fail"),
            Err(e) => e,
        };
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);

        let opts_pw = OpenOptions {
            index_compact_only: true,
            passwords: vec!["secret".into()],
            ..OpenOptions::default()
        };
        let unlocked = SevenZipMountSource::open_from_reader(
            Cursor::new(bytes),
            Path::new("nested://encrypted.7z"),
            None,
            &opts_pw,
            "0.1.0",
            true,
        )
        .expect("nested open_from_reader with password");
        let fi2 = unlocked.lookup("/secret.txt", 0).unwrap();
        let mut got = Vec::new();
        unlocked
            .open(&fi2, 0)
            .unwrap()
            .read_to_end(&mut got)
            .unwrap();
        assert_eq!(got, expected);
    }

    /// Wrong password fails closed at mount open (not silent metadata-only success).
    ///
    /// Regression: macOS Homebrew p7zip can emit store+AES without a folder CRC;
    /// a length-only trial then accepted garbage. The vendored fixture is
    /// LZMA2+AES; file-level CRC is also checked when folder CRC is absent.
    #[test]
    fn encrypted_wrong_password_fails_open() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = match ensure_encrypted_hello_fixture(dir.path()) {
            Some(v) => v,
            None => {
                eprintln!("skip: no encrypted fixture");
                return;
            }
        };
        let opts = OpenOptions {
            passwords: vec!["not-the-password".into()],
            ..OpenOptions::default()
        };
        let err = SevenZipMountSource::open(&path, None, &opts, "0.1.0", true)
            .err()
            .expect("wrong password must fail mount open");
        // Decoder may surface as lzma/AES error rather than a polished password string;
        // fail-closed (no metadata-only success) is the contract.
        let msg = err.to_string();
        assert!(
            !msg.is_empty(),
            "wrong password must produce an error (got empty)"
        );
    }

    /// Regression: store+AES (no LZMA2) still fail-closes on a wrong password via
    /// file CRC — Homebrew p7zip `-m0=LZMA2` can silently fall back to Copy.
    #[test]
    fn encrypted_store_aes_wrong_password_fails_open() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("store-aes.7z");
        if !write_encrypted_sample_7z_mx(&archive, "secret.txt", b"secret content\n", "secret", 0) {
            eprintln!("skip: 7z CLI could not create store+AES fixture");
            return;
        }
        let opts = OpenOptions {
            passwords: vec!["not-the-password".into()],
            ..OpenOptions::default()
        };
        SevenZipMountSource::open(&archive, None, &opts, "0.1.0", true)
            .err()
            .expect("Regression: store+AES wrong password must fail mount open");
    }

    /// Regression: a sibling index from a prior open must not skip the password trial.
    #[test]
    fn encrypted_wrong_password_fails_warm_index_open() {
        let dir = tempfile::tempdir().unwrap();
        let (path, _) = match ensure_encrypted_hello_fixture(dir.path()) {
            Some(v) => v,
            None => {
                eprintln!("skip: no encrypted fixture");
                return;
            }
        };
        let idx = dir.path().join("warm.sqlite");
        let good = OpenOptions {
            passwords: vec!["secret".into()],
            ..OpenOptions::default()
        };
        SevenZipMountSource::open(&path, Some(&idx), &good, "0.1.0", true)
            .expect("correct password must create a warm index");
        assert!(idx.is_file(), "index sidecar");
        let bad = OpenOptions {
            passwords: vec!["not-the-password".into()],
            ..OpenOptions::default()
        };
        SevenZipMountSource::open(&path, Some(&idx), &bad, "0.1.0", false)
            .err()
            .expect("Regression: warm index + wrong password must fail open");
    }

    #[test]
    fn bcj2_default_fixture() {
        let path = py_fixture("bcj2-default.7z");
        if !path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("i.sqlite");
        let m =
            SevenZipMountSource::open(&path, Some(&idx), &OpenOptions::default(), "0.1.0", true)
                .expect("open bcj2");
        // bcj2-x.bin is the typical payload name in the fixture set.
        let fi = m
            .lookup("/bcj2-x.bin", 0)
            .or_else(|| {
                if let Some(ListResult::Infos(infos)) = m.list("/") {
                    infos.into_iter().find(|(_, i)| i.size > 0).map(|(_, i)| i)
                } else {
                    None
                }
            })
            .expect("bcj2 member");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert!(!buf.is_empty());
    }

    /// Regression: AES+LZMA2 solid > 4 MiB uses Lzma2MemberReader (not full-folder cache).
    #[test]
    fn regression_aes_lzma2_solid_uses_member_reader_not_folder_cache() {
        let dir = tempfile::tempdir().unwrap();
        let sevenz = ["7zz", "7z", "7za"]
            .into_iter()
            .find(|c| std::process::Command::new(c).arg("--help").output().is_ok());
        let Some(sevenz) = sevenz else {
            eprintln!("skip: 7z CLI unavailable for AES+LZMA2 solid fixture");
            return;
        };

        let a_len = 3 * 1024 * 1024;
        let b_len = 2 * 1024 * 1024;
        let payload_a: Vec<u8> = (0..a_len)
            .map(|i| ((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 56) as u8)
            .collect();
        let payload_b: Vec<u8> = (0..b_len)
            .map(|i| ((i as u32).wrapping_mul(1664525).wrapping_add(1013904223) >> 24) as u8)
            .collect();
        std::fs::write(dir.path().join("a.bin"), &payload_a).unwrap();
        std::fs::write(dir.path().join("b.bin"), &payload_b).unwrap();
        let archive = dir.path().join("aes-lzma2-solid.7z");
        let out = std::process::Command::new(sevenz)
            .args([
                "a",
                "-t7z",
                "-m0=LZMA2",
                "-mx=1",
                "-ms=on",
                "-psecret",
                "-mhe=off",
            ])
            .arg(&archive)
            .arg("a.bin")
            .arg("b.bin")
            .current_dir(dir.path())
            .output()
            .expect("run 7z");
        if !out.status.success() || !archive.exists() {
            eprintln!(
                "skip: 7z AES+LZMA2 create failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }

        let bad = OpenOptions {
            passwords: vec!["not-the-password".into()],
            index_in_memory: true,
            ..OpenOptions::default()
        };
        SevenZipMountSource::open(&archive, None, &bad, "0.1.0", true)
            .err()
            .expect("Regression: AES+LZMA2 solid wrong password must fail mount trial");

        let opts = OpenOptions {
            passwords: vec!["secret".into()],
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let m = SevenZipMountSource::open(&archive, None, &opts, "0.1.0", true)
            .expect("open AES+LZMA2 solid");
        let fi_b = m
            .lookup("/b.bin", 0)
            .or_else(|| m.lookup("b.bin", 0))
            .expect("b.bin");
        assert!(
            !m.member_seek_is_cheap(&fi_b),
            "AES+LZMA2 folder > 4 MiB must use progressive Lzma2MemberReader"
        );
        let mut r = m.open(&fi_b, 0).expect("open second member");
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, payload_b, "AES+LZMA2 second member must cmp");
        assert_eq!(
            m.test_folder_cache_max_len(),
            0,
            "progressive path must not put a full unpack in folder_cache"
        );

        let fi_a = m
            .lookup("/a.bin", 0)
            .or_else(|| m.lookup("a.bin", 0))
            .expect("a.bin");
        let mut r = m.open(&fi_a, 0).expect("open first member");
        r.seek(SeekFrom::Start(100)).unwrap();
        let mut mid = [0u8; 64];
        r.read_exact(&mut mid).unwrap();
        assert_eq!(&mid, &payload_a[100..164]);
        assert_eq!(m.test_folder_cache_max_len(), 0);
    }

    /// Regression: encrypted COPY mid-member range via PackSourceReader
    /// (not SharedArchiveView on ciphertext; not folder_cache).
    #[test]
    fn regression_encrypted_copy_mid_member_pack_source_reader() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("store-aes-mid.7z");
        let payload: Vec<u8> = (0..32 * 1024).map(|i| (i % 251) as u8).collect();
        if !write_encrypted_sample_7z_mx(&archive, "blob.bin", &payload, "secret", 0) {
            eprintln!("skip: 7z CLI could not create store+AES fixture");
            return;
        }
        let opts = OpenOptions {
            passwords: vec!["secret".into()],
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let m = SevenZipMountSource::open(&archive, None, &opts, "0.1.0", true)
            .expect("open store+AES");
        let fi = m
            .lookup("/blob.bin", 0)
            .or_else(|| m.lookup("blob.bin", 0))
            .expect("blob.bin");
        let mut r = m.open(&fi, 0).expect("open encrypted COPY member");
        r.seek(SeekFrom::Start(1000)).unwrap();
        let mut mid = [0u8; 128];
        r.read_exact(&mut mid).unwrap();
        assert_eq!(&mid, &payload[1000..1128], "mid-member range must cmp");
        r.seek(SeekFrom::Start(0)).unwrap();
        let mut all = Vec::new();
        r.read_to_end(&mut all).unwrap();
        assert_eq!(all, payload);
        assert_eq!(
            m.test_folder_cache_max_len(),
            0,
            "encrypted COPY must not fill folder_cache"
        );
    }

    fn extract_7z_member_stdout(archive: &Path, member: &str) -> Option<Vec<u8>> {
        let archive_s = archive.to_str()?;
        for bin in ["7zz", "7z", "7za"] {
            let out = std::process::Command::new(bin)
                .args(["x", "-so", archive_s, member])
                .output()
                .ok()?;
            if out.status.success() && !out.stdout.is_empty() {
                return Some(out.stdout);
            }
        }
        None
    }

    #[test]
    fn bcj_lzma2_fixture() {
        let path = py_fixture("bcj-lzma2-x86.7z");
        if !path.exists() {
            eprintln!("skip missing {}", path.display());
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("i.sqlite");
        let m =
            SevenZipMountSource::open(&path, Some(&idx), &OpenOptions::default(), "0.1.0", true)
                .expect("open bcj+lzma2");
        let Some(ListResult::Infos(infos)) = m.list("/") else {
            panic!("expected Infos list");
        };
        let Some((name, fi)) = infos.into_iter().find(|(_, i)| i.size > 0) else {
            panic!("bcj+lzma2 fixture has no non-empty member");
        };
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf.len(), fi.size as usize);
        let member = name.trim_start_matches('/');
        if let Some(expected) = extract_7z_member_stdout(&path, member) {
            assert_eq!(
                buf, expected,
                "bcj-lzma2-x86.7z member {member} must cmp 7z x -so"
            );
        } else {
            eprintln!("skip: 7z x -so unavailable to cmp {}", path.display());
        }
    }

    /// Regression: `7z a -m0=BCJ -m1=LZMA2` late member cmps; no dict-reset resume.
    #[test]
    fn regression_bcj_lzma2_cli_solid_sequential_from_zero() {
        let dir = tempfile::tempdir().unwrap();
        let sevenz = ["7zz", "7z", "7za"]
            .into_iter()
            .find(|c| std::process::Command::new(c).arg("--help").output().is_ok());
        let Some(sevenz) = sevenz else {
            eprintln!("skip: 7z CLI unavailable for BCJ+LZMA2 solid fixture");
            return;
        };

        let a_len = 3 * 1024 * 1024;
        let b_len = 2 * 1024 * 1024;
        let payload_a: Vec<u8> = (0..a_len)
            .map(|i| ((i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 56) as u8)
            .collect();
        let payload_b: Vec<u8> = (0..b_len)
            .map(|i| ((i as u32).wrapping_mul(1664525).wrapping_add(1013904223) >> 24) as u8)
            .collect();
        std::fs::write(dir.path().join("a.bin"), &payload_a).unwrap();
        std::fs::write(dir.path().join("b.bin"), &payload_b).unwrap();
        let archive = dir.path().join("bcj-lzma2-solid.7z");
        let out = std::process::Command::new(sevenz)
            .args(["a", "-t7z", "-m0=BCJ", "-m1=LZMA2", "-mx=1", "-ms=on"])
            .arg(&archive)
            .arg("a.bin")
            .arg("b.bin")
            .current_dir(dir.path())
            .output()
            .expect("run 7z");
        if !out.status.success() || !archive.exists() {
            eprintln!(
                "skip: 7z BCJ+LZMA2 create failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }

        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let m = SevenZipMountSource::open(&archive, None, &opts, "0.1.0", true)
            .expect("open BCJ+LZMA2 solid");
        let fi_b = m
            .lookup("/b.bin", 0)
            .or_else(|| m.lookup("b.bin", 0))
            .expect("b.bin");
        let entry_b = m.find_entry(&fi_b).expect("entry b.bin");
        let folder = &m.archive.folders[entry_b.folder_index.expect("folder")];
        let has_bcj = folder.content_coders().iter().any(|c| {
            let mth = c.method.as_slice();
            mth == parse::METHOD_BCJ || mth == parse::METHOD_BCJ_X86
        });
        if !has_bcj {
            eprintln!(
                "skip: 7z did not emit a BCJ coder chain ({:?})",
                folder
                    .coders
                    .iter()
                    .map(|c| format!("{:02x?}", c.method))
                    .collect::<Vec<_>>()
            );
            return;
        }
        assert!(
            !m.member_seek_is_cheap(&fi_b),
            "BCJ+LZMA2 folder > 4 MiB must use progressive Lzma2MemberReader"
        );
        let mut r = m.open(&fi_b, 0).expect("open second member");
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, payload_b, "BCJ+LZMA2 second member must cmp");
        assert_eq!(
            m.test_last_resume_unpacked(&fi_b),
            Some(0),
            "BCJ must not independent-chunk resume"
        );
        assert_eq!(
            m.test_folder_cache_max_len(),
            0,
            "progressive path must not put a full unpack in folder_cache"
        );
    }

    /// Nested compact-only 7z: no SQLite files table; list/open; Arc::ptr_eq path pool.
    #[test]
    fn open_from_reader_compact_only_list_and_read() {
        let path = py_fixture("store-copy-two-files.7z");
        if !path.exists() {
            eprintln!("skip: missing fixture {}", path.display());
            return;
        }
        let bytes = std::fs::read(&path).unwrap();
        let opts = OpenOptions {
            index_compact_only: true,
            ..OpenOptions::default()
        };
        let src = SevenZipMountSource::open_from_reader(
            Cursor::new(bytes),
            Path::new("nested://store.7z"),
            None,
            &opts,
            "0.1.0",
            true,
        )
        .expect("compact open_from_reader");
        assert!(src.index_is_compact_only());
        let fi = src.lookup("/a.txt", 0).expect("lookup a.txt");
        let mut buf = Vec::new();
        src.open(&fi, 0).unwrap().read_to_end(&mut buf).unwrap();
        assert!(!buf.is_empty());
        // Every non-empty entry path must share the compact pool Arc.
        let mut shared = 0usize;
        for i in 0..src.archive.files.len() {
            let p = src.archive.files[i].path.as_ref();
            if p.is_empty() {
                continue;
            }
            assert!(
                src.entry_path_shares_pool(i),
                "7z entry path {p:?} must Arc::ptr_eq compact pool (not independent String heap)"
            );
            shared += 1;
        }
        assert!(shared >= 1, "expected at least one shared path");
    }

    #[test]
    fn open_from_reader_cursor_equals_path() {
        let path = py_fixture("store-copy-two-files.7z");
        if !path.exists() {
            return;
        }
        let bytes = std::fs::read(&path).unwrap();
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let from_path =
            SevenZipMountSource::open(&path, None, &opts, "0.1.0", true).expect("path open");
        let from_reader = SevenZipMountSource::open_from_reader(
            Cursor::new(bytes),
            Path::new("virtual/store.7z"),
            None,
            &opts,
            "0.1.0",
            true,
        )
        .expect("reader open");
        let fi_p = from_path.lookup("/a.txt", 0).expect("path a.txt");
        let fi_r = from_reader.lookup("/a.txt", 0).expect("reader a.txt");
        assert_eq!(fi_p.size, fi_r.size);
        let mut bp = Vec::new();
        let mut br = Vec::new();
        from_path
            .open(&fi_p, 0)
            .unwrap()
            .read_to_end(&mut bp)
            .unwrap();
        from_reader
            .open(&fi_r, 0)
            .unwrap()
            .read_to_end(&mut br)
            .unwrap();
        assert_eq!(bp, br);
        // Mid-member seek on reader-backed store.
        let mut r = from_reader.open(&fi_r, 0).unwrap();
        r.seek(SeekFrom::Start(1)).unwrap();
        let mut mid = Vec::new();
        r.read_to_end(&mut mid).unwrap();
        assert_eq!(mid.as_slice(), &bp[1..]);
    }

    #[test]
    fn nested_inner_hello_via_outer_member_reader() {
        // Outer archive holds an inner 7z; open the member as a seekable stream
        // without writing it to a temp file, then open the nested 7z from that stream.
        // Fixture is store/Copy (non-solid); see solid_outer_nested_via_member_reader.
        let path = py_fixture("nested-inner-hello.7z");
        if !path.exists() {
            return;
        }
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let outer =
            SevenZipMountSource::open(&path, None, &opts, "0.1.0", true).expect("outer open");
        // Find the nested .7z member (typically /inner-hello.7z).
        let nested_fi = outer
            .lookup("/inner-hello.7z", 0)
            .or_else(|| {
                if let Some(ListResult::Infos(infos)) = outer.list("/") {
                    infos
                        .into_iter()
                        .find(|(n, _)| n.ends_with(".7z"))
                        .map(|(_, i)| i)
                } else {
                    None
                }
            })
            .expect("inner 7z member");
        // Parent open returns ArchiveRead (Seek) — no temp spool.
        let nested_reader = outer
            .open(&nested_fi, 0)
            .expect("open nested member stream");
        let inner = SevenZipMountSource::open_from_reader(
            nested_reader,
            Path::new("inner-hello.7z"),
            None,
            &opts,
            "0.1.0",
            true,
        )
        .expect("inner open_from_reader");
        let hello = inner
            .lookup("/hello.txt", 0)
            .or_else(|| {
                if let Some(ListResult::Infos(infos)) = inner.list("/") {
                    infos.into_iter().find(|(_, i)| i.size > 0).map(|(_, i)| i)
                } else {
                    None
                }
            })
            .expect("hello in inner");
        let mut data = Vec::new();
        inner
            .open(&hello, 0)
            .unwrap()
            .read_to_end(&mut data)
            .unwrap();
        assert!(!data.is_empty(), "inner payload non-empty");
        // Random access still works on nested store members.
        let mut r = inner.open(&hello, 0).unwrap();
        r.seek(SeekFrom::Start(0)).unwrap();
        let mut again = Vec::new();
        r.read_to_end(&mut again).unwrap();
        assert_eq!(data, again);
    }

    /// Build a solid LZMA2 outer 7z containing an inner 7z (requires system `7z`/`7za`).
    fn make_solid_outer_nested_fixture(dir: &Path) -> Option<PathBuf> {
        let hello = dir.join("hello.txt");
        std::fs::write(&hello, b"hello solid nested\n").ok()?;
        let inner = dir.join("inner-hello.7z");
        let outer = dir.join("outer-solid-nested.7z");
        let pad = dir.join("pad.txt");
        std::fs::write(&pad, b"padding for solid folder").ok()?;

        let sevenz = ["7z", "7za"]
            .into_iter()
            .find(|c| std::process::Command::new(c).arg("--help").output().is_ok())?;

        let st_inner = std::process::Command::new(sevenz)
            .args(["a", "-t7z", "-m0=lzma2", "-mx=1"])
            .arg(&inner)
            .arg(&hello)
            .current_dir(dir)
            .output()
            .ok()?;
        if !st_inner.status.success() {
            return None;
        }
        // Solid block with two members so the nested .7z is not a lone copy stream.
        let st_outer = std::process::Command::new(sevenz)
            .args(["a", "-t7z", "-m0=lzma2", "-mx=1", "-ms=on"])
            .arg(&outer)
            .arg(&inner)
            .arg(&pad)
            .current_dir(dir)
            .output()
            .ok()?;
        if !st_outer.status.success() || !outer.exists() {
            return None;
        }
        Some(outer)
    }

    #[test]
    fn solid_outer_nested_via_member_reader() {
        // Solid outer member must still be seekable for open_from_reader (no temp spool).
        let dir = tempfile::tempdir().unwrap();
        let Some(path) = make_solid_outer_nested_fixture(dir.path()) else {
            eprintln!("skip: system 7z/7za unavailable for solid nested fixture");
            return;
        };
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let outer =
            SevenZipMountSource::open(&path, None, &opts, "0.1.0", true).expect("outer solid open");
        assert!(
            outer.archive.solid
                || outer.archive.folders.iter().any(|f| {
                    f.coders
                        .first()
                        .is_some_and(|c| c.method.as_slice() == parse::METHOD_LZMA2)
                }),
            "expected solid/LZMA2 outer"
        );
        let nested_fi = outer
            .lookup("/inner-hello.7z", 0)
            .or_else(|| {
                if let Some(ListResult::Infos(infos)) = outer.list("/") {
                    infos
                        .into_iter()
                        .find(|(n, _)| n.ends_with(".7z"))
                        .map(|(_, i)| i)
                } else {
                    None
                }
            })
            .expect("solid outer nested .7z member");

        // open() → seekable body (Cursor for small solid folders).
        let mut nested_reader = outer
            .open(&nested_fi, 0)
            .expect("open solid outer member stream");
        // Partial read then seek-to-0 must still feed a full nested open.
        let mut head = [0u8; 4];
        nested_reader.read_exact(&mut head).expect("read head");
        assert_eq!(
            &head, b"7z\xbc\xaf",
            "solid outer member starts with 7z magic"
        );
        nested_reader
            .seek(SeekFrom::Start(0))
            .expect("seek solid member to 0");

        let inner = SevenZipMountSource::open_from_reader(
            nested_reader,
            Path::new("inner-hello.7z"),
            None,
            &opts,
            "0.1.0",
            true,
        )
        .expect("inner open_from_reader from solid outer stream");
        let hello = inner
            .lookup("/hello.txt", 0)
            .or_else(|| {
                if let Some(ListResult::Infos(infos)) = inner.list("/") {
                    infos.into_iter().find(|(_, i)| i.size > 0).map(|(_, i)| i)
                } else {
                    None
                }
            })
            .expect("hello in solid-nested inner");
        let mut data = Vec::new();
        inner
            .open(&hello, 0)
            .unwrap()
            .read_to_end(&mut data)
            .unwrap();
        assert!(
            data.windows(b"hello".len()).any(|w| w == b"hello"),
            "inner payload from solid outer: {:?}",
            String::from_utf8_lossy(&data)
        );

        // Re-open outer solid member after first nested open (independent streams).
        let mut r2 = outer
            .open(&nested_fi, 0)
            .expect("re-open solid outer member");
        r2.seek(SeekFrom::Start(0)).unwrap();
        let mut again_head = [0u8; 2];
        r2.read_exact(&mut again_head).unwrap();
        assert_eq!(&again_head, b"7z");
    }

    #[test]
    fn solid_lzma2_member_seek_zero_after_partial_read() {
        // Solid pure-LZMA2 member: progressive/shared decoder must honor seek(0).
        let path = py_fixture("lzma2-two-files-and-medium.7z");
        if !path.exists() {
            return;
        }
        let opts = OpenOptions {
            index_in_memory: true,
            ..OpenOptions::default()
        };
        let m = SevenZipMountSource::open(&path, None, &opts, "0.1.0", true).expect("open");
        let med = m.lookup("/medium.bin", 0).expect("medium.bin");
        let mut r = m.open(&med, 0).expect("open medium");
        let mut prefix = [0u8; 64];
        r.read_exact(&mut prefix).unwrap();
        r.seek(SeekFrom::Start(0)).expect("seek to 0");
        let mut full = Vec::new();
        r.read_to_end(&mut full).unwrap();
        assert_eq!(full.len(), med.size as usize);
        assert_eq!(&full[..64], &prefix);

        // Second independent open matches (shared packed / decoder caches).
        let mut r2 = m.open(&med, 0).unwrap();
        let mut full2 = Vec::new();
        r2.read_to_end(&mut full2).unwrap();
        assert_eq!(full, full2);
    }

    #[test]
    fn lzma2_member_reader_progressive_seek_zero() {
        // Unit-level: Lzma2MemberReader over forced progressive decoder.
        use decode::{index_lzma2_chunks, Lzma2MemberReader, Lzma2RandomAccessDecoder};
        use parse::{Coder, Folder, METHOD_LZMA2};

        let data: Vec<u8> = (0u8..=255).cycle().take(128 * 1024).collect();
        let packed = {
            let status = std::process::Command::new("python3")
                .args([
                    "-c",
                    r#"
import lzma, sys
data = sys.stdin.buffer.read()
packed = lzma.compress(data, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2, "preset": 1}])
sys.stdout.buffer.write(packed)
"#,
                ])
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn();
            let Ok(mut child) = status else {
                eprintln!("skip: python3 unavailable");
                return;
            };
            use std::io::Write;
            if child.stdin.as_mut().unwrap().write_all(&data).is_err() {
                return;
            }
            let out = child.wait_with_output().unwrap();
            if !out.status.success() {
                return;
            }
            out.stdout
        };
        assert!(!index_lzma2_chunks(&packed).unwrap().is_empty());
        let folder = Folder {
            coders: vec![Coder {
                method: METHOD_LZMA2.to_vec(),
                num_in_streams: 1,
                num_out_streams: 1,
                properties: Some(vec![20]),
            }],
            bind_pairs: vec![],
            packed_indices: vec![],
            unpack_sizes: vec![data.len() as u64],
            has_crc: false,
            crc: 0,
        };
        let mut dec =
            Lzma2RandomAccessDecoder::with_chunk_size(&folder, packed, 16 * 1024, 4).unwrap();
        dec.force_progressive_for_test();
        let shared = Arc::new(Mutex::new(dec));

        // Two solid "members" in one folder (prefix + suffix slices).
        let m1_size = 40 * 1024u64;
        let mut r1 = Lzma2MemberReader::new(Arc::clone(&shared), 0, m1_size);
        let mut a = [0u8; 100];
        r1.read_exact(&mut a).unwrap();
        r1.seek(SeekFrom::Start(0)).unwrap();
        let mut again = Vec::new();
        r1.read_to_end(&mut again).unwrap();
        assert_eq!(again.len(), m1_size as usize);
        assert_eq!(&again[..100], &a);
        assert_eq!(&again, &data[..m1_size as usize]);

        let m2_start = m1_size;
        let m2_size = 8 * 1024u64;
        let mut r2 = Lzma2MemberReader::new(shared, m2_start, m2_size);
        r2.seek(SeekFrom::Start(10)).unwrap();
        let mut mid = [0u8; 32];
        r2.read_exact(&mut mid).unwrap();
        assert_eq!(
            &mid,
            &data[m2_start as usize + 10..m2_start as usize + 10 + 32]
        );
        r2.seek(SeekFrom::Start(0)).unwrap();
        let mut m2 = Vec::new();
        r2.read_to_end(&mut m2).unwrap();
        assert_eq!(m2, data[m2_start as usize..(m2_start + m2_size) as usize]);
    }

    /// After OpenOptions.hashes fill, list_xattr/get_xattr expose user.hash.* (store-copy fixture).
    #[test]
    fn content_hash_xattrs_store_copy() {
        let path = py_fixture("store-copy-two-files.7z");
        if !path.exists() {
            eprintln!("skip missing {}", path.display());
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("i.sqlite");
        let opts = OpenOptions {
            hashes: vec!["sha256".into(), "crc32".into()],
            ..OpenOptions::default()
        };
        let m = SevenZipMountSource::open(&path, Some(&idx), &opts, "0.1.0", true)
            .expect("open store-copy with hashes");

        let fi_a = m.lookup("/a.txt", 0).expect("a.txt");
        let mut keys = m.list_xattr(&fi_a);
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "user.hash.crc32".to_string(),
                "user.hash.sha256".to_string()
            ]
        );

        let mut a_bytes = Vec::new();
        m.open(&fi_a, 0).unwrap().read_to_end(&mut a_bytes).unwrap();
        let fi_b = m.lookup("/b.txt", 0).expect("b.txt");
        let mut b_bytes = Vec::new();
        m.open(&fi_b, 0).unwrap().read_to_end(&mut b_bytes).unwrap();

        let a_sha = hash_hex("sha256", &a_bytes).unwrap();
        let b_sha = hash_hex("sha256", &b_bytes).unwrap();
        let a_crc = hash_hex("crc32", &a_bytes).unwrap();
        let b_crc = hash_hex("crc32", &b_bytes).unwrap();

        let sha = m
            .get_xattr(&fi_a, "user.hash.sha256")
            .expect("user.hash.sha256 present");
        let crc = m
            .get_xattr(&fi_a, "user.hash.crc32")
            .expect("user.hash.crc32 present");
        let got_sha = String::from_utf8(sha).unwrap();
        let got_crc = String::from_utf8(crc).unwrap();
        // Solid Copy shares pack offsetheader; last INSERT OR REPLACE wins (Python parity).
        assert!(
            got_sha == a_sha || got_sha == b_sha,
            "sha256 xattr should match a member digest, got {got_sha}"
        );
        assert!(got_crc == a_crc || got_crc == b_crc);
        // Both members share offsetheader → same xattr view.
        assert_eq!(
            m.get_xattr(&fi_b, "user.hash.sha256").as_deref(),
            m.get_xattr(&fi_a, "user.hash.sha256").as_deref()
        );
        assert!(m.get_xattr(&fi_a, "user.hash.md5").is_none());
        assert!(m.get_xattr(&fi_a, "missing").is_none());
    }

    /// Single-file non-solid encrypted fixture: digests match opened content.
    #[test]
    fn content_hash_xattrs_encrypted_with_password() {
        let path = py_fixture("encrypted-hello.7z");
        if !path.exists() {
            eprintln!("skip missing {}", path.display());
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("i.sqlite");
        let opts = OpenOptions {
            passwords: vec!["secret".into()],
            hashes: vec!["sha256".into(), "crc32".into()],
            ..OpenOptions::default()
        };
        let m = SevenZipMountSource::open(&path, Some(&idx), &opts, "0.1.0", true)
            .expect("open encrypted with password+hashes");
        let fi = m.lookup("/secret.txt", 0).expect("secret.txt");
        let mut keys = m.list_xattr(&fi);
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "user.hash.crc32".to_string(),
                "user.hash.sha256".to_string()
            ]
        );
        let mut data = Vec::new();
        m.open(&fi, 0).unwrap().read_to_end(&mut data).unwrap();
        assert_eq!(
            m.get_xattr(&fi, "user.hash.sha256").as_deref(),
            Some(hash_hex("sha256", &data).unwrap().as_bytes())
        );
        assert_eq!(
            m.get_xattr(&fi, "user.hash.crc32").as_deref(),
            Some(hash_hex("crc32", &data).unwrap().as_bytes())
        );
        // Known vector for "secret content\n" if fixture payload is stable.
        if data.as_slice() == b"secret content\n" {
            assert_eq!(
                m.get_xattr(&fi, "user.hash.sha256").as_deref(),
                Some(
                    b"45fa64439f984bb596063451c78ffbca38dda79d33ef01dddd7faf62d3a4b9a8".as_slice()
                )
            );
            assert_eq!(
                m.get_xattr(&fi, "user.hash.crc32").as_deref(),
                Some(b"17156130".as_slice())
            );
        }
    }

    /// content_locked metadata-only mount skips hash fill (cannot read members).
    #[test]
    fn content_hash_skipped_when_content_locked() {
        let path = py_fixture("encrypted-hello.7z");
        if !path.exists() {
            eprintln!("skip missing {}", path.display());
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("i.sqlite");
        let opts = OpenOptions {
            hashes: vec!["sha256".into()],
            ..OpenOptions::default()
        };
        let m = SevenZipMountSource::open(&path, Some(&idx), &opts, "0.1.0", true)
            .expect("metadata-only mount");
        let fi = m.lookup("/secret.txt", 0).expect("list/stat works");
        assert!(m.list_xattr(&fi).is_empty());
        assert!(m.get_xattr(&fi, "user.hash.sha256").is_none());
    }

    /// Synthetic single-file non-solid 7z (system 7z): exact content-hash parity.
    #[test]
    fn content_hash_xattrs_synthetic_single_file() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"hello world\n";
        let payload = dir.path().join("hello.txt");
        std::fs::write(&payload, content).unwrap();
        let archive = dir.path().join("one.7z");

        let sevenz = ["7z", "7za"]
            .into_iter()
            .find(|c| std::process::Command::new(c).arg("--help").output().is_ok());
        let Some(sevenz) = sevenz else {
            eprintln!("skip: no 7z/7za for synthetic fixture");
            return;
        };
        // Non-solid so offsetheader is unique per file.
        let out = std::process::Command::new(sevenz)
            .args(["a", "-t7z", "-m0=Copy", "-ms=off"])
            .arg(&archive)
            .arg(&payload)
            .current_dir(dir.path())
            .output()
            .expect("run 7z");
        if !out.status.success() {
            eprintln!(
                "skip: 7z create failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }

        let idx = dir.path().join("i.sqlite");
        let opts = OpenOptions {
            hashes: vec!["sha256".into(), "crc32".into()],
            index_in_memory: false,
            ..OpenOptions::default()
        };
        let m = SevenZipMountSource::open(&archive, Some(&idx), &opts, "0.1.0", true)
            .expect("open synthetic");
        let fi = m.lookup("/hello.txt", 0).expect("hello.txt");
        let mut keys = m.list_xattr(&fi);
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "user.hash.crc32".to_string(),
                "user.hash.sha256".to_string()
            ]
        );
        assert_eq!(
            m.get_xattr(&fi, "user.hash.sha256").as_deref(),
            Some(hash_hex("sha256", content).unwrap().as_bytes())
        );
        assert_eq!(
            m.get_xattr(&fi, "user.hash.crc32").as_deref(),
            Some(hash_hex("crc32", content).unwrap().as_bytes())
        );
        // TAR known vector for "hello world\n"
        assert_eq!(
            m.get_xattr(&fi, "user.hash.sha256").as_deref(),
            Some(b"a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447".as_slice())
        );
        assert_eq!(
            m.get_xattr(&fi, "user.hash.crc32").as_deref(),
            Some(b"af083b2d".as_slice())
        );
    }

    /// Set file mtime portably (GNU `touch -d` is not available on BSD/macOS).
    #[cfg(unix)]
    fn set_mtime_unix(path: &std::path::Path, secs: i64) {
        use std::os::unix::ffi::OsStrExt;
        let c = std::ffi::CString::new(path.as_os_str().as_bytes()).expect("path cstring");
        let ts = libc::timespec {
            tv_sec: secs,
            tv_nsec: 0,
        };
        let times = [ts, ts];
        let rc = unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) };
        assert_eq!(
            rc,
            0,
            "utimensat failed for {}: {}",
            path.display(),
            std::io::Error::last_os_error()
        );
    }

    /// Regression: FILETIME→Unix delta must use 100ns ticks (not ns). Wrong delta
    /// made every 7z mtime a huge negative; FUSE then showed Dec 31 1969.
    #[test]
    fn mtime_from_7z_cli_fixture_is_not_epoch() {
        use std::process::Command;
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("file.txt");
        std::fs::write(&plain, b"hello\n").unwrap();
        // 2020-06-15 12:00:00 UTC — do not use GNU-only `touch -d` (breaks macOS CI).
        set_mtime_unix(&plain, 1_592_222_400);
        let archive = dir.path().join("t.7z");
        let status = Command::new("7z")
            .args([
                "a",
                "-t7z",
                archive.to_str().unwrap(),
                plain.to_str().unwrap(),
            ])
            .status();
        let Ok(status) = status else {
            eprintln!("skip: 7z not available");
            return;
        };
        if !status.success() {
            eprintln!("skip: 7z a failed");
            return;
        }
        // Parse layer
        let mut f = std::fs::File::open(&archive).unwrap();
        let info = crate::parse::parse_7z_archive(&mut f, |_, _| Ok(Vec::new())).unwrap();
        let entry = info
            .files
            .iter()
            .find(|e| e.path.ends_with("file.txt"))
            .expect("file.txt entry");
        let expected = 1_592_222_400.0; // 2020-06-15 12:00:00 UTC
        assert!(
            (entry.mtime - expected).abs() < 86400.0,
            "parse mtime {} far from expected {} (FILETIME epoch bug?)",
            entry.mtime,
            expected
        );
        // MountSource / index path
        let src = SevenZipMountSource::open(&archive, None, &OpenOptions::default(), "test", true)
            .expect("open 7z");
        let fi = src.lookup("/file.txt", 0).expect("lookup");
        assert!(
            (fi.mtime - expected).abs() < 86400.0,
            "index mtime {} far from expected {}",
            fi.mtime,
            expected
        );
        assert!(fi.mtime > 0.0, "mtime must be positive (not epoch)");
    }

    /// Embedded / nested path: `open_from_reader` must keep the same mtimes (no-tmp).
    #[test]
    fn mtime_open_from_reader_matches_path_open() {
        use std::io::Cursor;
        use std::process::Command;
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("nested.txt");
        std::fs::write(&plain, b"nested-mtime\n").unwrap();
        // 2021-03-01 00:00:00 UTC — portable utimensat (not GNU touch -d).
        set_mtime_unix(&plain, 1_614_556_800);
        let archive = dir.path().join("nested.7z");
        let status = Command::new("7z")
            .args([
                "a",
                "-t7z",
                archive.to_str().unwrap(),
                plain.to_str().unwrap(),
            ])
            .status();
        let Ok(status) = status else {
            eprintln!("skip: 7z not available");
            return;
        };
        if !status.success() {
            eprintln!("skip: 7z a failed");
            return;
        }
        let bytes = std::fs::read(&archive).unwrap();
        let opts = OpenOptions::default();
        let from_path =
            SevenZipMountSource::open(&archive, None, &opts, "test", true).expect("path open");
        let from_reader = SevenZipMountSource::open_from_reader(
            Cursor::new(bytes),
            std::path::Path::new("nested.7z"),
            None,
            &opts,
            "test",
            true,
        )
        .expect("reader open");
        let a = from_path.lookup("/nested.txt", 0).expect("path lookup");
        let b = from_reader.lookup("/nested.txt", 0).expect("reader lookup");
        assert!(
            a.mtime > 1.0e9 && b.mtime > 1.0e9,
            "mtimes must be real Unix times, got path={} reader={}",
            a.mtime,
            b.mtime
        );
        assert!(
            (a.mtime - b.mtime).abs() < 1.0,
            "path vs reader mtime mismatch {} vs {}",
            a.mtime,
            b.mtime
        );
        let expected = 1_614_556_800.0; // 2021-03-01 00:00:00 UTC
        assert!(
            (a.mtime - expected).abs() < 86400.0,
            "mtime {} far from {expected}",
            a.mtime
        );
    }

    /// Prefer Python `encrypted-hello.7z`, then the vendored testdata, then system `7z`.
    /// Returns `(archive_path, expected_secret_txt_bytes)`.
    fn ensure_encrypted_hello_fixture(work: &Path) -> Option<(PathBuf, Vec<u8>)> {
        let payload = b"secret content\n";
        let py = py_fixture("encrypted-hello.7z");
        if py.is_file() {
            return Some((py, payload.to_vec()));
        }
        // Vendored LZMA2+AES fixture so macOS CI (Homebrew p7zip) cannot
        // silently build store+AES without a folder CRC and accept a wrong key.
        let archive = work.join("encrypted-hello.7z");
        const BUNDLED: &[u8] = include_bytes!("../testdata/encrypted-hello.7z");
        if std::fs::write(&archive, BUNDLED).is_ok() {
            return Some((archive, payload.to_vec()));
        }
        if write_encrypted_sample_7z(&archive, "secret.txt", payload, "secret") {
            Some((archive, payload.to_vec()))
        } else {
            None
        }
    }

    /// Build an encrypted 7z (AES) via system CLI. Returns false if CLI missing/fails.
    fn write_encrypted_sample_7z(
        archive: &Path,
        member_name: &str,
        payload: &[u8],
        password: &str,
    ) -> bool {
        write_encrypted_sample_7z_mx(archive, member_name, payload, password, 1)
    }

    fn write_encrypted_sample_7z_mx(
        archive: &Path,
        member_name: &str,
        payload: &[u8],
        password: &str,
        mx: u8,
    ) -> bool {
        use std::process::Command;
        let dir = archive.parent().expect("archive parent");
        let plain = dir.join(member_name);
        if let Err(e) = std::fs::write(&plain, payload) {
            eprintln!("skip: write encrypted payload: {e}");
            return false;
        }
        let _ = std::fs::remove_file(archive);
        let archive_name = archive.file_name().and_then(|s| s.to_str()).unwrap();
        let pw_arg = format!("-p{password}");
        let mx_arg = format!("-mx={mx}");
        for bin in ["7zz", "7z", "7za"] {
            // Content encryption only (`-mhe=off`): list/stat works without password
            // (metadata-only mount). Header encryption would block listing.
            // Prefer LZMA2 (`mx>0`): store+AES can yield full-size garbage. Tests
            // that need Copy still pass mx=0 and rely on file-level CRC.
            let mut args = vec!["a", "-t7z"];
            if mx > 0 {
                args.extend(["-m0=LZMA2", mx_arg.as_str()]);
            } else {
                args.push(mx_arg.as_str());
            }
            args.extend([&pw_arg, "-mhe=off", archive_name, member_name]);
            let status = Command::new(bin).args(&args).current_dir(dir).status();
            if matches!(status, Ok(s) if s.success()) && archive.is_file() {
                return true;
            }
        }
        eprintln!("skip: 7z encrypted archive create failed");
        false
    }

    /// Build a minimal single-file 7z at `archive` containing `member_name` → `payload`.
    /// Returns false when the `7z` CLI is missing or fails (caller should skip).
    fn write_sample_7z(archive: &Path, member_name: &str, payload: &[u8]) -> bool {
        use std::process::Command;
        let dir = archive.parent().expect("archive parent");
        let plain = dir.join(member_name);
        if let Some(parent) = plain.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Err(e) = std::fs::write(&plain, payload) {
            eprintln!("skip: write payload: {e}");
            return false;
        }
        // Replace any previous archive so size/mtime always change.
        let _ = std::fs::remove_file(archive);
        let archive_name = archive.file_name().and_then(|s| s.to_str()).unwrap();
        let status = Command::new("7z")
            .args([
                "a",
                "-t7z",
                "-mx=0", // store: small, deterministic size change with payload
                archive_name,
                member_name,
            ])
            .current_dir(dir)
            .status();
        match status {
            Ok(s) if s.success() => true,
            Ok(_) => {
                eprintln!("skip: 7z a failed");
                false
            }
            Err(_) => {
                eprintln!("skip: 7z not available");
                false
            }
        }
    }

    /// Regression: open_existing_path rejects when archive size/mtime no longer match tarstats.
    #[test]
    fn warm_index_rejects_when_archive_size_or_mtime_changes() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("swap.7z");
        if !write_sample_7z(&archive, "hello.txt", b"7z-v1\n") {
            return;
        }
        let index = dir.path().join("swap.7z.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            write_index: true,
            ..OpenOptions::default()
        };

        let src = SevenZipMountSource::open(&archive, Some(&index), &opts, "test", true)
            .expect("cold create");
        let fi = src.lookup("/hello.txt", 0).expect("lookup v1");
        let mut buf = String::new();
        src.open(&fi, 0).unwrap().read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "7z-v1\n");
        drop(src);
        assert!(index.exists());

        // Matching archive still opens warm.
        SevenZipMountSource::open_existing_path(&archive, &index, &opts)
            .expect("warm match must succeed");

        // Replace archive content (size change) while reusing the sibling index path.
        if !write_sample_7z(&archive, "hello.txt", b"7z-v2-longer\n") {
            return;
        }

        match SevenZipMountSource::open_existing_path(&archive, &index, &opts) {
            Ok(_) => panic!("stale index must fail open_existing_path after archive replace"),
            Err(err) => {
                let msg = err.to_string();
                assert!(
                    msg.contains("size")
                        || msg.contains("mtime")
                        || msg.contains("mismatch")
                        || msg.contains("fingerprint"),
                    "unexpected error (expected tarstats mismatch): {msg}"
                );
            }
        }
    }

    /// Regression: warm 7z open rebuilds when archive content no longer matches tarstats.
    #[test]
    fn warm_index_rebuilds_when_archive_content_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("swap.7z");
        if !write_sample_7z(&archive, "hello.txt", b"7z-v1\n") {
            return;
        }
        let index = dir.path().join("swap.7z.index.sqlite");
        let opts = OpenOptions {
            index_file_path: Some(index.clone()),
            write_index: true,
            ..OpenOptions::default()
        };

        let src = SevenZipMountSource::open(&archive, Some(&index), &opts, "test", true)
            .expect("cold create");
        let fi = src.lookup("/hello.txt", 0).expect("lookup v1");
        let mut buf = String::new();
        src.open(&fi, 0).unwrap().read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "7z-v1\n");
        drop(src);
        assert!(index.exists());

        if !write_sample_7z(&archive, "hello.txt", b"7z-v2-longer\n") {
            return;
        }

        // recreate=false: tarstats mismatch must rebuild, not serve stale member rows.
        let src2 =
            SevenZipMountSource::open(&archive, Some(&index), &opts, "test", false).expect("warm");
        let fi2 = src2.lookup("/hello.txt", 0).expect("lookup v2");
        let mut buf2 = String::new();
        src2.open(&fi2, 0)
            .unwrap()
            .read_to_string(&mut buf2)
            .unwrap();
        assert_eq!(
            buf2, "7z-v2-longer\n",
            "must serve new 7z data after tarstats mismatch rebuild"
        );
    }

    /// Durable structure export/import: warm open skips header re-parse, still reads members.
    #[test]
    fn durable_structure_roundtrip_open_without_header_parse() {
        use ratarmount_index::{NestedBodyFingerprint, NESTED_FORMAT_SEVENZIP};
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("struct.7z");
        let payload = b"structure-warm-payload-xyz\n";
        if !write_sample_7z(&archive, "hello.txt", payload) {
            eprintln!("skip: 7z/7za not available");
            return;
        }
        let bytes = std::fs::read(&archive).unwrap();
        let body_size = bytes.len() as u64;
        let opts = OpenOptions {
            index_compact_only: true,
            ..OpenOptions::default()
        };
        let cold = SevenZipMountSource::open_from_reader(
            std::io::Cursor::new(bytes.clone()),
            "struct.7z",
            None,
            &opts,
            "test",
            true,
        )
        .expect("cold nested 7z");
        assert!(!cold.opened_from_durable_structure());
        let mut c = std::io::Cursor::new(bytes.clone());
        let fp = NestedBodyFingerprint::from_seekable_body(&mut c, body_size).unwrap();
        let blob_bytes = cold.export_nested_durable(fp.clone()).expect("export");
        let blob = ratarmount_index::DurableNestedBlob::from_bytes(&blob_bytes).unwrap();
        assert_eq!(blob.format, NESTED_FORMAT_SEVENZIP);
        assert!(
            blob.has_sevenzip_structure(),
            "export must include 7z structure sidecars"
        );
        // Pure structure round-trip (no I/O).
        let rebuilt = archive_info_from_durable(blob.sevenzip.as_ref().unwrap()).unwrap();
        assert_eq!(rebuilt.files.len(), cold.archive.files.len());
        assert_eq!(rebuilt.folders.len(), cold.archive.folders.len());
        drop(cold);

        let warm = SevenZipMountSource::open_from_reader_with_durable(
            std::io::Cursor::new(bytes),
            "struct.7z",
            &blob,
            &opts,
        )
        .expect("warm durable 7z");
        assert!(
            warm.opened_from_durable_structure(),
            "warm open must use structure sidecars (no header re-parse)"
        );
        assert!(warm.index_is_compact_only());
        let fi = warm.lookup("/hello.txt", 0).expect("lookup");
        let mut r = warm.open(&fi, 0).unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, payload);
    }

    /// Structure serialize/deserialize unit (no mount): empty structure rejected.
    #[test]
    fn durable_structure_empty_rejected() {
        let empty = ratarmount_index::DurableSevenZipArchive {
            after_header: 0,
            pack_pos_base: 0,
            folders: vec![],
            pack_info: None,
            files: vec![],
            solid: false,
        };
        assert!(archive_info_from_durable(&empty).is_err());
    }

    /// Optional existence check only. Member and parent SQL `type` are both 0 today, so
    /// `type == 0` cannot fail a dropped typeflag — TAR `'S'`/`'D'`/`'5'` and ZIP Deflate
    /// `8` are the coverage. Uses an on-disk sidecar (`index` is private; `:memory:` cannot reopen).
    #[test]
    fn regression_sql_files_type_row_exists_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("nested.7z");
        if !write_sample_7z(&archive, "a/b/hello.txt", b"hello\n") {
            eprintln!("skip: 7z CLI not available or failed to create fixture");
            return;
        }
        let idx_path = dir.path().join("nested.7z.index.sqlite");
        let opts = OpenOptions {
            index_in_memory: false,
            ..OpenOptions::default()
        };
        let m = SevenZipMountSource::open(&archive, Some(&idx_path), &opts, "0.1.0", true)
            .expect("open 7z");
        let fi = m.lookup("/a/b/hello.txt", 0).expect("hello.txt");
        let oh = match fi.userdata.first() {
            Some(UserData::Tar(ud)) => ud.offsetheader.expect("oh") as i64,
            _ => panic!("userdata"),
        };
        drop(m);

        let idx = SqliteIndex::open_read_only(&idx_path).expect("reopen on-disk sidecar");
        assert!(
            idx.sql_files_type("/a/b", "hello.txt", oh)
                .unwrap()
                .is_some(),
            "member row must exist after SoA flush"
        );
        assert!(
            idx.sql_files_type("", "a", 0).unwrap().is_some(),
            "generated parent row must exist"
        );
        assert!(idx.sql_files_type("/a", "b", 0).unwrap().is_some());
    }

    fn backward_start_count(starts: &[u64]) -> usize {
        starts.windows(2).filter(|w| w[1] < w[0]).count()
    }

    fn visible_fullpath(path: &str, name: &str) -> String {
        if path.is_empty() || path == "/" {
            format!("/{name}")
        } else {
            format!("{path}/{name}")
        }
    }

    fn payload_file_row(
        path: &str,
        name: &str,
        pack: i64,
        unpack: i64,
    ) -> ratarmount_index::FileRow {
        ratarmount_index::FileRow::new(
            path, name, pack, unpack, 4, 1.0, 0o100644, 0, "", 0, 0, false, false, false, 0,
        )
    }

    /// Regression: 7z shared pack offset ties break by UTF-8 name; synthetic flatten
    /// has zero backward `SeekFrom::Start` vs name-order ≥1 (no 7z CLI).
    #[test]
    fn regression_offset_order_shared_pack_name_tie_break() {
        const N_PER_DIR: usize = 16;
        let idx = SqliteIndex::create_writable(None).unwrap();
        idx.begin_write().unwrap();
        let mut rows = Vec::with_capacity(N_PER_DIR * 2 + 2);
        for i in 0..N_PER_DIR {
            let oh_z = (i as i64) * 200;
            let oh_a = oh_z + 100;
            rows.push(payload_file_row("/z", &format!("m{i:02}"), oh_z, 0));
            rows.push(payload_file_row("/a", &format!("m{i:02}"), oh_a, 0));
        }
        // Insert z.txt first; flatten must still be a then z (UTF-8 name tie-break).
        rows.push(payload_file_row("/solid", "z.txt", 9999, 0));
        rows.push(payload_file_row("/solid", "a.txt", 9999, 8));
        idx.insert_files_batch(&rows).unwrap();
        idx.commit_write().unwrap();
        let idx = idx.into_read_only().unwrap();

        let flat = idx.list_visible_files_by_offset().unwrap();
        assert_eq!(flat.len(), N_PER_DIR * 2 + 2);
        assert_eq!(visible_fullpath(&flat[0].path, &flat[0].name), "/z/m00");
        assert_eq!(visible_fullpath(&flat[1].path, &flat[1].name), "/a/m00");

        let solid: Vec<_> = flat.iter().filter(|m| m.path == "/solid").collect();
        assert_eq!(solid.len(), 2);
        assert_eq!(
            (solid[0].name.as_str(), solid[1].name.as_str()),
            ("a.txt", "z.txt"),
            "shared pack offset must tie-break by UTF-8 name, got {:?}",
            solid.iter().map(|m| m.name.as_str()).collect::<Vec<_>>()
        );
        assert_eq!(solid[0].cookie.offsetheader, 9999);
        assert_eq!(solid[1].cookie.offsetheader, 9999);

        let offset_starts: Vec<u64> = flat.iter().map(|m| m.cookie.offsetheader as u64).collect();
        assert_eq!(
            backward_start_count(&offset_starts),
            0,
            "flatten must have zero backward pack-offset Start, starts={offset_starts:?}"
        );

        let mut by_name = flat.clone();
        by_name.sort_by(|a, b| {
            visible_fullpath(&a.path, &a.name).cmp(&visible_fullpath(&b.path, &b.name))
        });
        let name_starts: Vec<u64> = by_name
            .iter()
            .map(|m| m.cookie.offsetheader as u64)
            .collect();
        assert!(
            backward_start_count(&name_starts) >= 1,
            "name-order control must have ≥1 backward Start (fixture shuffled), starts={name_starts:?}"
        );
    }

    fn is_az_payload(path: &str, name: &str) -> bool {
        (path == "/a" || path == "/z" || path == "a" || path == "z")
            && name.len() == 3
            && name.as_bytes()[0] == b'm'
    }

    /// Regression: offset-ordered 7z flatten has zero backward pack-offset seeks.
    ///
    /// Interleaved multi-dir pack (`z/m00`, `a/m00`, …) via non-solid Copy. Flatten
    /// must walk pack-offset order (zero backward `SeekFrom::Start`). Name-order on
    /// the same set has ≥1 backward Start only when the fixture is actually
    /// interleaved (7-Zip may name-sort). Skip if `7z`/`7za` is missing.
    #[test]
    fn regression_offset_order_seeks() {
        const N_PER_DIR: usize = 16;
        let dir = tempfile::tempdir().unwrap();
        let sevenz = ["7z", "7za"]
            .into_iter()
            .find(|c| std::process::Command::new(c).arg("--help").output().is_ok());
        let Some(sevenz) = sevenz else {
            eprintln!("skip: 7z/7za unavailable for offset-order flatten fixture");
            return;
        };

        std::fs::create_dir_all(dir.path().join("a")).unwrap();
        std::fs::create_dir_all(dir.path().join("z")).unwrap();
        let mut members: Vec<String> = Vec::with_capacity(N_PER_DIR * 2);
        for i in 0..N_PER_DIR {
            let z = format!("z/m{i:02}");
            let a = format!("a/m{i:02}");
            std::fs::write(dir.path().join(&z), vec![b'z'; 8 + i]).unwrap();
            std::fs::write(dir.path().join(&a), vec![b'a'; 8 + i]).unwrap();
            members.push(z);
            members.push(a);
        }
        let archive = dir.path().join("interleaved.7z");
        let mut cmd = std::process::Command::new(sevenz);
        cmd.args(["a", "-t7z", "-m0=Copy", "-ms=off"])
            .arg(&archive)
            .current_dir(dir.path());
        for m in &members {
            cmd.arg(m);
        }
        let out = cmd.output().expect("run 7z");
        if !out.status.success() || !archive.exists() {
            eprintln!(
                "skip: 7z create failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            return;
        }

        let bytes = std::fs::read(&archive).unwrap();
        let idx_path = dir.path().join("interleaved.7z.index.sqlite");
        let opts = OpenOptions {
            index_in_memory: false,
            ..OpenOptions::default()
        };
        let m = SevenZipMountSource::open(&archive, Some(&idx_path), &opts, "0.1.0", true)
            .expect("index interleaved 7z");
        drop(m);

        let idx = SqliteIndex::open_read_only(&idx_path).expect("reopen sidecar");
        let flat = idx.list_visible_files_by_offset().expect("flatten");
        let payloads: Vec<_> = flat
            .iter()
            .filter(|m| is_az_payload(&m.path, &m.name))
            .collect();
        assert_eq!(
            payloads.len(),
            32,
            "flatten must include the 32 a/z payload files, got {} (flat={})",
            payloads.len(),
            flat.len()
        );

        struct StartLog {
            inner: Cursor<Vec<u8>>,
            starts: Vec<u64>,
        }
        impl Seek for StartLog {
            fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
                if let SeekFrom::Start(n) = from {
                    self.starts.push(n);
                }
                self.inner.seek(from)
            }
        }

        let mut offset_reader = StartLog {
            inner: Cursor::new(bytes.clone()),
            starts: Vec::new(),
        };
        for mem in &payloads {
            assert!(
                mem.cookie.offsetheader >= 0,
                "7z pack offsetheader must be non-negative"
            );
            let oh = mem.cookie.offsetheader as u64;
            assert!(
                oh < bytes.len() as u64,
                "pack offset {oh} must lie inside the archive (len={})",
                bytes.len()
            );
            offset_reader.seek(SeekFrom::Start(oh)).unwrap();
        }
        let offset_back = backward_start_count(&offset_reader.starts);
        assert_eq!(
            offset_back, 0,
            "flatten must have zero backward pack-offset Start, starts={:?}",
            offset_reader.starts
        );

        let first = visible_fullpath(&payloads[0].path, &payloads[0].name);
        let second = visible_fullpath(&payloads[1].path, &payloads[1].name);
        let interleaved =
            (first == "/z/m00" || first == "z/m00") && (second == "/a/m00" || second == "a/m00");
        if !interleaved {
            eprintln!("skip: 7z fixture not interleaved (pack order follows name order)");
            return;
        }
        assert!(
            first == "/z/m00" || first == "z/m00",
            "flatten must start at first packed member, not per-dir concat, got {first}"
        );
        assert!(
            second == "/a/m00" || second == "a/m00",
            "flatten second member must be a/m00, got {second}"
        );

        let mut by_name = payloads.clone();
        by_name.sort_by(|a, b| {
            visible_fullpath(&a.path, &a.name).cmp(&visible_fullpath(&b.path, &b.name))
        });
        let mut name_reader = StartLog {
            inner: Cursor::new(bytes),
            starts: Vec::new(),
        };
        for mem in &by_name {
            name_reader
                .seek(SeekFrom::Start(mem.cookie.offsetheader as u64))
                .unwrap();
        }
        let name_back = backward_start_count(&name_reader.starts);
        assert!(
            name_back >= 1,
            "name-order control must have ≥1 backward Start (fixture shuffled), starts={:?}",
            name_reader.starts
        );
    }
}
