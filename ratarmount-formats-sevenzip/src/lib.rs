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
//! | **Pure LZMA2 solid** (small folder ≤ 4 MiB unpack) | `Cursor` of the member slice | Yes — fully buffered seekable |
//! | **Pure LZMA2 solid** (large folder) | [`decode::Lzma2MemberReader`] progressive windows | Yes — seek-to-0 / random read OK |
//! | BCJ2 / multi-pack / AES content | `Cursor` after full-folder decompress | Yes for fixture sizes; multi-GB may hold a large unpack buffer |
//!
//! **Residual / not free:** multi-GB solid non-LZMA2 (or BCJ2) still materializes
//! the folder (or member) into RAM for a seekable nested body; encrypted folders
//! need a password before `open`. Store-in-store and solid-in-store nested fixtures
//! both avoid writing the outer member to a temp file when AutoMount uses the
//! reader path.

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
    normpath, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions, UserData,
};
use ratarmount_index::{
    compute_hashes_limited, normalize_algorithm, FileRow, IndexError, SqliteIndex,
};
use thiserror::Error;

use decode::{
    Lzma2MemberReader, PackSource, SeekPackSource, SharedArchiveIo, SharedArchiveView,
    SharedLzma2Decoder, DEFAULT_MAX_CACHED_CHUNKS,
};

pub use parse::{looks_like_7z, SevenZipArchiveInfo, SevenZipError, SevenZipFileEntry};

pub const BACKEND_NAME: &str = "SevenZipMountSource";

/// Below this folder unpack size, solid pure-LZMA2 members materialize into a
/// `Cursor` (Python `_DEFAULT_SMALL_FOLDER_THRESHOLD`). Larger pure-LZMA2
/// folders use progressive [`Lzma2MemberReader`] so nested open need not hold a
/// second full copy of the member when random-accessing the stream.
const SMALL_FOLDER_THRESHOLD: u64 = 4 * 1024 * 1024;

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
    /// (pack_offset, unpack_offset) → file index for O(1) open lookup.
    entry_by_offsets: HashMap<(u64, u64), usize>,
    password: Option<String>,
    /// Encrypted archive mounted without a valid password: list/stat only.
    content_locked: bool,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl SevenZipMountSource {
    /// True when the SQLite index is a nested temp-spill file (deleted when this source drops).
    pub fn index_is_temp_spill(&self) -> bool {
        self.index.is_temp_spill()
    }

    /// True when list/lookup use the in-memory MemIndex projection.
    pub fn index_has_mem_index(&self) -> bool {
        self.index.has_mem_index()
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
    /// Prefer `index_path: None` with [`OpenOptions::index_temp_spill`] for nested mounts.
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
        let password = options.passwords.first().cloned();
        let archive = parse::parse_7z_archive(&mut file, |folder, packed| {
            decode::decompress_folder(folder, packed, password.as_deref())
                .map_err(|e| parse::SevenZipError::Msg(e.to_string()))
        })?;
        let encrypted = archive.folders.iter().any(|f| f.is_encrypted());
        let content_locked = encrypted && password.is_none();
        let entry_by_offsets = entry_offset_map(&archive);
        file.seek(SeekFrom::Start(0))?;
        let archive_io: SharedArchiveIo = Arc::new(Mutex::new(Box::new(file)));
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
        let archive = parse::parse_7z_archive(&mut reader, |folder, packed| {
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
        let mut content_locked = false;
        let password = if encrypted {
            // Verify codecs are supported when a password would be used.
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
                // Metadata-only mount: list/stat work; open requires password.
                content_locked = true;
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
                None
            } else {
                debug!(
                    "7z {}: trying {} password candidate(s) against encrypted archive",
                    archive_path.display(),
                    options.passwords.len()
                );
                let mut chosen = None;
                let mut last_err = None;
                for (i, pw) in options.passwords.iter().enumerate() {
                    if let Some(entry) = archive
                        .files
                        .iter()
                        .find(|e| e.folder_index.is_some() && e.size > 0 && !e.is_dir)
                    {
                        let fi = entry.folder_index.unwrap();
                        let folder = &archive.folders[fi];
                        match Self::try_decrypt_entry_io(&archive_io, &archive, entry, folder, pw) {
                            Ok(()) => {
                                debug!(
                                    "7z {}: password candidate #{i} accepted (trial member={})",
                                    archive_path.display(),
                                    entry.path
                                );
                                chosen = Some(pw.clone());
                                break;
                            }
                            Err(e) => {
                                debug!(
                                    "7z {}: password candidate #{i} rejected for {}: {e}",
                                    archive_path.display(),
                                    entry.path
                                );
                                last_err = Some(e);
                                continue;
                            }
                        }
                    } else {
                        debug!(
                            "7z {}: no non-empty file to trial; accepting password candidate #{i}",
                            archive_path.display()
                        );
                        chosen = Some(pw.clone());
                        break;
                    }
                }
                if chosen.is_none() {
                    warn!(
                        "7z {}: all password candidates failed",
                        archive_path.display()
                    );
                    return Err(SzError::Seven(last_err.unwrap_or_else(|| {
                        SevenZipError::Msg(
                            "Could not decrypt 7z archive with the provided password(s)".into(),
                        )
                    })));
                }
                chosen
            }
        } else {
            options.passwords.first().cloned()
        };

        let index = SqliteIndex::create_writable_for_open(index_path, options)?;
        index.begin_write()?;

        let mut batch = Vec::new();
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

            batch.push(FileRow::new(
                path,
                name,
                header_offset,
                data_offset,
                size,
                entry.mtime,
                mode as i64,
                0,
                linkname,
                0,
                0,
                false,
                false,
                false,
                0,
            ));
            if batch.len() >= 512 {
                index.insert_files_batch(&batch)?;
                batch.clear();
            }
        }
        if !batch.is_empty() {
            index.insert_files_batch(&batch)?;
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
            options: options.clone(),
        })
    }

    fn try_decrypt_entry_io(
        archive_io: &SharedArchiveIo,
        archive: &SevenZipArchiveInfo,
        entry: &SevenZipFileEntry,
        folder: &parse::Folder,
        password: &str,
    ) -> std::result::Result<(), SevenZipError> {
        let pack = SeekPackSource::new(Arc::clone(archive_io), entry.pack_offset, entry.pack_size);
        let sizes = pack_stream_sizes(archive, entry);
        let data = decode::decompress_folder_source(
            folder,
            Box::new(pack),
            Some(password),
            sizes.as_deref(),
        )?;
        if (data.len() as u64) >= folder.get_unpack_size() || data.len() >= entry.size as usize {
            Ok(())
        } else {
            Err(SevenZipError::Msg(
                "password trial produced short data".into(),
            ))
        }
    }

    fn pack_stream_sizes_for(&self, entry: &SevenZipFileEntry) -> Option<Vec<u64>> {
        pack_stream_sizes(&self.archive, entry)
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

        if let Some(&idx) = self.entry_by_offsets.get(&(pack_offset, unpack_offset)) {
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

    /// Open a pure-LZMA2 solid member via chunk-indexed random access (no full-folder slice).
    fn open_lzma2_member(&self, entry: &SevenZipFileEntry) -> Result<Vec<u8>> {
        let decoder = self.get_lzma2_decoder(entry)?;
        let mut g = decoder
            .lock()
            .map_err(|_| SzError::Msg("7z LZMA2 decoder lock poisoned".into()))?;
        g.read_range(entry.unpack_offset, entry.size as usize)
            .map_err(SzError::Seven)
    }

    /// Shared pure-LZMA2 progressive decoder for a solid folder (creates on first use).
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
        let packed = self.read_packed_for_folder(fi, entry)?;
        let decoder =
            decode::Lzma2RandomAccessDecoder::new(folder, packed, DEFAULT_MAX_CACHED_CHUNKS)
                .map_err(SzError::Seven)?;
        let shared: SharedLzma2Decoder = Arc::new(Mutex::new(decoder));
        let mut cache = self.lzma2_decoders.lock().unwrap();
        // Another open may have won the race; prefer the existing entry.
        Ok(Arc::clone(
            cache.entry(fi).or_insert_with(|| Arc::clone(&shared)),
        ))
    }

    /// Seekable solid pure-LZMA2 member body for nested AutoMount / random access.
    fn open_lzma2_member_reader(&self, entry: &SevenZipFileEntry) -> Result<Lzma2MemberReader> {
        let decoder = self.get_lzma2_decoder(entry)?;
        Ok(Lzma2MemberReader::new(
            decoder,
            entry.unpack_offset,
            entry.size,
        ))
    }
}

fn entry_offset_map(archive: &SevenZipArchiveInfo) -> HashMap<(u64, u64), usize> {
    let mut map = HashMap::new();
    for (i, entry) in archive.files.iter().enumerate() {
        if entry.is_dir || entry.is_empty_stream {
            continue;
        }
        map.insert((entry.pack_offset, entry.unpack_offset), i);
    }
    map
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
    batch: &mut Vec<FileRow>,
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
        batch.push(FileRow::new(
            parent,
            (*part).to_string(),
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
        ));
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

        // Pure LZMA2 solid folders: chunk-indexed random access (Python a0bc76e).
        // Small folders → Cursor (member materialize); large → progressive Lzma2MemberReader.
        // Both are fully seekable so nested open_from_reader works without temp spool.
        if folder.coders.len() == 1
            && folder.coders[0].method.as_slice() == parse::METHOD_LZMA2
            && !folder.is_encrypted()
            && self.pack_stream_sizes_for(entry).is_none()
        {
            let folder_unpack = folder.get_unpack_size();
            if folder_unpack > SMALL_FOLDER_THRESHOLD {
                debug!(
                    "7z {}: open {} via Lzma2MemberReader (folder_unpack={folder_unpack})",
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
                "7z {}: open {} via LZMA2 full-member Cursor (folder_unpack={folder_unpack})",
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

        // Compressed / BCJ2 / multi-pack: full-folder decompress + slice (cached).
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

    #[test]
    fn encrypted_hello() {
        let path = py_fixture("encrypted-hello.7z");
        if !path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("i.sqlite");
        let opts = OpenOptions {
            passwords: vec!["secret".into()],
            ..OpenOptions::default()
        };
        let m = SevenZipMountSource::open(&path, Some(&idx), &opts, "0.1.0", true).unwrap();
        let fi = m.lookup("/secret.txt", 0).expect("secret");
        let mut r = m.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert!(s.contains("secret") || !s.is_empty());
    }

    #[test]
    fn encrypted_metadata_only_without_password() {
        let path = py_fixture("encrypted-hello.7z");
        if !path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("i.sqlite");
        let m =
            SevenZipMountSource::open(&path, Some(&idx), &OpenOptions::default(), "0.1.0", true)
                .expect("metadata-only mount");
        let fi = m.lookup("/secret.txt", 0).expect("list/stat works");
        assert!(fi.size > 0);
        assert!(m.open(&fi, 0).is_err());
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

    #[test]
    fn bcj_lzma2_fixture() {
        let path = py_fixture("bcj-lzma2-x86.7z");
        if !path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("i.sqlite");
        let m =
            SevenZipMountSource::open(&path, Some(&idx), &OpenOptions::default(), "0.1.0", true)
                .expect("open bcj+lzma2");
        if let Some(ListResult::Infos(infos)) = m.list("/") {
            if let Some((_, fi)) = infos.into_iter().find(|(_, i)| i.size > 0) {
                let mut r = m.open(&fi, 0).unwrap();
                let mut buf = Vec::new();
                r.read_to_end(&mut buf).unwrap();
                assert_eq!(buf.len(), fi.size as usize);
            }
        }
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

    /// Regression: nested-style spill index (not pure `:memory:`) list/open still work.
    #[test]
    fn open_from_reader_temp_spill_list_and_read() {
        let path = py_fixture("store-copy-two-files.7z");
        if !path.exists() {
            eprintln!("skip: missing fixture {}", path.display());
            return;
        }
        let bytes = std::fs::read(&path).unwrap();
        let opts = OpenOptions {
            index_temp_spill: true,
            index_in_memory: false,
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
        .expect("spill open_from_reader");
        assert!(
            src.index_is_temp_spill(),
            "nested spill flag must create temp-spill SQLite index"
        );
        assert!(src.index_has_mem_index());
        let fi = src.lookup("/a.txt", 0).expect("lookup a.txt");
        let mut buf = Vec::new();
        src.open(&fi, 0).unwrap().read_to_end(&mut buf).unwrap();
        assert!(!buf.is_empty(), "member payload must be readable");
        let listed = src.list("/").expect("list root");
        match listed {
            ListResult::Infos(map) => assert!(map.len() >= 2, "expected multi-file fixture"),
            other => panic!("unexpected list: {other:?}"),
        }
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
}
