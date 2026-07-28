//! Compression backends (Phases 3–5 + stream codecs).
//!
//! * **gzip** — G3 Tier B seekable checkpoints + Tier C seek-index blob import/export (`gzip_seek`).
//! * **zstd** — multi-frame seek map + seekable-format seek table + Python
//!   `zstdblocks` offset-map import/export; single-frame full decode.
//! * **lz4** — frame block index (independent blocks; dependent → frame decode);
//!   `open_seekable_lz4_with_threads` for `-P` (parallel independent-block size discovery).
//! * **lzip** — multimember walk via trailer `member_size`;
//!   `open_seekable_lzip_with_threads` accepts `-P` (decode sequential for now).
//! * **lzo** — LZOP block index via liblzo2 (optional at runtime);
//!   `open_seekable_lzo_with_threads` accepts `-P` (decode sequential for now).
//! * **bzip2** — one-shot decode into RAM/temp; optional multi-block parallel decode (`-P`).
//! * **xz** — one-shot decode; multi-stream parallel decode via `open_seekable_xz_with_threads`.
//! * **zstd** — multi-frame / seek table; `open_seekable_zstd_with_threads` for `-P`.
//! * **gzip** — seek checkpoints; multi-member parallel decode (best-effort) + `-P` threads.
//! * **.Z / lzma / zlib** — one-shot decode into RAM/temp (`SeekableBody`);
//!   `open_seekable_*_with_threads` accepts `-P` (decode sequential: single stream).
//! * **lrzip** — detect magic/extension; materialize via external `lrzip`/`lrunzip` CLI
//!   when present. Python leaves pure RA on libarchive; factory falls back to
//!   `try_open_lrzip_via_libarchive` when CLI is missing (no in-process decoder here).
//! * CLI/helpers still expose `materialize_*` for plain single-file mounts.
//! * [`ParallelizationSpec`] parses Python-style `-P` backend matrices.

mod bzip2_seek;
mod compress_z_seek;
mod gzip_seek;
mod lrzip_seek;
mod lz4_seek;
mod lzip_seek;
mod lzma_seek;
mod lzo_seek;
mod seekable_body;
mod split;
mod xz_seek;
mod zlib_seek;
mod zstd_seek;

pub use split::{
    check_for_split_file_in, check_for_split_file_in_folder, is_first_split_extension,
    joined_base_name, materialize_joined_parts, JoinedFile, SplitFileSet,
};

pub use bzip2_seek::{
    open_seekable_bzip2, open_seekable_bzip2_from_reader, open_seekable_bzip2_with_threads,
    open_seekable_bzip2_with_threads_from_reader,
};
pub use compress_z_seek::{open_seekable_compress_z, open_seekable_compress_z_with_threads};
pub use gzip_seek::{
    encode_gzip_seek_index_blob, import_seek_points, import_seek_points_with_mode,
    open_seekable_gzip, open_seekable_gzip_from_reader, open_seekable_gzip_with_imported_index,
    open_seekable_gzip_with_imported_index_from_reader, open_seekable_gzip_with_threads,
    open_seekable_gzip_with_threads_from_reader, parse_gzip_seek_index_blob,
    parse_indexed_gzip_index_blob, try_import_gzip_seek_blob, try_parallel_multi_member_decode,
    GzipSeekBlobFormat, GzipSeekIndexBlob, SeekableGzip, SeekableGzipReader, SharedSeekableGzip,
    DEFAULT_GZIP_SEEK_SPACING, GZIP_SEEK_INDEX_MAGIC, GZIP_SEEK_INDEX_VERSION,
    INDEXED_GZIP_INDEX_MAGIC, INDEXED_GZIP_INDEX_VERSION,
};
pub use lrzip_seek::{
    looks_like_lrzip, lrzip_available, lrzip_cli_available, materialize_lrzip, LRZIP_CLI_MISSING_MSG,
    LRZIP_MAGIC,
};
pub use lz4_seek::{open_seekable_lz4, open_seekable_lz4_with_threads, SeekableLz4};
pub use lzip_seek::{open_seekable_lzip, open_seekable_lzip_with_threads, SeekableLzip};
pub use lzma_seek::{open_seekable_lzma, open_seekable_lzma_with_threads};
pub use lzo_seek::{
    lzo_available, open_seekable_lzo, open_seekable_lzo_with_threads, SeekableLzo,
};
/// Re-export for `-P` / backend matrix parsing at the compress boundary.
pub use ratarmount_core::ParallelizationSpec;
pub use seekable_body::{
    body_looks_like_tar, DecodedBody, SeekRead, SeekableBody, DEFAULT_MEMORY_CAP,
};
pub use xz_seek::{
    open_seekable_xz, open_seekable_xz_from_reader, open_seekable_xz_with_threads,
    open_seekable_xz_with_threads_from_reader,
};
pub use zlib_seek::{looks_like_zlib_header, open_seekable_zlib, open_seekable_zlib_with_threads};
pub use zstd_seek::{
    build_seek_table_skippable, export_zstd_blocks, export_zstd_blocks_from_reader,
    open_seekable_zstd, open_seekable_zstd_from_reader, open_seekable_zstd_with_threads,
    open_seekable_zstd_with_threads_from_reader, open_seekable_zstd_with_zstd_blocks,
    open_seekable_zstd_with_zstd_blocks_from_reader, SeekableZstd,
};

use std::fs::File;
use std::io::{self, copy, BufReader, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use bzip2::read::BzDecoder;
use flate2::read::MultiGzDecoder;
use log::debug;
use tempfile::NamedTempFile;
use thiserror::Error;
use xz2::read::XzDecoder;

#[derive(Debug, Error)]
pub enum CompressError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, CompressError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompressionFormat {
    None,
    Gzip,
    Bzip2,
    Xz,
    Zstd,
    Lz4,
    Lzip,
    Lzo,
    CompressZ,
    Lzma,
    /// RFC 1950 zlib wrapper (e.g. `.zlib`).
    Zlib,
    /// lrzip (magic `LRZI\x00`; CLI materialize; factory may use libarchive fallback).
    Lrzip,
}

/// Detect compression from magic bytes, with extension fallback for ambiguous formats.
pub fn detect_compression(path: &Path) -> Result<CompressionFormat> {
    let mut f = File::open(path)?;
    let mut magic = [0u8; 16];
    let n = f.read(&mut magic)?;
    let by_magic = detect_compression_magic(&magic[..n])?;
    if by_magic != CompressionFormat::None {
        return Ok(by_magic);
    }
    Ok(detect_compression_extension(path).unwrap_or(CompressionFormat::None))
}

pub fn detect_compression_magic(magic: &[u8]) -> Result<CompressionFormat> {
    if magic.len() >= 2 && magic[0] == 0x1f && magic[1] == 0x8b {
        return Ok(CompressionFormat::Gzip);
    }
    // Unix compress (.Z): 1f 9d or 1f a0
    if magic.len() >= 2 && magic[0] == 0x1f && (magic[1] == 0x9d || magic[1] == 0xa0) {
        return Ok(CompressionFormat::CompressZ);
    }
    if magic.len() >= 3 && magic[0] == b'B' && magic[1] == b'Z' && magic[2] == b'h' {
        return Ok(CompressionFormat::Bzip2);
    }
    if magic.len() >= 6 && magic[..6] == *b"\xFD7zXZ\0" {
        return Ok(CompressionFormat::Xz);
    }
    if magic.len() >= 4 && magic[..4] == *b"\x28\xb5\x2f\xfd" {
        return Ok(CompressionFormat::Zstd);
    }
    // LZ4 frame magic 0x184D2204 LE, or skippable 0x184D2A5x
    if magic.len() >= 4 {
        let m = u32::from_le_bytes([magic[0], magic[1], magic[2], magic[3]]);
        if m == 0x184D_2204 || (m & 0xFFFF_FFF0) == 0x184D_2A50 {
            return Ok(CompressionFormat::Lz4);
        }
    }
    if magic.len() >= 4 && &magic[..4] == b"LZIP" {
        return Ok(CompressionFormat::Lzip);
    }
    // lrzip: LRZI + major version 0 (Python FID.LRZIP)
    if looks_like_lrzip(magic) {
        return Ok(CompressionFormat::Lrzip);
    }
    if magic.len() >= 9 && magic[..9] == *b"\x89LZO\x00\x0d\x0a\x1a\x0a" {
        return Ok(CompressionFormat::Lzo);
    }
    // LZMA Alone often starts with 0x5d 0x00 0x00 (lc/lp/pb + dict); leave to extension if unsure.
    if magic.len() >= 3 && magic[0] == 0x5d && magic[1] == 0x00 && magic[2] == 0x00 {
        return Ok(CompressionFormat::Lzma);
    }
    // zlib (RFC 1950): CMF/FLG checksum, common magics 78 01 / 78 9c / 78 da / 78 5e …
    if looks_like_zlib_header(magic) {
        return Ok(CompressionFormat::Zlib);
    }
    Ok(CompressionFormat::None)
}

/// Extension-only detection (used when magic is absent/ambiguous).
pub fn detect_compression_extension(path: &Path) -> Option<CompressionFormat> {
    let name = path.file_name()?.to_str()?.to_ascii_lowercase();
    if name.ends_with(".lz4") {
        return Some(CompressionFormat::Lz4);
    }
    if name.ends_with(".lzip") || name.ends_with(".lz") {
        return Some(CompressionFormat::Lzip);
    }
    if name.ends_with(".lzo") || name.ends_with(".lzop") {
        return Some(CompressionFormat::Lzo);
    }
    if name.ends_with(".lzma") {
        return Some(CompressionFormat::Lzma);
    }
    if name.ends_with(".zlib") || name.ends_with(".zz") {
        return Some(CompressionFormat::Zlib);
    }
    if name.ends_with(".lrz") || name.ends_with(".lrzip") {
        return Some(CompressionFormat::Lrzip);
    }
    // Bare `.Z` / `.z` — careful: `.gz` already handled by magic; `.tz` etc. rare.
    if name.ends_with(".z")
        && !name.ends_with(".gz")
        && !name.ends_with(".bz")
        && !name.ends_with(".xz")
        && !name.ends_with(".lz")
        && !name.ends_with(".tz")
        && !name.ends_with(".zlib")
        && !name.ends_with(".lrz")
    {
        return Some(CompressionFormat::CompressZ);
    }
    None
}

/// TAR magic at offset 257: "ustar" or GNU.
pub fn looks_like_tar(path: &Path) -> Result<bool> {
    let mut f = File::open(path)?;
    if f.seek(SeekFrom::Start(257)).is_err() {
        return Ok(false);
    }
    let mut magic = [0u8; 5];
    let n = f.read(&mut magic)?;
    Ok(n == 5 && (&magic == b"ustar" || &magic == b"GNU  " || magic.starts_with(b"ustar")))
}

/// After decompression, check if buffer/path looks like TAR.
pub fn looks_like_tar_file(path: &Path) -> Result<bool> {
    looks_like_tar(path)
}

/// Placeholder for future seekable decoders.
pub trait SeekableDecoder: Read + Seek + Send {
    fn format(&self) -> CompressionFormat;
}

fn materialize_from_reader(
    mut decoder: impl Read,
    label: &str,
    path: &Path,
) -> Result<(NamedTempFile, u64)> {
    let mut tmp = NamedTempFile::new()?;
    let n = copy(&mut decoder, &mut tmp)?;
    tmp.flush()?;
    debug!(
        "materialized {} {} -> {} ({} bytes)",
        label,
        path.display(),
        tmp.path().display(),
        n
    );
    tmp.as_file().seek(SeekFrom::Start(0))?;
    Ok((tmp, n))
}

/// Decompress gzip into a persistent temp file; returns size.
pub fn materialize_gzip(path: &Path) -> Result<(NamedTempFile, u64)> {
    let input = File::open(path)?;
    let decoder = MultiGzDecoder::new(BufReader::new(input));
    materialize_from_reader(decoder, "gzip", path)
}

/// Decompress bzip2 into a persistent temp file.
pub fn materialize_bzip2(path: &Path) -> Result<(NamedTempFile, u64)> {
    let input = File::open(path)?;
    let decoder = BzDecoder::new(BufReader::new(input));
    materialize_from_reader(decoder, "bzip2", path)
}

/// Decompress xz into a persistent temp file.
pub fn materialize_xz(path: &Path) -> Result<(NamedTempFile, u64)> {
    let input = File::open(path)?;
    let decoder = XzDecoder::new(BufReader::new(input));
    materialize_from_reader(decoder, "xz", path)
}

/// Decompress zstd into a persistent temp file.
pub fn materialize_zstd(path: &Path) -> Result<(NamedTempFile, u64)> {
    let input = File::open(path)?;
    let decoder = zstd::stream::read::Decoder::new(BufReader::new(input))?;
    materialize_from_reader(decoder, "zstd", path)
}

fn materialize_from_body(
    path: &Path,
    body: Arc<dyn SeekableBody>,
    label: &str,
) -> Result<(NamedTempFile, u64)> {
    let mut reader = body.open_reader().map_err(CompressError::from)?;
    materialize_from_reader(&mut reader, label, path)
}

/// Materialize any known compressed format (not `None`).
pub fn materialize(path: &Path, format: CompressionFormat) -> Result<(NamedTempFile, u64)> {
    match format {
        CompressionFormat::None => Err(CompressError::Unsupported("no compression")),
        CompressionFormat::Gzip => materialize_gzip(path),
        CompressionFormat::Bzip2 => materialize_bzip2(path),
        CompressionFormat::Xz => materialize_xz(path),
        CompressionFormat::Zstd => materialize_zstd(path),
        CompressionFormat::Lz4 => materialize_from_body(path, open_seekable_lz4(path)?, "lz4"),
        CompressionFormat::Lzip => materialize_from_body(path, open_seekable_lzip(path)?, "lzip"),
        CompressionFormat::Lzo => materialize_from_body(path, open_seekable_lzo(path)?, "lzo"),
        CompressionFormat::CompressZ => {
            materialize_from_body(path, open_seekable_compress_z(path)?, "compress-z")
        }
        CompressionFormat::Lzma => materialize_from_body(path, open_seekable_lzma(path)?, "lzma"),
        CompressionFormat::Zlib => materialize_from_body(path, open_seekable_zlib(path)?, "zlib"),
        CompressionFormat::Lrzip => materialize_lrzip(path),
    }
}

/// True if the archive path name suggests a compressed TAR (before looking at body).
pub fn name_suggests_compressed_tar(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let l = name.to_ascii_lowercase();
    l.ends_with(".tar.gz")
        || l.ends_with(".tgz")
        || l.ends_with(".tar.gzip")
        || l.ends_with(".tar.bz2")
        || l.ends_with(".tbz2")
        || l.ends_with(".tbz")
        || l.ends_with(".tar.xz")
        || l.ends_with(".txz")
        || l.ends_with(".tar.zst")
        || l.ends_with(".tar.zstd")
        || l.ends_with(".tzst")
        || l.ends_with(".tar.lz4")
        || l.ends_with(".tlz4")
        || l.ends_with(".tar.lzip")
        || l.ends_with(".tar.lz")
        || l.ends_with(".tar.lzo")
        || l.ends_with(".tar.lzma")
        || l.ends_with(".tar.zlib")
        || l.ends_with(".tar.lrz")
        || l.ends_with(".tar.lrzip")
        || l.ends_with(".tar.z")
        || l.ends_with(".taz")
}

/// Zero-filled virtual file (sparse holes).
pub struct ZeroFile {
    size: u64,
    pos: u64,
}

impl ZeroFile {
    pub fn new(size: u64) -> Self {
        Self { size, pos: 0 }
    }
}

impl Read for ZeroFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.size {
            return Ok(0);
        }
        let remain = (self.size - self.pos) as usize;
        let n = remain.min(buf.len());
        buf[..n].fill(0);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for ZeroFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::End(o) => self.size as i64 + o,
            SeekFrom::Current(o) => self.pos as i64 + o,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

/// One logical segment of a sparse/desparsed file view.
#[derive(Debug, Clone)]
pub enum FileSegment {
    /// Read `len` bytes from `file_offset` in the underlying archive.
    Data { file_offset: u64, len: u64 },
    /// Synthesize `len` zero bytes (sparse hole).
    Zero { len: u64 },
}

/// Seekable reader over mixed data + zero hole segments (GNU sparse TAR open path).
pub struct SegmentedFile<R> {
    inner: R,
    segments: Vec<FileSegment>,
    /// Cumulative logical sizes: cumsizes[i] = start of segments[i].
    cumsizes: Vec<u64>,
    pos: u64,
}

impl<R: Read + Seek> SegmentedFile<R> {
    pub fn new(inner: R, segments: Vec<FileSegment>) -> Self {
        let segments: Vec<_> = segments
            .into_iter()
            .filter(|s| match s {
                FileSegment::Data { len, .. } | FileSegment::Zero { len } => *len > 0,
            })
            .collect();
        let mut cumsizes = vec![0u64];
        for s in &segments {
            let len = match s {
                FileSegment::Data { len, .. } | FileSegment::Zero { len } => *len,
            };
            cumsizes.push(cumsizes.last().copied().unwrap_or(0) + len);
        }
        Self {
            inner,
            segments,
            cumsizes,
            pos: 0,
        }
    }

    pub fn len(&self) -> u64 {
        *self.cumsizes.last().unwrap_or(&0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<R: Read + Seek> Read for SegmentedFile<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.len() {
            return Ok(0);
        }
        let mut idx = 0usize;
        while idx + 1 < self.cumsizes.len() && self.cumsizes[idx + 1] <= self.pos {
            idx += 1;
        }
        if idx >= self.segments.len() {
            return Ok(0);
        }
        let into = self.pos - self.cumsizes[idx];
        match self.segments[idx] {
            FileSegment::Data { file_offset, len } => {
                let avail = (len - into) as usize;
                let n = avail.min(buf.len());
                self.inner.seek(SeekFrom::Start(file_offset + into))?;
                let got = self.inner.read(&mut buf[..n])?;
                self.pos += got as u64;
                Ok(got)
            }
            FileSegment::Zero { len } => {
                let avail = (len - into) as usize;
                let n = avail.min(buf.len());
                buf[..n].fill(0);
                self.pos += n as u64;
                Ok(n)
            }
        }
    }
}

impl<R: Read + Seek> Seek for SegmentedFile<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::End(o) => self.len() as i64 + o,
            SeekFrom::Current(o) => self.pos as i64 + o,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

/// Shared seekable archive fd for single-threaded FUSE (no `try_clone` per open).
pub struct SharedArchiveFile {
    inner: std::sync::Mutex<std::fs::File>,
}

impl SharedArchiveFile {
    pub fn new(file: std::fs::File) -> Self {
        Self {
            inner: std::sync::Mutex::new(file),
        }
    }

    /// View of `[file_offset, file_offset+len)` with independent logical position.
    pub fn region(self: &std::sync::Arc<Self>, file_offset: u64, len: u64) -> SharedRegion {
        SharedRegion {
            shared: std::sync::Arc::clone(self),
            file_offset,
            len,
            pos: 0,
        }
    }
}

/// Random-access slice of a [`SharedArchiveFile`].
pub struct SharedRegion {
    shared: std::sync::Arc<SharedArchiveFile>,
    file_offset: u64,
    len: u64,
    pos: u64,
}

impl Read for SharedRegion {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let max = ((self.len - self.pos) as usize).min(buf.len());
        let mut guard = self.shared.inner.lock().expect("archive fd mutex");
        guard.seek(SeekFrom::Start(self.file_offset + self.pos))?;
        let n = guard.read(&mut buf[..max])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SharedRegion {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::End(o) => self.len as i64 + o,
            SeekFrom::Current(o) => self.pos as i64 + o,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

/// Stenciled view over one underlying reader (subset of Python StenciledFile).
pub struct StenciledFile<R> {
    inner: R,
    regions: Vec<(u64, u64)>,
    cumsizes: Vec<u64>,
    pos: u64,
}

impl<R: Read + Seek> StenciledFile<R> {
    pub fn new(inner: R, regions: Vec<(u64, u64)>) -> Self {
        let regions: Vec<_> = regions.into_iter().filter(|(_, len)| *len > 0).collect();
        let mut cumsizes = vec![0u64];
        for (_, len) in &regions {
            cumsizes.push(cumsizes.last().copied().unwrap_or(0) + len);
        }
        Self {
            inner,
            regions,
            cumsizes,
            pos: 0,
        }
    }

    pub fn len(&self) -> u64 {
        *self.cumsizes.last().unwrap_or(&0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<R: Read + Seek> Read for StenciledFile<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.len() {
            return Ok(0);
        }
        let mut idx = 0usize;
        while idx + 1 < self.cumsizes.len() && self.cumsizes[idx + 1] <= self.pos {
            idx += 1;
        }
        if idx >= self.regions.len() {
            return Ok(0);
        }
        let (file_off, region_len) = self.regions[idx];
        let region_start = self.cumsizes[idx];
        let into_region = self.pos - region_start;
        let avail = (region_len - into_region) as usize;
        let n = avail.min(buf.len());
        self.inner.seek(SeekFrom::Start(file_off + into_region))?;
        let got = self.inner.read(&mut buf[..n])?;
        self.pos += got as u64;
        Ok(got)
    }
}

impl<R: Read + Seek> Seek for StenciledFile<R> {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::End(o) => self.len() as i64 + o,
            SeekFrom::Current(o) => self.pos as i64 + o,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

/// Strip one compression suffix for display names (`.gz`, `.gzip`, …).
pub fn strip_compression_suffix(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    // Longer compound suffixes first.
    for (suf, replacement) in [
        (".tar.gz", ".tar"),
        (".tar.gzip", ".tar"),
        (".tar.bz2", ".tar"),
        (".tar.xz", ".tar"),
        (".tar.zst", ".tar"),
        (".tar.zstd", ".tar"),
        (".tar.lz4", ".tar"),
        (".tar.lzip", ".tar"),
        (".tar.lz", ".tar"),
        (".tar.lzo", ".tar"),
        (".tar.lzma", ".tar"),
        (".tar.zlib", ".tar"),
        (".tar.lrzip", ".tar"),
        (".tar.lrz", ".tar"),
        (".tar.z", ".tar"),
        (".tgz", ".tar"),
        (".taz", ".tar"),
        (".tbz2", ".tar"),
        (".tbz", ".tar"),
        (".txz", ".tar"),
        (".tzst", ".tar"),
        (".tlz4", ".tar"),
        (".gzip", ""),
        (".gz", ""),
        (".bz2", ""),
        (".xz", ""),
        (".zst", ""),
        (".zstd", ""),
        (".lz4", ""),
        (".lzip", ""),
        (".lzop", ""),
        (".lzo", ""),
        (".lzma", ""),
        (".zlib", ""),
        (".zz", ""),
        (".lrzip", ""),
        (".lrz", ""),
        (".lz", ""),
        (".z", ""),
    ] {
        if lower.ends_with(suf) {
            let base = &name[..name.len() - suf.len()];
            if replacement.is_empty() {
                return base.to_string();
            }
            return format!("{base}{replacement}");
        }
    }
    name.to_string()
}

/// Path helpers for materialised bodies.
pub fn path_buf(tmp: &NamedTempFile) -> PathBuf {
    tmp.path().to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn stencil_concat() {
        let data = b"abcdefghij";
        let mut s = StenciledFile::new(Cursor::new(data.as_slice()), vec![(0, 3), (5, 3)]);
        let mut out = Vec::new();
        s.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"abcfgh");
    }

    #[test]
    fn zero_file() {
        let mut z = ZeroFile::new(4);
        let mut buf = [1u8; 4];
        assert_eq!(z.read(&mut buf).unwrap(), 4);
        assert_eq!(buf, [0, 0, 0, 0]);
    }

    fn py_test(name: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        PathBuf::from(root).join("tests").join(name)
    }

    fn assert_simple_body(path: &Path, format: CompressionFormat) {
        if !path.exists() {
            eprintln!("skip: missing {}", path.display());
            return;
        }
        let (tmp, size) = materialize(path, format).unwrap();
        assert_eq!(size, 12, "{format:?}");
        let text = std::fs::read_to_string(tmp.path()).unwrap();
        assert_eq!(text, "foo fighter\n", "{format:?}");
    }

    #[test]
    fn materialize_simple_all_codecs() {
        assert_simple_body(&py_test("simple.gz"), CompressionFormat::Gzip);
        assert_simple_body(&py_test("simple.bz2"), CompressionFormat::Bzip2);
        assert_simple_body(&py_test("simple.xz"), CompressionFormat::Xz);
        assert_simple_body(&py_test("simple.zst"), CompressionFormat::Zstd);
        assert_simple_body(&py_test("simple.lz4"), CompressionFormat::Lz4);
        assert_simple_body(&py_test("simple.lzip"), CompressionFormat::Lzip);
        assert_simple_body(&py_test("simple.Z"), CompressionFormat::CompressZ);
        assert_simple_body(&py_test("simple.lzma"), CompressionFormat::Lzma);
        if lzo_available() {
            assert_simple_body(&py_test("simple.lzo"), CompressionFormat::Lzo);
        }
    }

    #[test]
    fn detect_magics() {
        assert_eq!(
            detect_compression_magic(&[0x1f, 0x8b, 0x08]).unwrap(),
            CompressionFormat::Gzip
        );
        assert_eq!(
            detect_compression_magic(b"BZh9").unwrap(),
            CompressionFormat::Bzip2
        );
        assert_eq!(
            detect_compression_magic(b"\xFD7zXZ\0").unwrap(),
            CompressionFormat::Xz
        );
        assert_eq!(
            detect_compression_magic(&[0x28, 0xb5, 0x2f, 0xfd]).unwrap(),
            CompressionFormat::Zstd
        );
        assert_eq!(
            detect_compression_magic(&[0x04, 0x22, 0x4d, 0x18]).unwrap(),
            CompressionFormat::Lz4
        );
        assert_eq!(
            detect_compression_magic(b"LZIP\x01").unwrap(),
            CompressionFormat::Lzip
        );
        assert_eq!(
            detect_compression_magic(&[0x1f, 0x9d, 0x90]).unwrap(),
            CompressionFormat::CompressZ
        );
        assert_eq!(
            detect_compression_magic(&[0x5d, 0x00, 0x00]).unwrap(),
            CompressionFormat::Lzma
        );
        assert_eq!(
            detect_compression_magic(b"\x89LZO\x00\x0d\x0a\x1a\x0a").unwrap(),
            CompressionFormat::Lzo
        );
        assert_eq!(
            detect_compression_magic(b"LRZI\x00\x06").unwrap(),
            CompressionFormat::Lrzip
        );
    }

    #[test]
    fn detect_lrzip_extension() {
        assert_eq!(
            detect_compression_extension(Path::new("archive.lrz")),
            Some(CompressionFormat::Lrzip)
        );
        assert_eq!(
            detect_compression_extension(Path::new("archive.lrzip")),
            Some(CompressionFormat::Lrzip)
        );
    }

    #[test]
    fn materialize_lrzip_skips_or_runs() {
        let path = py_test("simple.lrz");
        if !path.exists() {
            return;
        }
        if !lrzip_available() {
            let err = materialize(&path, CompressionFormat::Lrzip).unwrap_err();
            assert!(
                err.to_string().contains("lrzip not installed"),
                "got: {err}"
            );
            return;
        }
        assert_simple_body(&path, CompressionFormat::Lrzip);
    }

    #[test]
    fn strip_suffix() {
        assert_eq!(strip_compression_suffix("a.gz"), "a");
        assert_eq!(strip_compression_suffix("a.tgz"), "a.tar");
        assert_eq!(strip_compression_suffix("a.tar.bz2"), "a.tar");
        assert_eq!(strip_compression_suffix("a.lz4"), "a");
        assert_eq!(strip_compression_suffix("a.tar.lz4"), "a.tar");
        assert_eq!(strip_compression_suffix("a.lzip"), "a");
    }
}
