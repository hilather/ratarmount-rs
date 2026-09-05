//! Seekable zstd: multi-frame restart points + zstd seekable-format seek table
//! + Python `zstdblocks` offset-map import.
//!
//! User-facing guide (producer recipes, open priority): `docs/zstd-random-access.md`.
//!
//! Priority when opening (without an imported map):
//! 1. **Seek table** (zstd seekable format skippable footer, magic `0x8F92EAB1`) —
//!    gives compressed/decompressed sizes without decompressing during map build.
//! 2. **Multi-frame scan** — walk concatenated zstd frames; random access restores
//!    only the covering frame (cached per reader), never the full single-frame buffer.
//! 3. **Full decode** fallback for single large frames without a seek table.
//!
//! **Python `zstdblocks` parity** ([`open_seekable_zstd_with_zstd_blocks`] /
//! [`SeekableZstd::open_with_zstd_blocks`]): pairs are
//! `(blockoffset, dataoffset) = (compressed_offset, uncompressed_offset)`, matching
//! `indexed_zstd.IndexedZstdFile.block_offsets()` / SQLite `zstdblocks`. The last
//! pair is an EOF sentinel (totals). Import skips seek-table / multi-frame rescan.
//! Export via [`export_zstd_blocks`] / [`SeekableZstd::zstd_blocks`].
//!
//! **Density:** the live map is a sealed `Vec<FrameInfo>` (parallel offset/size
//! fields, no per-frame `HashMap`). `Vec<(u64, u64)>` exists only at the
//! import/export API to match Python/SQLite `zstdblocks`; it is converted into
//! `FrameInfo` rows on open and is not the hot-path store.
//!
//! Thread hint (`open_seekable_zstd_with_threads` / Python `-P` zstd backend):
//! * Multi-frame maps keep **per-frame** random access; frames are independent, so
//!   concurrent readers already decode different frames without a shared lock.
//! * When falling back to a full single-buffer decode of multi-frame input and
//!   `threads > 1`, frames are decompressed in parallel (the public `zstd` crate
//!   exposes multi-thread **encode** via `zstdmt`/`NbWorkers`; frame-level
//!   parallel **decode** is implemented here instead).
//!
//! Open paths:
//! * **Path-based** — reopen independent FDs per reader (`File::open`).
//! * **Reader-based** — any `Read + Seek + Send` (e.g. HTTP Range / in-memory
//!   `Cursor`); shared under a mutex so random Range reads drive frame decode.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

use ratarmount_core::ParallelizationSpec;

use crate::seekable_body::{DecodedBody, SeekRead, SeekableBody, DEFAULT_MEMORY_CAP};
use crate::{CompressError, Result};

/// Open zstd as a seekable body (multi-frame map, seek table, or full decode).
pub fn open_seekable_zstd(path: impl AsRef<Path>) -> Result<Arc<dyn SeekableBody>> {
    open_seekable_zstd_with_threads(path, 1)
}

/// Open zstd with a thread hint (Python `-P` / zstd backend).
///
/// `threads == 0` means “use CPU count”. See module docs for how threads are used.
pub fn open_seekable_zstd_with_threads(
    path: impl AsRef<Path>,
    threads: u32,
) -> Result<Arc<dyn SeekableBody>> {
    let threads = ParallelizationSpec::resolve_zero(threads).max(1);
    SeekableZstd::open_with_threads(path, threads)
}

/// Open seekable zstd from a seekable compressed reader.
///
/// `archive_label` is stored for logs / [`SeekableBody::path`] (URL or virtual name).
pub fn open_seekable_zstd_from_reader<R>(
    reader: R,
    archive_label: impl AsRef<Path>,
) -> Result<Arc<dyn SeekableBody>>
where
    R: Read + Seek + Send + 'static,
{
    open_seekable_zstd_with_threads_from_reader(reader, 1, archive_label)
}

/// Open seekable zstd from a seekable compressed reader with a thread hint.
///
/// See [`SeekableZstd::open_with_threads_from_reader`].
pub fn open_seekable_zstd_with_threads_from_reader<R>(
    reader: R,
    threads: u32,
    archive_label: impl AsRef<Path>,
) -> Result<Arc<dyn SeekableBody>>
where
    R: Read + Seek + Send + 'static,
{
    let threads = ParallelizationSpec::resolve_zero(threads).max(1);
    SeekableZstd::open_with_threads_from_reader(reader, threads, archive_label)
}

/// Open seekable zstd using a Python-compatible `zstdblocks` offset map.
///
/// `blocks` are `(blockoffset, dataoffset)` = `(compressed_offset, uncompressed_offset)`
/// pairs (last entry is the EOF sentinel). Skips seek-table / multi-frame rescan.
pub fn open_seekable_zstd_with_zstd_blocks(
    path: impl AsRef<Path>,
    threads: u32,
    blocks: &[(u64, u64)],
) -> Result<Arc<dyn SeekableBody>> {
    let body = SeekableZstd::open_with_zstd_blocks(path, threads, blocks)?;
    Ok(body as Arc<dyn SeekableBody>)
}

/// Open seekable zstd from a reader using a Python-compatible `zstdblocks` map.
///
/// See [`SeekableZstd::open_with_zstd_blocks_from_reader`].
pub fn open_seekable_zstd_with_zstd_blocks_from_reader<R>(
    reader: R,
    threads: u32,
    archive_label: impl AsRef<Path>,
    blocks: &[(u64, u64)],
) -> Result<Arc<dyn SeekableBody>>
where
    R: Read + Seek + Send + 'static,
{
    let body =
        SeekableZstd::open_with_zstd_blocks_from_reader(reader, threads, archive_label, blocks)?;
    Ok(body as Arc<dyn SeekableBody>)
}

/// Scan a multi-frame / seek-table zstd file and export Python `zstdblocks` pairs.
///
/// See [`export_zstd_blocks_from_reader`].
pub fn export_zstd_blocks(path: impl AsRef<Path>) -> Result<Vec<(u64, u64)>> {
    let mut file = File::open(path)?;
    export_zstd_blocks_from_reader(&mut file)
}

/// Build Python `zstdblocks` pairs from a seekable compressed stream.
///
/// Prefers an official seek-table footer when present; otherwise multi-frame scan.
/// Last pair is the EOF sentinel (totals), matching `indexed_zstd`.
pub fn export_zstd_blocks_from_reader<R: Read + Seek>(reader: &mut R) -> Result<Vec<(u64, u64)>> {
    if let Ok((frames, uncomp)) = try_load_seek_table_from_reader(reader) {
        if !frames.is_empty() {
            return Ok(zstd_blocks_from_frames(&frames, uncomp));
        }
    }
    let (frames, uncomp) = build_frame_map_from_reader(reader)?;
    Ok(zstd_blocks_from_frames(&frames, uncomp))
}

/// One zstd data frame with concrete sizes (`scan_zstd_frames` errors if unknown).
///
/// Not a copy of the private [`FrameInfo`] used by [`SeekableZstd`] (those sizes are `Option`).
#[derive(Clone, Debug)]
pub struct ZstdFrameInfo {
    pub compressed_offset: u64,
    pub uncompressed_offset: u64,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
}

/// Frame map for persist / last-N rewrite. Every size is a concrete `u64`.
#[derive(Clone, Debug)]
pub struct ZstdFrameMap {
    pub frames: Vec<ZstdFrameInfo>,
    /// Byte range of the skippable seek-table frame if present `[start, file_len)`.
    pub seek_table: Option<std::ops::Range<u64>>,
}

/// Initial per-frame window for streaming scan. Doubled until the frame fits; no 64 MiB cap.
const SCAN_FRAME_WINDOW_START: usize = 256 * 1024;

/// Scan concatenated zstd frames without slurping a multi-frame file.
///
/// Prefers an official seek-table footer when present; otherwise walks frames
/// with a growing per-frame window (`ZSTD_findFrameCompressedSize`).
pub fn scan_zstd_frames<R: Read + Seek>(reader: &mut R) -> Result<ZstdFrameMap> {
    if let Ok((frames, _)) = try_load_seek_table_from_reader(reader) {
        if !frames.is_empty() {
            let seek_table = Some(seek_table_span_from_footer(reader)?);
            return Ok(ZstdFrameMap {
                frames: public_frames_from_private(&frames)?,
                seek_table,
            });
        }
    }
    scan_zstd_frames_walk(reader)
}

/// [`scan_zstd_frames`] from a filesystem path.
pub fn scan_zstd_frames_path(path: &Path) -> Result<ZstdFrameMap> {
    let mut file = File::open(path)?;
    scan_zstd_frames(&mut file)
}

/// Decode frames `[from_idx..]` into `out` (Cursor, tempfile, …). Last-N only.
pub fn decode_zstd_frames_to<R, W>(
    reader: &mut R,
    map: &ZstdFrameMap,
    from_idx: usize,
    out: &mut W,
) -> Result<u64>
where
    R: Read + Seek,
    W: Write,
{
    if from_idx > map.frames.len() {
        return Err(CompressError::Msg(format!(
            "decode from_idx {from_idx} past {} frames",
            map.frames.len()
        )));
    }
    let mut written = 0u64;
    for frame in &map.frames[from_idx..] {
        reader.seek(SeekFrom::Start(frame.compressed_offset))?;
        // Limit to this frame so the decoder cannot pull the next frame's bytes.
        let mut limited = reader.by_ref().take(frame.compressed_size);
        let mut decoder = zstd::stream::read::Decoder::new(&mut limited)
            .map_err(|e| CompressError::Msg(e.to_string()))?
            .single_frame();
        written += io::copy(&mut decoder, out)?;
    }
    Ok(written)
}

/// Streaming encode of one zstd frame. Returns `(compressed_len, plain_len)`.
pub fn encode_zstd_frame_to<R, W>(mut src: R, dst: &mut W, level: i32) -> Result<(u64, u64)>
where
    R: Read,
    W: Write,
{
    let mut encoder = zstd::stream::write::Encoder::new(
        CountingWriter {
            inner: dst,
            written: 0,
        },
        level,
    )
    .map_err(|e| CompressError::Msg(e.to_string()))?;
    let plain_len = io::copy(&mut src, &mut encoder)?;
    let counted = encoder
        .finish()
        .map_err(|e| CompressError::Msg(e.to_string()))?;
    Ok((counted.written, plain_len))
}

/// Convenience for tests / tiny frames only — not the persist path.
pub fn encode_zstd_frame(data: &[u8], level: i32) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    encode_zstd_frame_to(data, &mut out, level)?;
    Ok(out)
}

struct CountingWriter<W> {
    inner: W,
    written: u64,
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.written += n as u64;
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn public_frames_from_private(frames: &[FrameInfo]) -> Result<Vec<ZstdFrameInfo>> {
    frames
        .iter()
        .map(|f| {
            let compressed_size = f
                .compressed_size
                .ok_or_else(|| CompressError::Msg("zstd frame compressed size unknown".into()))?;
            let uncompressed_size = f
                .uncompressed_size
                .ok_or_else(|| CompressError::Msg("zstd frame uncompressed size unknown".into()))?;
            if compressed_size == 0 {
                return Err(CompressError::Msg(
                    "zstd frame compressed size unknown".into(),
                ));
            }
            Ok(ZstdFrameInfo {
                compressed_offset: f.compressed_offset,
                uncompressed_offset: f.uncompressed_offset,
                compressed_size,
                uncompressed_size,
            })
        })
        .collect()
}

/// Footer-only span of the seek-table skippable (`[start, file_len)`).
fn seek_table_span_from_footer<R: Read + Seek>(reader: &mut R) -> Result<std::ops::Range<u64>> {
    let file_len = reader.seek(SeekFrom::End(0))?;
    if file_len < SEEK_TABLE_FOOTER_SIZE + SKIPPABLE_HEADER_SIZE {
        return Err(CompressError::Msg("file too small for seek table".into()));
    }
    reader.seek(SeekFrom::End(-(SEEK_TABLE_FOOTER_SIZE as i64)))?;
    let mut footer = [0u8; 9];
    reader.read_exact(&mut footer)?;
    let num_frames = u32::from_le_bytes(footer[0..4].try_into().unwrap());
    let descriptor = footer[4];
    let magic = u32::from_le_bytes(footer[5..9].try_into().unwrap());
    if magic != SEEKABLE_MAGIC {
        return Err(CompressError::Msg("no zstd seekable footer magic".into()));
    }
    let checksum_flag = descriptor & 0x80 != 0;
    let size_per_entry: u64 = if checksum_flag { 12 } else { 8 };
    let table_size = size_per_entry * u64::from(num_frames);
    let frame_size = table_size + SEEK_TABLE_FOOTER_SIZE + SKIPPABLE_HEADER_SIZE;
    if frame_size > file_len {
        return Err(CompressError::Msg("seek table larger than file".into()));
    }
    Ok((file_len - frame_size)..file_len)
}

/// Walk frames with a growing per-frame window. Does not slurp the whole multi-frame file.
fn scan_zstd_frames_walk<R: Read + Seek>(reader: &mut R) -> Result<ZstdFrameMap> {
    let file_len = reader.seek(SeekFrom::End(0))?;
    let mut frames = Vec::new();
    let mut pos = 0u64;
    let mut uncomp = 0u64;
    let mut seek_table = None;

    while pos + 4 <= file_len {
        reader.seek(SeekFrom::Start(pos))?;
        let mut magic_buf = [0u8; 4];
        match reader.read_exact(&mut magic_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
        let magic = u32::from_le_bytes(magic_buf);

        if (SKIPPABLE_MAGIC_MIN..=SKIPPABLE_MAGIC_MAX).contains(&magic) {
            let mut size_buf = [0u8; 4];
            match reader.read_exact(&mut size_buf) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.into()),
            }
            let skip_size = u32::from_le_bytes(size_buf) as u64;
            let span_end = pos
                .checked_add(SKIPPABLE_HEADER_SIZE + skip_size)
                .ok_or_else(|| CompressError::Msg("zstd skippable frame size overflow".into()))?;
            if magic == SEEK_TABLE_SKIPPABLE_MAGIC && skip_size >= 4 && span_end <= file_len {
                reader.seek(SeekFrom::Start(span_end - 4))?;
                let mut footer_magic = [0u8; 4];
                if reader.read_exact(&mut footer_magic).is_ok()
                    && u32::from_le_bytes(footer_magic) == SEEKABLE_MAGIC
                {
                    seek_table = Some(pos..span_end);
                }
            }
            pos = span_end;
            continue;
        }
        if magic_buf != ZSTD_MAGIC {
            break;
        }

        let (comp, frame_uncomp) = measure_frame_at(reader, pos, file_len)?;
        frames.push(ZstdFrameInfo {
            compressed_offset: pos,
            uncompressed_offset: uncomp,
            compressed_size: comp,
            uncompressed_size: frame_uncomp,
        });
        uncomp += frame_uncomp;
        pos += comp;
    }

    if frames.is_empty() {
        return Err(CompressError::Msg("no zstd frames found".into()));
    }
    Ok(ZstdFrameMap { frames, seek_table })
}

/// Compressed + uncompressed size of the frame at `pos`.
///
/// Grows a buffer from 256 KiB (double, no 64 MiB cap) until
/// `find_frame_compressed_size` succeeds. Uncompressed size uses
/// [`measure_frame_slice`] on that buffer — never a live file decoder
/// (the Rust zstd decoder over-reads past the frame end).
fn measure_frame_at<R: Read + Seek>(reader: &mut R, pos: u64, file_len: u64) -> Result<(u64, u64)> {
    let remaining = file_len.saturating_sub(pos);
    if remaining == 0 {
        return Err(CompressError::Msg(
            "zstd frame compressed size unknown".into(),
        ));
    }
    let mut window = SCAN_FRAME_WINDOW_START;
    loop {
        let to_read = window.min(remaining as usize);
        reader.seek(SeekFrom::Start(pos))?;
        let mut buf = vec![0u8; to_read];
        reader.read_exact(&mut buf).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                CompressError::Msg("zstd frame compressed size unknown".into())
            } else {
                CompressError::from(e)
            }
        })?;
        match zstd::zstd_safe::find_frame_compressed_size(&buf) {
            Ok(comp) if comp > 0 && comp <= buf.len() => {
                return measure_frame_slice(&buf);
            }
            _ => {
                if (to_read as u64) >= remaining {
                    return Err(CompressError::Msg(
                        "zstd frame compressed size unknown".into(),
                    ));
                }
                window = window.checked_mul(2).ok_or_else(|| {
                    CompressError::Msg("zstd frame compressed size unknown".into())
                })?;
            }
        }
    }
}

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
const SKIPPABLE_MAGIC_MIN: u32 = 0x184D2A50;
const SKIPPABLE_MAGIC_MAX: u32 = 0x184D2A5F;
/// Seekable-format skippable frame subtype (`ZSTD_MAGIC_SKIPPABLE_START | 0xE`).
const SEEK_TABLE_SKIPPABLE_MAGIC: u32 = 0x184D2A5E;
/// Footer magic for the zstd seekable format seek table (`0x8F92EAB1`).
pub const SEEKABLE_MAGIC: u32 = 0x8F92_EAB1;
const SEEK_TABLE_FOOTER_SIZE: u64 = 9;
const SKIPPABLE_HEADER_SIZE: u64 = 8;

#[derive(Clone, Debug)]
struct FrameInfo {
    /// Byte offset of frame magic in the compressed file.
    compressed_offset: u64,
    /// Uncompressed offset at start of this frame.
    uncompressed_offset: u64,
    /// Compressed size of this frame including header (None if unknown — last resort).
    compressed_size: Option<u64>,
    /// Uncompressed size if present in frame header or seek table.
    uncompressed_size: Option<u64>,
}

/// How compressed bytes are re-opened for independent frame readers.
enum ZstdBackend {
    /// Local path: each reader opens its own `File`.
    Path(PathBuf),
    /// Shared seekable stream (HTTP Range, Cursor, etc.).
    Shared(Arc<Mutex<Box<dyn SeekRead>>>),
}

/// Where the per-frame restart map came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum FrameMapSource {
    /// Concatenated multi-frame walk (`ZSTD_findFrameCompressedSize`).
    MultiFrameScan,
    /// Official zstd seekable-format seek table footer.
    SeekTable,
    /// Python SQLite `zstdblocks` / `indexed_zstd` offset pairs.
    ZstdBlocks,
}

/// Outcome of classifying a zstd stream (seek table / multi-frame map / full decode).
enum ZstdPlan {
    /// Use per-frame random access.
    Mapped {
        frames: Vec<FrameInfo>,
        uncompressed_size: u64,
        source: FrameMapSource,
    },
    /// Materialize the whole uncompressed stream.
    FullDecode,
}

/// Shared seekable zstd file.
pub struct SeekableZstd {
    /// Label for logs / index metadata (filesystem path, URL, or virtual name).
    path: PathBuf,
    backend: ZstdBackend,
    frames: Vec<FrameInfo>,
    uncompressed_size: u64,
    /// When only one large frame (or scan failed), fall back to full decode.
    fallback: Option<Arc<DecodedBody>>,
    /// Origin of `frames` (scan / seek table / imported `zstdblocks`).
    map_source: FrameMapSource,
}

impl SeekableZstd {
    pub fn open(path: impl AsRef<Path>) -> Result<Arc<dyn SeekableBody>> {
        Self::open_with_threads(path, 1)
    }

    /// Open with a thread hint. See [`open_seekable_zstd_with_threads`].
    ///
    /// Path openers open a `File` for map/seek-table import, then keep a path
    /// backend so each reader reopens an independent FD.
    pub fn open_with_threads(
        path: impl AsRef<Path>,
        threads: u32,
    ) -> Result<Arc<dyn SeekableBody>> {
        let path = path.as_ref().to_path_buf();
        let threads = ParallelizationSpec::resolve_zero(threads).max(1);
        let mut file = File::open(&path)?;
        match classify_zstd(&mut file, threads)? {
            ZstdPlan::Mapped {
                frames,
                uncompressed_size,
                source,
            } => Ok(Arc::new(Self {
                path: path.clone(),
                backend: ZstdBackend::Path(path),
                frames,
                uncompressed_size,
                fallback: None,
                map_source: source,
            })),
            ZstdPlan::FullDecode => decode_full(&path, threads),
        }
    }

    /// Open from an already-seekable compressed stream (HTTP Range, memory, …).
    ///
    /// `archive_label` is stored for [`SeekableBody::path`] / logs (URL or virtual name).
    pub fn open_from_reader<R>(
        reader: R,
        archive_label: impl AsRef<Path>,
    ) -> Result<Arc<dyn SeekableBody>>
    where
        R: Read + Seek + Send + 'static,
    {
        Self::open_with_threads_from_reader(reader, 1, archive_label)
    }

    /// Like [`Self::open_from_reader`] with a thread hint (Python `-P`).
    pub fn open_with_threads_from_reader<R>(
        mut reader: R,
        threads: u32,
        archive_label: impl AsRef<Path>,
    ) -> Result<Arc<dyn SeekableBody>>
    where
        R: Read + Seek + Send + 'static,
    {
        let path = archive_label.as_ref().to_path_buf();
        let threads = ParallelizationSpec::resolve_zero(threads).max(1);
        match classify_zstd(&mut reader, threads)? {
            ZstdPlan::Mapped {
                frames,
                uncompressed_size,
                source,
            } => {
                let shared: Arc<Mutex<Box<dyn SeekRead>>> = Arc::new(Mutex::new(Box::new(reader)));
                Ok(Arc::new(Self {
                    path,
                    backend: ZstdBackend::Shared(shared),
                    frames,
                    uncompressed_size,
                    fallback: None,
                    map_source: source,
                }))
            }
            ZstdPlan::FullDecode => decode_full_from_reader(reader, &path, threads),
        }
    }

    /// Open using a Python-compatible `zstdblocks` map (no stream rescan).
    ///
    /// `blocks` are `(blockoffset, dataoffset)` = `(compressed_offset, uncompressed_offset)`
    /// pairs; the last entry is the EOF sentinel (totals). See module docs.
    /// `threads` is accepted for API parity with other openers (`0` → CPU count);
    /// random access remains per-frame.
    pub fn open_with_zstd_blocks(
        path: impl AsRef<Path>,
        threads: u32,
        blocks: &[(u64, u64)],
    ) -> Result<Arc<Self>> {
        let path = path.as_ref().to_path_buf();
        let _threads = ParallelizationSpec::resolve_zero(threads).max(1);
        let (frames, uncompressed_size) = frames_from_zstd_blocks(blocks)?;
        // Best-effort bounds check against file length when available.
        if let Ok(meta) = std::fs::metadata(&path) {
            if let Some(last) = frames.last() {
                let end = last.compressed_offset + last.compressed_size.unwrap_or(0);
                if end > meta.len() {
                    return Err(CompressError::Msg(format!(
                        "zstdblocks compressed end {end} exceeds file size {}",
                        meta.len()
                    )));
                }
            }
        }
        Ok(Arc::new(Self {
            path: path.clone(),
            backend: ZstdBackend::Path(path),
            frames,
            uncompressed_size,
            fallback: None,
            map_source: FrameMapSource::ZstdBlocks,
        }))
    }

    /// Open from a seekable stream using a Python-compatible `zstdblocks` map.
    ///
    /// See [`Self::open_with_zstd_blocks`].
    pub fn open_with_zstd_blocks_from_reader<R>(
        reader: R,
        threads: u32,
        archive_label: impl AsRef<Path>,
        blocks: &[(u64, u64)],
    ) -> Result<Arc<Self>>
    where
        R: Read + Seek + Send + 'static,
    {
        let path = archive_label.as_ref().to_path_buf();
        let _threads = ParallelizationSpec::resolve_zero(threads).max(1);
        let (frames, uncompressed_size) = frames_from_zstd_blocks(blocks)?;
        let shared: Arc<Mutex<Box<dyn SeekRead>>> = Arc::new(Mutex::new(Box::new(reader)));
        Ok(Arc::new(Self {
            path,
            backend: ZstdBackend::Shared(shared),
            frames,
            uncompressed_size,
            fallback: None,
            map_source: FrameMapSource::ZstdBlocks,
        }))
    }

    /// Diagnostic: whether the frame map was imported from a seek table.
    pub fn used_seek_table(&self) -> bool {
        self.map_source == FrameMapSource::SeekTable
    }

    /// Diagnostic: whether the frame map was imported from `zstdblocks` pairs.
    pub fn used_zstd_blocks(&self) -> bool {
        self.map_source == FrameMapSource::ZstdBlocks
    }

    /// Export Python-compatible `zstdblocks` pairs including the EOF sentinel.
    ///
    /// Returns `None` when this body fell back to full decode (no frame map).
    pub fn zstd_blocks(&self) -> Option<Vec<(u64, u64)>> {
        if self.fallback.is_some() || self.frames.is_empty() {
            return None;
        }
        Some(zstd_blocks_from_frames(
            &self.frames,
            self.uncompressed_size,
        ))
    }
}

/// Classify stream into multi-frame map or full-decode fallback.
///
/// Prefer seek-table import; else multi-frame scan. Path and reader openers share
/// this so HTTP Range / `Cursor` get the same map semantics as local files.
fn classify_zstd<R: Read + Seek>(reader: &mut R, threads: u32) -> Result<ZstdPlan> {
    let _ = threads; // reserved for future concurrent map builders
                     // 1) Prefer official seekable-format seek table when present.
    if let Ok((frames, uncomp_size)) = try_load_seek_table_from_reader(reader) {
        if frames.len() > 1 {
            return Ok(ZstdPlan::Mapped {
                frames,
                uncompressed_size: uncomp_size,
                source: FrameMapSource::SeekTable,
            });
        }
        if frames.len() == 1 {
            if let Some(sz) = frames[0].uncompressed_size {
                if sz <= DEFAULT_MEMORY_CAP {
                    return Ok(ZstdPlan::FullDecode);
                }
            }
            // Single large frame with known compressed bounds: still use frame reader
            // so we do not force a permanent materialised path.
            return Ok(ZstdPlan::Mapped {
                frames,
                uncompressed_size: uncomp_size,
                source: FrameMapSource::SeekTable,
            });
        }
    }

    // 2) Multi-frame (or single-frame) scan without seek table.
    match build_frame_map_from_reader(reader) {
        Ok((frames, uncomp_size)) if frames.len() > 1 => Ok(ZstdPlan::Mapped {
            frames,
            uncompressed_size: uncomp_size,
            source: FrameMapSource::MultiFrameScan,
        }),
        Ok((frames, uncomp_size)) if frames.len() == 1 => {
            // Single frame: decode fully (small → RAM; large → temp via DecodedBody).
            let _ = (frames, uncomp_size);
            Ok(ZstdPlan::FullDecode)
        }
        Ok(_) => Ok(ZstdPlan::FullDecode),
        Err(_) => Ok(ZstdPlan::FullDecode),
    }
}

fn decode_full(path: &Path, threads: u32) -> Result<Arc<dyn SeekableBody>> {
    // Best-effort: multi-frame full materialization with parallel frame decode.
    if threads > 1 {
        if let Ok(data) = try_parallel_frame_decode(path, threads) {
            if data.len() as u64 <= DEFAULT_MEMORY_CAP {
                return Ok(DecodedBody::from_bytes(path, "zstd", data) as Arc<dyn SeekableBody>);
            }
            let cursor = std::io::Cursor::new(data);
            let body = DecodedBody::from_decoder(path, "zstd", cursor, DEFAULT_MEMORY_CAP)?;
            return Ok(body as Arc<dyn SeekableBody>);
        }
    }
    let file = File::open(path)?;
    let dec =
        zstd::stream::read::Decoder::new(file).map_err(|e| CompressError::Msg(e.to_string()))?;
    let body = DecodedBody::from_decoder(path, "zstd", dec, DEFAULT_MEMORY_CAP)?;
    Ok(body)
}

fn decode_full_from_reader<R>(
    mut reader: R,
    path: &Path,
    threads: u32,
) -> Result<Arc<dyn SeekableBody>>
where
    R: Read + Seek + Send + 'static,
{
    if threads > 1 {
        if let Ok(data) = try_parallel_frame_decode_from_reader(&mut reader, threads) {
            if data.len() as u64 <= DEFAULT_MEMORY_CAP {
                return Ok(DecodedBody::from_bytes(path, "zstd", data) as Arc<dyn SeekableBody>);
            }
            let cursor = std::io::Cursor::new(data);
            let body = DecodedBody::from_decoder(path, "zstd", cursor, DEFAULT_MEMORY_CAP)?;
            return Ok(body as Arc<dyn SeekableBody>);
        }
        // Rewind for sequential fallback after a failed parallel attempt.
        let _ = reader.seek(SeekFrom::Start(0));
    }
    reader.seek(SeekFrom::Start(0))?;
    let dec =
        zstd::stream::read::Decoder::new(reader).map_err(|e| CompressError::Msg(e.to_string()))?;
    let body = DecodedBody::from_decoder(path, "zstd", dec, DEFAULT_MEMORY_CAP)?;
    Ok(body)
}

/// Parallel decompress of independent zstd frames into one contiguous buffer.
fn try_parallel_frame_decode(path: &Path, threads: u32) -> Result<Vec<u8>> {
    let data = std::fs::read(path)?;
    try_parallel_frame_decode_bytes(&data, threads)
}

fn try_parallel_frame_decode_from_reader<R: Read + Seek>(
    reader: &mut R,
    threads: u32,
) -> Result<Vec<u8>> {
    reader.seek(SeekFrom::Start(0))?;
    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;
    try_parallel_frame_decode_bytes(&data, threads)
}

fn try_parallel_frame_decode_bytes(data: &[u8], threads: u32) -> Result<Vec<u8>> {
    let (frames, _total) = build_frame_map_from_bytes(data)?;
    if frames.len() < 2 {
        return Err(CompressError::Msg(
            "single zstd frame; sequential path".into(),
        ));
    }
    let mut slices: Vec<&[u8]> = Vec::with_capacity(frames.len());
    for f in &frames {
        let start = f.compressed_offset as usize;
        let len = f
            .compressed_size
            .ok_or_else(|| CompressError::Msg("zstd frame size unknown".into()))?
            as usize;
        if start + len > data.len() {
            return Err(CompressError::Msg("zstd frame out of bounds".into()));
        }
        slices.push(&data[start..start + len]);
    }
    parallel_decode_frame_slices(&slices, threads)
}

fn parallel_decode_frame_slices(parts: &[&[u8]], threads: u32) -> Result<Vec<u8>> {
    let n_workers = (threads as usize).min(parts.len()).max(1);
    let mut results: Vec<Option<Result<Vec<u8>>>> = (0..parts.len()).map(|_| None).collect();

    thread::scope(|scope| {
        let chunk = parts.len().div_ceil(n_workers).max(1);
        let mut handles = Vec::new();
        for (worker_id, part_chunk) in parts.chunks(chunk).enumerate() {
            let base = worker_id * chunk;
            let owned: Vec<Vec<u8>> = part_chunk.iter().map(|p| p.to_vec()).collect();
            handles.push(scope.spawn(move || {
                let mut outs = Vec::with_capacity(owned.len());
                for p in &owned {
                    outs.push(decode_one_zstd_frame(p));
                }
                (base, outs)
            }));
        }
        for h in handles {
            if let Ok((base, outs)) = h.join() {
                for (i, r) in outs.into_iter().enumerate() {
                    results[base + i] = Some(r);
                }
            }
        }
    });

    let mut out = Vec::new();
    for r in results {
        out.extend(r.ok_or_else(|| CompressError::Msg("zstd parallel worker missing".into()))??);
    }
    Ok(out)
}

fn decode_one_zstd_frame(frame: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = zstd::stream::read::Decoder::new(frame)
        .map_err(|e| CompressError::Msg(e.to_string()))?
        .single_frame();
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| CompressError::Msg(e.to_string()))?;
    Ok(out)
}

fn build_frame_map_from_bytes(data: &[u8]) -> Result<(Vec<FrameInfo>, u64)> {
    let file_len = data.len() as u64;
    let mut frames = Vec::new();
    let mut pos = 0usize;
    let mut uncomp = 0u64;

    while pos + 4 <= data.len() {
        let magic = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap());

        if (SKIPPABLE_MAGIC_MIN..=SKIPPABLE_MAGIC_MAX).contains(&magic) {
            if pos + 8 > data.len() {
                break;
            }
            let sz = u32::from_le_bytes(data[pos + 4..pos + 8].try_into().unwrap()) as usize;
            pos += 8 + sz;
            continue;
        }
        if data[pos..pos + 4] != ZSTD_MAGIC {
            break;
        }

        let frame_start = pos as u64;
        let (comp_size, frame_uncomp) = measure_frame_slice(&data[pos..])?;

        frames.push(FrameInfo {
            compressed_offset: frame_start,
            uncompressed_offset: uncomp,
            compressed_size: Some(comp_size),
            uncompressed_size: Some(frame_uncomp),
        });
        uncomp += frame_uncomp;
        pos += comp_size as usize;
        if pos as u64 > file_len {
            break;
        }
    }

    if frames.is_empty() {
        return Err(CompressError::Msg("no zstd frames found".into()));
    }
    Ok((frames, uncomp))
}

impl SeekableBody for SeekableZstd {
    fn path(&self) -> &Path {
        &self.path
    }

    fn size(&self) -> u64 {
        if let Some(fb) = &self.fallback {
            return fb.size();
        }
        self.uncompressed_size
    }

    fn open_reader(&self) -> io::Result<Box<dyn SeekRead>> {
        if let Some(fb) = &self.fallback {
            return fb.open_reader();
        }
        Ok(Box::new(ZstdFrameReader::open(self)?))
    }

    fn kind(&self) -> &'static str {
        match self.map_source {
            FrameMapSource::SeekTable => "zstd-seek-table",
            FrameMapSource::ZstdBlocks => "zstd-blocks",
            FrameMapSource::MultiFrameScan => "zstd-frames",
        }
    }

    fn checkpoint_count(&self) -> usize {
        self.frames.len().max(1)
    }
}

/// Compressed-stream handle used during frame decode (path FD or shared mutex stream).
///
/// Shared holds a private compressed offset so concurrent [`ZstdFrameReader`]s
/// (nested AutoMount / multi-open FUSE) do not interleave `seek` + `read` on the
/// shared cursor. That race previously produced truncated / wrong frame data only
/// on the embedded (from-reader) path — host files use a private FD per open and
/// were fine.
enum CompressedHandle {
    File(File),
    Shared {
        inner: Arc<Mutex<Box<dyn SeekRead>>>,
        /// Logical position in the compressed stream for *this* handle.
        pos: u64,
    },
}

impl Read for CompressedHandle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            CompressedHandle::File(f) => f.read(buf),
            CompressedHandle::Shared { inner, pos } => {
                let mut guard = inner
                    .lock()
                    .map_err(|_| io::Error::other("zstd backend mutex poisoned"))?;
                guard.seek(SeekFrom::Start(*pos))?;
                let n = guard.read(buf)?;
                *pos += n as u64;
                Ok(n)
            }
        }
    }
}

impl Seek for CompressedHandle {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match self {
            CompressedHandle::File(f) => f.seek(pos),
            CompressedHandle::Shared {
                inner,
                pos: logical,
            } => {
                let new = match pos {
                    SeekFrom::Start(o) => o as i64,
                    SeekFrom::Current(o) => *logical as i64 + o,
                    SeekFrom::End(o) => {
                        let mut guard = inner
                            .lock()
                            .map_err(|_| io::Error::other("zstd backend mutex poisoned"))?;
                        let end = guard.seek(SeekFrom::End(0))? as i64;
                        end + o
                    }
                };
                if new < 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "seek before start of compressed stream",
                    ));
                }
                *logical = new as u64;
                Ok(*logical)
            }
        }
    }
}

struct ZstdFrameReader {
    backend: ZstdBackend,
    frames: Vec<FrameInfo>,
    size: u64,
    pos: u64,
    /// Cached decompressed frame.
    frame_idx: Option<usize>,
    frame_data: Vec<u8>,
    frame_start: u64,
}

impl ZstdFrameReader {
    fn open(z: &SeekableZstd) -> io::Result<Self> {
        let backend = match &z.backend {
            ZstdBackend::Path(p) => ZstdBackend::Path(p.clone()),
            ZstdBackend::Shared(shared) => ZstdBackend::Shared(Arc::clone(shared)),
        };
        Ok(Self {
            backend,
            frames: z.frames.clone(),
            size: z.uncompressed_size,
            pos: 0,
            frame_idx: None,
            frame_data: Vec::new(),
            frame_start: 0,
        })
    }

    fn open_compressed(&self) -> io::Result<CompressedHandle> {
        match &self.backend {
            ZstdBackend::Path(p) => Ok(CompressedHandle::File(File::open(p)?)),
            ZstdBackend::Shared(shared) => Ok(CompressedHandle::Shared {
                inner: Arc::clone(shared),
                pos: 0,
            }),
        }
    }

    fn ensure_frame(&mut self, target: u64) -> io::Result<()> {
        if target >= self.size {
            return Ok(());
        }
        // Already have covering frame?
        if let Some(_i) = self.frame_idx {
            let start = self.frame_start;
            let end = start + self.frame_data.len() as u64;
            if target >= start && target < end {
                return Ok(());
            }
        }
        let mut best = 0usize;
        for (i, f) in self.frames.iter().enumerate() {
            if f.uncompressed_offset <= target {
                best = i;
            } else {
                break;
            }
        }
        let info = &self.frames[best];
        let mut file = self.open_compressed()?;
        file.seek(SeekFrom::Start(info.compressed_offset))?;
        // Limit reader to this frame's compressed bytes when known — never decode the whole file.
        let mut data = Vec::new();
        if let Some(csz) = info.compressed_size {
            // Copy compressed frame under the (optional) shared lock, then decode.
            let mut compressed = vec![0u8; csz as usize];
            file.read_exact(&mut compressed)?;
            drop(file);
            let mut decoder = zstd::stream::read::Decoder::new(compressed.as_slice())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            decoder.read_to_end(&mut data)?;
        } else {
            let mut decoder = zstd::stream::read::Decoder::new(file)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?
                .single_frame();
            decoder.read_to_end(&mut data)?;
        }
        self.frame_idx = Some(best);
        self.frame_start = info.uncompressed_offset;
        self.frame_data = data;
        Ok(())
    }
}

impl Read for ZstdFrameReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.size {
            return Ok(0);
        }
        self.ensure_frame(self.pos)?;
        let into = (self.pos - self.frame_start) as usize;
        if into >= self.frame_data.len() {
            return Ok(0);
        }
        let n = (self.frame_data.len() - into).min(buf.len());
        buf[..n].copy_from_slice(&self.frame_data[into..into + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for ZstdFrameReader {
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

/// Load frame map from a zstd seekable-format seek table at EOF, if present.
///
/// Layout (see `zstd/contrib/seekable_format`):
/// * Skippable frame magic `0x184D2A5E` + size
/// * Entries: per frame `cSize:u32le`, `dSize:u32le` [, `checksum:u32le` if flag]
/// * Footer (9 bytes): `numFrames:u32le`, descriptor byte, magic `0x8F92EAB1`
fn try_load_seek_table_from_reader<R: Read + Seek>(
    reader: &mut R,
) -> Result<(Vec<FrameInfo>, u64)> {
    let file_len = reader.seek(SeekFrom::End(0))?;
    if file_len < SEEK_TABLE_FOOTER_SIZE + SKIPPABLE_HEADER_SIZE {
        return Err(CompressError::Msg("file too small for seek table".into()));
    }

    reader.seek(SeekFrom::End(-(SEEK_TABLE_FOOTER_SIZE as i64)))?;
    let mut footer = [0u8; 9];
    reader.read_exact(&mut footer)?;
    let num_frames = u32::from_le_bytes(footer[0..4].try_into().unwrap());
    let descriptor = footer[4];
    let magic = u32::from_le_bytes(footer[5..9].try_into().unwrap());
    if magic != SEEKABLE_MAGIC {
        return Err(CompressError::Msg("no zstd seekable footer magic".into()));
    }
    // Reserved bits [2..7) of descriptor must be zero.
    if (descriptor >> 2) & 0x1f != 0 {
        return Err(CompressError::Msg("corrupt seek table descriptor".into()));
    }
    let checksum_flag = descriptor & 0x80 != 0;
    let size_per_entry: u64 = if checksum_flag { 12 } else { 8 };
    let table_size = size_per_entry * u64::from(num_frames);
    let frame_size = table_size + SEEK_TABLE_FOOTER_SIZE + SKIPPABLE_HEADER_SIZE;
    if frame_size > file_len {
        return Err(CompressError::Msg("seek table larger than file".into()));
    }

    reader.seek(SeekFrom::End(-(frame_size as i64)))?;
    let mut header = [0u8; 8];
    reader.read_exact(&mut header)?;
    let skip_magic = u32::from_le_bytes(header[0..4].try_into().unwrap());
    let skip_size = u32::from_le_bytes(header[4..8].try_into().unwrap()) as u64;
    if skip_magic != SEEK_TABLE_SKIPPABLE_MAGIC {
        return Err(CompressError::Msg(
            "seek table skippable magic mismatch".into(),
        ));
    }
    if skip_size + SKIPPABLE_HEADER_SIZE != frame_size {
        return Err(CompressError::Msg("seek table size mismatch".into()));
    }

    let mut entries = vec![0u8; table_size as usize];
    reader.read_exact(&mut entries)?;

    let mut frames = Vec::with_capacity(num_frames as usize);
    let mut c_off = 0u64;
    let mut d_off = 0u64;
    let mut pos = 0usize;
    for _ in 0..num_frames {
        let c_size = u32::from_le_bytes(entries[pos..pos + 4].try_into().unwrap()) as u64;
        pos += 4;
        let d_size = u32::from_le_bytes(entries[pos..pos + 4].try_into().unwrap()) as u64;
        pos += 4;
        if checksum_flag {
            pos += 4; // ignore checksum for map build
        }
        frames.push(FrameInfo {
            compressed_offset: c_off,
            uncompressed_offset: d_off,
            compressed_size: Some(c_size),
            uncompressed_size: Some(d_size),
        });
        c_off += c_size;
        d_off += d_size;
    }
    // Seek table occupies the tail; compressed frames should end at skippable start.
    let frames_end = file_len - frame_size;
    if c_off > frames_end {
        return Err(CompressError::Msg(
            "seek table compressed offsets past data".into(),
        ));
    }
    if frames.is_empty() {
        return Err(CompressError::Msg("empty seek table".into()));
    }
    Ok((frames, d_off))
}

/// Scan zstd frames from a seekable reader; returns (frames, total uncompressed size).
fn build_frame_map_from_reader<R: Read + Seek>(reader: &mut R) -> Result<(Vec<FrameInfo>, u64)> {
    reader.seek(SeekFrom::Start(0))?;
    let mut data = Vec::new();
    reader.read_to_end(&mut data)?;
    build_frame_map_from_bytes(&data)
}

/// Exact compressed size + uncompressed size for the first zstd frame in `src`.
fn measure_frame_slice(src: &[u8]) -> Result<(u64, u64)> {
    let comp = zstd::zstd_safe::find_frame_compressed_size(src)
        .map_err(|e| CompressError::Msg(format!("ZSTD_findFrameCompressedSize: {e}")))?;
    if comp == 0 || comp > src.len() {
        return Err(CompressError::Msg(format!(
            "invalid frame compressed size {comp}"
        )));
    }
    let frame = &src[..comp];
    let frame_uncomp = match zstd::zstd_safe::get_frame_content_size(frame) {
        Ok(Some(n)) => n,
        Ok(None) | Err(_) => {
            // Decompress only this frame (exact slice — no over-read into next frame).
            let mut decoder = zstd::stream::read::Decoder::new(frame)
                .map_err(|e| CompressError::Msg(e.to_string()))?
                .single_frame();
            let mut out = Vec::new();
            decoder
                .read_to_end(&mut out)
                .map_err(|e| CompressError::Msg(e.to_string()))?;
            out.len() as u64
        }
    };
    Ok((comp as u64, frame_uncomp))
}

/// Convert Python `zstdblocks` pairs into an internal frame map.
///
/// Each pair is `(blockoffset, dataoffset)` = `(compressed_offset, uncompressed_offset)`.
/// Pairs must be sorted with both compressed and uncompressed offsets monotonically
/// non-decreasing. The last entry is the EOF sentinel (totals), matching
/// `indexed_zstd.IndexedZstdFile.block_offsets()`.
///
/// Frame *i* spans `[blocks[i], blocks[i + 1])` in compressed and uncompressed space.
///
/// Returns `(frames, total_uncompressed_size)`.
fn frames_from_zstd_blocks(blocks: &[(u64, u64)]) -> Result<(Vec<FrameInfo>, u64)> {
    if blocks.len() < 2 {
        return Err(CompressError::Msg(
            "zstdblocks map needs at least one frame start and an EOF sentinel".into(),
        ));
    }
    for window in blocks.windows(2) {
        let (c0, d0) = window[0];
        let (c1, d1) = window[1];
        if c1 < c0 {
            return Err(CompressError::Msg(format!(
                "zstdblocks compressed offsets not monotonic: {c0} -> {c1}"
            )));
        }
        if d1 < d0 {
            return Err(CompressError::Msg(format!(
                "zstdblocks data offsets not monotonic: {d0} -> {d1}"
            )));
        }
    }

    let mut frames = Vec::with_capacity(blocks.len() - 1);
    for i in 0..blocks.len() - 1 {
        let (c0, d0) = blocks[i];
        let (c1, d1) = blocks[i + 1];
        let c_size = c1 - c0;
        let d_size = d1 - d0;
        if c_size == 0 && d_size == 0 {
            // Degenerate zero-length span — skip.
            continue;
        }
        if c_size == 0 {
            return Err(CompressError::Msg(format!(
                "zstdblocks frame at compressed offset {c0} has zero compressed size but \
                 uncompressed size {d_size}"
            )));
        }
        frames.push(FrameInfo {
            compressed_offset: c0,
            uncompressed_offset: d0,
            compressed_size: Some(c_size),
            uncompressed_size: Some(d_size),
        });
    }
    if frames.is_empty() {
        return Err(CompressError::Msg(
            "zstdblocks map produced no frames".into(),
        ));
    }
    let total_uncomp = blocks[blocks.len() - 1].1;
    Ok((frames, total_uncomp))
}

/// Export a frame map as Python `zstdblocks` pairs (including EOF sentinel).
///
/// Pair *i* is the start of frame *i*; the final pair is
/// `(end_of_last_frame_compressed, total_uncompressed)`.
fn zstd_blocks_from_frames(frames: &[FrameInfo], uncompressed_size: u64) -> Vec<(u64, u64)> {
    let mut out = Vec::with_capacity(frames.len() + 1);
    for f in frames {
        out.push((f.compressed_offset, f.uncompressed_offset));
    }
    let last = match frames.last() {
        Some(f) => f,
        None => {
            out.push((0, uncompressed_size));
            return out;
        }
    };
    let c_end = last
        .compressed_size
        .map(|sz| last.compressed_offset + sz)
        .unwrap_or(last.compressed_offset);
    let d_end = last
        .uncompressed_size
        .map(|sz| last.uncompressed_offset + sz)
        .unwrap_or(uncompressed_size)
        .max(uncompressed_size);
    out.push((c_end, d_end));
    out
}

/// Build a seekable-format seek table skippable frame (no per-frame checksums).
/// Used by tests; also useful for tooling that concatenates independent frames.
pub fn build_seek_table_skippable(frames: &[(u32, u32)]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(frames.len() * 8 + 9);
    for &(c_size, d_size) in frames {
        payload.extend_from_slice(&c_size.to_le_bytes());
        payload.extend_from_slice(&d_size.to_le_bytes());
    }
    let num = frames.len() as u32;
    payload.extend_from_slice(&num.to_le_bytes());
    payload.push(0); // descriptor: no checksum, reserved 0
    payload.extend_from_slice(&SEEKABLE_MAGIC.to_le_bytes());
    let mut out = Vec::with_capacity(8 + payload.len());
    out.extend_from_slice(&SEEK_TABLE_SKIPPABLE_MAGIC.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    fn py_test(name: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        PathBuf::from(root).join("tests").join(name)
    }

    fn encode_frame(part: &[u8]) -> Vec<u8> {
        let mut enc = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
        enc.write_all(part).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn simple_zst() {
        let path = py_test("simple.zst");
        if !path.exists() {
            return;
        }
        let body = SeekableZstd::open(&path).unwrap();
        assert_eq!(body.size(), 12);
        let mut r = body.open_reader().unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "foo fighter\n");
    }

    #[test]
    fn multi_frame_zstd_random_access() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("multi.zst");
        // Three independent frames concatenated (no seek table).
        let parts: [&[u8]; 3] = [b"AAAA", b"BBBBCCCC", b"DD"];
        let mut out = File::create(&path).unwrap();
        for part in parts {
            out.write_all(&encode_frame(part)).unwrap();
        }
        drop(out);

        let body = SeekableZstd::open(&path).unwrap();
        assert!(
            body.checkpoint_count() >= 2,
            "expected multi-frame map, checkpoints={}",
            body.checkpoint_count()
        );
        assert_eq!(body.kind(), "zstd-frames");
        assert_eq!(body.size(), 14);

        let mut r = body.open_reader().unwrap();
        let mut all = Vec::new();
        r.read_to_end(&mut all).unwrap();
        assert_eq!(all, b"AAAABBBBCCCCDD");

        // Seek into middle of frame 1
        r.seek(SeekFrom::Start(4)).unwrap();
        let mut mid = [0u8; 4];
        r.read_exact(&mut mid).unwrap();
        assert_eq!(&mid, b"BBBB");

        // Seek into frame 2
        r.seek(SeekFrom::Start(12)).unwrap();
        let mut tail = Vec::new();
        r.read_to_end(&mut tail).unwrap();
        assert_eq!(tail, b"DD");

        // Seek backwards across frames
        r.seek(SeekFrom::Start(2)).unwrap();
        let mut early = [0u8; 4];
        r.read_exact(&mut early).unwrap();
        assert_eq!(&early, b"AABB");
    }

    #[test]
    fn multi_frame_with_seek_table() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seekable.zst");
        let parts: [&[u8]; 3] = [b"hello world!!!!", b"second frame payload", b"third!"];
        let mut frames_bin = Vec::new();
        let mut table_entries = Vec::new();
        for part in parts {
            let f = encode_frame(part);
            table_entries.push((f.len() as u32, part.len() as u32));
            frames_bin.extend_from_slice(&f);
        }
        let table = build_seek_table_skippable(&table_entries);
        let mut out = File::create(&path).unwrap();
        out.write_all(&frames_bin).unwrap();
        out.write_all(&table).unwrap();
        drop(out);

        // Seek table import
        let mut f = File::open(&path).unwrap();
        let (map, total) = try_load_seek_table_from_reader(&mut f).unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(total, parts.iter().map(|p| p.len() as u64).sum::<u64>());
        assert_eq!(map[0].compressed_offset, 0);
        assert_eq!(map[1].uncompressed_offset, parts[0].len() as u64);

        let body = SeekableZstd::open(&path).unwrap();
        assert_eq!(body.kind(), "zstd-seek-table");
        assert_eq!(body.checkpoint_count(), 3);
        assert_eq!(body.size(), total);

        let mut r = body.open_reader().unwrap();
        let mut all = Vec::new();
        r.read_to_end(&mut all).unwrap();
        let mut expected = Vec::new();
        for p in parts {
            expected.extend_from_slice(p);
        }
        assert_eq!(all, expected);

        // Random access into second frame only
        let off = parts[0].len() as u64 + 7;
        r.seek(SeekFrom::Start(off)).unwrap();
        let mut chunk = [0u8; 5];
        r.read_exact(&mut chunk).unwrap();
        assert_eq!(&chunk, &parts[1][7..12]);
    }

    #[test]
    fn seek_table_absent_on_plain_multi_frame() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.zst");
        let mut out = File::create(&path).unwrap();
        out.write_all(&encode_frame(b"aa")).unwrap();
        out.write_all(&encode_frame(b"bb")).unwrap();
        drop(out);
        let mut f = File::open(&path).unwrap();
        assert!(try_load_seek_table_from_reader(&mut f).is_err());
        let body = SeekableZstd::open(&path).unwrap();
        assert_eq!(body.kind(), "zstd-frames");
        assert!(body.checkpoint_count() >= 2);
    }

    #[test]
    fn open_seekable_zstd_with_threads_equals_single() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("threads.zst");
        let parts: [&[u8]; 3] = [b"frame-one!!!!", b"frame-two-data", b"f3"];
        let mut out = File::create(&path).unwrap();
        for p in parts {
            out.write_all(&encode_frame(p)).unwrap();
        }
        drop(out);

        let mut expected = Vec::new();
        for p in parts {
            expected.extend_from_slice(p);
        }

        let body1 = open_seekable_zstd_with_threads(&path, 1).unwrap();
        let body4 = open_seekable_zstd_with_threads(&path, 4).unwrap();
        // Multi-frame path keeps frame map (not full parallel materialize).
        assert!(body1.checkpoint_count() >= 2);
        assert!(body4.checkpoint_count() >= 2);

        let mut a = Vec::new();
        body1.open_reader().unwrap().read_to_end(&mut a).unwrap();
        let mut b = Vec::new();
        body4.open_reader().unwrap().read_to_end(&mut b).unwrap();
        assert_eq!(a, expected);
        assert_eq!(b, expected);
    }

    #[test]
    fn parallel_frame_decode_matches_sequential() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("par.zst");
        let parts: [&[u8]; 3] = [b"AAAA", b"BBBBCCCC", b"DD"];
        let mut out = File::create(&path).unwrap();
        for p in parts {
            out.write_all(&encode_frame(p)).unwrap();
        }
        drop(out);

        let par = try_parallel_frame_decode(&path, 4).unwrap();
        let mut seq = Vec::new();
        let file = File::open(&path).unwrap();
        let mut dec = zstd::stream::read::Decoder::new(file).unwrap();
        dec.read_to_end(&mut seq).unwrap();
        assert_eq!(par, seq);
        assert_eq!(par, b"AAAABBBBCCCCDD");
    }

    #[test]
    fn threads_zero_means_cpu_count_zstd() {
        let path = py_test("simple.zst");
        if !path.exists() {
            return;
        }
        let body = open_seekable_zstd_with_threads(&path, 0).unwrap();
        assert_eq!(body.size(), 12);
    }

    #[test]
    fn multi_frame_zstd_from_reader_equals_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cursor.zst");
        let parts: [&[u8]; 3] = [b"AAAA", b"BBBBCCCC", b"DD"];
        let mut compressed = Vec::new();
        for part in parts {
            compressed.extend_from_slice(&encode_frame(part));
        }
        std::fs::write(&path, &compressed).unwrap();

        let path_body = SeekableZstd::open(&path).unwrap();
        let reader_body = SeekableZstd::open_with_threads_from_reader(
            Cursor::new(compressed.clone()),
            1,
            Path::new("memory://cursor.zst"),
        )
        .unwrap();

        assert_eq!(path_body.size(), reader_body.size());
        assert_eq!(path_body.kind(), reader_body.kind());
        assert_eq!(path_body.checkpoint_count(), reader_body.checkpoint_count());
        assert!(reader_body.checkpoint_count() >= 2);
        assert_eq!(reader_body.path(), Path::new("memory://cursor.zst"));

        let mut path_r = path_body.open_reader().unwrap();
        let mut mem_r = reader_body.open_reader().unwrap();

        let mut path_all = Vec::new();
        let mut mem_all = Vec::new();
        path_r.read_to_end(&mut path_all).unwrap();
        mem_r.read_to_end(&mut mem_all).unwrap();
        assert_eq!(path_all, b"AAAABBBBCCCCDD");
        assert_eq!(mem_all, path_all);

        // Random seeks across frames
        let offsets = [0u64, 2, 4, 8, 12];
        for &off in &offsets {
            path_r.seek(SeekFrom::Start(off)).unwrap();
            mem_r.seek(SeekFrom::Start(off)).unwrap();
            let mut pb = [0u8; 4];
            let mut mb = [0u8; 4];
            let pn = path_r.read(&mut pb).unwrap();
            let mn = mem_r.read(&mut mb).unwrap();
            assert_eq!(pn, mn, "offset {off}");
            assert_eq!(&pb[..pn], &mb[..mn], "offset {off}");
        }

        // Free-function openers
        let free_body = open_seekable_zstd_with_threads_from_reader(
            Cursor::new(compressed.clone()),
            2,
            Path::new("label.zst"),
        )
        .unwrap();
        assert_eq!(free_body.path(), Path::new("label.zst"));
        assert_eq!(free_body.size(), 14);
        let mut free_r = free_body.open_reader().unwrap();
        free_r.seek(SeekFrom::Start(4)).unwrap();
        let mut free_chunk = [0u8; 4];
        free_r.read_exact(&mut free_chunk).unwrap();
        assert_eq!(&free_chunk, b"BBBB");

        let free2 = open_seekable_zstd_from_reader(Cursor::new(compressed), "virt.zst").unwrap();
        assert_eq!(free2.path(), Path::new("virt.zst"));
        let mut out = Vec::new();
        free2.open_reader().unwrap().read_to_end(&mut out).unwrap();
        assert_eq!(out, b"AAAABBBBCCCCDD");
    }

    /// Nested AutoMount path uses Shared backend; concurrent FUSE opens must not
    /// race seek+read on the shared compressed cursor (was truncated / wrong frame data).
    ///
    /// Regression: interleaved seek+read under mutex without private compressed offset.
    #[test]
    fn shared_zstd_from_reader_concurrent_readers_full_payload() {
        use std::thread;

        // Multi-frame body so frame decode re-seeks the shared compressed cursor.
        let mut raw = Vec::new();
        for i in 0..4000 {
            writeln!(&mut raw, "line {i:05} {}", "y".repeat(64)).unwrap();
        }
        // Chunk into many independent frames (like producer recipes / zstd --rsyncable style).
        const FRAME_BYTES: usize = 2048;
        let mut compressed = Vec::new();
        let mut off = 0usize;
        while off < raw.len() {
            let end = (off + FRAME_BYTES).min(raw.len());
            compressed.extend_from_slice(&encode_frame(&raw[off..end]));
            off = end;
        }
        assert!(
            compressed.len() > FRAME_BYTES,
            "expected multi-frame compressed body"
        );

        let body = SeekableZstd::open_from_reader(
            Cursor::new(compressed),
            Path::new("nested://concurrent.zst"),
        )
        .unwrap();
        assert!(
            body.checkpoint_count() >= 2,
            "need multi-frame map for concurrent frame decode race, checkpoints={}",
            body.checkpoint_count()
        );
        assert_eq!(body.size(), raw.len() as u64);

        let expected = Arc::new(raw);
        let mut handles = Vec::new();
        for t in 0..8 {
            let b = Arc::clone(&body);
            let exp = Arc::clone(&expected);
            handles.push(thread::spawn(move || {
                // Mix full reads and mid-stream seeks like multi-open FUSE.
                for pass in 0..4 {
                    let mut r = b.open_reader().unwrap();
                    if pass % 2 == 0 {
                        let mut out = Vec::new();
                        r.read_to_end(&mut out).unwrap();
                        assert_eq!(out, *exp, "thread {t} pass {pass} full read");
                    } else {
                        let mid = exp.len() as u64 / 2;
                        r.seek(SeekFrom::Start(mid)).unwrap();
                        let mut out = Vec::new();
                        r.read_to_end(&mut out).unwrap();
                        assert_eq!(out, exp[mid as usize..], "thread {t} pass {pass} mid seek");
                    }
                }
            }));
        }
        for h in handles {
            h.join()
                .expect("worker panicked (likely shared zstd seek+read race)");
        }
    }

    #[test]
    fn seek_table_from_reader_equals_path() {
        let parts: [&[u8]; 3] = [b"hello world!!!!", b"second frame payload", b"third!"];
        let mut frames_bin = Vec::new();
        let mut table_entries = Vec::new();
        for part in parts {
            let f = encode_frame(part);
            table_entries.push((f.len() as u32, part.len() as u32));
            frames_bin.extend_from_slice(&f);
        }
        let table = build_seek_table_skippable(&table_entries);
        let mut compressed = frames_bin;
        compressed.extend_from_slice(&table);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seekable-cursor.zst");
        std::fs::write(&path, &compressed).unwrap();

        let path_body = SeekableZstd::open(&path).unwrap();
        let reader_body = SeekableZstd::open_from_reader(
            Cursor::new(compressed),
            Path::new("memory://seekable.zst"),
        )
        .unwrap();

        assert_eq!(path_body.kind(), "zstd-seek-table");
        assert_eq!(reader_body.kind(), "zstd-seek-table");
        assert_eq!(path_body.size(), reader_body.size());
        assert_eq!(path_body.checkpoint_count(), reader_body.checkpoint_count());
        assert_eq!(reader_body.path(), Path::new("memory://seekable.zst"));

        let mut expected = Vec::new();
        for p in parts {
            expected.extend_from_slice(p);
        }
        let mut a = Vec::new();
        path_body
            .open_reader()
            .unwrap()
            .read_to_end(&mut a)
            .unwrap();
        let mut b = Vec::new();
        reader_body
            .open_reader()
            .unwrap()
            .read_to_end(&mut b)
            .unwrap();
        assert_eq!(a, expected);
        assert_eq!(b, expected);
    }

    #[test]
    fn zstd_blocks_pair_round_trip_from_pairs() {
        // (compressed_offset, uncompressed_offset); last is EOF sentinel.
        let blocks = [(0u64, 0u64), (13, 4), (30, 12), (41, 14)];
        let (frames, total) = frames_from_zstd_blocks(&blocks).unwrap();
        assert_eq!(frames.len(), 3);
        assert_eq!(total, 14);
        assert_eq!(frames[0].compressed_offset, 0);
        assert_eq!(frames[0].uncompressed_offset, 0);
        assert_eq!(frames[0].compressed_size, Some(13));
        assert_eq!(frames[0].uncompressed_size, Some(4));
        assert_eq!(frames[1].compressed_offset, 13);
        assert_eq!(frames[1].uncompressed_offset, 4);
        assert_eq!(frames[1].compressed_size, Some(17));
        assert_eq!(frames[1].uncompressed_size, Some(8));
        assert_eq!(frames[2].compressed_offset, 30);
        assert_eq!(frames[2].uncompressed_offset, 12);
        assert_eq!(frames[2].compressed_size, Some(11));
        assert_eq!(frames[2].uncompressed_size, Some(2));

        let exported = zstd_blocks_from_frames(&frames, total);
        assert_eq!(exported, blocks.to_vec());
    }

    #[test]
    fn zstd_blocks_rejects_empty_and_non_monotonic() {
        assert!(frames_from_zstd_blocks(&[]).is_err());
        assert!(frames_from_zstd_blocks(&[(0, 0)]).is_err());
        assert!(frames_from_zstd_blocks(&[(10, 0), (5, 4)]).is_err());
        assert!(frames_from_zstd_blocks(&[(0, 10), (5, 4)]).is_err());
        assert!(frames_from_zstd_blocks(&[(0, 0), (0, 4)]).is_err()); // zero c_size, nonzero d
    }

    #[test]
    fn multi_frame_export_import_zstd_blocks_random_access() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blocks.zst");
        let parts: [&[u8]; 3] = [b"AAAA", b"BBBBCCCC", b"DD"];
        let mut compressed = Vec::new();
        for part in parts {
            compressed.extend_from_slice(&encode_frame(part));
        }
        std::fs::write(&path, &compressed).unwrap();

        // Export from multi-frame scan (no seek table).
        let blocks = export_zstd_blocks(&path).unwrap();
        assert!(
            blocks.len() >= 4,
            "expected 3 frame starts + sentinel, got {}",
            blocks.len()
        );
        assert_eq!(blocks[0], (0, 0));
        assert_eq!(blocks.last().unwrap().1, 14);
        assert_eq!(blocks.last().unwrap().0, compressed.len() as u64);

        // Round-trip through frames_from_zstd_blocks must preserve pairs.
        let (frames, total) = frames_from_zstd_blocks(&blocks).unwrap();
        assert_eq!(frames.len(), 3);
        assert_eq!(total, 14);
        assert_eq!(zstd_blocks_from_frames(&frames, total), blocks);

        // Reimport equals multi-frame random access.
        let scanned = SeekableZstd::open(&path).unwrap();
        let imported = SeekableZstd::open_with_zstd_blocks(&path, 1, &blocks).unwrap();
        assert!(imported.used_zstd_blocks());
        assert!(!imported.used_seek_table());
        assert_eq!(imported.kind(), "zstd-blocks");
        assert_eq!(imported.size(), scanned.size());
        assert_eq!(imported.checkpoint_count(), scanned.checkpoint_count());
        assert_eq!(imported.zstd_blocks().unwrap(), blocks);

        let mut expected = Vec::new();
        for p in parts {
            expected.extend_from_slice(p);
        }

        let mut s_all = Vec::new();
        scanned
            .open_reader()
            .unwrap()
            .read_to_end(&mut s_all)
            .unwrap();
        let mut i_all = Vec::new();
        imported
            .open_reader()
            .unwrap()
            .read_to_end(&mut i_all)
            .unwrap();
        assert_eq!(s_all, expected);
        assert_eq!(i_all, expected);

        let mut s_r = scanned.open_reader().unwrap();
        let mut i_r = imported.open_reader().unwrap();
        let offsets = [0u64, 2, 4, 8, 12];
        for &off in &offsets {
            s_r.seek(SeekFrom::Start(off)).unwrap();
            i_r.seek(SeekFrom::Start(off)).unwrap();
            let mut sb = [0u8; 4];
            let mut ib = [0u8; 4];
            let sn = s_r.read(&mut sb).unwrap();
            let inn = i_r.read(&mut ib).unwrap();
            assert_eq!(sn, inn, "offset {off}");
            assert_eq!(&sb[..sn], &ib[..inn], "offset {off}");
        }

        // Free-function openers
        let free = open_seekable_zstd_with_zstd_blocks(&path, 2, &blocks).unwrap();
        assert_eq!(free.kind(), "zstd-blocks");
        assert_eq!(free.size(), 14);
        let mut r = free.open_reader().unwrap();
        r.seek(SeekFrom::Start(4)).unwrap();
        let mut mid = [0u8; 4];
        r.read_exact(&mut mid).unwrap();
        assert_eq!(&mid, b"BBBB");

        // Reader-based import
        let mem = open_seekable_zstd_with_zstd_blocks_from_reader(
            Cursor::new(compressed.clone()),
            1,
            Path::new("memory://blocks.zst"),
            &blocks,
        )
        .unwrap();
        assert_eq!(mem.kind(), "zstd-blocks");
        assert_eq!(mem.path(), Path::new("memory://blocks.zst"));
        let mut mem_all = Vec::new();
        mem.open_reader()
            .unwrap()
            .read_to_end(&mut mem_all)
            .unwrap();
        assert_eq!(mem_all, expected);

        // export_zstd_blocks_from_reader
        let mut cur = Cursor::new(compressed);
        let blocks2 = export_zstd_blocks_from_reader(&mut cur).unwrap();
        assert_eq!(blocks2, blocks);
    }

    #[test]
    fn zstd_blocks_export_import_with_seek_table() {
        let parts: [&[u8]; 3] = [b"hello world!!!!", b"second frame payload", b"third!"];
        let mut frames_bin = Vec::new();
        let mut table_entries = Vec::new();
        for part in parts {
            let f = encode_frame(part);
            table_entries.push((f.len() as u32, part.len() as u32));
            frames_bin.extend_from_slice(&f);
        }
        let table = build_seek_table_skippable(&table_entries);
        let mut compressed = frames_bin;
        compressed.extend_from_slice(&table);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seekable-blocks.zst");
        std::fs::write(&path, &compressed).unwrap();

        // Export prefers seek table; reimport must still random-access correctly.
        let blocks = export_zstd_blocks(&path).unwrap();
        assert_eq!(blocks.len(), 4); // 3 frames + sentinel
        let total: u64 = parts.iter().map(|p| p.len() as u64).sum();
        assert_eq!(blocks.last().unwrap().1, total);

        let imported = SeekableZstd::open_with_zstd_blocks(&path, 1, &blocks).unwrap();
        assert!(imported.used_zstd_blocks());
        assert_eq!(imported.kind(), "zstd-blocks");
        assert_eq!(imported.size(), total);
        assert_eq!(imported.checkpoint_count(), 3);

        let mut expected = Vec::new();
        for p in parts {
            expected.extend_from_slice(p);
        }
        let mut all = Vec::new();
        imported
            .open_reader()
            .unwrap()
            .read_to_end(&mut all)
            .unwrap();
        assert_eq!(all, expected);

        let off = parts[0].len() as u64 + 7;
        let mut r = imported.open_reader().unwrap();
        r.seek(SeekFrom::Start(off)).unwrap();
        let mut chunk = [0u8; 5];
        r.read_exact(&mut chunk).unwrap();
        assert_eq!(&chunk, &parts[1][7..12]);
    }

    /// Streaming `Read+Seek` that forbids slurping the whole file (K9).
    struct NoSlurp<T> {
        inner: T,
        file_len: u64,
        max_read_len: usize,
    }

    impl<T: Read> Read for NoSlurp<T> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.len() as u64 >= self.file_len {
                panic!(
                    "scan_zstd_frames must not request the entire file in one read (buf={}, file={})",
                    buf.len(),
                    self.file_len
                );
            }
            self.max_read_len = self.max_read_len.max(buf.len());
            self.inner.read(buf)
        }

        fn read_to_end(&mut self, _buf: &mut Vec<u8>) -> io::Result<usize> {
            panic!("scan_zstd_frames must not slurp via read_to_end");
        }
    }

    impl<T: Seek> Seek for NoSlurp<T> {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.inner.seek(pos)
        }
    }

    /// xorshift64* stream — incompressible and not stored in git.
    struct XorShiftBytes {
        state: u64,
        remaining: u64,
    }

    impl XorShiftBytes {
        fn new(seed: u64, remaining: u64) -> Self {
            Self {
                state: seed | 1,
                remaining,
            }
        }
    }

    impl Read for XorShiftBytes {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.remaining == 0 || buf.is_empty() {
                return Ok(0);
            }
            let n = (buf.len() as u64).min(self.remaining) as usize;
            for chunk in buf[..n].chunks_mut(8) {
                self.state ^= self.state << 13;
                self.state ^= self.state >> 7;
                self.state ^= self.state << 17;
                let bytes = self.state.to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
            self.remaining -= n as u64;
            Ok(n)
        }
    }

    /// Regression: `scan_zstd_frames` must not slurp the whole file (`read_to_end`)
    /// or issue a single `read` of the entire length (K9 streaming scan).
    #[test]
    fn scan_zstd_frames_mock_read_does_not_slurp_whole_file() {
        // Two ~200 KiB incompressible frames so the 256 KiB window is smaller
        // than the file and still covers frame 0.
        const PLAIN: u64 = 200 * 1024;
        let mut data = Vec::new();
        let (c0, _) =
            encode_zstd_frame_to(XorShiftBytes::new(0x1234_5678, PLAIN), &mut data, 1).unwrap();
        let (c1, _) =
            encode_zstd_frame_to(XorShiftBytes::new(0x9abc_def0, PLAIN), &mut data, 1).unwrap();
        let file_len = data.len() as u64;
        assert!(
            file_len > SCAN_FRAME_WINDOW_START as u64,
            "fixture must exceed the initial scan window so a whole-file read is detectable"
        );
        assert!(c0 > 0 && c1 > 0);

        let mut mock = NoSlurp {
            inner: Cursor::new(data),
            file_len,
            max_read_len: 0,
        };
        let map = scan_zstd_frames(&mut mock).unwrap();
        assert_eq!(map.frames.len(), 2);
        assert_eq!(map.frames[0].compressed_offset, 0);
        assert_eq!(map.frames[1].compressed_offset, c0);
        assert_eq!(
            map.frames[0].compressed_size + map.frames[1].compressed_size,
            file_len
        );
        assert!(
            (mock.max_read_len as u64) < file_len,
            "max read {} must be < file {}",
            mock.max_read_len,
            file_len
        );
        assert!(map.seek_table.is_none());
    }

    /// Regression: per-frame grow window has no 64 MiB cap; frame 1 offset is
    /// the real start of frame 1 after a >64 MiB compressed frame 0.
    #[test]
    fn scan_zstd_frames_first_frame_larger_than_64mib() {
        const OVER_64MIB: u64 = 64 * 1024 * 1024 + 64 * 1024;
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        let (c0, p0) = encode_zstd_frame_to(
            XorShiftBytes::new(0xC0FFEE, OVER_64MIB),
            tmp.as_file_mut(),
            1,
        )
        .unwrap();
        assert!(
            c0 > 64 * 1024 * 1024,
            "frame 0 compressed size {c0} must exceed 64 MiB (plain {p0})"
        );
        let (c1, p1) =
            encode_zstd_frame_to(&b"tiny-second-frame"[..], tmp.as_file_mut(), 1).unwrap();
        assert_eq!(p1, 17);

        tmp.as_file_mut().seek(SeekFrom::Start(0)).unwrap();
        let map = scan_zstd_frames(tmp.as_file_mut()).unwrap();
        assert_eq!(map.frames.len(), 2, "expected two data frames");
        assert_eq!(
            map.frames[1].compressed_offset, c0,
            "frame 1 offset must equal the real start of frame 1"
        );
        assert_eq!(map.frames[0].compressed_size, c0);
        assert_eq!(map.frames[0].uncompressed_size, p0);
        assert_eq!(map.frames[1].compressed_size, c1);
        assert_eq!(map.frames[1].uncompressed_size, p1);
        assert!(map.seek_table.is_none());

        let via_path = scan_zstd_frames_path(tmp.path()).unwrap();
        assert_eq!(via_path.frames.len(), 2);
        assert_eq!(via_path.frames[1].compressed_offset, c0);
    }

    /// Seek-table footer is recorded as `seek_table` and is not a data frame.
    #[test]
    fn scan_zstd_frames_seek_table_excluded_from_frames() {
        let parts: [&[u8]; 3] = [b"hello world!!!!", b"second frame payload", b"third!"];
        let mut frames_bin = Vec::new();
        let mut table_entries = Vec::new();
        for part in parts {
            let f = encode_zstd_frame(part, 1).unwrap();
            table_entries.push((f.len() as u32, part.len() as u32));
            frames_bin.extend_from_slice(&f);
        }
        let table = build_seek_table_skippable(&table_entries);
        let table_start = frames_bin.len() as u64;
        let mut compressed = frames_bin;
        compressed.extend_from_slice(&table);
        let file_len = compressed.len() as u64;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seekable-scan.zst");
        std::fs::write(&path, &compressed).unwrap();

        let map = scan_zstd_frames_path(&path).unwrap();
        assert_eq!(map.frames.len(), 3);
        assert_eq!(
            map.seek_table,
            Some(table_start..file_len),
            "seek_table must be the skippable footer span"
        );
        let frames_end: u64 = map.frames.iter().map(|f| f.compressed_size).sum();
        assert_eq!(frames_end, table_start);
        assert_eq!(map.frames[0].uncompressed_offset, 0);
        assert_eq!(map.frames[1].uncompressed_offset, parts[0].len() as u64);
        let total_plain: u64 = parts.iter().map(|p| p.len() as u64).sum();
        assert_eq!(
            map.frames.last().unwrap().uncompressed_offset
                + map.frames.last().unwrap().uncompressed_size,
            total_plain
        );
    }

    /// encode_zstd_frame_to / decode_zstd_frames_to persist-API roundtrip.
    #[test]
    fn encode_zstd_frame_to_decode_zstd_frames_to_roundtrip() {
        let mut plain = Vec::new();
        for i in 0..4000u32 {
            writeln!(&mut plain, "line {i:05} {}", "z".repeat(32)).unwrap();
        }

        let mut compressed = Vec::new();
        let (c0, p0) = encode_zstd_frame_to(&plain[..], &mut compressed, 3).unwrap();
        assert_eq!(p0, plain.len() as u64);
        assert_eq!(c0, compressed.len() as u64);

        let map = scan_zstd_frames(&mut Cursor::new(&compressed)).unwrap();
        assert_eq!(map.frames.len(), 1);
        assert_eq!(map.frames[0].compressed_size, c0);
        assert_eq!(map.frames[0].uncompressed_size, p0);

        let mut out = Vec::new();
        let n = decode_zstd_frames_to(&mut Cursor::new(&compressed), &map, 0, &mut out).unwrap();
        assert_eq!(n, p0);
        assert_eq!(out, plain);

        // Last-N: two generated frames, decode only frame 1.
        let tail = b"second-generated-frame";
        let mut two = compressed;
        let (c1, p1) = encode_zstd_frame_to(&tail[..], &mut two, 3).unwrap();
        let map2 = scan_zstd_frames(&mut Cursor::new(&two)).unwrap();
        assert_eq!(map2.frames.len(), 2);
        assert_eq!(map2.frames[1].compressed_offset, c0);
        assert_eq!(map2.frames[1].compressed_size, c1);
        assert_eq!(map2.frames[1].uncompressed_size, p1);
        let mut last = Vec::new();
        let n1 = decode_zstd_frames_to(&mut Cursor::new(&two), &map2, 1, &mut last).unwrap();
        assert_eq!(n1, p1);
        assert_eq!(last, tail);
    }
}
