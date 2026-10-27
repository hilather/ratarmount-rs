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
//!   sequential readers with `threads > 1` also use a bounded decode-ahead pool.
//! * When falling back to a full single-buffer decode of multi-frame input and
//!   `threads > 1`, frames are decompressed in parallel (the public `zstd` crate
//!   exposes multi-thread **encode** via `zstdmt`/`NbWorkers`; frame-level
//!   parallel **decode** is implemented here instead).
//!
//! Open paths:
//! * **Path-based** — reopen independent FDs per reader (`File::open`).
//! * **Reader-based** — any `Read + Seek + Send` (e.g. HTTP Range / in-memory
//!   `Cursor`); shared under a mutex so random Range reads drive frame decode.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc, Mutex,
};

#[path = "zstd_decode_ahead.rs"]
mod decode_ahead;

/// Per-reader decode-ahead and backing-page policy. One thread preserves serial reads.
#[derive(Clone, Copy, Debug)]
pub struct ZstdReadOptions {
    pub threads: u32,
    /// Speculative decoded-byte budget (clamped to 64 MiB); zero disables prefetch.
    pub readahead_bytes: u64,
    pub direct_io: bool,
}

impl Default for ZstdReadOptions {
    fn default() -> Self {
        Self {
            threads: 1,
            readahead_bytes: 16 * 1024 * 1024,
            direct_io: false,
        }
    }
}
use std::thread;

use ratarmount_core::ParallelizationSpec;

use crate::seekable_body::{DecodedBody, SeekRead, SeekableBody, DEFAULT_MEMORY_CAP};
use crate::{CompressError, Result};

/// Completed-reader counters. Take a difference around a workload after dropping its readers.
#[derive(Clone, Copy, Debug, Default)]
pub struct ZstdDecodeStats {
    pub prefetched: u64,
    pub ready: u64,
    pub waited: u64,
    pub synchronous: u64,
    pub synchronous_ns: u64,
    pub wait_ns: u64,
    pub reused: u64,
}

static DECODE_COUNTERS: [AtomicU64; 7] = [const { AtomicU64::new(0) }; 7];

pub fn zstd_decode_stats() -> ZstdDecodeStats {
    let values = DECODE_COUNTERS
        .each_ref()
        .map(|v| v.load(Ordering::Relaxed));
    ZstdDecodeStats {
        prefetched: values[0],
        ready: values[1],
        waited: values[2],
        synchronous: values[3],
        synchronous_ns: values[4],
        wait_ns: values[5],
        reused: values[6],
    }
}

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
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0269-M01","item":"ratarmount_compress::zstd_seek::export_zstd_blocks","disposition":"residual","reason":"path form of the zstd frame scan (compress cannot depend on the managed reader); its remaining callers read a mounted or committed base archive (write_overlay commits, the factory's zstdblocks export, the live-commit last-frame warning); the mandatory export-index frame map and the Hub live commit's zstdblocks use the reader form on a ManagedReadCursor","family":"factory-and-format-readers","issue":"#196","category":"factory-and-format-readers","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
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
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0270-M01","item":"ratarmount_compress::zstd_seek::scan_zstd_frames_path","disposition":"residual","reason":"path form of the zstd frame scan (compress cannot depend on the managed reader); its remaining callers read a mounted or committed base archive (write_overlay commits, the factory's zstdblocks export, the live-commit last-frame warning); the mandatory export-index frame map and the Hub live commit's zstdblocks use the reader form on a ManagedReadCursor","family":"factory-and-format-readers","issue":"#196","category":"factory-and-format-readers","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
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
/// Footer magic for the zstd seekable format seek table.
const SEEKABLE_MAGIC: u32 = 0x8F92_EAB1;
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
#[derive(Clone)]
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
    options: ZstdReadOptions,
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
        Self::open_with_options(
            path,
            ZstdReadOptions {
                threads,
                ..Default::default()
            },
        )
    }

    pub fn open_with_options(
        path: impl AsRef<Path>,
        options: ZstdReadOptions,
    ) -> Result<Arc<dyn SeekableBody>> {
        let path = path.as_ref().to_path_buf();
        let threads = ParallelizationSpec::resolve_zero(options.threads).max(1);
        let options = ZstdReadOptions { threads, ..options };
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-B0271-M01","item":"<ratarmount_compress::zstd_seek::SeekableZstd>::open_with_options","disposition":"residual","reason":"archive/format backend or probe reader of a mounted base; broader backend migration is excluded and SQLAR's own probes do not protect earlier probes","family":"factory-and-format-readers","issue":"#196","category":"factory-and-format-readers","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
        )]
        let mut file = File::open(&path)?;
        match classify_zstd(&mut file, threads)? {
            ZstdPlan::Mapped {
                frames,
                uncompressed_size,
                source,
            } => Ok(Arc::new(Self {
                path: path.clone(),
                backend: ZstdBackend::Path(path),
                options,
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
                    options: ZstdReadOptions {
                        threads,
                        ..Default::default()
                    },
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
    /// `threads > 1` enables bounded sequential decode-ahead (`0` → CPU count);
    /// random access remains per-frame.
    pub fn open_with_zstd_blocks(
        path: impl AsRef<Path>,
        threads: u32,
        blocks: &[(u64, u64)],
    ) -> Result<Arc<Self>> {
        Self::open_with_zstd_blocks_options(
            path,
            ZstdReadOptions {
                threads,
                ..Default::default()
            },
            blocks,
        )
    }

    pub fn open_with_zstd_blocks_options(
        path: impl AsRef<Path>,
        options: ZstdReadOptions,
        blocks: &[(u64, u64)],
    ) -> Result<Arc<Self>> {
        let path = path.as_ref().to_path_buf();
        let options = ZstdReadOptions {
            threads: ParallelizationSpec::resolve_zero(options.threads).max(1),
            ..options
        };
        let (frames, uncompressed_size) = frames_from_zstd_blocks(blocks)?;
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-M0221-M01","item":"<ratarmount_compress::zstd_seek::SeekableZstd>::open_with_zstd_blocks_options","disposition":"residual","reason":"read-only open of the mounted base archive body to validate the imported zstdblocks terminal sentinel (same file the path backend reopens); never an index, companion or overlay file","family":"factory-and-format-readers","issue":"#196","category":"factory-and-format-readers","creation":{"policy":"none","basis":"Existing archive body only; terminal-sentinel validation creates no pathname."}}"###
        )]
        let mut file = File::open(&path)?;
        validate_zstd_blocks_terminal(&mut file, blocks)?;
        Ok(Arc::new(Self {
            path: path.clone(),
            backend: ZstdBackend::Path(path),
            options,
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
        mut reader: R,
        threads: u32,
        archive_label: impl AsRef<Path>,
        blocks: &[(u64, u64)],
    ) -> Result<Arc<Self>>
    where
        R: Read + Seek + Send + 'static,
    {
        let path = archive_label.as_ref().to_path_buf();
        let threads = ParallelizationSpec::resolve_zero(threads).max(1);
        let (frames, uncompressed_size) = frames_from_zstd_blocks(blocks)?;
        validate_zstd_blocks_terminal(&mut reader, blocks)?;
        let shared: Arc<Mutex<Box<dyn SeekRead>>> = Arc::new(Mutex::new(Box::new(reader)));
        Ok(Arc::new(Self {
            path,
            backend: ZstdBackend::Shared(shared),
            options: ZstdReadOptions {
                threads,
                ..Default::default()
            },
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
    if threads > 1 && !ratarmount_core::budget::MemoryBudget::global().enabled() {
        if let Ok(data) = try_parallel_frame_decode(path, threads) {
            if data.len() as u64 <= DEFAULT_MEMORY_CAP {
                return Ok(DecodedBody::from_bytes(path, "zstd", data)? as Arc<dyn SeekableBody>);
            }
            let cursor = std::io::Cursor::new(data);
            let body = DecodedBody::from_decoder(path, "zstd", cursor, DEFAULT_MEMORY_CAP)?;
            return Ok(body as Arc<dyn SeekableBody>);
        }
    }
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0272-M01","item":"ratarmount_compress::zstd_seek::decode_full","disposition":"residual","reason":"archive/format backend or probe reader of a mounted base; broader backend migration is excluded and SQLAR's own probes do not protect earlier probes","family":"factory-and-format-readers","issue":"#196","category":"factory-and-format-readers","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
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
    if threads > 1 && !ratarmount_core::budget::MemoryBudget::global().enabled() {
        if let Ok(data) = try_parallel_frame_decode_from_reader(&mut reader, threads) {
            if data.len() as u64 <= DEFAULT_MEMORY_CAP {
                return Ok(DecodedBody::from_bytes(path, "zstd", data)? as Arc<dyn SeekableBody>);
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
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0273-M01","item":"ratarmount_compress::zstd_seek::try_parallel_frame_decode","disposition":"residual","reason":"archive/format backend or probe reader of a mounted base; broader backend migration is excluded and SQLAR's own probes do not protect earlier probes","family":"factory-and-format-readers","issue":"#196","category":"factory-and-format-readers","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
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

#[derive(Debug)]
struct Reservation {
    _memory: ratarmount_core::budget::Reservation,
    _pressure: Option<ratarmount_core::budget::PressureHook>,
    used: Arc<AtomicU64>,
    slots: Arc<AtomicU64>,
    bytes: u64,
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::AcqRel);
        self.slots.fetch_sub(1, Ordering::AcqRel);
    }
}

struct PendingFrame {
    index: usize,
    result: mpsc::Receiver<(io::Result<Vec<u8>>, Reservation)>,
}

struct ZstdFrameReader {
    backend: ZstdBackend,
    frames: Vec<FrameInfo>,
    options: ZstdReadOptions,
    size: u64,
    pos: u64,
    frame_idx: Option<usize>,
    frame_data: Vec<u8>,
    frame_reservation: Option<Reservation>,
    frame_memory: Option<ratarmount_core::budget::Reservation>,
    frame_spool: Option<File>,
    frame_start: u64,
    progress: u64,
    bytes_read: u64,
    stats: ZstdDecodeStats,
    pending: VecDeque<PendingFrame>,
    cancelled: Arc<AtomicBool>,
    reserved: Arc<AtomicU64>,
    reserved_slots: Arc<AtomicU64>,
    #[cfg(test)]
    decode_hook: Option<Arc<dyn Fn() + Send + Sync>>,
}

impl ZstdBackend {
    fn open_compressed(&self) -> io::Result<CompressedHandle> {
        match self {
            Self::Path(p) => Ok(CompressedHandle::File({
                #[expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-B0274-M01","item":"<ratarmount_compress::zstd_seek::ZstdBackend>::open_compressed","disposition":"residual","reason":"zstd backend reader of a mounted base; broader backend migration is excluded","family":"factory-and-format-readers","issue":"#196","category":"factory-and-format-readers","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
                )]
                let __inventory_value_0 = File::open(p);
                __inventory_value_0
            }?)),
            Self::Shared(shared) => Ok(CompressedHandle::Shared {
                inner: Arc::clone(shared),
                pos: 0,
            }),
        }
    }
}

/// Advisory only: unsupported descriptors/platforms leave reads unchanged.
fn advise(file: &CompressedHandle, offset: u64, len: u64, sequential: bool) {
    #[cfg(target_os = "linux")]
    if let CompressedHandle::File(file) = file {
        use std::os::fd::AsRawFd;
        if let (Ok(offset), Ok(len)) = (libc::off_t::try_from(offset), libc::off_t::try_from(len)) {
            // SAFETY: this File owns a live descriptor; advice never changes file contents.
            unsafe {
                libc::posix_fadvise(
                    file.as_raw_fd(),
                    offset,
                    len,
                    if sequential {
                        libc::POSIX_FADV_SEQUENTIAL
                    } else {
                        libc::POSIX_FADV_DONTNEED
                    },
                );
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (file, offset, len, sequential);
}

fn decode_frame(
    backend: &ZstdBackend,
    info: &FrameInfo,
    expected: u64,
    sequential: bool,
    direct_io: bool,
    mut data: Vec<u8>,
) -> io::Result<Vec<u8>> {
    let mut file = backend.open_compressed()?;
    if sequential {
        advise(&file, 0, 0, true);
    }
    file.seek(SeekFrom::Start(info.compressed_offset))?;
    // Streaming input avoids retaining a second frame-sized compressed buffer.
    let input = (&mut file).take(info.compressed_size.unwrap_or(u64::MAX));
    let mut decoder = zstd::stream::read::Decoder::new(input)?.single_frame();
    let len = usize::try_from(expected).map_err(|_| io::Error::other("zstd frame too large"))?;
    if data.capacity() < len {
        data.try_reserve_exact(len - data.len())
            .map_err(io::Error::other)?;
    }
    data.resize(len, 0);
    decoder.read_exact(&mut data)?;
    if decoder.read(&mut [0u8; 1])? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "zstd frame size differs from frame map",
        ));
    }
    if direct_io {
        if let Some(len) = info.compressed_size {
            if len != 0 {
                advise(&file, info.compressed_offset, len, false);
            }
        }
    }
    Ok(data)
}

impl ZstdFrameReader {
    fn open(z: &SeekableZstd) -> io::Result<Self> {
        Ok(Self {
            backend: z.backend.clone(),
            frames: z.frames.clone(),
            options: z.options,
            size: z.uncompressed_size,
            pos: 0,
            frame_idx: None,
            frame_data: Vec::new(),
            frame_reservation: None,
            frame_memory: None,
            frame_spool: None,
            frame_start: 0,
            progress: 0,
            bytes_read: 0,
            stats: ZstdDecodeStats::default(),
            pending: VecDeque::new(),
            cancelled: Arc::new(AtomicBool::new(false)),
            reserved: Arc::new(AtomicU64::new(0)),
            reserved_slots: Arc::new(AtomicU64::new(0)),
            #[cfg(test)]
            decode_hook: None,
        })
    }

    fn frame_size(&self, index: usize) -> u64 {
        self.frames
            .get(index + 1)
            .map_or(self.size, |f| f.uncompressed_offset)
            - self.frames[index].uncompressed_offset
    }

    fn cancel(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        self.pending.clear();
        self.cancelled = Arc::new(AtomicBool::new(false));
        self.progress = 0;
    }

    fn reserve_frame(&self, bytes: u64, budget: u64) -> Option<Reservation> {
        let pool = ratarmount_core::budget::MemoryPool::global(
            "zstd-decode-ahead",
            64 * 1024 * 1024,
            ratarmount_core::budget::Priority::Speculative,
        );
        let memory = pool.reserve(bytes)?;
        let weak = Arc::downgrade(&self.cancelled);
        let pressure = pool.enabled().then(|| {
            pool.on_pressure(move || {
                if let Some(cancelled) = weak.upgrade() {
                    cancelled.store(true, Ordering::Release);
                }
            })
        });
        ratarmount_core::try_update_u64(
            &self.reserved_slots,
            Ordering::AcqRel,
            Ordering::Acquire,
            |slots| (slots < u64::from(self.options.threads.min(16))).then_some(slots + 1),
        )
        .ok()?;
        if ratarmount_core::try_update_u64(
            &self.reserved,
            Ordering::AcqRel,
            Ordering::Acquire,
            |used| used.checked_add(bytes).filter(|&total| total <= budget),
        )
        .is_err()
        {
            self.reserved_slots.fetch_sub(1, Ordering::AcqRel);
            return None;
        }
        Some(Reservation {
            _memory: memory,
            _pressure: pressure,
            used: Arc::clone(&self.reserved),
            slots: Arc::clone(&self.reserved_slots),
            bytes,
        })
    }

    #[cfg(any(target_os = "linux", test))]
    fn compressed_prefetch_range(&self, next: usize, budget: u64) -> Option<(u64, u64)> {
        let slots = u64::from(self.options.threads.min(16))
            .saturating_sub(self.reserved_slots.load(Ordering::Acquire))
            as usize;
        let mut remaining = budget.saturating_sub(self.reserved.load(Ordering::Acquire));
        let start = self.frames.get(next)?.compressed_offset;
        let mut end = start;
        for index in next..self.frames.len().min(next + slots) {
            let size = self.frame_size(index);
            if size == 0 || size > remaining {
                break;
            }
            let Some(frame_end) = self.frames[index]
                .compressed_size
                .and_then(|size| self.frames[index].compressed_offset.checked_add(size))
            else {
                break;
            };
            remaining -= size;
            end = frame_end;
        }
        let len = end.saturating_sub(start).min(64 * 1024 * 1024);
        (len != 0).then_some((start, len))
    }

    fn prefetch(&mut self, mut reusable: Vec<u8>) {
        if self.cancelled.load(Ordering::Acquire) {
            self.cancel();
            return;
        }
        if self.options.threads <= 1
            || self.options.readahead_bytes == 0
            || self.progress < 128 * 1024
        {
            return;
        }
        let Some(current) = self.frame_idx else {
            return;
        };
        let budget = self.options.readahead_bytes.min(64 * 1024 * 1024);
        let mut next = self.pending.back().map_or(current + 1, |p| p.index + 1);
        // Queue contiguous disk I/O before workers race to decode independent
        // frames. Independent FD readahead otherwise follows worker order,
        // causing cold sequential reads to behave like scattered small reads.
        #[cfg(target_os = "linux")]
        if let ZstdBackend::Path(path) = &self.backend {
            if let Some((offset, len)) = self.compressed_prefetch_range(next, budget) {
                if let (Ok(file), Ok(offset), Ok(len)) = (
                    {
                        #[expect(
                            clippy::disallowed_methods,
                            reason = r###"internal-read:v1 {"id":"IR-B0275-M01","item":"<ratarmount_compress::zstd_seek::ZstdFrameReader>::prefetch","disposition":"residual","reason":"archive/format backend or probe reader of a mounted base; broader backend migration is excluded and SQLAR's own probes do not protect earlier probes","family":"factory-and-format-readers","issue":"#196","category":"factory-and-format-readers","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
                        )]
                        let __inventory_value_0 = File::open(path);
                        __inventory_value_0
                    },
                    libc::off_t::try_from(offset),
                    libc::off_t::try_from(len),
                ) {
                    use std::os::fd::AsRawFd;
                    // SAFETY: owned live fd and checked nonnegative range.
                    unsafe {
                        libc::posix_fadvise(
                            file.as_raw_fd(),
                            offset,
                            len,
                            libc::POSIX_FADV_WILLNEED,
                        );
                    }
                }
            }
        }
        while next < self.frames.len()
            && self.pending.len() < (self.options.threads as usize).min(16)
        {
            let bytes = self.frame_size(next);
            // A frame larger than the budget stays on the synchronous path.
            if bytes == 0 || bytes > budget {
                break;
            }
            let Some(reservation) = self.reserve_frame(bytes, budget) else {
                break;
            };
            // Hand the consumed buffer back to a decoder. Repeated allocation,
            // zero-fill and cross-thread frees otherwise cost more than decoding
            // cheap frames. Oversized buffers cannot escape the reservation cap.
            let buffer = if reusable.capacity() as u64 == bytes {
                self.stats.reused += 1;
                std::mem::take(&mut reusable)
            } else {
                Vec::new()
            };
            let (tx, result) = mpsc::channel();
            let backend = self.backend.clone();
            let info = self.frames[next].clone();
            let cancelled = Arc::clone(&self.cancelled);
            let direct_io = self.options.direct_io;
            #[cfg(test)]
            let hook = self.decode_hook.clone();
            if !decode_ahead::submit(
                self.options.threads,
                Box::new(move || {
                    if cancelled.load(Ordering::Acquire) {
                        return;
                    }
                    #[cfg(test)]
                    if let Some(hook) = hook {
                        hook();
                    }
                    if cancelled.load(Ordering::Acquire) {
                        return;
                    }
                    let data = decode_frame(&backend, &info, bytes, true, direct_io, buffer);
                    let _ = tx.send((data, reservation));
                }),
            ) {
                break;
            }
            self.stats.prefetched += 1;
            self.pending.push_back(PendingFrame {
                index: next,
                result,
            });
            next += 1;
        }
    }

    fn ensure_frame(&mut self, target: u64) -> io::Result<()> {
        if self.cancelled.load(Ordering::Acquire) {
            self.cancel();
        }
        if target >= self.size {
            return Ok(());
        }
        let cached_len = if self.frame_spool.is_some() {
            self.frame_idx.map_or(0, |index| self.frame_size(index))
        } else {
            self.frame_data.len() as u64
        };
        if self.frame_idx.is_some()
            && target >= self.frame_start
            && target < self.frame_start + cached_len
        {
            return Ok(());
        }
        let best = self
            .frames
            .partition_point(|f| f.uncompressed_offset <= target)
            .saturating_sub(1);
        let prefetched = if self.pending.front().is_some_and(|p| p.index == best) {
            // Only the frame at the requested offset can deliver an error. Retry a
            // failed speculative decode synchronously (transient I/O may recover).
            let pending = self.pending.pop_front().unwrap();
            let result = match pending.result.try_recv() {
                Ok(value) => {
                    self.stats.ready += 1;
                    Some(value)
                }
                Err(mpsc::TryRecvError::Empty) => {
                    self.stats.waited += 1;
                    let start = std::time::Instant::now();
                    let value = pending.result.recv().ok();
                    self.stats.wait_ns += start.elapsed().as_nanos() as u64;
                    value
                }
                Err(mpsc::TryRecvError::Disconnected) => None,
            };
            result.and_then(|(data, reservation)| data.ok().map(|data| (data, reservation)))
        } else {
            None
        };
        let mut reusable = std::mem::take(&mut self.frame_data);
        if ratarmount_core::budget::MemoryBudget::global().enabled() {
            reusable = Vec::new();
            self.frame_reservation = None;
            self.frame_memory = None;
            self.frame_spool = None;
            if prefetched.is_none() {
                let pool = ratarmount_core::budget::MemoryPool::global(
                    "zstd-frame",
                    64 * 1024 * 1024,
                    ratarmount_core::budget::Priority::Cache,
                );
                self.frame_memory = pool.reserve(self.frame_size(best));
                if self.frame_memory.is_none() {
                    let mut input = self.backend.open_compressed()?;
                    let info = &self.frames[best];
                    input.seek(SeekFrom::Start(info.compressed_offset))?;
                    let decoder = zstd::stream::read::Decoder::new(
                        input.take(info.compressed_size.unwrap_or(u64::MAX)),
                    )?
                    .single_frame();
                    #[expect(
                        clippy::disallowed_methods,
                        reason = r###"internal-read:v1 {"id":"IR-B0276-M01","item":"<ratarmount_compress::zstd_seek::ZstdFrameReader>::ensure_frame","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
                    )]
                    let mut spool = tempfile::tempfile()?;
                    let expected = self.frame_size(best);
                    let size = io::copy(&mut decoder.take(expected.saturating_add(1)), &mut spool)?;
                    if size != expected {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "zstd frame size differs from frame map",
                        ));
                    }
                    self.frame_spool = Some(spool);
                    self.frame_idx = Some(best);
                    self.frame_start = info.uncompressed_offset;
                    self.stats.synchronous += 1;
                    self.prefetch(Vec::new());
                    return Ok(());
                }
            }
        }
        self.frame_data = match prefetched {
            Some((data, reservation)) => {
                if ratarmount_core::budget::MemoryBudget::global().enabled() {
                    self.frame_reservation = Some(reservation);
                }
                data
            }
            None => {
                self.stats.synchronous += 1;
                let start = std::time::Instant::now();
                let result = decode_frame(
                    &self.backend,
                    &self.frames[best],
                    self.frame_size(best),
                    self.options.threads > 1
                        && self.options.readahead_bytes > 0
                        && self.progress >= 128 * 1024,
                    self.options.direct_io,
                    std::mem::take(&mut reusable),
                );
                self.stats.synchronous_ns += start.elapsed().as_nanos() as u64;
                result?
            }
        };
        self.frame_idx = Some(best);
        self.frame_start = self.frames[best].uncompressed_offset;
        self.prefetch(reusable);
        Ok(())
    }
}

impl Drop for ZstdFrameReader {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Release);
        let stats = self.stats;
        for (counter, value) in DECODE_COUNTERS.iter().zip([
            stats.prefetched,
            stats.ready,
            stats.waited,
            stats.synchronous,
            stats.synchronous_ns,
            stats.wait_ns,
            stats.reused,
        ]) {
            counter.fetch_add(value, Ordering::Relaxed);
        }
        if self.bytes_read != 0 {
            log::info!("zstd-read-summary bytes={} prefetched={} ready={} waited={} synchronous={} synchronous_ns={} wait_ns={} reused={}",
                self.bytes_read, stats.prefetched, stats.ready, stats.waited, stats.synchronous, stats.synchronous_ns, stats.wait_ns, stats.reused);
        }
    }
}

impl Read for ZstdFrameReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.size {
            return Ok(0);
        }
        self.ensure_frame(self.pos)?;
        let into = (self.pos - self.frame_start) as usize;
        let remaining = self
            .frame_size(self.frame_idx.unwrap())
            .saturating_sub(into as u64);
        let n = remaining.min(buf.len() as u64) as usize;
        if let Some(spool) = &mut self.frame_spool {
            spool.seek(SeekFrom::Start(into as u64))?;
            spool.read_exact(&mut buf[..n])?;
        } else {
            buf[..n].copy_from_slice(&self.frame_data[into..into + n]);
        }
        self.pos += n as u64;
        self.progress = self.progress.saturating_add(n as u64);
        self.bytes_read += n as u64;
        self.prefetch(Vec::new());
        Ok(n)
    }
}

impl Seek for ZstdFrameReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => Some(o),
            SeekFrom::End(o) => self.size.checked_add_signed(o),
            SeekFrom::Current(o) => self.pos.checked_add_signed(o),
        }
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek outside stream address range",
            )
        })?;
        // StenciledFile seeks to the current offset before every read.
        if new != self.pos {
            self.cancel();
        }
        self.pos = new;
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
    if blocks[0].1 != 0 {
        return Err(CompressError::Msg(
            "zstdblocks requires an initial frame at data offset 0".into(),
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

/// Verify that the supplied terminal entry omits no data frame. Only complete
/// skippable frames (including a seek-table footer) may follow it.
fn validate_zstd_blocks_terminal<R: Read + Seek>(
    reader: &mut R,
    blocks: &[(u64, u64)],
) -> Result<()> {
    let saved = reader.stream_position()?;
    let result = (|| {
        let len = reader.seek(SeekFrom::End(0))?;
        let mut offset = blocks
            .last()
            .ok_or_else(|| CompressError::Msg("zstdblocks missing terminal sentinel".into()))?
            .0;
        if offset > len {
            return Err(CompressError::Msg(
                "zstdblocks terminal sentinel exceeds source size".into(),
            ));
        }
        while offset < len {
            if len - offset < 8 {
                return Err(CompressError::Msg(
                    "zstdblocks terminal sentinel has a truncated skippable tail".into(),
                ));
            }
            reader.seek(SeekFrom::Start(offset))?;
            let mut header = [0; 8];
            reader.read_exact(&mut header)?;
            let magic = u32::from_le_bytes(header[..4].try_into().unwrap());
            if magic & 0xfffffff0 != 0x184d2a50 {
                return Err(CompressError::Msg(
                    "zstdblocks terminal sentinel precedes a data frame or invalid tail".into(),
                ));
            }
            offset = offset.checked_add(8).and_then(|n| n.checked_add(u64::from(u32::from_le_bytes(header[4..].try_into().unwrap()))))
                .filter(|&n| n <= len)
                .ok_or_else(|| CompressError::Msg("zstdblocks terminal sentinel has an overflowing or truncated skippable tail".into()))?;
        }
        Ok(())
    })();
    reader.seek(SeekFrom::Start(saved))?;
    result
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

    /// Regression: a tiny memory budget must degrade without corrupting reads.
    #[test]
    fn regression_memory_budget_zstd_tracks_active_and_prefetched_frames() {
        let name = std::thread::current().name().unwrap().to_string();
        if std::env::var("RATARMOUNT_BUDGET_TEST").ok().as_deref() != Some(&name) {
            assert!(std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env("RATARMOUNT_BUDGET_TEST", &name)
                .status()
                .unwrap()
                .success());
            return;
        }
        ratarmount_core::budget::MemoryBudget::install(8388608).unwrap();

        let (_dir, mut reader, expected) = ahead_fixture(4, 512 * 1024);
        let mut actual = Vec::new();
        reader.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, expected);
        assert!(reader.stats.prefetched > 0);
        let snapshot = ratarmount_core::budget::MemoryBudget::global().snapshot();
        assert!(snapshot.high_water > 0 && snapshot.high_water <= 8388608);
        assert!(snapshot.pools.iter().all(|p| p.high_water <= p.cap));
    }

    /// Regression: a tiny memory budget must degrade without corrupting reads.
    #[test]
    fn regression_memory_budget_zstd_ahead_degrades() {
        let name = std::thread::current().name().unwrap().to_string();
        if std::env::var("RATARMOUNT_BUDGET_TEST").ok().as_deref() != Some(&name) {
            assert!(std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &name, "--nocapture"])
                .env("RATARMOUNT_BUDGET_TEST", &name)
                .status()
                .unwrap()
                .success());
            return;
        }
        ratarmount_core::budget::MemoryBudget::install(64).unwrap();

        let (_dir, mut reader, expected) = ahead_fixture(4, 512 * 1024);
        let mut actual = Vec::new();
        reader.read_to_end(&mut actual).unwrap();
        assert_eq!(actual, expected);
        assert_eq!(reader.stats.prefetched, 0);
        assert_eq!(
            ratarmount_core::budget::MemoryBudget::global()
                .snapshot()
                .reserved,
            0
        );
        let path = _dir.path().join("single.zst");
        std::fs::write(&path, encode_frame(&expected)).unwrap();
        let body = open_seekable_zstd_with_threads(&path, 4).unwrap();
        let mut actual = Vec::new();
        body.open_reader()
            .unwrap()
            .read_to_end(&mut actual)
            .unwrap();
        assert_eq!(actual, expected);
        assert_eq!(
            ratarmount_core::budget::MemoryBudget::global()
                .snapshot()
                .reserved,
            0
        );
        regression_decode_ahead_error_at_requested_offset_and_retry();
    }
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

    fn ahead_fixture(threads: u32, budget: u64) -> (tempfile::TempDir, ZstdFrameReader, Vec<u8>) {
        ahead_fixture_with_frame_size(threads, budget, 128 * 1024)
    }

    fn ahead_fixture_with_frame_size(
        threads: u32,
        budget: u64,
        frame_size: usize,
    ) -> (tempfile::TempDir, ZstdFrameReader, Vec<u8>) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ahead.zst");
        let data: Vec<u8> = (0..2 * 1024 * 1024)
            .map(|i| ((i * 31 + i / 997) % 251) as u8)
            .collect();
        let mut file = File::create(&path).unwrap();
        let mut blocks = Vec::new();
        let mut compressed_offset = 0;
        for (i, part) in data.chunks(frame_size).enumerate() {
            blocks.push((compressed_offset, (i * frame_size) as u64));
            let compressed = encode_frame(part);
            file.write_all(&compressed).unwrap();
            compressed_offset += compressed.len() as u64;
        }
        blocks.push((compressed_offset, data.len() as u64));
        let body = SeekableZstd::open_with_zstd_blocks_options(
            &path,
            ZstdReadOptions {
                threads,
                readahead_bytes: budget,
                direct_io: true,
            },
            &blocks,
        )
        .unwrap();
        (dir, ZstdFrameReader::open(&body).unwrap(), data)
    }

    /// Regression: sequential parallel reads must recycle consumed frame buffers
    /// instead of allocating/zeroing and freeing a frame on every handoff.
    #[test]
    fn regression_decode_ahead_recycles_consumed_buffers() {
        let (_dir, mut reader, data) = ahead_fixture(4, 512 * 1024);
        let mut got = Vec::new();
        reader.read_to_end(&mut got).unwrap();
        assert_eq!(got, data);
        assert!(reader.stats.reused >= 10, "{:?}", reader.stats);
        assert!(reader.reserved.load(Ordering::Acquire) <= 512 * 1024);
    }

    /// Regression: cold parallel reads must request contiguous backing ranges
    /// within the available window, never an unbounded len=0 (through EOF) hint.
    #[test]
    fn regression_decode_ahead_cold_io_hints_follow_bounded_frame_order() {
        let (_dir, reader, _) = ahead_fixture(4, 256 * 1024);
        assert_eq!(
            reader.compressed_prefetch_range(1, 256 * 1024),
            Some((
                reader.frames[1].compressed_offset,
                reader.frames[3].compressed_offset - reader.frames[1].compressed_offset
            ))
        );
        let reservation = reader.reserve_frame(128 * 1024, 256 * 1024).unwrap();
        assert_eq!(
            reader.compressed_prefetch_range(1, 256 * 1024),
            Some((
                reader.frames[1].compressed_offset,
                reader.frames[1].compressed_size.unwrap()
            ))
        );
        assert_eq!(reader.compressed_prefetch_range(1, 0), None);
        assert_eq!(
            reader.compressed_prefetch_range(reader.frames.len(), 256 * 1024),
            None
        );
        drop(reservation);
        let mut reader = reader;
        reader.frames[1].compressed_size = Some(0);
        assert_eq!(reader.compressed_prefetch_range(1, 128 * 1024), None);
    }

    /// Regression: FUSE's 128 KiB reads and same-position seeks must keep
    /// decode-ahead active, with completed frames consumed without waiting.
    #[test]
    fn regression_decode_ahead_128k_requests_keep_ready_frames() {
        let (_dir, mut reader, data) =
            ahead_fixture_with_frame_size(4, 4 * 1024 * 1024, 1024 * 1024);
        let mut buffer = vec![0; 128 * 1024];
        reader.read_exact(&mut buffer).unwrap();
        assert_eq!(buffer, data[..buffer.len()]);
        assert_eq!(reader.stats.prefetched, 1);
        // Choose a deterministic consumer schedule: let the real worker finish
        // while the consumer is still inside frame 0. Requeue its result so the
        // normal try_recv path, rather than wall-clock timing, is asserted.
        let result = reader.pending[0]
            .result
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap();
        let (tx, rx) = mpsc::channel();
        tx.send(result).unwrap();
        reader.pending[0].result = rx;
        for offset in (buffer.len()..data.len()).step_by(buffer.len()) {
            reader.seek(SeekFrom::Start(offset as u64)).unwrap();
            assert!(!reader.cancelled.load(Ordering::Acquire));
            reader.read_exact(&mut buffer).unwrap();
            assert_eq!(buffer, data[offset..offset + buffer.len()]);
        }
        assert_eq!(reader.stats.synchronous, 1);
        assert_eq!(reader.stats.ready, 1);
        assert_eq!(reader.stats.waited, 0);
        assert_eq!(reader.read(&mut buffer).unwrap(), 0);
    }

    /// Regression: decode-ahead must preserve bytes across frames, nontrivial seeks and EOF.
    #[test]
    fn regression_decode_ahead_seek_boundaries_and_eof() {
        let (_dir, mut reader, data) = ahead_fixture(4, 512 * 1024);
        let mut prefix = vec![0; 700_001];
        reader.read_exact(&mut prefix).unwrap();
        assert_eq!(prefix, data[..prefix.len()]);
        for offset in [17, 1_111_117, 900_013, 0] {
            reader.seek(SeekFrom::Start(offset)).unwrap();
            let mut got = vec![0; 300_007];
            reader.read_exact(&mut got).unwrap();
            assert_eq!(got, data[offset as usize..offset as usize + got.len()]);
        }
        let mut tail = Vec::new();
        reader.read_to_end(&mut tail).unwrap();
        assert_eq!(tail, data[300_007..]);
        assert_eq!(reader.read(&mut [0; 10]).unwrap(), 0);
        reader.seek(SeekFrom::End(99)).unwrap();
        assert_eq!(reader.read(&mut [0; 10]).unwrap(), 0);
    }

    /// Regression: overflowing relative seeks must return an error, not panic or wrap.
    #[test]
    fn regression_decode_ahead_seek_overflow_returns_error() {
        let (_dir, mut reader, _) = ahead_fixture(4, 512 * 1024);
        assert_eq!(reader.seek(SeekFrom::Start(u64::MAX)).unwrap(), u64::MAX);
        assert!(reader.seek(SeekFrom::Current(1)).is_err());
        assert_eq!(reader.pos, u64::MAX);
        assert!(reader.seek(SeekFrom::End(i64::MIN)).is_err());
    }

    /// Regression: a forged frame size must not grow a speculative output past its reservation.
    #[test]
    fn regression_decode_ahead_wrong_frame_size_returns_error() {
        let (_dir, mut reader, _) = ahead_fixture(4, 512 * 1024);
        reader.frames[1].uncompressed_offset -= 1;
        assert_eq!(
            reader.read(&mut [0; 1]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(reader.pos, 0);
    }

    /// Regression: cold scanned maps and shared-reader maps must also use correct decode-ahead bytes.
    #[test]
    fn regression_decode_ahead_scanned_and_shared_maps() {
        let (dir, _reader, data) = ahead_fixture(4, 512 * 1024);
        let path = dir.path().join("ahead.zst");
        let body = SeekableZstd::open_with_options(
            &path,
            ZstdReadOptions {
                threads: 4,
                readahead_bytes: 512 * 1024,
                direct_io: true,
            },
        )
        .unwrap();
        let mut got = Vec::new();
        body.open_reader().unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, data);
        let body = SeekableZstd::open_with_threads_from_reader(
            std::io::Cursor::new(std::fs::read(path).unwrap()),
            4,
            "shared.zst",
        )
        .unwrap();
        got.clear();
        body.open_reader().unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, data);
    }

    /// Regression: serial library defaults and random reads must not submit work.
    #[test]
    fn regression_decode_ahead_serial_and_random_no_workers() {
        let (_dir, mut serial, data) = ahead_fixture(1, 512 * 1024);
        serial.decode_hook = Some(Arc::new(|| panic!("serial reader scheduled a worker")));
        let mut got = Vec::new();
        serial.read_to_end(&mut got).unwrap();
        assert_eq!(got, data);
        assert!(serial.pending.is_empty());
        assert_eq!(serial.reserved.load(Ordering::Acquire), 0);
        assert_eq!(ZstdReadOptions::default().threads, 1);
        let (_dir2, mut random, _) = ahead_fixture(4, 512 * 1024);
        for offset in [0, 500_000, 7, 800_000] {
            random.seek(SeekFrom::Start(offset)).unwrap();
            random.read_exact(&mut [0; 4096]).unwrap();
            assert!(random.pending.is_empty());
        }
        random.options.readahead_bytes = 0;
        random.read_to_end(&mut Vec::new()).unwrap();
        assert!(random.pending.is_empty());
    }

    /// Regression: workers must overlap; seek cannot join blocked decoders or reset their budget.
    #[test]
    fn regression_decode_ahead_concurrent_cancel_and_memory_bound() {
        use std::sync::Condvar;
        use std::time::{Duration, Instant};
        let (_dir, mut reader, _) = ahead_fixture(4, 256 * 1024);
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let (tx, rx) = mpsc::channel();
        let active = Arc::new(AtomicU64::new(0));
        let peak = Arc::new(AtomicU64::new(0));
        let g = Arc::clone(&gate);
        let a = Arc::clone(&active);
        let p = Arc::clone(&peak);
        reader.decode_hook = Some(Arc::new(move || {
            let now = a.fetch_add(1, Ordering::SeqCst) + 1;
            p.fetch_max(now, Ordering::SeqCst);
            tx.send(()).unwrap();
            let (lock, cv) = &*g;
            let _guard = cv
                .wait_timeout_while(lock.lock().unwrap(), Duration::from_secs(10), |released| {
                    !*released
                })
                .unwrap();
            a.fetch_sub(1, Ordering::SeqCst);
        }));
        reader.read_exact(&mut vec![0; 128 * 1024]).unwrap();
        let first = rx.recv_timeout(Duration::from_secs(5));
        let second = rx.recv_timeout(Duration::from_secs(5));
        let before = Instant::now();
        reader.seek(SeekFrom::Start(7)).unwrap();
        let elapsed = before.elapsed();
        let held = reader.reserved.load(Ordering::Acquire);
        // A new sequential run cannot allocate over reservations held by cancelled jobs.
        reader.read_exact(&mut vec![0; 128 * 1024]).unwrap();
        let after = reader.reserved.load(Ordering::Acquire);
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        assert!(first.is_ok() && second.is_ok(), "two workers did not start");
        assert!(peak.load(Ordering::SeqCst) >= 2);
        assert!(
            elapsed < Duration::from_millis(250),
            "seek waited {elapsed:?}"
        );
        assert_eq!(held, 256 * 1024);
        assert!(after <= 256 * 1024);
        assert!(reader.pending.is_empty());
    }

    /// Regression: variable-size frames and cancelled generations share byte/slot limits.
    #[test]
    fn regression_decode_ahead_variable_sizes_and_sixteen_slot_limit() {
        let (_dir, mut reader, _) = ahead_fixture(32, 1024);
        let a = reader.reserve_frame(700, 1024).unwrap();
        assert!(reader.reserve_frame(400, 1024).is_none());
        let b = reader.reserve_frame(324, 1024).unwrap();
        reader.cancel();
        assert!(reader.reserve_frame(1, 1024).is_none());
        assert_eq!(reader.reserved_slots.load(Ordering::Acquire), 2);
        drop((a, b));
        let held: Vec<_> = (0..16)
            .map(|_| reader.reserve_frame(1, 1024).unwrap())
            .collect();
        assert!(reader.reserve_frame(1, 1024).is_none());
        drop(held);
        assert_eq!(reader.reserved.load(Ordering::Acquire), 0);
        assert_eq!(reader.reserved_slots.load(Ordering::Acquire), 0);
    }

    /// Regression: a frame larger than the window must not exceed the speculative budget.
    #[test]
    fn regression_decode_ahead_oversize_frame_stays_serial() {
        let (_dir, mut reader, data) = ahead_fixture(4, 64 * 1024);
        let mut got = Vec::new();
        reader.read_to_end(&mut got).unwrap();
        assert_eq!(got, data);
        assert!(reader.pending.is_empty());
        assert_eq!(reader.reserved.load(Ordering::Acquire), 0);
    }

    /// Regression: speculative failures surface only at their frame and retry synchronously.
    #[test]
    fn regression_decode_ahead_error_at_requested_offset_and_retry() {
        let (_dir, mut reader, data) = ahead_fixture(4, 512 * 1024);
        reader.read_exact(&mut vec![0; 128 * 1024]).unwrap();
        for pending in reader.pending.drain(..) {
            drop(pending.result.recv().unwrap());
        }
        reader.cancel();
        let (tx, result) = mpsc::channel();
        tx.send((
            Err(io::Error::other("transient prefetch error")),
            reader.reserve_frame(1, 512 * 1024).unwrap(),
        ))
        .unwrap();
        reader.pending.push_back(PendingFrame { index: 1, result });
        let mut got = vec![0; 128 * 1024];
        reader.read_exact(&mut got).unwrap();
        assert_eq!(got, data[128 * 1024..256 * 1024]);
        reader.cancel();
        // Corrupt a later frame on disk; earlier valid bytes must still be returned.
        let ZstdBackend::Path(path) = &reader.backend else {
            unreachable!()
        };
        let mut file = std::fs::OpenOptions::new().write(true).open(path).unwrap();
        file.seek(SeekFrom::Start(reader.frames[3].compressed_offset))
            .unwrap();
        file.write_all(&[0; 4]).unwrap();
        reader.seek(SeekFrom::Start(256 * 1024)).unwrap();
        reader.read_exact(&mut got).unwrap();
        assert_eq!(got, data[256 * 1024..384 * 1024]);
        assert!(reader.read(&mut got).is_err());
        assert_eq!(reader.pos, 384 * 1024);
        // A failed replacement must not advertise the now-empty previous frame.
        reader.seek(SeekFrom::Start(256 * 1024)).unwrap();
        reader.read_exact(&mut got).unwrap();
        assert_eq!(got, data[256 * 1024..384 * 1024]);
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

    fn prepared_zstd_fixture(tail: &[u8]) -> (Vec<u8>, Vec<(u64, u64)>, Vec<u8>) {
        let parts: [&[u8]; 2] = [b"first frame data", b"final frame bytes"];
        let mut compressed = Vec::new();
        let mut pairs = Vec::new();
        let mut data = Vec::new();
        for part in parts {
            pairs.push((compressed.len() as u64, data.len() as u64));
            compressed.extend(encode_frame(part));
            data.extend(part);
        }
        pairs.push((compressed.len() as u64, data.len() as u64));
        compressed.extend(tail);
        (compressed, pairs, data)
    }

    fn prepared_zstd_refuses_both(bytes: &[u8], pairs: &[(u64, u64)], symptom: &str) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("prepared.zst");
        std::fs::write(&path, bytes).unwrap();
        let a = SeekableZstd::open_with_zstd_blocks(&path, 1, pairs)
            .err()
            .expect("path must refuse");
        let b = SeekableZstd::open_with_zstd_blocks_from_reader(
            Cursor::new(bytes.to_vec()),
            1,
            &path,
            pairs,
        )
        .err()
        .expect("reader must refuse");
        for e in [a, b] {
            assert!(e.to_string().contains(symptom), "{e}");
        }
    }

    /// Regression: genuine frame-map suffixes lack initial uncompressed coverage.
    #[test]
    fn regression_prepared_index_zstd_usable_state_requires_initial_frame() {
        let (bytes, pairs, _) = prepared_zstd_fixture(&[]);
        prepared_zstd_refuses_both(&bytes, &pairs[1..], "initial frame");
        prepared_zstd_refuses_both(&bytes, &[], "EOF sentinel");
        prepared_zstd_refuses_both(&bytes, &[(0, 0), (0, 0)], "no frames");
        prepared_zstd_refuses_both(&bytes, &[(1, 0), (0, 1)], "monotonic");
    }

    /// Regression: dropping only EOF silently omitted the last genuine zstd data frame.
    #[test]
    fn regression_prepared_index_zstd_requires_genuine_terminal_sentinel() {
        let (bytes, pairs, _) = prepared_zstd_fixture(&[]);
        prepared_zstd_refuses_both(&bytes, &pairs[..pairs.len() - 1], "terminal sentinel");
        let mut outside = pairs.clone();
        outside.last_mut().unwrap().0 = bytes.len() as u64 + 1;
        prepared_zstd_refuses_both(&bytes, &outside, "terminal sentinel");
        for tail in [
            &b"\x50\x2a\x4d\x18"[..],
            &b"\x50\x2a\x4d\x18\xff\xff\xff\xff"[..],
        ] {
            let (bytes, pairs, _) = prepared_zstd_fixture(tail);
            prepared_zstd_refuses_both(&bytes, &pairs, "terminal sentinel");
        }
    }

    /// Regression: an EOF before complete skippable tails is a valid zstd terminal.
    #[test]
    fn regression_prepared_index_zstd_terminal_preserves_skippable_tails() {
        let (base, pairs, data) = prepared_zstd_fixture(&[]);
        let mut generic = 0x184d2a50u32.to_le_bytes().to_vec();
        generic.extend(3u32.to_le_bytes());
        generic.extend(b"abc");
        let entries: Vec<_> = pairs
            .windows(2)
            .map(|w| ((w[1].0 - w[0].0) as u32, (w[1].1 - w[0].1) as u32))
            .collect();
        for tail in [generic, build_seek_table_skippable(&entries)] {
            let mut bytes = base.clone();
            bytes.extend(tail);
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("tails.zst");
            std::fs::write(&path, &bytes).unwrap();
            let path_body = SeekableZstd::open_with_zstd_blocks(&path, 1, &pairs).unwrap();
            let reader_body = SeekableZstd::open_with_zstd_blocks_from_reader(
                Cursor::new(bytes),
                1,
                &path,
                &pairs,
            )
            .unwrap();
            for body in [path_body, reader_body] {
                assert_eq!(body.size(), data.len() as u64);
                let mut got = Vec::new();
                body.open_reader().unwrap().read_to_end(&mut got).unwrap();
                assert_eq!(got, data);
                let mut reader = body.open_reader().unwrap();
                reader.seek(SeekFrom::End(-5)).unwrap();
                let mut last = [0; 5];
                reader.read_exact(&mut last).unwrap();
                assert_eq!(&last, &data[data.len() - 5..]);
            }
        }
    }
}
