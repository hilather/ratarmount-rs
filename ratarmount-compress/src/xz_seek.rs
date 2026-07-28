//! Seekable xz via multi-stream / multi-block Index map.
//!
//! Priority when opening:
//! 1. **Stream Footer + Index parse** — walk concatenated xz streams, read each
//!    stream's Index records, and build a block map
//!    `{compressed_offset, compressed_size, uncompressed_offset, uncompressed_size}`.
//!    Covers multi-stream concatenation **and** single-stream multi-block (e.g. pixz /
//!    `xz --block-size=…`) without decoding payload during map build.
//! 2. **Multi-stream decode map** — if Index parse fails but independent stream
//!    magics split cleanly, decode each stream (optionally in parallel) only to
//!    learn uncompressed sizes and keep a stream-level restart map.
//! 3. **Full decode** fallback into [`DecodedBody`] (single-block small files, corrupt
//!    / exotic layouts). Parallel multi-stream full decode when `threads > 1`.
//!
//! Readers seek by locating the covering block/stream and re-decoding only that
//! unit (last-unit cache). Single-block mini-streams are reconstructed from the
//! original Stream Header + Block + a one-record Index + Footer.
//!
//! **Limitation:** single-stream multi-block random access needs a valid Index
//! (always present in well-formed xz). If Index/footer validation fails, we fall
//! back to full decode rather than partial block isolation.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use ratarmount_core::ParallelizationSpec;
use xz2::read::XzDecoder;

use crate::seekable_body::{DecodedBody, SeekRead, SeekableBody, DEFAULT_MEMORY_CAP};
use crate::{CompressError, Result};

/// xz stream header magic (`FD 37 7A 58 5A 00`).
const XZ_MAGIC: [u8; 6] = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];
/// Stream Footer magic (`YZ`).
const FOOTER_MAGIC: [u8; 2] = [0x59, 0x5A];

/// Open xz as a seekable body (block/stream map when possible, else full decode).
pub fn open_seekable_xz(path: impl AsRef<Path>) -> Result<Arc<dyn SeekableBody>> {
    open_seekable_xz_with_threads(path, 1)
}

/// Open xz using up to `threads` workers for multi-stream size discovery / fallback.
///
/// `threads == 0` means “use CPU count” (Python `-P 0` semantics).
///
/// * **Multi-stream / multi-block Index map**: Index parse is sequential and cheap;
///   `threads` is unused for map build.
/// * **Multi-stream decode map** (Index failed): stream sizes are discovered in
///   parallel when `threads > 1`.
/// * **Full decode fallback**: multi-stream parallel decode when `threads > 1`.
pub fn open_seekable_xz_with_threads(
    path: impl AsRef<Path>,
    threads: u32,
) -> Result<Arc<dyn SeekableBody>> {
    let path = path.as_ref();
    let threads = ParallelizationSpec::resolve_zero(threads).max(1);

    let mut file = File::open(path)?;
    let mut compressed = Vec::new();
    file.read_to_end(&mut compressed)?;
    if compressed.len() < 12 || compressed[..6] != XZ_MAGIC {
        return Err(CompressError::Msg("not an xz stream".into()));
    }

    // 1) Footer + Index → block map (multi-stream and multi-block).
    if let Ok((blocks, uncomp_size)) = build_block_map_from_index(&compressed) {
        if blocks.len() >= 2 {
            return Ok(Arc::new(SeekableXz {
                path: path.to_path_buf(),
                compressed: Arc::new(compressed),
                blocks: Arc::new(blocks),
                uncompressed_size: uncomp_size,
                kind: "xz-blocks",
            }));
        }
        // Single block: full decode is fine (small files; same content either way).
    }

    // 2) Multi-stream map via per-stream decode (sizes only; keep restart points).
    if let Ok((blocks, uncomp_size)) = build_stream_map_by_decode(&compressed, threads) {
        if blocks.len() >= 2 {
            return Ok(Arc::new(SeekableXz {
                path: path.to_path_buf(),
                compressed: Arc::new(compressed),
                blocks: Arc::new(blocks),
                uncompressed_size: uncomp_size,
                kind: "xz-streams",
            }));
        }
    }

    // 3) Full one-shot decode.
    full_decode_body(path, &compressed, threads)
}

fn full_decode_body(
    path: &Path,
    compressed: &[u8],
    threads: u32,
) -> Result<Arc<dyn SeekableBody>> {
    let decoded = if threads > 1 {
        match try_parallel_multi_stream(compressed, threads) {
            Ok(data) => data,
            Err(_) => decode_sequential(compressed)?,
        }
    } else {
        decode_sequential(compressed)?
    };

    if decoded.len() as u64 <= DEFAULT_MEMORY_CAP {
        Ok(DecodedBody::from_bytes(path, "xz", decoded))
    } else {
        let cursor = std::io::Cursor::new(decoded);
        let body = DecodedBody::from_decoder(path, "xz", cursor, DEFAULT_MEMORY_CAP)?;
        Ok(body)
    }
}

/// One restart unit: an Index block record or a whole independent stream.
#[derive(Clone, Debug)]
struct BlockInfo {
    /// Absolute compressed offset of the Block (or stream start if `whole_stream`).
    compressed_offset: u64,
    /// On-disk size to feed the decoder (`ceil4(unpadded)` for blocks, full stream
    /// length for `whole_stream`).
    compressed_size: u64,
    /// Index “Unpadded Size” (0 when `whole_stream`).
    unpadded_size: u64,
    uncompressed_offset: u64,
    uncompressed_size: u64,
    /// Offset of the 12-byte Stream Header for mini-stream reconstruction.
    stream_header_offset: u64,
    stream_flags: [u8; 2],
    /// When true, slice is a complete xz stream (decode directly; no mini rebuild).
    whole_stream: bool,
}

/// Seekable xz body backed by a retained block/stream map.
pub struct SeekableXz {
    path: PathBuf,
    compressed: Arc<Vec<u8>>,
    blocks: Arc<Vec<BlockInfo>>,
    uncompressed_size: u64,
    kind: &'static str,
}

impl SeekableBody for SeekableXz {
    fn path(&self) -> &Path {
        &self.path
    }

    fn size(&self) -> u64 {
        self.uncompressed_size
    }

    fn open_reader(&self) -> io::Result<Box<dyn SeekRead>> {
        Ok(Box::new(XzBlockReader {
            compressed: Arc::clone(&self.compressed),
            blocks: Arc::clone(&self.blocks),
            size: self.uncompressed_size,
            pos: 0,
            cache_idx: None,
            cache_data: Vec::new(),
        }))
    }

    fn kind(&self) -> &'static str {
        self.kind
    }

    fn checkpoint_count(&self) -> usize {
        self.blocks.len().max(1)
    }
}

struct XzBlockReader {
    compressed: Arc<Vec<u8>>,
    blocks: Arc<Vec<BlockInfo>>,
    size: u64,
    pos: u64,
    cache_idx: Option<usize>,
    cache_data: Vec<u8>,
}

impl XzBlockReader {
    fn find_block(&self, pos: u64) -> (usize, u64) {
        if self.blocks.is_empty() {
            return (0, 0);
        }
        if pos >= self.size {
            let last = self.blocks.len() - 1;
            return (last, self.blocks[last].uncompressed_size);
        }
        let idx = self
            .blocks
            .partition_point(|b| b.uncompressed_offset + b.uncompressed_size <= pos);
        let idx = idx.min(self.blocks.len() - 1);
        let within = pos.saturating_sub(self.blocks[idx].uncompressed_offset);
        (idx, within)
    }

    fn ensure_block(&mut self, idx: usize) -> io::Result<()> {
        if self.cache_idx == Some(idx) {
            return Ok(());
        }
        let b = &self.blocks[idx];
        let plain = decode_block_unit(&self.compressed, b)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        self.cache_idx = Some(idx);
        self.cache_data = plain;
        Ok(())
    }
}

impl Read for XzBlockReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.size {
            return Ok(0);
        }
        let (idx, within) = self.find_block(self.pos);
        self.ensure_block(idx)?;
        let into = within as usize;
        if into >= self.cache_data.len() {
            return Ok(0);
        }
        let n = (self.cache_data.len() - into).min(buf.len());
        buf[..n].copy_from_slice(&self.cache_data[into..into + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for XzBlockReader {
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

fn decode_block_unit(data: &[u8], block: &BlockInfo) -> Result<Vec<u8>> {
    let start = block.compressed_offset as usize;
    let end = start
        .checked_add(block.compressed_size as usize)
        .ok_or_else(|| CompressError::Msg("xz block size overflow".into()))?;
    if end > data.len() {
        return Err(CompressError::Msg("xz block out of bounds".into()));
    }
    if block.whole_stream {
        return decode_one_stream(&data[start..end]);
    }
    // Reconstruct a single-block xz stream: Header + Block + Index(1) + Footer.
    let hs = block.stream_header_offset as usize;
    if hs + 12 > data.len() {
        return Err(CompressError::Msg("xz stream header out of bounds".into()));
    }
    let header = &data[hs..hs + 12];
    let block_bytes = &data[start..end];

    let mut index = Vec::with_capacity(32);
    index.push(0); // Index Indicator
    index.extend_from_slice(&encode_vli(1));
    index.extend_from_slice(&encode_vli(block.unpadded_size));
    index.extend_from_slice(&encode_vli(block.uncompressed_size));
    while index.len() % 4 != 0 {
        index.push(0);
    }
    let ic = crc32_ieee(&index);
    index.extend_from_slice(&ic.to_le_bytes());

    let backward = (index.len() as u32 / 4).saturating_sub(1);
    let mut foot_body = Vec::with_capacity(6);
    foot_body.extend_from_slice(&backward.to_le_bytes());
    foot_body.extend_from_slice(&block.stream_flags);
    let fc = crc32_ieee(&foot_body);
    let mut footer = Vec::with_capacity(12);
    footer.extend_from_slice(&fc.to_le_bytes());
    footer.extend_from_slice(&foot_body);
    footer.extend_from_slice(&FOOTER_MAGIC);

    let mut mini = Vec::with_capacity(12 + block_bytes.len() + index.len() + 12);
    mini.extend_from_slice(header);
    mini.extend_from_slice(block_bytes);
    mini.extend_from_slice(&index);
    mini.extend_from_slice(&footer);
    decode_one_stream(&mini)
}

// ── Index / stream parsing ──────────────────────────────────────────────────

fn ceil4(n: u64) -> u64 {
    n.saturating_add(3) & !3
}

fn read_vli(data: &[u8], pos: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for i in 0..9 {
        if *pos >= data.len() {
            return None;
        }
        let b = data[*pos];
        *pos += 1;
        value |= u64::from(b & 0x7f) << (i * 7);
        if b & 0x80 == 0 {
            // Leading zeros in VLI encoding are invalid except for zero itself,
            // but we accept any well-formed decode for robustness.
            return Some(value);
        }
    }
    None
}

fn encode_vli(mut n: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(9);
    loop {
        let mut b = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            b |= 0x80;
            out.push(b);
        } else {
            out.push(b);
            break;
        }
    }
    out
}

/// IEEE CRC-32 (poly 0xEDB88320), as used by the xz container.
fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Parse Index field starting at `index_start` with known `index_size` (incl. CRC).
///
/// Returns list of `(unpadded_size, uncompressed_size)`.
fn parse_index_records(
    data: &[u8],
    index_start: usize,
    index_size: usize,
) -> Option<Vec<(u64, u64)>> {
    if index_size < 8 || index_start + index_size > data.len() {
        return None;
    }
    let index = &data[index_start..index_start + index_size];
    if index[0] != 0x00 {
        return None;
    }
    // Verify CRC32 of Index excluding last 4 bytes.
    let body = &index[..index_size - 4];
    let expect = u32::from_le_bytes(index[index_size - 4..].try_into().ok()?);
    if crc32_ieee(body) != expect {
        return None;
    }
    let mut pos = 1usize;
    let n_records = read_vli(index, &mut pos)?;
    if n_records > 1_000_000 {
        return None;
    }
    let mut records = Vec::with_capacity(n_records as usize);
    for _ in 0..n_records {
        let unpadded = read_vli(index, &mut pos)?;
        let uncomp = read_vli(index, &mut pos)?;
        if unpadded == 0 {
            return None;
        }
        records.push((unpadded, uncomp));
    }
    // Index Padding: zeros to 4-byte alignment (CRC already excluded).
    while !pos.is_multiple_of(4) {
        if pos >= body.len() || index[pos] != 0 {
            return None;
        }
        pos += 1;
    }
    if pos != body.len() {
        return None;
    }
    Some(records)
}

/// Try to interpret `data[start..end]` as one complete xz stream (no padding).
///
/// `end` is the exclusive offset of the first byte after Stream Footer.
fn try_parse_stream(
    data: &[u8],
    start: usize,
    end: usize,
) -> Option<(Vec<BlockInfo>, u64)> {
    if end < start + 32 || end > data.len() {
        return None;
    }
    if !(end - start).is_multiple_of(4) {
        return None;
    }
    if !is_xz_magic(&data[start..]) {
        return None;
    }
    let stream_flags = [data[start + 6], data[start + 7]];
    // Stream Footer (12 bytes) at end-12.
    let foff = end - 12;
    if data[foff + 10..foff + 12] != FOOTER_MAGIC {
        return None;
    }
    if data[foff + 8] != stream_flags[0] || data[foff + 9] != stream_flags[1] {
        return None;
    }
    let backward_field = u32::from_le_bytes(data[foff + 4..foff + 8].try_into().ok()?);
    let index_size = (backward_field as usize)
        .checked_add(1)?
        .checked_mul(4)?;
    if index_size + 12 > end - start {
        return None;
    }
    let index_start = end - 12 - index_size;
    if index_start < start + 12 {
        return None;
    }
    // Footer CRC over (Backward Size || Stream Flags).
    let foot_crc = u32::from_le_bytes(data[foff..foff + 4].try_into().ok()?);
    if crc32_ieee(&data[foff + 4..foff + 10]) != foot_crc {
        return None;
    }

    let records = parse_index_records(data, index_start, index_size)?;
    let blocks_region = (index_start - start - 12) as u64;
    let sum: u64 = records.iter().map(|(up, _)| ceil4(*up)).sum();
    if sum != blocks_region {
        return None;
    }

    let mut blocks = Vec::with_capacity(records.len());
    let mut bpos = start as u64 + 12;
    let mut u_off = 0u64;
    for (unpadded, uncomp) in records {
        let on_disk = ceil4(unpadded);
        blocks.push(BlockInfo {
            compressed_offset: bpos,
            compressed_size: on_disk,
            unpadded_size: unpadded,
            uncompressed_offset: u_off,
            uncompressed_size: uncomp,
            stream_header_offset: start as u64,
            stream_flags,
            whole_stream: false,
        });
        bpos += on_disk;
        u_off += uncomp;
    }
    Some((blocks, u_off))
}

/// Build a block map by parsing every stream's Footer + Index.
fn build_block_map_from_index(data: &[u8]) -> Result<(Vec<BlockInfo>, u64)> {
    let mut pos = 0usize;
    let mut all_blocks = Vec::new();
    let mut total_uncomp = 0u64;
    let mut streams = 0usize;

    while pos + 12 <= data.len() {
        // Stream Padding: null bytes, multiple of four, before next stream / EOF.
        let pad_start = pos;
        while pos < data.len() && data[pos] == 0 {
            pos += 1;
        }
        if pos >= data.len() {
            break;
        }
        let pad_len = pos - pad_start;
        if pad_len > 0 && !pad_len.is_multiple_of(4) {
            if all_blocks.is_empty() {
                return Err(CompressError::Msg("xz stream padding misaligned".into()));
            }
            break;
        }
        if !is_xz_magic(&data[pos..]) {
            if all_blocks.is_empty() {
                return Err(CompressError::Msg("xz stream magic missing".into()));
            }
            break;
        }

        let stream_start = pos;
        let (footer_end, mut blocks, stream_uncomp) = locate_and_parse_stream(data, stream_start)
            .ok_or_else(|| {
                CompressError::Msg(format!(
                    "xz index/footer parse failed at offset {stream_start}"
                ))
            })?;

        for b in &mut blocks {
            b.uncompressed_offset += total_uncomp;
        }
        total_uncomp += stream_uncomp;
        all_blocks.append(&mut blocks);
        streams += 1;

        // Continue after stream (padding handled at loop top).
        pos = footer_end;
        if pos > data.len() {
            break;
        }
        // Avoid infinite loop on zero advance.
        if pos <= stream_start {
            return Err(CompressError::Msg("xz stream parse made no progress".into()));
        }
    }

    if all_blocks.is_empty() {
        return Err(CompressError::Msg("no xz blocks found".into()));
    }
    let _ = streams;
    Ok((all_blocks, total_uncomp))
}

/// Locate stream end and parse Index for stream starting at `start`.
///
/// Returns `(footer_end_exclusive, blocks_with_local_u_off, stream_uncomp)`.
fn locate_and_parse_stream(
    data: &[u8],
    start: usize,
) -> Option<(usize, Vec<BlockInfo>, u64)> {
    // Candidate upper bounds: next stream magics, then EOF.
    let mut uppers: Vec<usize> = find_xz_magic_offsets(data)
        .into_iter()
        .filter(|&m| m > start)
        .collect();
    if !uppers.contains(&data.len()) {
        uppers.push(data.len());
    }
    // Prefer nearer candidates first.
    uppers.sort_unstable();

    for &upper in &uppers {
        // Strip stream padding (trailing NULs before next magic / EOF).
        let mut end = upper;
        while end > start + 12 && data[end - 1] == 0 {
            end -= 1;
        }
        // Align: stream size excl. padding is multiple of 4.
        end -= end % 4;
        if end <= start {
            continue;
        }
        if let Some((blocks, uncomp)) = try_parse_stream(data, start, end) {
            return Some((end, blocks, uncomp));
        }
        // Also try without aggressive strip — footer may sit at upper if no padding.
        let end2 = upper - (upper % 4);
        if end2 != end {
            if let Some((blocks, uncomp)) = try_parse_stream(data, start, end2) {
                return Some((end2, blocks, uncomp));
            }
        }
    }

    // Slow path: scan for Footer Magic with matching stream flags (4-byte steps).
    if start + 6 + 2 > data.len() {
        return None;
    }
    let flags = [data[start + 6], data[start + 7]];
    let mut end = start + 32;
    end += (4 - end % 4) % 4;
    while end <= data.len() {
        if data[end - 2] == FOOTER_MAGIC[0]
            && data[end - 1] == FOOTER_MAGIC[1]
            && data[end - 4] == flags[0]
            && data[end - 3] == flags[1]
        {
            if let Some((blocks, uncomp)) = try_parse_stream(data, start, end) {
                return Some((end, blocks, uncomp));
            }
        }
        end += 4;
    }
    None
}

/// Multi-stream map by decoding each independent stream for uncompressed size.
fn build_stream_map_by_decode(
    compressed: &[u8],
    threads: u32,
) -> Result<(Vec<BlockInfo>, u64)> {
    let parts = split_xz_stream_slices(compressed)
        .ok_or_else(|| CompressError::Msg("cannot split xz streams".into()))?;
    if parts.len() < 2 {
        return Err(CompressError::Msg("single xz stream".into()));
    }

    // Decode each stream (parallel when requested) to learn sizes.
    let plains = if threads > 1 {
        parallel_decode_stream_list(&parts, threads)?
    } else {
        let mut sizes = Vec::with_capacity(parts.len());
        for p in &parts {
            sizes.push(decode_one_stream(p)?);
        }
        sizes
    };

    let mut blocks = Vec::with_capacity(parts.len());
    let mut u_off = 0u64;
    // Recompute part offsets from split (parts are sub-slices of compressed).
    let base = compressed.as_ptr() as usize;
    for (part, plain) in parts.iter().zip(plains.iter()) {
        let start = part.as_ptr() as usize - base;
        let flags = if part.len() >= 8 {
            [part[6], part[7]]
        } else {
            [0, 0]
        };
        let uncomp = plain.len() as u64;
        blocks.push(BlockInfo {
            compressed_offset: start as u64,
            compressed_size: part.len() as u64,
            unpadded_size: 0,
            uncompressed_offset: u_off,
            uncompressed_size: uncomp,
            stream_header_offset: start as u64,
            stream_flags: flags,
            whole_stream: true,
        });
        u_off += uncomp;
    }
    Ok((blocks, u_off))
}

fn parallel_decode_stream_list(parts: &[&[u8]], threads: u32) -> Result<Vec<Vec<u8>>> {
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
                    outs.push(decode_one_stream(p));
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

    let mut out = Vec::with_capacity(parts.len());
    for r in results {
        out.push(
            r.ok_or_else(|| CompressError::Msg("xz parallel worker missing".into()))??,
        );
    }
    Ok(out)
}

// ── Decode helpers ──────────────────────────────────────────────────────────

/// Multi-decoder handles concatenated xz streams (and optional zero padding).
fn decode_sequential(compressed: &[u8]) -> Result<Vec<u8>> {
    let mut dec = XzDecoder::new_multi_decoder(compressed);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)
        .map_err(|e| CompressError::Msg(format!("xz decode: {e}")))?;
    Ok(out)
}

fn decode_one_stream(compressed: &[u8]) -> Result<Vec<u8>> {
    let mut dec = XzDecoder::new(compressed);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)
        .map_err(|e| CompressError::Msg(format!("xz stream decode: {e}")))?;
    Ok(out)
}

fn is_xz_magic(data: &[u8]) -> bool {
    data.len() >= 6 && data[..6] == XZ_MAGIC
}

/// Locate stream-header magic offsets (including the start at 0).
fn find_xz_magic_offsets(data: &[u8]) -> Vec<usize> {
    let mut markers = Vec::new();
    let mut i = 0usize;
    while i + 6 <= data.len() {
        if is_xz_magic(&data[i..]) {
            markers.push(i);
            i += 6;
        } else {
            i += 1;
        }
    }
    markers
}

/// Try to split multi-stream xz at header magics into independent compressed slices.
///
/// Does **not** fully decode: only checks magic layout. Callers decode slices
/// (in parallel when desired). Mid-stream false magics are rejected when a slice
/// fails to decode as a complete single stream.
fn split_xz_stream_slices(compressed: &[u8]) -> Option<Vec<&[u8]>> {
    if !is_xz_magic(compressed) {
        return None;
    }
    let markers = find_xz_magic_offsets(compressed);
    if markers.len() < 2 {
        return None;
    }
    let mut ends = markers;
    ends.push(compressed.len());
    let mut parts = Vec::with_capacity(ends.len() - 1);
    for w in ends.windows(2) {
        let start = w[0];
        let end = w[1];
        if end <= start + 12 {
            return None;
        }
        // Include possible stream-padding NULs before the next magic; the single-stream
        // decoder stops at stream end and ignores trailing padding.
        parts.push(&compressed[start..end]);
    }
    Some(parts)
}

/// Parallel decode of independent multi-stream xz (one decode pass, N workers).
fn try_parallel_multi_stream(compressed: &[u8], threads: u32) -> Result<Vec<u8>> {
    let parts = split_xz_stream_slices(compressed)
        .ok_or_else(|| CompressError::Msg("single xz stream; sequential path".into()))?;
    if parts.len() < 2 {
        return Err(CompressError::Msg("single xz stream; sequential path".into()));
    }
    parallel_map_decode_slices(&parts, threads)
}

fn parallel_map_decode_slices(parts: &[&[u8]], threads: u32) -> Result<Vec<u8>> {
    let plains = parallel_decode_stream_list(parts, threads)?;
    let mut out = Vec::new();
    for p in plains {
        out.extend(p);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::PathBuf;
    use std::process::Command;

    use xz2::write::XzEncoder;

    fn py_test(name: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        PathBuf::from(root).join("tests").join(name)
    }

    fn encode_xz(data: &[u8]) -> Vec<u8> {
        let mut enc = XzEncoder::new(Vec::new(), 6);
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn simple_xz() {
        let path = py_test("simple.xz");
        if !path.exists() {
            return;
        }
        let body = open_seekable_xz(&path).unwrap();
        assert_eq!(body.size(), 12);
        let mut r = body.open_reader().unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "foo fighter\n");
    }

    #[test]
    fn parallel_concatenated_streams() {
        let a = b"stream-A-payload-aaaa";
        let b = b"stream-B-payload-bbbb-EXTRA";
        let mut compressed = encode_xz(a);
        compressed.extend_from_slice(&encode_xz(b));

        let streams = split_xz_stream_slices(&compressed).expect("split streams");
        assert!(
            streams.len() >= 2,
            "expected ≥2 streams, got {}",
            streams.len()
        );

        let seq = decode_sequential(&compressed).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(a);
        expected.extend_from_slice(b);
        assert_eq!(seq, expected);

        let par = try_parallel_multi_stream(&compressed, 4).unwrap();
        assert_eq!(par, seq);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("multi-stream.xz");
        std::fs::write(&path, &compressed).unwrap();
        let body = open_seekable_xz_with_threads(&path, 4).unwrap();
        assert!(
            body.checkpoint_count() >= 2,
            "expected multi-unit map, kind={}, checkpoints={}",
            body.kind(),
            body.checkpoint_count()
        );
        let mut r = body.open_reader().unwrap();
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, expected);

        // Random access across stream boundary.
        r.seek(SeekFrom::Start(a.len() as u64)).unwrap();
        let mut tail = Vec::new();
        r.read_to_end(&mut tail).unwrap();
        assert_eq!(tail, b);
    }

    #[test]
    fn multi_stream_random_access() {
        let a = b"alpha-content-1111";
        let b = b"beta-content-22222222";
        let c = b"gamma-333";
        let mut compressed = encode_xz(a);
        compressed.extend_from_slice(&encode_xz(b));
        compressed.extend_from_slice(&encode_xz(c));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("three.xz");
        std::fs::write(&path, &compressed).unwrap();

        let body = open_seekable_xz(&path).unwrap();
        assert!(body.kind() == "xz-blocks" || body.kind() == "xz-streams");
        assert!(body.checkpoint_count() >= 3);

        let mut expected = Vec::new();
        expected.extend_from_slice(a);
        expected.extend_from_slice(b);
        expected.extend_from_slice(c);
        assert_eq!(body.size(), expected.len() as u64);

        let mut r = body.open_reader().unwrap();
        // Seek into middle of second stream.
        let mid = a.len() as u64 + 5;
        r.seek(SeekFrom::Start(mid)).unwrap();
        let mut got = vec![0u8; 8];
        r.read_exact(&mut got).unwrap();
        assert_eq!(&got, &expected[mid as usize..mid as usize + 8]);

        // Seek backwards into first stream.
        r.seek(SeekFrom::Start(2)).unwrap();
        let mut got2 = vec![0u8; 4];
        r.read_exact(&mut got2).unwrap();
        assert_eq!(&got2, &expected[2..6]);
    }

    #[test]
    fn multi_block_single_stream_index_map() {
        // Build multi-block xz via system xz when available.
        let dir = tempfile::tempdir().unwrap();
        let raw = dir.path().join("big.bin");
        let xz_path = dir.path().join("multi-block.xz");
        let payload = vec![b'X'; 100_000];
        std::fs::write(&raw, &payload).unwrap();
        let status = Command::new("xz")
            .args(["-T1", "--block-size=16384", "-k", "-f", "-c"])
            .arg(&raw)
            .output();
        let Ok(out) = status else {
            return; // xz not installed
        };
        if !out.status.success() || out.stdout.len() < 32 {
            return;
        }
        std::fs::write(&xz_path, &out.stdout).unwrap();

        let (blocks, uncomp) = build_block_map_from_index(&out.stdout).expect("index map");
        assert!(
            blocks.len() >= 2,
            "expected multi-block map, got {}",
            blocks.len()
        );
        assert_eq!(uncomp, payload.len() as u64);
        assert!(blocks.iter().all(|b| !b.whole_stream));

        let body = open_seekable_xz(&xz_path).unwrap();
        assert_eq!(body.kind(), "xz-blocks");
        assert!(body.checkpoint_count() >= 2);
        assert_eq!(body.size(), payload.len() as u64);

        let mut r = body.open_reader().unwrap();
        // Seek into later block.
        r.seek(SeekFrom::Start(50_000)).unwrap();
        let mut chunk = vec![0u8; 64];
        r.read_exact(&mut chunk).unwrap();
        assert_eq!(chunk, vec![b'X'; 64]);

        r.seek(SeekFrom::Start(0)).unwrap();
        let mut all = Vec::new();
        r.read_to_end(&mut all).unwrap();
        assert_eq!(all, payload);
    }

    #[test]
    fn threads_zero_means_cpu_count() {
        let path = py_test("simple.xz");
        if !path.exists() {
            return;
        }
        let body = open_seekable_xz_with_threads(&path, 0).unwrap();
        assert_eq!(body.size(), 12);
    }

    #[test]
    fn sequential_still_works_with_threads() {
        let data = b"hello xz parallelization";
        let compressed = encode_xz(data);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("one.xz");
        std::fs::write(&path, &compressed).unwrap();
        let body = open_seekable_xz_with_threads(&path, 8).unwrap();
        let mut r = body.open_reader().unwrap();
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn with_threads_equals_single_thread() {
        let a = b"alpha-xz-member";
        let b = b"beta-xz-member!!";
        let mut compressed = encode_xz(a);
        compressed.extend_from_slice(&encode_xz(b));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eq.xz");
        std::fs::write(&path, &compressed).unwrap();

        let mut one = Vec::new();
        open_seekable_xz_with_threads(&path, 1)
            .unwrap()
            .open_reader()
            .unwrap()
            .read_to_end(&mut one)
            .unwrap();
        let mut many = Vec::new();
        open_seekable_xz_with_threads(&path, 4)
            .unwrap()
            .open_reader()
            .unwrap()
            .read_to_end(&mut many)
            .unwrap();
        assert_eq!(one, many);
        let mut expected = Vec::new();
        expected.extend_from_slice(a);
        expected.extend_from_slice(b);
        assert_eq!(one, expected);
    }

    #[test]
    fn index_map_matches_decode() {
        let a = b"stream-A-payload-aaaa";
        let b = b"stream-B-payload-bbbb-EXTRA";
        let mut compressed = encode_xz(a);
        compressed.extend_from_slice(&encode_xz(b));
        let (blocks, total) = build_block_map_from_index(&compressed).unwrap();
        assert_eq!(blocks.len(), 2);
        assert_eq!(total, (a.len() + b.len()) as u64);
        assert_eq!(blocks[0].uncompressed_size, a.len() as u64);
        assert_eq!(blocks[1].uncompressed_size, b.len() as u64);
        // Decode each unit independently.
        let p0 = decode_block_unit(&compressed, &blocks[0]).unwrap();
        let p1 = decode_block_unit(&compressed, &blocks[1]).unwrap();
        assert_eq!(p0, a);
        assert_eq!(p1, b);
    }

    #[test]
    fn crc32_ieee_known_vector() {
        // ISO HDLC / gzip/xz CRC32 of "123456789" is 0xCBF43926.
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF4_3926);
    }
}
