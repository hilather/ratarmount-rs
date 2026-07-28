//! Seekable bzip2 via a true bit-block map (indexed_bzip2 class).
//!
//! At open we:
//! 1. Walk independent streams (`BZh[1-9]` members) and bit-scan block ranges
//! 2. Decode each block once (optionally in parallel) to learn uncompressed sizes
//! 3. Retain `{start_bit, end_bit, uncompressed_offset, uncompressed_size}` per block
//!
//! Readers seek by locating the covering block and re-decoding only that block
//! (last-block cache for sequential reads). When the bit scan fails (large-file
//! policy, single block, corrupt), we fall back to a one-shot [`DecodedBody`]
//! (still multi-stream / multi-block parallel when `threads > 1`).

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use bzip2::read::BzDecoder;
use ratarmount_core::ParallelizationSpec;

use crate::seekable_body::{DecodedBody, SeekRead, SeekableBody, DEFAULT_MEMORY_CAP};
use crate::{CompressError, Result};

/// Open bzip2 as a seekable body (bit-block map when possible, else full decode).
pub fn open_seekable_bzip2(path: impl AsRef<Path>) -> Result<Arc<dyn SeekableBody>> {
    open_seekable_bzip2_with_threads(path, 1)
}

/// Open bzip2 using up to `threads` workers for block size discovery / fallback decode.
///
/// `threads == 0` means “use CPU count” (Python `-P 0` semantics).
pub fn open_seekable_bzip2_with_threads(
    path: impl AsRef<Path>,
    threads: u32,
) -> Result<Arc<dyn SeekableBody>> {
    let path = path.as_ref();
    let threads = ParallelizationSpec::resolve_zero(threads).max(1);
    let mut file = File::open(path)?;
    let mut compressed = Vec::new();
    file.read_to_end(&mut compressed)?;
    if compressed.len() < 4 || &compressed[..3] != b"BZh" {
        return Err(CompressError::Msg("not a bzip2 stream".into()));
    }

    match try_build_bit_block_map(&compressed, threads) {
        Ok(blocks) if blocks.len() >= 2 => {
            let uncompressed_size = blocks
                .last()
                .map(|b| b.uncompressed_offset + b.uncompressed_size)
                .unwrap_or(0);
            return Ok(Arc::new(SeekableBzip2 {
                path: path.to_path_buf(),
                compressed: Arc::new(compressed),
                blocks: Arc::new(blocks),
                uncompressed_size,
            }));
        }
        Ok(_) | Err(_) => {
            // Single block, large-file policy, corrupt scan, etc. → full decode.
        }
    }

    full_decode_body(path, &compressed, threads)
}

fn full_decode_body(
    path: &Path,
    compressed: &[u8],
    threads: u32,
) -> Result<Arc<dyn SeekableBody>> {
    let decoded = if threads > 1 {
        match try_parallel_decode(compressed, threads) {
            Ok(data) => data,
            Err(_) => decode_sequential(compressed)?,
        }
    } else {
        decode_sequential(compressed)?
    };

    if decoded.len() as u64 <= DEFAULT_MEMORY_CAP {
        Ok(DecodedBody::from_bytes(path, "bzip2", decoded))
    } else {
        let cursor = std::io::Cursor::new(decoded);
        let body = DecodedBody::from_decoder(path, "bzip2", cursor, DEFAULT_MEMORY_CAP)?;
        Ok(body)
    }
}

/// Per-block restart record (absolute bit offsets into the full compressed blob).
#[derive(Clone, Debug)]
struct BlockInfo {
    /// Stream header `BZh[1-9]` for reconstructing a single-block stream.
    header: [u8; 4],
    start_bit: u64,
    end_bit: u64,
    uncompressed_offset: u64,
    uncompressed_size: u64,
}

/// Seekable bzip2 body backed by a retained bit-block map.
pub struct SeekableBzip2 {
    path: PathBuf,
    compressed: Arc<Vec<u8>>,
    blocks: Arc<Vec<BlockInfo>>,
    uncompressed_size: u64,
}

impl SeekableBody for SeekableBzip2 {
    fn path(&self) -> &Path {
        &self.path
    }

    fn size(&self) -> u64 {
        self.uncompressed_size
    }

    fn open_reader(&self) -> io::Result<Box<dyn SeekRead>> {
        Ok(Box::new(Bzip2BlockReader {
            compressed: Arc::clone(&self.compressed),
            blocks: Arc::clone(&self.blocks),
            size: self.uncompressed_size,
            pos: 0,
            cache_idx: None,
            cache_data: Vec::new(),
        }))
    }

    fn kind(&self) -> &'static str {
        "bzip2-blocks"
    }

    fn checkpoint_count(&self) -> usize {
        self.blocks.len().max(1)
    }
}

struct Bzip2BlockReader {
    compressed: Arc<Vec<u8>>,
    blocks: Arc<Vec<BlockInfo>>,
    size: u64,
    pos: u64,
    cache_idx: Option<usize>,
    cache_data: Vec<u8>,
}

impl Bzip2BlockReader {
    fn find_block(&self, pos: u64) -> (usize, u64) {
        if self.blocks.is_empty() {
            return (0, 0);
        }
        if pos >= self.size {
            let last = self.blocks.len() - 1;
            return (last, self.blocks[last].uncompressed_size);
        }
        // First block whose end is strictly past `pos`.
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
        let plain = decode_one_block(b.header, &self.compressed, b.start_bit, b.end_bit)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        self.cache_idx = Some(idx);
        self.cache_data = plain;
        Ok(())
    }
}

impl Read for Bzip2BlockReader {
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

impl Seek for Bzip2BlockReader {
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

/// Build a global block map across one or more concatenated bzip2 streams.
///
/// Fails (caller falls back to full decode) when:
/// * the file is larger than the bit-scan cap
/// * fewer than 2 blocks are found overall
/// * magic scan / block decode fails
fn try_build_bit_block_map(compressed: &[u8], threads: u32) -> Result<Vec<BlockInfo>> {
    // Cap total scan cost for large files (same policy as per-stream scan).
    if compressed.len() > 8 * 1024 * 1024 {
        return Err(CompressError::Msg("bzip2 block scan skipped (file large)".into()));
    }

    let mut all_blocks: Vec<BlockInfo> = Vec::new();
    let mut u_off = 0u64;
    let mut byte_pos = 0usize;

    while byte_pos + 4 <= compressed.len() && is_bzh_header(&compressed[byte_pos..]) {
        let header: [u8; 4] = compressed[byte_pos..byte_pos + 4].try_into().unwrap();
        let stream = &compressed[byte_pos..];
        let ranges = scan_block_bit_ranges(stream)?;
        if ranges.is_empty() {
            return Err(CompressError::Msg("no bzip2 blocks in stream".into()));
        }

        let sizes = decode_block_sizes(header, stream, &ranges, threads)?;
        if sizes.len() != ranges.len() {
            return Err(CompressError::Msg("bzip2 block size count mismatch".into()));
        }

        let bit_base = (byte_pos as u64) * 8;
        for (i, &(start_bit, end_bit)) in ranges.iter().enumerate() {
            let usize_ = sizes[i];
            all_blocks.push(BlockInfo {
                header,
                start_bit: bit_base + start_bit,
                end_bit: bit_base + end_bit,
                uncompressed_offset: u_off,
                uncompressed_size: usize_,
            });
            u_off += usize_;
        }

        // Last range end is the bit offset of EOS magic within this stream.
        let eos_bit = ranges.last().unwrap().1;
        // EOS (48) + CRC (32); then pad to next byte for the next stream member.
        let after_stream_bits = eos_bit + 48 + 32;
        let stream_bytes = after_stream_bits.div_ceil(8) as usize;
        if stream_bytes == 0 {
            return Err(CompressError::Msg("degenerate bzip2 stream length".into()));
        }
        byte_pos += stream_bytes;

        // Skip any zero padding between members (defensive).
        while byte_pos < compressed.len() && compressed[byte_pos] == 0 {
            byte_pos += 1;
        }
    }

    if all_blocks.is_empty() {
        return Err(CompressError::Msg("no bzip2 blocks indexed".into()));
    }
    // Require multi-block map; single-block falls back to DecodedBody.
    if all_blocks.len() < 2 {
        return Err(CompressError::Msg("single bzip2 block; full-decode path".into()));
    }
    Ok(all_blocks)
}

/// Decode each block (optionally in parallel) and return uncompressed sizes.
fn decode_block_sizes(
    header: [u8; 4],
    stream: &[u8],
    ranges: &[(u64, u64)],
    threads: u32,
) -> Result<Vec<u64>> {
    if ranges.is_empty() {
        return Ok(Vec::new());
    }
    if threads <= 1 || ranges.len() == 1 {
        let mut sizes = Vec::with_capacity(ranges.len());
        for &(start_bit, end_bit) in ranges {
            let plain = decode_one_block(header, stream, start_bit, end_bit)?;
            sizes.push(plain.len() as u64);
        }
        return Ok(sizes);
    }

    let n_workers = (threads as usize).min(ranges.len()).max(1);
    let mut results: Vec<Option<Result<u64>>> = (0..ranges.len()).map(|_| None).collect();

    thread::scope(|scope| {
        let chunk = ranges.len().div_ceil(n_workers).max(1);
        let mut handles = Vec::new();
        for (worker_id, range_chunk) in ranges.chunks(chunk).enumerate() {
            let base = worker_id * chunk;
            let owned: Vec<(u64, u64)> = range_chunk.to_vec();
            handles.push(scope.spawn(move || {
                let mut outs = Vec::with_capacity(owned.len());
                for &(start_bit, end_bit) in &owned {
                    outs.push(
                        decode_one_block(header, stream, start_bit, end_bit)
                            .map(|p| p.len() as u64),
                    );
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

    let mut sizes = Vec::with_capacity(results.len());
    for r in results {
        sizes.push(
            r.ok_or_else(|| CompressError::Msg("bzip2 size worker missing".into()))??,
        );
    }
    Ok(sizes)
}

/// Decode one or more concatenated bzip2 streams (libbz2 stops at the first
/// stream end; we restart for subsequent `BZh` members).
fn decode_sequential(compressed: &[u8]) -> Result<Vec<u8>> {
    if let Some(parts) = split_bzip2_streams_at_markers(compressed) {
        let mut out = Vec::new();
        for part in parts {
            out.extend(decode_one_stream(part)?);
        }
        return Ok(out);
    }
    decode_one_stream(compressed)
}

fn decode_one_stream(compressed: &[u8]) -> Result<Vec<u8>> {
    let mut dec = BzDecoder::new(compressed);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)
        .map_err(|e| CompressError::Msg(format!("bzip2 decode: {e}")))?;
    Ok(out)
}

/// Parallel decode entry: prefer independent concatenated streams; fall back to bit-level
/// multi-block when a cheap scan finds ≥2 blocks.
fn try_parallel_decode(compressed: &[u8], threads: u32) -> Result<Vec<u8>> {
    if let Some(parts) = split_bzip2_streams_at_markers(compressed) {
        if parts.len() >= 2 {
            return parallel_map_decode_slices(&parts, threads);
        }
    }
    // Multi-block within one stream (best-effort; may fail and fall back).
    try_parallel_block_decode(compressed, threads)
}

/// Find concatenated independent bzip2 streams by locating `BZh[1-9]` markers and
/// verifying each segment decodes on its own (no full pre-pass of the joined stream).
fn split_bzip2_streams_at_markers(compressed: &[u8]) -> Option<Vec<&[u8]>> {
    if !is_bzh_header(compressed) {
        return None;
    }
    let mut markers = vec![0usize];
    for i in 4..compressed.len().saturating_sub(3) {
        if is_bzh_header(&compressed[i..]) {
            markers.push(i);
        }
    }
    if markers.len() < 2 {
        return None;
    }
    markers.push(compressed.len());
    let mut parts = Vec::with_capacity(markers.len() - 1);
    for w in markers.windows(2) {
        let slice = &compressed[w[0]..w[1]];
        // Reject empty / tiny segments and false-positive mid-stream BZh.
        if slice.len() < 14 {
            return None;
        }
        if decode_one_stream(slice).is_err() {
            return None;
        }
        parts.push(slice);
    }
    Some(parts)
}

fn parallel_map_decode_slices(parts: &[&[u8]], threads: u32) -> Result<Vec<u8>> {
    let owned: Vec<Vec<u8>> = parts.iter().map(|p| p.to_vec()).collect();
    parallel_map_decode(&owned, threads)
}

fn is_bzh_header(data: &[u8]) -> bool {
    data.len() >= 4
        && data[0] == b'B'
        && data[1] == b'Z'
        && data[2] == b'h'
        && (b'1'..=b'9').contains(&data[3])
}

fn parallel_map_decode(parts: &[Vec<u8>], threads: u32) -> Result<Vec<u8>> {
    let n_workers = (threads as usize).min(parts.len()).max(1);
    let mut results: Vec<Option<Result<Vec<u8>>>> = (0..parts.len()).map(|_| None).collect();

    thread::scope(|scope| {
        let chunk = parts.len().div_ceil(n_workers).max(1);
        let mut handles = Vec::new();
        for (worker_id, part_chunk) in parts.chunks(chunk).enumerate() {
            let base = worker_id * chunk;
            let owned: Vec<Vec<u8>> = part_chunk.to_vec();
            handles.push(scope.spawn(move || {
                let mut outs = Vec::with_capacity(owned.len());
                for p in &owned {
                    // Each part is already a single independent stream.
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

    let mut out = Vec::new();
    for r in results {
        out.extend(
            r.ok_or_else(|| CompressError::Msg("bzip2 parallel worker missing".into()))??,
        );
    }
    Ok(out)
}

/// 48-bit bzip2 block magic (π).
const BLOCK_MAGIC: u64 = 0x0000_3141_5926_5359;
/// 48-bit end-of-stream magic (√π).
const EOS_MAGIC: u64 = 0x0000_1772_4538_5090;

/// Best-effort multi-block parallel full decode via bit-aligned magic scan (fallback path).
fn try_parallel_block_decode(compressed: &[u8], threads: u32) -> Result<Vec<u8>> {
    if compressed.len() < 10 || !is_bzh_header(compressed) {
        return Err(CompressError::Msg("bzip2 too short for block scan".into()));
    }
    let header: [u8; 4] = compressed[..4].try_into().unwrap();
    let blocks = scan_block_bit_ranges(compressed)?;
    if blocks.len() < 2 {
        return Err(CompressError::Msg("single bzip2 block; sequential path".into()));
    }

    let n_workers = (threads as usize).min(blocks.len()).max(1);
    let mut parts: Vec<Option<Result<Vec<u8>>>> = (0..blocks.len()).map(|_| None).collect();

    thread::scope(|scope| {
        let chunk = blocks.len().div_ceil(n_workers).max(1);
        let mut handles = Vec::new();
        for (worker_id, block_chunk) in blocks.chunks(chunk).enumerate() {
            let base = worker_id * chunk;
            let owned: Vec<(u64, u64)> = block_chunk.to_vec();
            handles.push(scope.spawn(move || {
                let mut outs = Vec::with_capacity(owned.len());
                for &(start_bit, end_bit) in &owned {
                    outs.push(decode_one_block(header, compressed, start_bit, end_bit));
                }
                (base, outs)
            }));
        }
        for h in handles {
            if let Ok((base, outs)) = h.join() {
                for (i, r) in outs.into_iter().enumerate() {
                    parts[base + i] = Some(r);
                }
            }
        }
    });

    let mut out = Vec::new();
    for p in parts {
        out.extend(
            p.ok_or_else(|| CompressError::Msg("bzip2 block worker missing".into()))??,
        );
    }
    Ok(out)
}

/// Returns (start_bit, end_bit) for each block (bits from start of `compressed`, MSB-first).
fn scan_block_bit_ranges(compressed: &[u8]) -> Result<Vec<(u64, u64)>> {
    let total_bits = compressed.len() as u64 * 8;
    // Cap scan cost for large files: only attempt when compressed size is modest.
    if total_bits > 8 * 1024 * 1024 * 8 {
        return Err(CompressError::Msg("bzip2 block scan skipped (file large)".into()));
    }
    let mut starts = Vec::new();
    let mut eos_bit: Option<u64> = None;
    let mut bit = 32u64;
    while bit + 48 <= total_bits {
        let mag = match read_bits_msb(compressed, bit, 48) {
            Some(v) => v,
            None => break,
        };
        if mag == BLOCK_MAGIC {
            starts.push(bit);
            bit += 48;
            continue;
        }
        if mag == EOS_MAGIC {
            eos_bit = Some(bit);
            break;
        }
        bit += 1;
    }
    let Some(eos) = eos_bit else {
        return Err(CompressError::Msg("bzip2 EOS magic not found".into()));
    };
    if starts.is_empty() {
        return Err(CompressError::Msg("no bzip2 blocks found".into()));
    }
    let mut ranges = Vec::with_capacity(starts.len());
    for i in 0..starts.len() {
        let start = starts[i];
        let end = if i + 1 < starts.len() {
            starts[i + 1]
        } else {
            eos
        };
        if end <= start + 48 {
            return Err(CompressError::Msg("degenerate bzip2 block range".into()));
        }
        ranges.push((start, end));
    }
    Ok(ranges)
}

fn read_bits_msb(data: &[u8], start_bit: u64, n: u32) -> Option<u64> {
    if n == 0 {
        return Some(0);
    }
    if start_bit + u64::from(n) > data.len() as u64 * 8 {
        return None;
    }
    let mut v = 0u64;
    for i in 0..n {
        let bi = start_bit + u64::from(i);
        let byte = data[(bi / 8) as usize];
        let off = 7 - (bi % 8) as u8;
        let bit = (byte >> off) & 1;
        v = (v << 1) | u64::from(bit);
    }
    Some(v)
}

fn decode_one_block(
    header: [u8; 4],
    compressed: &[u8],
    start_bit: u64,
    end_bit: u64,
) -> Result<Vec<u8>> {
    let block_crc = read_bits_msb(compressed, start_bit + 48, 32)
        .ok_or_else(|| CompressError::Msg("bzip2 block CRC bits".into()))?;

    let mut stream = BitWriter::new();
    stream.write_bytes(&header);
    stream.write_bit_range(compressed, start_bit, end_bit);
    stream.write_bits(EOS_MAGIC, 48);
    stream.write_bits(block_crc, 32);
    let blob = stream.finish();

    let mut dec = BzDecoder::new(&blob[..]);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)
        .map_err(|e| CompressError::Msg(format!("bzip2 block decode: {e}")))?;
    Ok(out)
}

struct BitWriter {
    buf: Vec<u8>,
    acc: u8,
    acc_bits: u8,
}

impl BitWriter {
    fn new() -> Self {
        Self {
            buf: Vec::new(),
            acc: 0,
            acc_bits: 0,
        }
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        if self.acc_bits == 0 {
            self.buf.extend_from_slice(bytes);
            return;
        }
        for &b in bytes {
            self.write_bits(u64::from(b), 8);
        }
    }

    fn write_bits(&mut self, value: u64, n: u32) {
        for i in (0..n).rev() {
            let bit = ((value >> i) & 1) as u8;
            self.acc = (self.acc << 1) | bit;
            self.acc_bits += 1;
            if self.acc_bits == 8 {
                self.buf.push(self.acc);
                self.acc = 0;
                self.acc_bits = 0;
            }
        }
    }

    fn write_bit_range(&mut self, data: &[u8], start_bit: u64, end_bit: u64) {
        let mut bit = start_bit;
        if bit.is_multiple_of(8) && self.acc_bits == 0 && end_bit >= bit + 8 {
            let idx = (bit / 8) as usize;
            let end_idx = (end_bit / 8) as usize;
            if end_idx > idx {
                self.buf.extend_from_slice(&data[idx..end_idx]);
                bit = end_idx as u64 * 8;
            }
        }
        while bit < end_bit {
            let take = (end_bit - bit).min(8) as u32;
            if let Some(b) = read_bits_msb(data, bit, take) {
                self.write_bits(b, take);
            }
            bit += u64::from(take);
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.acc_bits > 0 {
            self.acc <<= 8 - self.acc_bits;
            self.buf.push(self.acc);
        }
        self.buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::PathBuf;

    use bzip2::write::BzEncoder;
    use bzip2::Compression;

    fn py_test(name: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        PathBuf::from(root).join("tests").join(name)
    }

    fn encode_bz2(data: &[u8]) -> Vec<u8> {
        let mut enc = BzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn encode_bz2_level(data: &[u8], level: u32) -> Vec<u8> {
        let mut enc = BzEncoder::new(Vec::new(), Compression::new(level));
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    /// Build compressible multi-block payload (block size 100 KiB at level 1).
    fn multi_block_payload() -> Vec<u8> {
        let mut data = Vec::with_capacity(350_000);
        for i in 0..350_000u32 {
            // Repeating pattern keeps compressed size modest while spanning >1 block.
            data.push(((i / 17) % 251) as u8);
        }
        data
    }

    #[test]
    fn simple_bz2() {
        let path = py_test("simple.bz2");
        if !path.exists() {
            return;
        }
        let body = open_seekable_bzip2(&path).unwrap();
        assert_eq!(body.size(), 12);
        let mut r = body.open_reader().unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "foo fighter\n");
    }

    #[test]
    fn parallel_concatenated_streams() {
        // Two independent bzip2 streams concatenated (valid multi-stream .bz2).
        let a = b"stream-A-payload-aaaa";
        let b = b"stream-B-payload-bbbb-EXTRA";
        let mut compressed = encode_bz2(a);
        compressed.extend_from_slice(&encode_bz2(b));

        let streams = split_bzip2_streams_at_markers(&compressed).expect("split streams");
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

        let par = try_parallel_decode(&compressed, 4).unwrap();
        assert_eq!(par, seq);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("multi-stream.bz2");
        std::fs::write(&path, &compressed).unwrap();
        let body = open_seekable_bzip2_with_threads(&path, 4).unwrap();
        assert!(
            body.checkpoint_count() >= 2,
            "multi-stream should expose ≥2 checkpoints, got {}",
            body.checkpoint_count()
        );
        let mut r = body.open_reader().unwrap();
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn multi_block_random_seeks_match_sequential() {
        let data = multi_block_payload();
        let compressed = encode_bz2_level(&data, 1);
        let ranges = scan_block_bit_ranges(&compressed).expect("block scan");
        assert!(
            ranges.len() >= 2,
            "expected multi-block bz2, got {} blocks (compressed {} bytes)",
            ranges.len(),
            compressed.len()
        );

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("multi-block.bz2");
        std::fs::write(&path, &compressed).unwrap();

        let body = open_seekable_bzip2(&path).unwrap();
        assert_eq!(body.kind(), "bzip2-blocks");
        assert_eq!(body.checkpoint_count(), ranges.len());
        assert_eq!(body.size(), data.len() as u64);

        // Full sequential read via block map.
        let mut r = body.open_reader().unwrap();
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, data);

        // Random seeks: sample offsets across the body.
        let mut r = body.open_reader().unwrap();
        let samples: Vec<u64> = {
            let n = data.len() as u64;
            let mut v = vec![0, 1, n / 4, n / 2, (3 * n) / 4, n.saturating_sub(1)];
            // Near block boundaries if we know sizes from a second open path.
            if let Ok(blocks) = try_build_bit_block_map(&compressed, 1) {
                for b in &blocks {
                    if b.uncompressed_offset > 0 {
                        v.push(b.uncompressed_offset);
                        v.push(b.uncompressed_offset.saturating_sub(1));
                    }
                    v.push(b.uncompressed_offset + b.uncompressed_size / 2);
                }
            }
            v.into_iter().filter(|&o| o < n).collect()
        };
        for &off in &samples {
            r.seek(SeekFrom::Start(off)).unwrap();
            let mut buf = [0u8; 64];
            let n = r.read(&mut buf).unwrap();
            assert!(n > 0, "expected data at offset {off}");
            assert_eq!(&buf[..n], &data[off as usize..off as usize + n]);
        }

        // Seek to EOF then backward.
        assert_eq!(r.seek(SeekFrom::End(0)).unwrap(), data.len() as u64);
        r.seek(SeekFrom::Start(100)).unwrap();
        let mut one = [0u8; 1];
        r.read_exact(&mut one).unwrap();
        assert_eq!(one[0], data[100]);
    }

    #[test]
    fn with_threads_equals_single_thread() {
        let data = multi_block_payload();
        let compressed = encode_bz2_level(&data, 1);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("threads.bz2");
        std::fs::write(&path, &compressed).unwrap();

        let body1 = open_seekable_bzip2_with_threads(&path, 1).unwrap();
        let body4 = open_seekable_bzip2_with_threads(&path, 4).unwrap();
        assert_eq!(body1.size(), body4.size());
        assert_eq!(body1.checkpoint_count(), body4.checkpoint_count());

        let mut a = Vec::new();
        let mut b = Vec::new();
        body1.open_reader().unwrap().read_to_end(&mut a).unwrap();
        body4.open_reader().unwrap().read_to_end(&mut b).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, data);

        // Multi-stream: threads vs single-thread.
        let mut multi = encode_bz2(b"aaa-stream");
        multi.extend_from_slice(&encode_bz2(b"bbb-stream-extra"));
        let path2 = dir.path().join("multi-threads.bz2");
        std::fs::write(&path2, &multi).unwrap();
        let s1 = open_seekable_bzip2_with_threads(&path2, 1).unwrap();
        let s4 = open_seekable_bzip2_with_threads(&path2, 4).unwrap();
        let mut x = Vec::new();
        let mut y = Vec::new();
        s1.open_reader().unwrap().read_to_end(&mut x).unwrap();
        s4.open_reader().unwrap().read_to_end(&mut y).unwrap();
        assert_eq!(x, y);
    }

    #[test]
    fn single_block_falls_back_to_decoded_body() {
        let data = b"tiny single block payload";
        let compressed = encode_bz2(data);
        let ranges = scan_block_bit_ranges(&compressed).unwrap();
        assert_eq!(ranges.len(), 1, "fixture must be single-block");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("single.bz2");
        std::fs::write(&path, &compressed).unwrap();
        let body = open_seekable_bzip2(&path).unwrap();
        // DecodedBody uses kind "bzip2"; block map uses "bzip2-blocks".
        assert_eq!(body.kind(), "bzip2");
        assert_eq!(body.checkpoint_count(), 1);
        let mut got = Vec::new();
        body.open_reader().unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn large_file_scan_policy_rejects() {
        // Synthetic oversize buffer: scan must refuse without hanging.
        let mut huge = vec![0u8; 8 * 1024 * 1024 + 16];
        huge[..4].copy_from_slice(b"BZh9");
        let err = scan_block_bit_ranges(&huge).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("large") || msg.contains("EOS"),
            "unexpected error: {msg}"
        );
        // try_build must also refuse large inputs before bit-walking.
        let err = try_build_bit_block_map(&huge, 1).unwrap_err();
        assert!(
            err.to_string().contains("large"),
            "expected large-file skip, got {}",
            err
        );
    }

    #[test]
    fn multi_stream_random_seeks() {
        let a: Vec<u8> = (0..50_000u32).map(|i| (i % 200) as u8).collect();
        let b: Vec<u8> = (0..80_000u32).map(|i| ((i * 3) % 200) as u8).collect();
        let mut compressed = encode_bz2_level(&a, 1);
        compressed.extend_from_slice(&encode_bz2_level(&b, 1));
        let mut expected = a.clone();
        expected.extend_from_slice(&b);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ms-seek.bz2");
        std::fs::write(&path, &compressed).unwrap();
        let body = open_seekable_bzip2_with_threads(&path, 2).unwrap();
        assert!(body.checkpoint_count() >= 2);
        assert_eq!(body.size(), expected.len() as u64);

        let mut r = body.open_reader().unwrap();
        // Seek into second stream region.
        let mid = a.len() as u64 + 100;
        r.seek(SeekFrom::Start(mid)).unwrap();
        let mut buf = [0u8; 32];
        let n = r.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], &expected[mid as usize..mid as usize + n]);

        r.seek(SeekFrom::Start(0)).unwrap();
        let mut all = Vec::new();
        r.read_to_end(&mut all).unwrap();
        assert_eq!(all, expected);
    }

    #[test]
    fn threads_zero_means_cpu_count() {
        let path = py_test("simple.bz2");
        if !path.exists() {
            return;
        }
        let body = open_seekable_bzip2_with_threads(&path, 0).unwrap();
        assert_eq!(body.size(), 12);
    }

    #[test]
    fn parallelization_spec_bzip2_backend() {
        let spec = ParallelizationSpec::parse("bzip2:2,:1").unwrap();
        assert_eq!(spec.threads_for("bzip2"), 2);
        assert_eq!(spec.threads_for("gzip"), 1);
    }

    #[test]
    fn sequential_still_works_with_threads() {
        let data = b"hello bzip2 parallelization";
        let compressed = encode_bz2(data);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("one.bz2");
        std::fs::write(&path, &compressed).unwrap();
        let body = open_seekable_bzip2_with_threads(&path, 8).unwrap();
        let mut r = body.open_reader().unwrap();
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, data);
    }
}
