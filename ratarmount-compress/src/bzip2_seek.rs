//! Seekable bzip2: full decode into RAM/temp (Tier B lite).
//!
//! True mid-stream random restart needs an on-disk block index (indexed_bzip2 class).
//! Until that lands, we decode once into a [`DecodedBody`]. When `threads > 1` and the
//! file is a concatenation of independent bzip2 *streams* (or multi-block single streams
//! when a fast bit scan finds ≥2 blocks), streams/blocks are decompressed in parallel
//! (Python `BlockParallelReaders` / rapidgzip-bzip2 foundation).

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::thread;

use bzip2::read::BzDecoder;
use ratarmount_core::ParallelizationSpec;

use crate::seekable_body::{DecodedBody, SeekableBody, DEFAULT_MEMORY_CAP};
use crate::{CompressError, Result};

/// Open bzip2 as a seekable body (one-shot decode, memory or temp spill).
pub fn open_seekable_bzip2(path: impl AsRef<Path>) -> Result<Arc<dyn SeekableBody>> {
    open_seekable_bzip2_with_threads(path, 1)
}

/// Open bzip2 using up to `threads` workers for multi-stream / multi-block parallel decode.
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

    let decoded = if threads > 1 {
        match try_parallel_decode(&compressed, threads) {
            Ok(data) => data,
            Err(_) => decode_sequential(&compressed)?,
        }
    } else {
        decode_sequential(&compressed)?
    };

    if decoded.len() as u64 <= DEFAULT_MEMORY_CAP {
        Ok(DecodedBody::from_bytes(path, "bzip2", decoded))
    } else {
        let cursor = std::io::Cursor::new(decoded);
        let body = DecodedBody::from_decoder(path, "bzip2", cursor, DEFAULT_MEMORY_CAP)?;
        Ok(body)
    }
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

/// Best-effort multi-block parallel decode via bit-aligned magic scan.
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
    use std::io::{Read, Write};
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
        let mut r = body.open_reader().unwrap();
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, expected);
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
