//! Seekable bzip2 via a true bit-block map (indexed_bzip2 class).
//!
//! At open we:
//! 1. Walk independent streams (`BZh[1-9]` members) and bit-scan block ranges
//! 2. Decode each block once (optionally in parallel) to learn uncompressed sizes
//! 3. Retain `{start_bit, end_bit, uncompressed_offset, uncompressed_size}` per block
//!
//! Readers seek by locating the covering block and re-decoding only that block
//! (last-block cache for sequential reads). When the bit scan fails (single
//! block, corrupt, empty), we fall back to a one-shot [`DecodedBody`] (still
//! multi-stream / multi-block parallel when `threads > 1` and the compressed
//! payload is in memory).
//!
//! # Opening from paths and readers
//!
//! * **Path open**: compressed size ≤ [`IN_MEMORY_COMPRESSED_CAP`] (256 MiB)
//!   loads into `Arc<Vec<u8>>`; larger files keep an open [`File`] behind a
//!   mutex and never hold the full compressed blob in a `Vec`.
//! * **Reader open** (`Read + Seek`): same in-memory threshold; over-cap inputs
//!   are spooled to a tempfile so the map path can seek compressed ranges
//!   without an `Arc<Vec<u8>>` of multi‑GB data. Remote/HTTP range sources work
//!   the same (spool once at open).
//!
//! # Size policy
//!
//! * **In-memory store + slice bit-scan**: capped at [`IN_MEMORY_COMPRESSED_CAP`]
//!   / [`BIT_BLOCK_SCAN_MAX_BYTES`] (256 MiB).
//! * **File-backed store**: buffered sliding-window bit scan over the compressed
//!   stream with **no 256 MiB wall** — only residual limits are open-time CPU
//!   (one full pass + one decode per block for sizes) and on-demand per-block
//!   re-decode RAM. No mmap dependency.
//! * **Fallback**: scan/map failure → full decode via [`DecodedBody`] (memory
//!   or temp for uncompressed). Large file-backed fallback streams with
//!   [`bzip2::read::MultiBzDecoder`] (no parallel block path).

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

use bzip2::read::{BzDecoder, MultiBzDecoder};
use ratarmount_core::ParallelizationSpec;
use tempfile::NamedTempFile;

use crate::seekable_body::{DecodedBody, SeekRead, SeekableBody, DEFAULT_MEMORY_CAP};
use crate::{CompressError, Result};

/// Prefer an in-memory compressed store at or below this size (256 MiB).
///
/// Above this, path opens keep a shared [`File`]; generic readers spool to a
/// tempfile. Aligns with [`DEFAULT_MEMORY_CAP`].
const IN_MEMORY_COMPRESSED_CAP: u64 = DEFAULT_MEMORY_CAP;

/// Maximum compressed size for **in-memory** (`&[u8]`) bit-block scanning.
///
/// File-backed scans are not subject to this cap. Kept for slice helpers used
/// by the memory map path and parallel full-decode fallback.
const BIT_BLOCK_SCAN_MAX_BYTES: usize = IN_MEMORY_COMPRESSED_CAP as usize;

/// Read buffer size for file-backed sliding-window bit scans.
const BIT_SCAN_READ_BUF: usize = 256 * 1024;

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
    let file = File::open(path)?;
    let len = file.metadata()?.len();
    open_seekable_bzip2_with_file(file, len, threads, path, IN_MEMORY_COMPRESSED_CAP)
}

/// Open bzip2 from a seekable compressed reader (bit-block map when possible).
///
/// `archive_label` is stored for diagnostics ([`SeekableBody::path`] — URL or virtual name).
/// Compressed payloads ≤ [`IN_MEMORY_COMPRESSED_CAP`] are loaded into memory;
/// larger inputs are spooled to a tempfile for the file-backed map path.
pub fn open_seekable_bzip2_from_reader<R>(
    reader: R,
    archive_label: impl AsRef<Path>,
) -> Result<Arc<dyn SeekableBody>>
where
    R: Read + Seek,
{
    open_seekable_bzip2_with_threads_from_reader(reader, 1, archive_label)
}

/// Open bzip2 from a seekable compressed reader with a thread hint.
///
/// See [`open_seekable_bzip2_from_reader`]. `threads == 0` means “use CPU count”.
pub fn open_seekable_bzip2_with_threads_from_reader<R>(
    reader: R,
    threads: u32,
    archive_label: impl AsRef<Path>,
) -> Result<Arc<dyn SeekableBody>>
where
    R: Read + Seek,
{
    open_seekable_bzip2_from_reader_with_cap(
        reader,
        threads,
        archive_label.as_ref(),
        IN_MEMORY_COMPRESSED_CAP,
    )
}

/// Path open with an explicit in-memory size threshold (used by tests to force
/// the file-backed store on small fixtures).
fn open_seekable_bzip2_with_file(
    mut file: File,
    len: u64,
    threads: u32,
    path: &Path,
    memory_cap: u64,
) -> Result<Arc<dyn SeekableBody>> {
    let threads = ParallelizationSpec::resolve_zero(threads).max(1);
    validate_bzip2_header_reader(&mut file, len)?;
    let store = if len <= memory_cap {
        let mut compressed = Vec::with_capacity(len as usize);
        file.read_to_end(&mut compressed)?;
        if compressed.len() as u64 != len && len > 0 {
            // Metadata size can race; trust what we read.
        }
        CompressedStore::Memory(Arc::new(compressed))
    } else {
        CompressedStore::shared_file(file, len, None)
    };
    finish_open(path, store, threads)
}

fn open_seekable_bzip2_from_reader_with_cap<R>(
    mut reader: R,
    threads: u32,
    path: &Path,
    memory_cap: u64,
) -> Result<Arc<dyn SeekableBody>>
where
    R: Read + Seek,
{
    let threads = ParallelizationSpec::resolve_zero(threads).max(1);
    let len = reader.seek(SeekFrom::End(0))?;
    reader.seek(SeekFrom::Start(0))?;
    validate_bzip2_header_reader(&mut reader, len)?;

    let store = if len <= memory_cap {
        let mut compressed = Vec::with_capacity(len as usize);
        reader.read_to_end(&mut compressed)?;
        CompressedStore::Memory(Arc::new(compressed))
    } else {
        // Spool once so we retain seekable compressed storage without Arc<Vec>.
        let mut tmp = NamedTempFile::new()?;
        io::copy(&mut reader, tmp.as_file_mut())?;
        tmp.as_file_mut().flush()?;
        let spool_len = tmp.as_file().metadata()?.len();
        let reopened = tmp.reopen()?;
        CompressedStore::shared_file(reopened, spool_len, Some(tmp))
    };
    finish_open(path, store, threads)
}

fn validate_bzip2_header_reader<R: Read + Seek>(reader: &mut R, len: u64) -> Result<()> {
    if len < 4 {
        return Err(CompressError::Msg("not a bzip2 stream".into()));
    }
    let mut header = [0u8; 4];
    reader.read_exact(&mut header)?;
    reader.seek(SeekFrom::Start(0))?;
    if !is_bzh_header(&header) {
        return Err(CompressError::Msg("not a bzip2 stream".into()));
    }
    Ok(())
}

fn finish_open(
    path: &Path,
    store: CompressedStore,
    threads: u32,
) -> Result<Arc<dyn SeekableBody>> {
    match try_build_bit_block_map_store(&store, threads) {
        Ok(blocks) if blocks.len() >= 2 => {
            let uncompressed_size = blocks
                .last()
                .map(|b| b.uncompressed_offset + b.uncompressed_size)
                .unwrap_or(0);
            return Ok(Arc::new(SeekableBzip2 {
                path: path.to_path_buf(),
                store,
                blocks: Arc::new(blocks),
                uncompressed_size,
            }));
        }
        Ok(_) | Err(_) => {
            // Single block, corrupt scan, etc. → full decode.
        }
    }

    full_decode_from_store(path, store, threads)
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

fn full_decode_from_store(
    path: &Path,
    store: CompressedStore,
    threads: u32,
) -> Result<Arc<dyn SeekableBody>> {
    match store {
        CompressedStore::Memory(v) => full_decode_body(path, &v, threads),
        CompressedStore::Shared(shared) => {
            // Stream multi-member bzip2 without loading the compressed blob.
            let mut guard = shared
                .inner
                .lock()
                .map_err(|_| CompressError::Msg("bzip2 compressed store lock poisoned".into()))?;
            guard.seek(SeekFrom::Start(0))?;
            let dec = MultiBzDecoder::new(&mut **guard);
            let body = DecodedBody::from_decoder(path, "bzip2", dec, DEFAULT_MEMORY_CAP)?;
            Ok(body as Arc<dyn SeekableBody>)
        }
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

/// Retained compressed payload for the bit-block map path.
#[derive(Clone)]
enum CompressedStore {
    Memory(Arc<Vec<u8>>),
    Shared(Arc<SharedCompressed>),
}

/// Shared seekable compressed source (path [`File`] or tempfile spool).
struct SharedCompressed {
    inner: Mutex<Box<dyn SeekRead>>,
    len: u64,
    /// Keeps a spool tempfile alive for the lifetime of the store.
    _keep: Option<NamedTempFile>,
}

impl CompressedStore {
    fn shared_file(file: File, len: u64, keep: Option<NamedTempFile>) -> Self {
        CompressedStore::Shared(Arc::new(SharedCompressed {
            inner: Mutex::new(Box::new(file)),
            len,
            _keep: keep,
        }))
    }

    fn len(&self) -> u64 {
        match self {
            CompressedStore::Memory(v) => v.len() as u64,
            CompressedStore::Shared(s) => s.len,
        }
    }

    fn read_exact_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        if buf.is_empty() {
            return Ok(());
        }
        let end = offset
            .checked_add(buf.len() as u64)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "read range overflow"))?;
        if end > self.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "read past end of compressed store",
            ));
        }
        match self {
            CompressedStore::Memory(v) => {
                let start = offset as usize;
                buf.copy_from_slice(&v[start..start + buf.len()]);
                Ok(())
            }
            CompressedStore::Shared(s) => {
                let mut guard = s
                    .inner
                    .lock()
                    .map_err(|_| io::Error::other("bzip2 compressed store lock poisoned"))?;
                guard.seek(SeekFrom::Start(offset))?;
                guard.read_exact(buf)
            }
        }
    }

    fn read_range(&self, start: u64, end: u64) -> io::Result<Vec<u8>> {
        if end < start {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid compressed range",
            ));
        }
        let mut buf = vec![0u8; (end - start) as usize];
        self.read_exact_at(start, &mut buf)?;
        Ok(buf)
    }
}

/// Seekable bzip2 body backed by a retained bit-block map.
pub struct SeekableBzip2 {
    path: PathBuf,
    store: CompressedStore,
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
            store: self.store.clone(),
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
    store: CompressedStore,
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
        let plain = decode_one_block_store(&self.store, b.header, b.start_bit, b.end_bit)
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

/// True when `compressed_len` is within the **in-memory** bit-block scan budget.
#[inline]
fn bit_scan_size_ok(compressed_len: usize) -> bool {
    compressed_len <= BIT_BLOCK_SCAN_MAX_BYTES
}

fn reject_if_too_large_for_bit_scan(compressed_len: usize) -> Result<()> {
    if bit_scan_size_ok(compressed_len) {
        return Ok(());
    }
    Err(CompressError::Msg(format!(
        "bzip2 block scan skipped (in-memory file large: {compressed_len} bytes > {BIT_BLOCK_SCAN_MAX_BYTES} byte cap)"
    )))
}

/// Build a global block map from the retained compressed store.
fn try_build_bit_block_map_store(store: &CompressedStore, threads: u32) -> Result<Vec<BlockInfo>> {
    match store {
        CompressedStore::Memory(v) => try_build_bit_block_map(v, threads),
        CompressedStore::Shared(_) => try_build_bit_block_map_file(store, threads),
    }
}

/// Build a global block map across one or more concatenated bzip2 streams (memory).
///
/// Fails (caller falls back to full decode) when:
/// * the in-memory buffer is larger than [`BIT_BLOCK_SCAN_MAX_BYTES`]
/// * fewer than 2 blocks are found overall
/// * magic scan / block decode fails
fn try_build_bit_block_map(compressed: &[u8], threads: u32) -> Result<Vec<BlockInfo>> {
    reject_if_too_large_for_bit_scan(compressed.len())?;

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

/// File-backed multi-stream bit-block map (no compressed-size RAM cap).
fn try_build_bit_block_map_file(store: &CompressedStore, threads: u32) -> Result<Vec<BlockInfo>> {
    let len = store.len();
    let mut all_blocks: Vec<BlockInfo> = Vec::new();
    let mut u_off = 0u64;
    let mut byte_pos = 0u64;

    while byte_pos + 4 <= len {
        let mut header = [0u8; 4];
        store
            .read_exact_at(byte_pos, &mut header)
            .map_err(|e| CompressError::Msg(format!("bzip2 header read: {e}")))?;
        if !is_bzh_header(&header) {
            break;
        }

        let remaining = len - byte_pos;
        let ranges = scan_block_bit_ranges_at(store, byte_pos, remaining)?;
        if ranges.is_empty() {
            return Err(CompressError::Msg("no bzip2 blocks in stream".into()));
        }

        // Absolute bit offsets into the full compressed blob.
        let bit_base = byte_pos * 8;
        let abs_ranges: Vec<(u64, u64)> = ranges
            .iter()
            .map(|&(s, e)| (bit_base + s, bit_base + e))
            .collect();

        let sizes = decode_block_sizes_store(header, store, &abs_ranges, threads)?;
        if sizes.len() != abs_ranges.len() {
            return Err(CompressError::Msg("bzip2 block size count mismatch".into()));
        }

        for (i, &(start_bit, end_bit)) in abs_ranges.iter().enumerate() {
            let usize_ = sizes[i];
            all_blocks.push(BlockInfo {
                header,
                start_bit,
                end_bit,
                uncompressed_offset: u_off,
                uncompressed_size: usize_,
            });
            u_off += usize_;
        }

        let eos_bit = ranges.last().unwrap().1;
        let after_stream_bits = eos_bit + 48 + 32;
        let stream_bytes = after_stream_bits.div_ceil(8);
        if stream_bytes == 0 {
            return Err(CompressError::Msg("degenerate bzip2 stream length".into()));
        }
        byte_pos += stream_bytes;

        while byte_pos < len {
            let mut b = [0u8; 1];
            store
                .read_exact_at(byte_pos, &mut b)
                .map_err(|e| CompressError::Msg(format!("bzip2 pad read: {e}")))?;
            if b[0] != 0 {
                break;
            }
            byte_pos += 1;
        }
    }

    if all_blocks.is_empty() {
        return Err(CompressError::Msg("no bzip2 blocks indexed".into()));
    }
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

/// Decode block sizes from absolute bit ranges against a compressed store.
fn decode_block_sizes_store(
    header: [u8; 4],
    store: &CompressedStore,
    ranges: &[(u64, u64)],
    threads: u32,
) -> Result<Vec<u64>> {
    if ranges.is_empty() {
        return Ok(Vec::new());
    }
    if threads <= 1 || ranges.len() == 1 {
        let mut sizes = Vec::with_capacity(ranges.len());
        for &(start_bit, end_bit) in ranges {
            let plain = decode_one_block_store(store, header, start_bit, end_bit)?;
            sizes.push(plain.len() as u64);
        }
        return Ok(sizes);
    }

    // Parallel size discovery: each worker loads its own compressed range.
    let n_workers = (threads as usize).min(ranges.len()).max(1);
    let mut results: Vec<Option<Result<u64>>> = (0..ranges.len()).map(|_| None).collect();
    let store_ref = store;

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
                        decode_one_block_store(store_ref, header, start_bit, end_bit)
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
///
/// Uses a sliding 48-bit window so each input bit is examined once (O(n) with
/// small constants). Subject to [`BIT_BLOCK_SCAN_MAX_BYTES`] (in-memory only).
fn scan_block_bit_ranges(compressed: &[u8]) -> Result<Vec<(u64, u64)>> {
    reject_if_too_large_for_bit_scan(compressed.len())?;
    scan_block_bit_ranges_bytes(compressed)
}

/// Slice bit-scan without the size gate (caller enforces policy).
fn scan_block_bit_ranges_bytes(compressed: &[u8]) -> Result<Vec<(u64, u64)>> {
    let total_bits = compressed.len() as u64 * 8;
    if total_bits < 32 + 48 {
        return Err(CompressError::Msg("bzip2 too short for block scan".into()));
    }

    // Sliding 48-bit window (MSB-first). After processing bit index `bit`
    // (0-based), `window` holds bits `[bit-47 ..= bit]` when `bit >= 47`.
    let mut window = 0u64;
    let mut starts = Vec::new();
    let mut eos_bit: Option<u64> = None;
    // First candidate magic may start at bit 32 (after `BZh[1-9]`).
    const MAGIC_BITS: u64 = 48;
    const HEADER_BITS: u64 = 32;
    let mask48 = (1u64 << MAGIC_BITS) - 1;
    // After a block magic match, skip candidate starts inside that magic
    // (matches the previous bit-step scanner's `bit += 48` after a hit).
    let mut next_allowed_start = HEADER_BITS;

    for bit in 0..total_bits {
        let byte = compressed[(bit / 8) as usize];
        let off = 7 - (bit % 8) as u8;
        let b = u64::from((byte >> off) & 1);
        window = ((window << 1) | b) & mask48;

        if bit + 1 < HEADER_BITS + MAGIC_BITS {
            continue;
        }
        // Window now equals bits starting at `start`.
        let start = bit + 1 - MAGIC_BITS;
        if start < next_allowed_start {
            continue;
        }
        if window == BLOCK_MAGIC {
            starts.push(start);
            next_allowed_start = start + MAGIC_BITS;
            continue;
        }
        if window == EOS_MAGIC {
            eos_bit = Some(start);
            break;
        }
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
        if end <= start + MAGIC_BITS {
            return Err(CompressError::Msg("degenerate bzip2 block range".into()));
        }
        ranges.push((start, end));
    }
    Ok(ranges)
}

/// Buffered bit-scan of a compressed stream region starting at `byte_offset`.
///
/// Reads via the store with a sliding window — does **not** load the whole
/// region into a `Vec`. Bit offsets in the result are relative to `byte_offset`.
fn scan_block_bit_ranges_at(
    store: &CompressedStore,
    byte_offset: u64,
    stream_len: u64,
) -> Result<Vec<(u64, u64)>> {
    if stream_len < 10 {
        return Err(CompressError::Msg("bzip2 too short for block scan".into()));
    }

    match store {
        CompressedStore::Memory(v) => {
            let start = byte_offset as usize;
            let end = (byte_offset + stream_len).min(v.len() as u64) as usize;
            // Memory store is already size-gated at open; scan the stream slice.
            scan_block_bit_ranges_bytes(&v[start..end])
        }
        CompressedStore::Shared(shared) => {
            let mut guard = shared.inner.lock().map_err(|_| {
                CompressError::Msg("bzip2 compressed store lock poisoned".into())
            })?;
            guard
                .seek(SeekFrom::Start(byte_offset))
                .map_err(|e| CompressError::Msg(format!("bzip2 scan seek: {e}")))?;
            let take = (&mut **guard).take(stream_len);
            scan_block_bit_ranges_reader(take, stream_len)
        }
    }
}

/// Sliding-window bit scan over a sequential reader (file-backed path).
///
/// `stream_len` is the maximum number of compressed bytes to examine.
/// No compressed-size RAM cap — only a fixed read buffer is held.
fn scan_block_bit_ranges_reader<R: Read>(
    mut reader: R,
    stream_len: u64,
) -> Result<Vec<(u64, u64)>> {
    let total_bits = stream_len.saturating_mul(8);
    if total_bits < 32 + 48 {
        return Err(CompressError::Msg("bzip2 too short for block scan".into()));
    }

    const MAGIC_BITS: u64 = 48;
    const HEADER_BITS: u64 = 32;
    let mask48 = (1u64 << MAGIC_BITS) - 1;

    let mut window = 0u64;
    let mut starts = Vec::new();
    let mut eos_bit: Option<u64> = None;
    let mut next_allowed_start = HEADER_BITS;
    let mut bit: u64 = 0;
    let mut bytes_seen: u64 = 0;
    let mut buf = vec![0u8; BIT_SCAN_READ_BUF];

    'read: while bytes_seen < stream_len {
        let want = ((stream_len - bytes_seen) as usize).min(buf.len());
        let n = reader
            .read(&mut buf[..want])
            .map_err(|e| CompressError::Msg(format!("bzip2 bit scan read: {e}")))?;
        if n == 0 {
            break;
        }
        for &byte in &buf[..n] {
            for off in (0..8).rev() {
                if bit >= total_bits {
                    break 'read;
                }
                let b = u64::from((byte >> off) & 1);
                window = ((window << 1) | b) & mask48;

                if bit + 1 >= HEADER_BITS + MAGIC_BITS {
                    let start = bit + 1 - MAGIC_BITS;
                    if start >= next_allowed_start {
                        if window == BLOCK_MAGIC {
                            starts.push(start);
                            next_allowed_start = start + MAGIC_BITS;
                        } else if window == EOS_MAGIC {
                            eos_bit = Some(start);
                            break 'read;
                        }
                    }
                }
                bit += 1;
            }
            bytes_seen += 1;
            if bytes_seen >= stream_len {
                break 'read;
            }
        }
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
        if end <= start + MAGIC_BITS {
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

/// Decode one block using absolute bit offsets into a compressed store.
///
/// Memory store: zero-copy into the existing `Vec`. File store: seek+read only
/// the covering compressed byte range into a mini buffer.
fn decode_one_block_store(
    store: &CompressedStore,
    header: [u8; 4],
    start_bit: u64,
    end_bit: u64,
) -> Result<Vec<u8>> {
    match store {
        CompressedStore::Memory(v) => decode_one_block(header, v, start_bit, end_bit),
        CompressedStore::Shared(_) => {
            if end_bit < start_bit {
                return Err(CompressError::Msg("degenerate bzip2 block range".into()));
            }
            // Cover [start_bit, end_bit) and the 32-bit block CRC at start+48.
            let crc_end_bit = start_bit.saturating_add(48 + 32);
            let need_end_bit = end_bit.max(crc_end_bit);
            let byte_start = start_bit / 8;
            let byte_end = need_end_bit.div_ceil(8).min(store.len());
            let data = store
                .read_range(byte_start, byte_end)
                .map_err(|e| CompressError::Msg(format!("bzip2 block range read: {e}")))?;
            let adj_start = start_bit - byte_start * 8;
            let adj_end = end_bit - byte_start * 8;
            decode_one_block(header, &data, adj_start, adj_end)
        }
    }
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
    fn large_file_scan_policy() {
        // Medium buffers may enter the in-memory scanner (content failures only).
        assert!(bit_scan_size_ok(8 * 1024 * 1024 + 16));
        assert!(bit_scan_size_ok(BIT_BLOCK_SCAN_MAX_BYTES));
        assert!(!bit_scan_size_ok(BIT_BLOCK_SCAN_MAX_BYTES + 1));

        let mut medium = vec![0u8; 8 * 1024 * 1024 + 16];
        medium[..4].copy_from_slice(b"BZh9");
        let err = scan_block_bit_ranges(&medium).unwrap_err();
        let msg = err.to_string();
        assert!(
            !msg.contains("large"),
            "8 MiB+ must no longer be skipped as large, got: {msg}"
        );
        assert!(
            msg.contains("EOS") || msg.contains("block"),
            "expected content-level scan failure, got: {msg}"
        );

        // In-memory slice scan still refuses multi-GB without allocating.
        let err = reject_if_too_large_for_bit_scan(BIT_BLOCK_SCAN_MAX_BYTES + 1).unwrap_err();
        assert!(
            err.to_string().contains("large"),
            "expected large-file skip, got {}",
            err
        );
        assert!(reject_if_too_large_for_bit_scan(BIT_BLOCK_SCAN_MAX_BYTES).is_ok());
        assert!(reject_if_too_large_for_bit_scan(0).is_ok());
    }

    #[test]
    fn file_backed_reader_scan_matches_slice() {
        let data = multi_block_payload();
        let compressed = encode_bz2_level(&data, 1);
        let slice_ranges = scan_block_bit_ranges(&compressed).expect("slice scan");
        assert!(slice_ranges.len() >= 2);

        let reader_ranges =
            scan_block_bit_ranges_reader(std::io::Cursor::new(&compressed), compressed.len() as u64)
                .expect("reader scan");
        assert_eq!(reader_ranges, slice_ranges);
    }

    #[test]
    fn file_backed_map_forced_by_zero_memory_cap() {
        // Documents the large-file path: memory_cap 0 forces tempfile/file store
        // + buffered scan + on-demand block reads (no Arc of full compressed Vec
        // retained on the map body). Synthetic multi-block stays small for CI.
        let data = multi_block_payload();
        let compressed = encode_bz2_level(&data, 1);
        // Ensure >8 KiB uncompressed still maps (goal: no 8 MiB wall regression).
        assert!(data.len() > 8 * 1024);
        let slice_ranges = scan_block_bit_ranges(&compressed).expect("multi-block");
        assert!(slice_ranges.len() >= 2);

        let body = open_seekable_bzip2_from_reader_with_cap(
            std::io::Cursor::new(compressed.clone()),
            2,
            Path::new("forced-file-backed.bz2"),
            0, // force Shared store
        )
        .unwrap();
        assert_eq!(body.kind(), "bzip2-blocks");
        assert_eq!(body.checkpoint_count(), slice_ranges.len());
        assert_eq!(body.size(), data.len() as u64);

        let mut got = Vec::new();
        body.open_reader().unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, data);

        // Random seeks still work via seek+read block ranges.
        let mut r = body.open_reader().unwrap();
        let n = data.len() as u64;
        for &off in &[0u64, n / 3, n / 2, n.saturating_sub(10)] {
            r.seek(SeekFrom::Start(off)).unwrap();
            let mut buf = [0u8; 32];
            let rn = r.read(&mut buf).unwrap();
            assert!(rn > 0, "offset {off}");
            assert_eq!(&buf[..rn], &data[off as usize..off as usize + rn]);
        }

        // Path open with cap 0 likewise uses the file-backed store.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("path-file-backed.bz2");
        std::fs::write(&path, &compressed).unwrap();
        let file = File::open(&path).unwrap();
        let len = file.metadata().unwrap().len();
        let path_body =
            open_seekable_bzip2_with_file(file, len, 1, &path, 0).unwrap();
        assert_eq!(path_body.kind(), "bzip2-blocks");
        assert_eq!(path_body.size(), data.len() as u64);
        let mut path_got = Vec::new();
        path_body
            .open_reader()
            .unwrap()
            .read_to_end(&mut path_got)
            .unwrap();
        assert_eq!(path_got, data);
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

    #[test]
    fn from_reader_multi_block_equals_path() {
        let data = multi_block_payload();
        let compressed = encode_bz2_level(&data, 1);
        let ranges = scan_block_bit_ranges(&compressed).expect("block scan");
        assert!(ranges.len() >= 2, "fixture must be multi-block");

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("from-reader-mb.bz2");
        std::fs::write(&path, &compressed).unwrap();

        let path_body = open_seekable_bzip2(&path).unwrap();
        let reader_body = open_seekable_bzip2_from_reader(
            std::io::Cursor::new(compressed.clone()),
            Path::new("memory://multi-block.bz2"),
        )
        .unwrap();

        assert_eq!(path_body.kind(), "bzip2-blocks");
        assert_eq!(reader_body.kind(), "bzip2-blocks");
        assert_eq!(path_body.size(), reader_body.size());
        assert_eq!(path_body.checkpoint_count(), reader_body.checkpoint_count());
        assert_eq!(reader_body.path(), Path::new("memory://multi-block.bz2"));
        assert_eq!(path_body.path(), path.as_path());

        let mut path_all = Vec::new();
        let mut mem_all = Vec::new();
        path_body
            .open_reader()
            .unwrap()
            .read_to_end(&mut path_all)
            .unwrap();
        reader_body
            .open_reader()
            .unwrap()
            .read_to_end(&mut mem_all)
            .unwrap();
        assert_eq!(path_all, data);
        assert_eq!(mem_all, data);

        // Random seeks match between path and Cursor opens.
        let mut path_r = path_body.open_reader().unwrap();
        let mut mem_r = reader_body.open_reader().unwrap();
        let n = data.len() as u64;
        for &off in &[0u64, 1, n / 4, n / 2, (3 * n) / 4, n.saturating_sub(1)] {
            path_r.seek(SeekFrom::Start(off)).unwrap();
            mem_r.seek(SeekFrom::Start(off)).unwrap();
            let mut pb = [0u8; 48];
            let mut mb = [0u8; 48];
            let pn = path_r.read(&mut pb).unwrap();
            let mn = mem_r.read(&mut mb).unwrap();
            assert_eq!(pn, mn, "offset {off}");
            assert_eq!(&pb[..pn], &mb[..mn], "offset {off}");
        }

        // Threaded free-function reader path.
        let body4 = open_seekable_bzip2_with_threads_from_reader(
            std::io::Cursor::new(compressed),
            4,
            "label.bz2",
        )
        .unwrap();
        assert_eq!(body4.size(), data.len() as u64);
        assert_eq!(body4.checkpoint_count(), path_body.checkpoint_count());
        let mut got = Vec::new();
        body4.open_reader().unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn from_reader_multi_stream_equals_path() {
        let a: Vec<u8> = (0..40_000u32).map(|i| (i % 200) as u8).collect();
        let b: Vec<u8> = (0..60_000u32).map(|i| ((i * 3) % 200) as u8).collect();
        let mut compressed = encode_bz2_level(&a, 1);
        compressed.extend_from_slice(&encode_bz2_level(&b, 1));
        let mut expected = a.clone();
        expected.extend_from_slice(&b);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("from-reader-ms.bz2");
        std::fs::write(&path, &compressed).unwrap();

        let path_body = open_seekable_bzip2_with_threads(&path, 2).unwrap();
        let reader_body = open_seekable_bzip2_with_threads_from_reader(
            std::io::Cursor::new(compressed.clone()),
            2,
            Path::new("memory://multi-stream.bz2"),
        )
        .unwrap();

        assert!(path_body.checkpoint_count() >= 2);
        assert_eq!(path_body.size(), reader_body.size());
        assert_eq!(path_body.checkpoint_count(), reader_body.checkpoint_count());
        assert_eq!(reader_body.path(), Path::new("memory://multi-stream.bz2"));

        let mut path_all = Vec::new();
        let mut mem_all = Vec::new();
        path_body
            .open_reader()
            .unwrap()
            .read_to_end(&mut path_all)
            .unwrap();
        reader_body
            .open_reader()
            .unwrap()
            .read_to_end(&mut mem_all)
            .unwrap();
        assert_eq!(path_all, expected);
        assert_eq!(mem_all, expected);

        // Seek into second stream region.
        let mid = a.len() as u64 + 100;
        let mut path_r = path_body.open_reader().unwrap();
        let mut mem_r = reader_body.open_reader().unwrap();
        path_r.seek(SeekFrom::Start(mid)).unwrap();
        mem_r.seek(SeekFrom::Start(mid)).unwrap();
        let mut pb = [0u8; 32];
        let mut mb = [0u8; 32];
        let pn = path_r.read(&mut pb).unwrap();
        let mn = mem_r.read(&mut mb).unwrap();
        assert_eq!(pn, mn);
        assert_eq!(&pb[..pn], &mb[..mn]);
    }

    #[test]
    fn from_reader_threads_zero_ok() {
        let data = multi_block_payload();
        let compressed = encode_bz2_level(&data, 1);
        let body = open_seekable_bzip2_with_threads_from_reader(
            std::io::Cursor::new(compressed),
            0,
            "threads-zero.bz2",
        )
        .unwrap();
        assert_eq!(body.size(), data.len() as u64);
        assert!(body.checkpoint_count() >= 2);
        let mut got = Vec::new();
        body.open_reader().unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn from_reader_single_block_fallback() {
        let data = b"tiny single block from reader";
        let compressed = encode_bz2(data);
        let body = open_seekable_bzip2_from_reader(
            std::io::Cursor::new(compressed),
            Path::new("virt-single.bz2"),
        )
        .unwrap();
        assert_eq!(body.kind(), "bzip2");
        assert_eq!(body.path(), Path::new("virt-single.bz2"));
        let mut got = Vec::new();
        body.open_reader().unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn file_backed_multi_stream_and_single_fallback() {
        // Multi-stream over file-backed store.
        let a: Vec<u8> = (0..40_000u32).map(|i| (i % 200) as u8).collect();
        let b: Vec<u8> = (0..60_000u32).map(|i| ((i * 3) % 200) as u8).collect();
        let mut compressed = encode_bz2_level(&a, 1);
        compressed.extend_from_slice(&encode_bz2_level(&b, 1));
        let mut expected = a.clone();
        expected.extend_from_slice(&b);

        let body = open_seekable_bzip2_from_reader_with_cap(
            std::io::Cursor::new(compressed),
            2,
            Path::new("fb-multi.bz2"),
            0,
        )
        .unwrap();
        assert!(body.checkpoint_count() >= 2);
        let mut got = Vec::new();
        body.open_reader().unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, expected);

        // Single-block still falls back when forced file-backed.
        let tiny = b"tiny fb single";
        let c = encode_bz2(tiny);
        let body = open_seekable_bzip2_from_reader_with_cap(
            std::io::Cursor::new(c),
            1,
            Path::new("fb-single.bz2"),
            0,
        )
        .unwrap();
        assert_eq!(body.kind(), "bzip2");
        let mut got = Vec::new();
        body.open_reader().unwrap().read_to_end(&mut got).unwrap();
        assert_eq!(got, tiny);
    }
}
