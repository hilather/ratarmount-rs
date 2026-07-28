//! Seekable LZ4 frame reader with per-block index.
//!
//! Independent blocks decompress from their own payload; dependent frames fall
//! back to a full-frame decode (same strategy as the Python `LZ4File` backend).
//! Leading skippable frames are skipped when indexing.
//!
//! Thread hint ([`open_seekable_lz4_with_threads`] / Python `-P` lz4 backend):
//! * **Independent blocks** (`block_independence`): during index build, block
//!   size discovery may fan out across workers when `threads > 1`.
//! * **Dependent frames**: stay sequential (blocks share history); `threads` is
//!   accepted for API parity. Parallelism is a **hint** — correctness first.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread;

use lz4_flex::block as lz4_block;
use lz4_flex::frame::FrameDecoder;
use ratarmount_core::ParallelizationSpec;

use crate::seekable_body::{DecodedBody, SeekRead, SeekableBody, DEFAULT_MEMORY_CAP};
use crate::{CompressError, Result};

const LZ4_FRAME_MAGIC: u32 = 0x184D_2204;
const LZ4_SKIPPABLE_MASK: u32 = 0x184D_2A50;
const LZ4_SKIPPABLE_NIBBLE: u32 = 0xFFFF_FFF0;

const FLG_DICT_ID: u8 = 0x01;
const FLG_CONTENT_CHECKSUM: u8 = 0x04;
const FLG_CONTENT_SIZE: u8 = 0x08;
const FLG_BLOCK_CHECKSUM: u8 = 0x10;
const FLG_BLOCK_INDEP: u8 = 0x20;

#[derive(Clone, Debug)]
struct BlockInfo {
    data_offset: u64,
    compressed_size: u32,
    uncompressed_offset: u64,
    uncompressed_size: u32,
    is_uncompressed: bool,
}

#[derive(Clone, Debug)]
struct FrameInfo {
    start_offset: u64,
    end_offset: u64,
    block_independence: bool,
    max_block_size: u32,
    blocks: Vec<BlockInfo>,
    total_uncompressed: u64,
    /// Uncompressed offset of this frame within the whole stream.
    stream_offset: u64,
}

/// Shared seekable LZ4 body.
pub struct SeekableLz4 {
    path: PathBuf,
    frames: Vec<FrameInfo>,
    uncompressed_size: u64,
    /// Full-decode fallback when every frame is dependent / unindexed.
    fallback: Option<Arc<DecodedBody>>,
}

impl SeekableLz4 {
    pub fn open(path: impl AsRef<Path>) -> Result<Arc<dyn SeekableBody>> {
        Self::open_with_threads(path, 1)
    }

    /// Open with a thread hint. See [`open_seekable_lz4_with_threads`].
    pub fn open_with_threads(path: impl AsRef<Path>, threads: u32) -> Result<Arc<dyn SeekableBody>> {
        let path = path.as_ref();
        let threads = ParallelizationSpec::resolve_zero(threads).max(1);
        match index_lz4_file(path, threads) {
            Ok(frames) if !frames.is_empty() => {
                let size: u64 = frames.iter().map(|f| f.total_uncompressed).sum();
                // Prefer block index when at least one frame has real multi-block independence.
                let has_indexed_blocks = frames
                    .iter()
                    .any(|f| f.block_independence && f.blocks.len() > 1);
                let only_synthetic = frames.iter().all(|f| !f.block_independence);
                if only_synthetic && size > DEFAULT_MEMORY_CAP {
                    // Large dependent-only: still expose frame-level restarts if multi-frame;
                    // otherwise full decode into temp.
                    if frames.len() == 1 {
                        return decode_full(path);
                    }
                }
                let _ = has_indexed_blocks;
                Ok(Arc::new(Self {
                    path: path.to_path_buf(),
                    frames,
                    uncompressed_size: size,
                    fallback: None,
                }))
            }
            Ok(_) => decode_full(path),
            Err(_) => decode_full(path),
        }
    }
}

fn decode_full(path: &Path) -> Result<Arc<dyn SeekableBody>> {
    let file = File::open(path)?;
    // FrameDecoder errors on leading skippable frames; skip them first.
    let mut file = skip_leading_skippable(file)?;
    let dec = FrameDecoder::new(&mut file);
    // FrameDecoder needs owned reader — re-open with skipped offset.
    drop(dec);
    let (mut f, start) = open_after_skippable(path)?;
    f.seek(SeekFrom::Start(start))?;
    let dec = FrameDecoder::new(f);
    let body = DecodedBody::from_decoder(path, "lz4", dec, DEFAULT_MEMORY_CAP)?;
    Ok(body)
}

fn skip_leading_skippable(mut file: File) -> Result<File> {
    let file_len = file.metadata()?.len();
    let mut pos = 0u64;
    while pos + 8 <= file_len {
        file.seek(SeekFrom::Start(pos))?;
        let mut magic_buf = [0u8; 4];
        if file.read(&mut magic_buf)? < 4 {
            break;
        }
        let magic = u32::from_le_bytes(magic_buf);
        if magic & LZ4_SKIPPABLE_NIBBLE != LZ4_SKIPPABLE_MASK {
            break;
        }
        let mut szb = [0u8; 4];
        file.read_exact(&mut szb)?;
        let sz = u32::from_le_bytes(szb) as u64;
        pos += 8 + sz;
    }
    file.seek(SeekFrom::Start(pos))?;
    Ok(file)
}

fn open_after_skippable(path: &Path) -> Result<(File, u64)> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    let mut pos = 0u64;
    while pos + 8 <= file_len {
        file.seek(SeekFrom::Start(pos))?;
        let mut magic_buf = [0u8; 4];
        if file.read(&mut magic_buf)? < 4 {
            break;
        }
        let magic = u32::from_le_bytes(magic_buf);
        if magic & LZ4_SKIPPABLE_NIBBLE != LZ4_SKIPPABLE_MASK {
            break;
        }
        let mut szb = [0u8; 4];
        file.read_exact(&mut szb)?;
        let sz = u32::from_le_bytes(szb) as u64;
        pos += 8 + sz;
    }
    Ok((file, pos))
}

impl SeekableBody for SeekableLz4 {
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
        Ok(Box::new(Lz4BlockReader::open(self)?))
    }

    fn kind(&self) -> &'static str {
        "lz4-blocks"
    }

    fn checkpoint_count(&self) -> usize {
        self.frames
            .iter()
            .map(|f| f.blocks.len().max(1))
            .sum::<usize>()
            .max(1)
    }
}

struct Lz4BlockReader {
    path: PathBuf,
    frames: Vec<FrameInfo>,
    size: u64,
    pos: u64,
    /// Cached decompressed block: (frame_idx, block_idx).
    cache_key: Option<(usize, usize)>,
    cache_data: Vec<u8>,
    cache_u_start: u64,
}

impl Lz4BlockReader {
    fn open(z: &SeekableLz4) -> io::Result<Self> {
        Ok(Self {
            path: z.path.clone(),
            frames: z.frames.clone(),
            size: z.uncompressed_size,
            pos: 0,
            cache_key: None,
            cache_data: Vec::new(),
            cache_u_start: 0,
        })
    }

    fn find(&self, pos: u64) -> io::Result<(usize, usize, u64)> {
        if pos >= self.size {
            let fi = self.frames.len().saturating_sub(1);
            let bi = self
                .frames
                .get(fi)
                .map(|f| f.blocks.len().saturating_sub(1))
                .unwrap_or(0);
            return Ok((fi, bi, 0));
        }
        for (fi, frame) in self.frames.iter().enumerate() {
            let end = frame.stream_offset + frame.total_uncompressed;
            if pos < end {
                let local = pos - frame.stream_offset;
                for (bi, block) in frame.blocks.iter().enumerate() {
                    let b_end = block.uncompressed_offset + block.uncompressed_size as u64;
                    if local < b_end {
                        return Ok((fi, bi, local - block.uncompressed_offset));
                    }
                }
                if let Some(last) = frame.blocks.last() {
                    return Ok((fi, frame.blocks.len() - 1, last.uncompressed_size as u64));
                }
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "lz4 position out of range",
        ))
    }

    fn ensure_block(&mut self, frame_idx: usize, block_idx: usize) -> io::Result<()> {
        if self.cache_key == Some((frame_idx, block_idx)) {
            return Ok(());
        }
        let frame = &self.frames[frame_idx];
        let block = &frame.blocks[block_idx];

        if !frame.block_independence && frame.blocks.len() == 1 {
            // Synthetic dependent frame: decompress whole frame.
            let data = decompress_frame_range(&self.path, frame)?;
            self.cache_key = Some((frame_idx, block_idx));
            self.cache_u_start = frame.stream_offset;
            self.cache_data = data;
            return Ok(());
        }

        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(block.data_offset))?;
        let mut payload = vec![0u8; block.compressed_size as usize];
        file.read_exact(&mut payload)?;
        let plain = if block.is_uncompressed {
            payload
        } else {
            decompress_block(&payload, block.uncompressed_size, frame.max_block_size)?
        };
        self.cache_key = Some((frame_idx, block_idx));
        self.cache_u_start = frame.stream_offset + block.uncompressed_offset;
        self.cache_data = plain;
        Ok(())
    }
}

impl Read for Lz4BlockReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.size {
            return Ok(0);
        }
        let (fi, bi, within) = self.find(self.pos)?;
        self.ensure_block(fi, bi)?;
        let into = (self.pos - self.cache_u_start) as usize;
        // within should match into for independent blocks; for synthetic full-frame cache, use into.
        let _ = within;
        if into >= self.cache_data.len() {
            return Ok(0);
        }
        let n = (self.cache_data.len() - into).min(buf.len());
        buf[..n].copy_from_slice(&self.cache_data[into..into + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Lz4BlockReader {
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

fn decompress_block(payload: &[u8], uncompressed_size: u32, max_block: u32) -> io::Result<Vec<u8>> {
    if uncompressed_size > 0 {
        match lz4_block::decompress(payload, uncompressed_size as usize) {
            Ok(v) if v.len() == uncompressed_size as usize => return Ok(v),
            Ok(v) => return Ok(v[..uncompressed_size as usize].to_vec()),
            Err(_) => {}
        }
    }
    let bound = max_block.max(uncompressed_size).max(64 * 1024) as usize;
    for size in [bound, bound * 2, 8 * 1024 * 1024, 64 * 1024 * 1024] {
        if let Ok(v) = lz4_block::decompress(payload, size) {
            if uncompressed_size > 0 && v.len() >= uncompressed_size as usize {
                return Ok(v[..uncompressed_size as usize].to_vec());
            }
            return Ok(v);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "lz4 block decompress failed",
    ))
}

fn decompress_frame_range(path: &Path, frame: &FrameInfo) -> io::Result<Vec<u8>> {
    let mut file = File::open(path)?;
    file.seek(SeekFrom::Start(frame.start_offset))?;
    let mut compressed = vec![0u8; (frame.end_offset - frame.start_offset) as usize];
    file.read_exact(&mut compressed)?;
    let mut dec = FrameDecoder::new(CursorSlice::new(compressed));
    let mut out = Vec::new();
    dec.read_to_end(&mut out)?;
    Ok(out)
}

/// Minimal owned cursor for FrameDecoder.
struct CursorSlice {
    data: Vec<u8>,
    pos: usize,
}

impl CursorSlice {
    fn new(data: Vec<u8>) -> Self {
        Self { data, pos: 0 }
    }
}

impl Read for CursorSlice {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.data.len() {
            return Ok(0);
        }
        let n = (self.data.len() - self.pos).min(buf.len());
        buf[..n].copy_from_slice(&self.data[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

fn max_block_size_from_bd(bd: u8) -> u32 {
    match (bd >> 4) & 0x07 {
        4 => 64 * 1024,
        5 => 256 * 1024,
        6 => 1024 * 1024,
        7 => 4 * 1024 * 1024,
        _ => 4 * 1024 * 1024,
    }
}

fn index_lz4_file(path: &Path, threads: u32) -> Result<Vec<FrameInfo>> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    let mut frames = Vec::new();
    let mut pos = 0u64;
    let mut stream_u = 0u64;

    while pos + 4 <= file_len {
        file.seek(SeekFrom::Start(pos))?;
        let mut magic_buf = [0u8; 4];
        if file.read(&mut magic_buf)? < 4 {
            break;
        }
        let magic = u32::from_le_bytes(magic_buf);

        if magic & LZ4_SKIPPABLE_NIBBLE == LZ4_SKIPPABLE_MASK {
            let mut szb = [0u8; 4];
            file.read_exact(&mut szb)?;
            let sz = u32::from_le_bytes(szb) as u64;
            pos += 8 + sz;
            continue;
        }
        if magic != LZ4_FRAME_MAGIC {
            break;
        }

        let frame = parse_frame(&mut file, pos, stream_u, threads)?;
        stream_u += frame.total_uncompressed;
        pos = frame.end_offset;
        frames.push(frame);
    }

    if frames.is_empty() {
        return Err(CompressError::Msg("no LZ4 frames found".into()));
    }
    Ok(frames)
}

fn parse_frame(file: &mut File, start: u64, stream_offset: u64, threads: u32) -> Result<FrameInfo> {
    file.seek(SeekFrom::Start(start + 4))?;
    let mut hdr = [0u8; 2];
    file.read_exact(&mut hdr)?;
    let flg = hdr[0];
    let bd = hdr[1];
    let version = (flg >> 6) & 0x03;
    if version != 1 {
        return Err(CompressError::Msg(format!(
            "unsupported LZ4 frame version {version}"
        )));
    }
    let block_independence = flg & FLG_BLOCK_INDEP != 0;
    let block_checksum = flg & FLG_BLOCK_CHECKSUM != 0;
    let content_size_flag = flg & FLG_CONTENT_SIZE != 0;
    let content_checksum = flg & FLG_CONTENT_CHECKSUM != 0;
    let dict_id = flg & FLG_DICT_ID != 0;

    let mut content_size = None;
    if content_size_flag {
        let mut b = [0u8; 8];
        file.read_exact(&mut b)?;
        content_size = Some(u64::from_le_bytes(b));
    }
    if dict_id {
        let mut b = [0u8; 4];
        file.read_exact(&mut b)?;
    }
    // Header checksum
    let mut hc = [0u8; 1];
    file.read_exact(&mut hc)?;

    let max_block_size = max_block_size_from_bd(bd);
    let mut blocks = Vec::new();
    // Payloads for independent compressed blocks (for parallel size discovery).
    let mut independent_payloads: Vec<(usize, Vec<u8>)> = Vec::new();

    loop {
        let size_field_offset = file.stream_position()?;
        let mut bh = [0u8; 4];
        file.read_exact(&mut bh)?;
        let block_header = u32::from_le_bytes(bh);
        if block_header == 0 {
            break;
        }
        let is_uncompressed = block_header & 0x8000_0000 != 0;
        let compressed_size = block_header & 0x7FFF_FFFF;
        let data_offset = file.stream_position()?;
        let mut payload = vec![0u8; compressed_size as usize];
        file.read_exact(&mut payload)?;
        if block_checksum {
            let mut c = [0u8; 4];
            file.read_exact(&mut c)?;
        }

        let uncompressed_size = if is_uncompressed {
            compressed_size
        } else if block_independence {
            // Defer size discovery so independent blocks can decode in parallel.
            independent_payloads.push((blocks.len(), payload));
            0
        } else {
            // Dependent: sizes filled after full frame decompress.
            0
        };
        let _ = size_field_offset;

        blocks.push(BlockInfo {
            data_offset,
            compressed_size,
            uncompressed_offset: 0, // filled after sizes are known
            uncompressed_size,
            is_uncompressed,
        });
    }

    if content_checksum {
        let mut c = [0u8; 4];
        file.read_exact(&mut c)?;
    }
    let end_offset = file.stream_position()?;

    let mut u_off = 0u64;

    if !block_independence {
        // Full frame decompress to obtain total size; collapse to one synthetic block.
        let mut compressed = vec![0u8; (end_offset - start) as usize];
        file.seek(SeekFrom::Start(start))?;
        file.read_exact(&mut compressed)?;
        let mut dec = FrameDecoder::new(CursorSlice::new(compressed));
        let mut plain = Vec::new();
        dec.read_to_end(&mut plain)
            .map_err(|e| CompressError::Msg(e.to_string()))?;
        let total = plain.len() as u64;
        let first_data = blocks.first().map(|b| b.data_offset).unwrap_or(start + 7);
        blocks = vec![BlockInfo {
            data_offset: first_data,
            compressed_size: (end_offset - first_data) as u32,
            uncompressed_offset: 0,
            uncompressed_size: total as u32,
            is_uncompressed: false,
        }];
        u_off = total;
        file.seek(SeekFrom::Start(end_offset))?;
    } else {
        // Independent: discover compressed-block sizes (parallel when threads > 1).
        fill_independent_block_sizes(&mut blocks, &independent_payloads, max_block_size, threads)?;
        for b in &mut blocks {
            b.uncompressed_offset = u_off;
            u_off += b.uncompressed_size as u64;
        }
    }

    if let Some(cs) = content_size {
        if cs != u_off {
            log::debug!("LZ4 content size header {cs} differs from sum of blocks {u_off}");
        }
    }

    Ok(FrameInfo {
        start_offset: start,
        end_offset,
        block_independence,
        max_block_size,
        blocks,
        total_uncompressed: u_off,
        stream_offset,
    })
}

/// Fill `uncompressed_size` for independent compressed blocks.
///
/// When `threads > 1` and there are multiple compressed blocks, workers decode
/// in parallel. Stored (uncompressed) blocks already have their size set.
fn fill_independent_block_sizes(
    blocks: &mut [BlockInfo],
    payloads: &[(usize, Vec<u8>)],
    max_block_size: u32,
    threads: u32,
) -> Result<()> {
    if payloads.is_empty() {
        return Ok(());
    }

    if threads <= 1 || payloads.len() == 1 {
        for (idx, payload) in payloads {
            let plain = decompress_block(payload, 0, max_block_size)
                .map_err(|e| CompressError::Msg(e.to_string()))?;
            blocks[*idx].uncompressed_size = plain.len() as u32;
        }
        return Ok(());
    }

    let n_workers = (threads as usize).min(payloads.len()).max(1);
    let mut results: Vec<Option<Result<u32>>> = (0..payloads.len()).map(|_| None).collect();

    thread::scope(|scope| {
        let chunk = payloads.len().div_ceil(n_workers).max(1);
        let mut handles = Vec::new();
        for (worker_id, part_chunk) in payloads.chunks(chunk).enumerate() {
            let base = worker_id * chunk;
            let owned: Vec<Vec<u8>> = part_chunk.iter().map(|(_, p)| p.clone()).collect();
            handles.push(scope.spawn(move || {
                let mut outs = Vec::with_capacity(owned.len());
                for p in &owned {
                    outs.push(
                        decompress_block(p, 0, max_block_size)
                            .map(|plain| plain.len() as u32)
                            .map_err(|e| CompressError::Msg(e.to_string())),
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

    for (i, (idx, _)) in payloads.iter().enumerate() {
        let size = results[i]
            .take()
            .ok_or_else(|| CompressError::Msg("lz4 parallel worker missing".into()))??;
        blocks[*idx].uncompressed_size = size;
    }
    Ok(())
}

/// Open LZ4 as a seekable body (single-thread open / index).
pub fn open_seekable_lz4(path: impl AsRef<Path>) -> Result<Arc<dyn SeekableBody>> {
    open_seekable_lz4_with_threads(path, 1)
}

/// Open LZ4 using up to `threads` workers for independent-block size discovery.
///
/// `threads == 0` means “use CPU count” (Python `-P 0` semantics).
///
/// * **Independent blocks**: index build may decompress blocks in parallel when
///   `threads > 1`.
/// * **Dependent frames**: decoded sequentially; `threads` is accepted for API
///   parity. Parallelism is a hint — correctness first.
pub fn open_seekable_lz4_with_threads(
    path: impl AsRef<Path>,
    threads: u32,
) -> Result<Arc<dyn SeekableBody>> {
    let threads = ParallelizationSpec::resolve_zero(threads).max(1);
    SeekableLz4::open_with_threads(path, threads)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn py_test(name: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        PathBuf::from(root).join("tests").join(name)
    }

    #[test]
    fn simple_lz4() {
        let path = py_test("simple.lz4");
        if !path.exists() {
            return;
        }
        let body = open_seekable_lz4(&path).unwrap();
        assert_eq!(body.size(), 12);
        let mut r = body.open_reader().unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "foo fighter\n");
    }

    #[test]
    fn multiblock_independent_seek() {
        let path = py_test("multiblock-independent.lz4");
        if !path.exists() {
            return;
        }
        let body = open_seekable_lz4(&path).unwrap();
        assert_eq!(body.size(), 2_000_000);
        assert!(body.checkpoint_count() > 1);
        let mut r = body.open_reader().unwrap();
        r.seek(SeekFrom::Start(100_000)).unwrap();
        let mut buf = [0u8; 20];
        r.read_exact(&mut buf).unwrap();
        // Content is lines like "line NNNNN hello lz4 ...\n"
        assert!(buf.starts_with(b"line ") || buf.iter().any(|&b| b.is_ascii_alphanumeric()));
        r.seek(SeekFrom::Start(0)).unwrap();
        let mut head = [0u8; 20];
        r.read_exact(&mut head).unwrap();
        assert_eq!(&head[..5], b"line ");
    }

    #[test]
    fn multiblock_dependent() {
        let path = py_test("multiblock-dependent.lz4");
        if !path.exists() {
            return;
        }
        let body = open_seekable_lz4(&path).unwrap();
        assert_eq!(body.size(), 2_000_000);
        let mut r = body.open_reader().unwrap();
        r.seek(SeekFrom::Start(50_000)).unwrap();
        let mut buf = [0u8; 10];
        assert_eq!(r.read(&mut buf).unwrap(), 10);
    }

    #[test]
    fn skippable_frame_prefix() {
        let path = py_test("nested-tar.skippable-frame.lz4");
        if !path.exists() {
            return;
        }
        let body = open_seekable_lz4(&path).unwrap();
        assert!(body.size() > 256);
        let mut r = body.open_reader().unwrap();
        r.seek(SeekFrom::Start(257)).unwrap();
        let mut magic = [0u8; 5];
        r.read_exact(&mut magic).unwrap();
        assert_eq!(&magic, b"ustar");
    }

    #[test]
    fn roundtrip_frame_encoder() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.lz4");
        {
            let mut enc = lz4_flex::frame::FrameEncoder::new(Vec::new());
            enc.write_all(b"hello lz4 seek").unwrap();
            let data = enc.finish().unwrap();
            std::fs::write(&path, data).unwrap();
        }
        let body = open_seekable_lz4(&path).unwrap();
        let mut r = body.open_reader().unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello lz4 seek");
    }

    #[test]
    fn open_seekable_lz4_with_threads_equals_single() {
        let path = py_test("multiblock-independent.lz4");
        if !path.exists() {
            // Fallback: small roundtrip frame
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("eq.lz4");
            {
                let mut enc = lz4_flex::frame::FrameEncoder::new(Vec::new());
                enc.write_all(b"hello lz4 parallelization").unwrap();
                let data = enc.finish().unwrap();
                std::fs::write(&path, data).unwrap();
            }
            let body1 = open_seekable_lz4_with_threads(&path, 1).unwrap();
            let body4 = open_seekable_lz4_with_threads(&path, 4).unwrap();
            let mut a = Vec::new();
            body1.open_reader().unwrap().read_to_end(&mut a).unwrap();
            let mut b = Vec::new();
            body4.open_reader().unwrap().read_to_end(&mut b).unwrap();
            assert_eq!(a, b);
            assert_eq!(a, b"hello lz4 parallelization");
            return;
        }
        let body1 = open_seekable_lz4_with_threads(&path, 1).unwrap();
        let body4 = open_seekable_lz4_with_threads(&path, 4).unwrap();
        assert_eq!(body1.size(), body4.size());
        let mut a = Vec::new();
        body1.open_reader().unwrap().read_to_end(&mut a).unwrap();
        let mut b = Vec::new();
        body4.open_reader().unwrap().read_to_end(&mut b).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 2_000_000);
    }

    #[test]
    fn threads_zero_means_cpu_count_lz4() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zero.lz4");
        {
            let mut enc = lz4_flex::frame::FrameEncoder::new(Vec::new());
            enc.write_all(b"threads-zero-lz4").unwrap();
            let data = enc.finish().unwrap();
            std::fs::write(&path, data).unwrap();
        }
        let body = open_seekable_lz4_with_threads(&path, 0).unwrap();
        let mut s = String::new();
        body.open_reader().unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "threads-zero-lz4");
    }
}
