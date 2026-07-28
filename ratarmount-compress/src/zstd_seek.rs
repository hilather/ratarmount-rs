//! Seekable zstd: multi-frame restart points + zstd seekable-format seek table.
//!
//! Priority when opening:
//! 1. **Seek table** (zstd seekable format skippable footer, magic `0x8F92EAB1`) —
//!    gives compressed/decompressed sizes without decompressing during map build.
//! 2. **Multi-frame scan** — walk concatenated zstd frames; random access restores
//!    only the covering frame (cached per reader), never the full single-frame buffer.
//! 3. **Full decode** fallback for single large frames without a seek table.
//!
//! Thread hint (`open_seekable_zstd_with_threads` / Python `-P` zstd backend):
//! * Multi-frame maps keep **per-frame** random access; frames are independent, so
//!   concurrent readers already decode different frames without a shared lock.
//! * When falling back to a full single-buffer decode of multi-frame input and
//!   `threads > 1`, frames are decompressed in parallel (the public `zstd` crate
//!   exposes multi-thread **encode** via `zstdmt`/`NbWorkers`; frame-level
//!   parallel **decode** is implemented here instead).

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;
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

/// Shared seekable zstd file.
pub struct SeekableZstd {
    path: PathBuf,
    frames: Vec<FrameInfo>,
    uncompressed_size: u64,
    /// When only one large frame (or scan failed), fall back to full decode.
    fallback: Option<Arc<DecodedBody>>,
    /// True when frame map came from a seekable-format seek table.
    from_seek_table: bool,
}

impl SeekableZstd {
    pub fn open(path: impl AsRef<Path>) -> Result<Arc<dyn SeekableBody>> {
        Self::open_with_threads(path, 1)
    }

    /// Open with a thread hint. See [`open_seekable_zstd_with_threads`].
    pub fn open_with_threads(path: impl AsRef<Path>, threads: u32) -> Result<Arc<dyn SeekableBody>> {
        let path = path.as_ref();
        let threads = ParallelizationSpec::resolve_zero(threads).max(1);

        // 1) Prefer official seekable-format seek table when present.
        if let Ok((frames, uncomp_size)) = try_load_seek_table(path) {
            if frames.len() > 1 {
                return Ok(Arc::new(Self {
                    path: path.to_path_buf(),
                    frames,
                    uncompressed_size: uncomp_size,
                    fallback: None,
                    from_seek_table: true,
                }));
            }
            if frames.len() == 1 {
                if let Some(sz) = frames[0].uncompressed_size {
                    if sz <= DEFAULT_MEMORY_CAP {
                        return decode_full(path, threads);
                    }
                }
                // Single large frame with known compressed bounds: still use frame reader
                // so we do not force a permanent materialised path.
                return Ok(Arc::new(Self {
                    path: path.to_path_buf(),
                    frames,
                    uncompressed_size: uncomp_size,
                    fallback: None,
                    from_seek_table: true,
                }));
            }
        }

        // 2) Multi-frame (or single-frame) scan without seek table.
        match build_frame_map(path) {
            Ok((frames, uncomp_size)) if frames.len() > 1 => Ok(Arc::new(Self {
                path: path.to_path_buf(),
                frames,
                uncompressed_size: uncomp_size,
                fallback: None,
                from_seek_table: false,
            })),
            Ok((frames, uncomp_size)) if frames.len() == 1 => {
                // Single frame: if small content size known, decode that frame only once into memory.
                if let Some(sz) = frames[0].uncompressed_size {
                    if sz <= DEFAULT_MEMORY_CAP {
                        return decode_full(path, threads);
                    }
                }
                let _ = (frames, uncomp_size);
                decode_full(path, threads)
            }
            Ok(_) => decode_full(path, threads),
            Err(_) => decode_full(path, threads),
        }
    }

    /// Diagnostic: whether the frame map was imported from a seek table.
    pub fn used_seek_table(&self) -> bool {
        self.from_seek_table
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

/// Parallel decompress of independent zstd frames into one contiguous buffer.
fn try_parallel_frame_decode(path: &Path, threads: u32) -> Result<Vec<u8>> {
    let data = std::fs::read(path)?;
    let (frames, _total) = build_frame_map_from_bytes(&data)?;
    if frames.len() < 2 {
        return Err(CompressError::Msg("single zstd frame; sequential path".into()));
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
        out.extend(
            r.ok_or_else(|| CompressError::Msg("zstd parallel worker missing".into()))??,
        );
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
        if self.from_seek_table {
            "zstd-seek-table"
        } else {
            "zstd-frames"
        }
    }

    fn checkpoint_count(&self) -> usize {
        self.frames.len().max(1)
    }
}

struct ZstdFrameReader {
    path: PathBuf,
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
        Ok(Self {
            path: z.path.clone(),
            frames: z.frames.clone(),
            size: z.uncompressed_size,
            pos: 0,
            frame_idx: None,
            frame_data: Vec::new(),
            frame_start: 0,
        })
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
        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(info.compressed_offset))?;
        // Limit reader to this frame's compressed bytes when known — never decode the whole file.
        let mut data = Vec::new();
        if let Some(csz) = info.compressed_size {
            let limited = file.take(csz);
            let mut decoder = zstd::stream::read::Decoder::new(limited)
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
fn try_load_seek_table(path: &Path) -> Result<(Vec<FrameInfo>, u64)> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    if file_len < SEEK_TABLE_FOOTER_SIZE + SKIPPABLE_HEADER_SIZE {
        return Err(CompressError::Msg("file too small for seek table".into()));
    }

    file.seek(SeekFrom::End(-(SEEK_TABLE_FOOTER_SIZE as i64)))?;
    let mut footer = [0u8; 9];
    file.read_exact(&mut footer)?;
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

    file.seek(SeekFrom::End(-(frame_size as i64)))?;
    let mut header = [0u8; 8];
    file.read_exact(&mut header)?;
    let skip_magic = u32::from_le_bytes(header[0..4].try_into().unwrap());
    let skip_size = u32::from_le_bytes(header[4..8].try_into().unwrap()) as u64;
    if skip_magic != SEEK_TABLE_SKIPPABLE_MAGIC {
        return Err(CompressError::Msg("seek table skippable magic mismatch".into()));
    }
    if skip_size + SKIPPABLE_HEADER_SIZE != frame_size {
        return Err(CompressError::Msg("seek table size mismatch".into()));
    }

    let mut entries = vec![0u8; table_size as usize];
    file.read_exact(&mut entries)?;

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
        return Err(CompressError::Msg("seek table compressed offsets past data".into()));
    }
    if frames.is_empty() {
        return Err(CompressError::Msg("empty seek table".into()));
    }
    Ok((frames, d_off))
}

/// Scan zstd frames; returns (frames, total uncompressed size).
///
/// Uses `ZSTD_findFrameCompressedSize` so multi-frame maps are accurate even when
/// a streaming decoder would over-read into the next frame.
fn build_frame_map(path: &Path) -> Result<(Vec<FrameInfo>, u64)> {
    let data = std::fs::read(path)?;
    build_frame_map_from_bytes(&data)
}

/// Exact compressed size + uncompressed size for the first zstd frame in `src`.
fn measure_frame_slice(src: &[u8]) -> Result<(u64, u64)> {
    let comp = zstd::zstd_safe::find_frame_compressed_size(src).map_err(|e| {
        CompressError::Msg(format!("ZSTD_findFrameCompressedSize: {e}"))
    })?;
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
    use std::io::Write;

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
        let parts: [&[u8]; 3] = [
            b"hello world!!!!",
            b"second frame payload",
            b"third!",
        ];
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
        let (map, total) = try_load_seek_table(&path).unwrap();
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
        assert!(try_load_seek_table(&path).is_err());
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
}
