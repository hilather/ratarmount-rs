//! Seekable zstd: multi-frame restart points + full-decode fallback for single frames.
//!
//! Each zstd frame is independently decompressible. We scan frame boundaries and
//! record (compressed_offset, uncompressed_offset). Random access restores the
//! covering frame and decompresses only that frame (cached per reader).

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::seekable_body::{DecodedBody, SeekRead, SeekableBody, DEFAULT_MEMORY_CAP};
use crate::{CompressError, Result};

const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];
const SKIPPABLE_MAGIC_MIN: u32 = 0x184D2A50;
const SKIPPABLE_MAGIC_MAX: u32 = 0x184D2A5F;

#[derive(Clone, Debug)]
struct FrameInfo {
    /// Byte offset of frame magic in the compressed file.
    compressed_offset: u64,
    /// Uncompressed offset at start of this frame.
    uncompressed_offset: u64,
    /// Compressed size of this frame including header (None if unknown — last resort).
    compressed_size: Option<u64>,
    /// Uncompressed size if present in frame header.
    uncompressed_size: Option<u64>,
}

/// Shared seekable zstd file.
pub struct SeekableZstd {
    path: PathBuf,
    frames: Vec<FrameInfo>,
    uncompressed_size: u64,
    /// When only one large frame (or scan failed), fall back to full decode.
    fallback: Option<Arc<DecodedBody>>,
}

impl SeekableZstd {
    pub fn open(path: impl AsRef<Path>) -> Result<Arc<dyn SeekableBody>> {
        let path = path.as_ref();
        match build_frame_map(path) {
            Ok((frames, uncomp_size)) if frames.len() > 1 => Ok(Arc::new(Self {
                path: path.to_path_buf(),
                frames,
                uncompressed_size: uncomp_size,
                fallback: None,
            })),
            Ok((frames, uncomp_size)) if frames.len() == 1 => {
                // Single frame: if small content size known, decode that frame only once into memory.
                // Otherwise full decode (same cost as materialize, but unified SeekableBody).
                if let Some(sz) = frames[0].uncompressed_size {
                    if sz <= DEFAULT_MEMORY_CAP {
                        return decode_full(path);
                    }
                }
                // Unknown or large — still use full decode path (no permanent sidecar).
                let _ = (frames, uncomp_size);
                decode_full(path)
            }
            Ok(_) => decode_full(path),
            Err(_) => decode_full(path),
        }
    }
}

fn decode_full(path: &Path) -> Result<Arc<dyn SeekableBody>> {
    let file = File::open(path)?;
    let dec =
        zstd::stream::read::Decoder::new(file).map_err(|e| CompressError::Msg(e.to_string()))?;
    let body = DecodedBody::from_decoder(path, "zstd", dec, DEFAULT_MEMORY_CAP)?;
    Ok(body)
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
        "zstd-frames"
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
        if let Some(i) = self.frame_idx {
            let start = self.frame_start;
            let end = start + self.frame_data.len() as u64;
            if target >= start && target < end {
                return Ok(());
            }
            let _ = i;
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
        // Limit reader to this frame's compressed bytes when known.
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

/// Scan zstd frames; returns (frames, total uncompressed size).
fn build_frame_map(path: &Path) -> Result<(Vec<FrameInfo>, u64)> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    let mut frames = Vec::new();
    let mut pos = 0u64;
    let mut uncomp = 0u64;

    while pos + 4 <= file_len {
        file.seek(SeekFrom::Start(pos))?;
        let mut magic_buf = [0u8; 4];
        if file.read(&mut magic_buf)? < 4 {
            break;
        }
        let magic = u32::from_le_bytes(magic_buf);

        // Skippable frame
        if (SKIPPABLE_MAGIC_MIN..=SKIPPABLE_MAGIC_MAX).contains(&magic) {
            let mut szb = [0u8; 4];
            file.read_exact(&mut szb)?;
            let sz = u32::from_le_bytes(szb) as u64;
            pos += 8 + sz;
            continue;
        }
        if magic_buf != ZSTD_MAGIC {
            break;
        }

        let frame_start = pos;
        // Parse frame header for content size (Zstd frame format).
        let (header_size, content_size) = parse_frame_header(&mut file, pos)?;
        // Determine compressed frame size by decompressing (reliable) when content size unknown,
        // or by scanning: use decoder to measure compressed consumed.
        let (comp_size, frame_uncomp) = measure_frame(&mut file, frame_start, content_size)?;

        frames.push(FrameInfo {
            compressed_offset: frame_start,
            uncompressed_offset: uncomp,
            compressed_size: Some(comp_size),
            uncompressed_size: Some(frame_uncomp),
        });
        uncomp += frame_uncomp;
        pos = frame_start + comp_size;
        let _ = header_size;
    }

    if frames.is_empty() {
        return Err(CompressError::Msg("no zstd frames found".into()));
    }
    Ok((frames, uncomp))
}

fn parse_frame_header(file: &mut File, frame_start: u64) -> Result<(u64, Option<u64>)> {
    // After magic (4 bytes): Frame_Header_Descriptor (1 byte) + optional fields.
    file.seek(SeekFrom::Start(frame_start + 4))?;
    let mut desc = [0u8; 1];
    file.read_exact(&mut desc)?;
    let d = desc[0];
    let mut offset = frame_start + 5;
    // Window_Descriptor if !Single_Segment
    let single_segment = d & 0x20 != 0;
    if !single_segment {
        offset += 1;
        file.seek(SeekFrom::Start(offset - 1))?;
        let mut w = [0u8; 1];
        file.read_exact(&mut w)?;
    }
    // Dictionary_ID
    let did_size = match d & 0x3 {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        _ => 0,
    };
    offset += did_size;
    // Frame_Content_Size
    let fcs_size = match (d >> 6) & 0x3 {
        0 if single_segment => 1,
        0 => 0,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => 0,
    };
    let content_size = if fcs_size > 0 {
        file.seek(SeekFrom::Start(offset))?;
        let mut buf = [0u8; 8];
        file.read_exact(&mut buf[..fcs_size as usize])?;
        let v = match fcs_size {
            1 => buf[0] as u64,
            2 => u16::from_le_bytes([buf[0], buf[1]]) as u64 + 256,
            4 => u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64,
            8 => u64::from_le_bytes(buf),
            _ => 0,
        };
        offset += fcs_size;
        Some(v)
    } else {
        None
    };
    Ok((offset - frame_start, content_size))
}

fn measure_frame(
    file: &mut File,
    frame_start: u64,
    content_size: Option<u64>,
) -> Result<(u64, u64)> {
    file.seek(SeekFrom::Start(frame_start))?;
    // Use zstd streaming decoder single frame; track compressed via total read.
    // Read whole remainder into memory for small files; for large use streaming.
    let file_len = file.metadata()?.len();
    let remain = file_len - frame_start;
    // Cap intermediate buffer for measurement — stream with take progressive.
    let limited = file.take(remain);
    // We need compressed bytes consumed: wrap counting reader.
    let mut counter = CountingReader {
        inner: limited,
        n: 0,
    };
    let mut decoder = zstd::stream::read::Decoder::new(&mut counter)
        .map_err(|e| CompressError::Msg(e.to_string()))?
        .single_frame();
    let mut out = Vec::new();
    if let Some(cs) = content_size {
        out.reserve(cs.min(64 * 1024 * 1024) as usize);
    }
    decoder
        .read_to_end(&mut out)
        .map_err(|e| CompressError::Msg(e.to_string()))?;
    Ok((counter.n, out.len() as u64))
}

struct CountingReader<R> {
    inner: R,
    n: u64,
}

impl<R: Read> Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let got = self.inner.read(buf)?;
        self.n += got as u64;
        Ok(got)
    }
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
    fn multi_frame_zstd() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("multi.zst");
        // Two independent frames concatenated.
        let mut out = File::create(&path).unwrap();
        for part in [b"AAAA".as_slice(), b"BBBBCCCC".as_slice()] {
            let mut enc = zstd::stream::write::Encoder::new(Vec::new(), 1).unwrap();
            enc.write_all(part).unwrap();
            let frame = enc.finish().unwrap();
            out.write_all(&frame).unwrap();
        }
        drop(out);
        let body = SeekableZstd::open(&path).unwrap();
        assert!(body.checkpoint_count() >= 1);
        let mut r = body.open_reader().unwrap();
        let mut all = Vec::new();
        r.read_to_end(&mut all).unwrap();
        assert_eq!(all, b"AAAABBBBCCCC");
        r.seek(SeekFrom::Start(4)).unwrap();
        let mut mid = Vec::new();
        r.read_to_end(&mut mid).unwrap();
        assert_eq!(mid, b"BBBBCCCC");
    }
}
