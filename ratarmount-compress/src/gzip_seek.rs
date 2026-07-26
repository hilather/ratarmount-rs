//! Seekable gzip (G3 Tier B): rebuild-only checkpoints via `miniz_oxide` state clones.
//!
//! On first open we scan the compressed stream once, cloning inflate state every
//! `spacing` uncompressed bytes. Random access restores the nearest checkpoint and
//! decodes forward (at most ~spacing work per seek). Checkpoints live for the mount
//! lifetime (rebuild-on-load is acceptable; Python-compatible blob import is Tier C).

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use miniz_oxide::inflate::stream::{inflate, InflateState};
use miniz_oxide::{DataFormat, MZFlush, MZStatus};

use crate::{CompressError, Result};

/// Default seek-point spacing (uncompressed), matching Python CLI default (16 MiB).
pub const DEFAULT_GZIP_SEEK_SPACING: u64 = 16 * 1024 * 1024;

/// Inflate state snapshot at a known compressed/uncompressed pair.
struct Checkpoint {
    /// Next compressed byte to feed (absolute file offset).
    compressed_offset: u64,
    /// Uncompressed bytes produced before this state.
    uncompressed_offset: u64,
    state: Box<InflateState>,
}

/// Built seek table for one gzip file (possibly multi-member).
pub struct GzipSeekIndex {
    checkpoints: Vec<Checkpoint>,
    uncompressed_size: u64,
    spacing: u64,
}

/// Shared seekable gzip file (index + path). Readers open independent handles.
pub struct SeekableGzip {
    path: PathBuf,
    index: GzipSeekIndex,
}

impl SeekableGzip {
    /// Open and build (or rebuild) a seek index for `path`.
    pub fn open(path: impl AsRef<Path>, spacing: u64) -> Result<Arc<Self>> {
        let path = path.as_ref().to_path_buf();
        let spacing = spacing.max(64 * 1024); // avoid pathological tiny spacing
        let index = build_index(&path, spacing)?;
        Ok(Arc::new(Self { path, index }))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn uncompressed_size(&self) -> u64 {
        self.index.uncompressed_size
    }

    pub fn checkpoint_count(&self) -> usize {
        self.index.checkpoints.len()
    }

    pub fn spacing(&self) -> u64 {
        self.index.spacing
    }

    /// Independent reader (own file fd + logical position).
    pub fn reader(self: &Arc<Self>) -> io::Result<SeekableGzipReader> {
        SeekableGzipReader::open(Arc::clone(self))
    }
}

/// Read + Seek view of a [`SeekableGzip`].
pub struct SeekableGzipReader {
    gzip: Arc<SeekableGzip>,
    file: File,
    pos: u64,
    /// Decoded window starting at `buf_start` (absolute uncompressed offset).
    buf: Vec<u8>,
    buf_start: u64,
    /// Inflate cursor: next uncompressed byte inflate will produce.
    next_out: u64,
    compressed_at: u64,
    state: Box<InflateState>,
    eof: bool,
    /// Whether inflate cursor is valid (false after construction until primed).
    primed: bool,
}

impl SeekableGzipReader {
    fn open(gzip: Arc<SeekableGzip>) -> io::Result<Self> {
        let file = File::open(&gzip.path)?;
        Ok(Self {
            gzip,
            file,
            pos: 0,
            buf: Vec::new(),
            buf_start: 0,
            next_out: 0,
            compressed_at: 0,
            state: Box::new(InflateState::new(DataFormat::Raw)),
            eof: false,
            primed: false,
        })
    }

    /// Restore nearest checkpoint ≤ `target` and discard output until `target`.
    fn prime_at(&mut self, target: u64) -> io::Result<()> {
        let size = self.gzip.index.uncompressed_size;
        if target >= size {
            self.eof = true;
            self.primed = true;
            self.buf.clear();
            self.buf_start = target;
            self.next_out = size;
            return Ok(());
        }

        // Reuse if buffer already covers target or we can only decode forward.
        if self.primed {
            let buf_end = self.buf_start + self.buf.len() as u64;
            if target >= self.buf_start && target < buf_end {
                return Ok(());
            }
            if target >= self.next_out
                && !self.eof
                && target - self.next_out < self.gzip.index.spacing.saturating_mul(2)
            {
                // Decode forward discarding until target.
                self.discard_until(target)?;
                return Ok(());
            }
        }

        let cps = &self.gzip.index.checkpoints;
        let mut best = 0usize;
        for (i, cp) in cps.iter().enumerate() {
            if cp.uncompressed_offset <= target {
                best = i;
            } else {
                break;
            }
        }
        let cp = &cps[best];
        self.state = cp.state.clone();
        self.compressed_at = cp.compressed_offset;
        self.next_out = cp.uncompressed_offset;
        self.buf.clear();
        self.buf_start = self.next_out;
        self.eof = false;
        self.primed = true;
        self.discard_until(target)?;
        Ok(())
    }

    fn discard_until(&mut self, target: u64) -> io::Result<()> {
        let mut scratch = vec![0u8; 256 * 1024];
        while self.next_out < target && !self.eof {
            let want = (target - self.next_out).min(scratch.len() as u64) as usize;
            let n = inflate_more(
                &mut self.file,
                self.state.as_mut(),
                &mut self.compressed_at,
                &mut scratch[..want],
            )?;
            if n == 0 {
                self.eof = true;
                break;
            }
            let keep_from = if self.next_out + n as u64 > target {
                (target - self.next_out) as usize
            } else {
                n // discard all
            };
            self.next_out += n as u64;
            if keep_from < n {
                // Kept tail becomes the buffer starting at `target`.
                self.buf.clear();
                self.buf.extend_from_slice(&scratch[keep_from..n]);
                self.buf_start = target;
                return Ok(());
            }
        }
        // Landed exactly on target with empty buffer — prefetch.
        self.buf.clear();
        self.buf_start = target;
        if !self.eof && self.next_out == target {
            let mut chunk = vec![0u8; 64 * 1024];
            let n = inflate_more(
                &mut self.file,
                self.state.as_mut(),
                &mut self.compressed_at,
                &mut chunk,
            )?;
            if n == 0 {
                self.eof = true;
            } else {
                self.buf.extend_from_slice(&chunk[..n]);
                self.next_out += n as u64;
            }
        }
        Ok(())
    }

    fn fill_buf(&mut self) -> io::Result<()> {
        if self.eof {
            return Ok(());
        }
        let mut chunk = vec![0u8; 64 * 1024];
        let n = inflate_more(
            &mut self.file,
            self.state.as_mut(),
            &mut self.compressed_at,
            &mut chunk,
        )?;
        if n == 0 {
            self.eof = true;
            return Ok(());
        }
        // Append if contiguous, else replace.
        let buf_end = self.buf_start + self.buf.len() as u64;
        if buf_end == self.next_out {
            self.buf.extend_from_slice(&chunk[..n]);
        } else {
            self.buf.clear();
            self.buf.extend_from_slice(&chunk[..n]);
            self.buf_start = self.next_out;
        }
        self.next_out += n as u64;
        Ok(())
    }
}

impl Read for SeekableGzipReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.gzip.index.uncompressed_size {
            return Ok(0);
        }
        self.prime_at(self.pos)?;
        let buf_end = self.buf_start + self.buf.len() as u64;
        if self.pos < self.buf_start || self.pos >= buf_end {
            // Buffer empty or miss — try fill.
            if self.pos == self.next_out {
                self.fill_buf()?;
            } else {
                self.prime_at(self.pos)?;
            }
        }
        let buf_end = self.buf_start + self.buf.len() as u64;
        if self.pos >= buf_end {
            return Ok(0);
        }
        let into = (self.pos - self.buf_start) as usize;
        let avail = self.buf.len() - into;
        let n = avail.min(buf.len());
        buf[..n].copy_from_slice(&self.buf[into..into + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for SeekableGzipReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let size = self.gzip.index.uncompressed_size as i64;
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::End(o) => size + o,
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

/// Feed inflate from `file` at `compressed_at`, writing into `out`.
/// Returns bytes written to `out` (0 = EOF of all members).
fn inflate_more(
    file: &mut File,
    state: &mut InflateState,
    compressed_at: &mut u64,
    out: &mut [u8],
) -> io::Result<usize> {
    if out.is_empty() {
        return Ok(0);
    }
    let mut total_written = 0usize;
    let mut in_buf = [0u8; 64 * 1024];

    loop {
        if total_written == out.len() {
            return Ok(total_written);
        }
        file.seek(SeekFrom::Start(*compressed_at))?;
        let n_in = file.read(&mut in_buf)?;
        let input = if n_in == 0 { &[][..] } else { &in_buf[..n_in] };

        let res = inflate(
            state,
            input,
            &mut out[total_written..],
            if n_in == 0 { MZFlush::Finish } else { MZFlush::None },
        );
        match res.status {
            Ok(MZStatus::Ok) | Ok(MZStatus::StreamEnd) | Ok(MZStatus::NeedDict) => {}
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("gzip inflate error: {e:?}"),
                ));
            }
        }
        *compressed_at += res.bytes_consumed as u64;
        total_written += res.bytes_written;

        if res.bytes_written > 0 {
            return Ok(total_written);
        }

        if matches!(res.status, Ok(MZStatus::StreamEnd)) {
            // Consume gzip trailer (CRC32 + ISIZE) and optional next member header.
            if let Some(next) = skip_trailer_and_next_header(file, *compressed_at)? {
                *compressed_at = next;
                // Reset state for next member's raw deflate.
                *state = InflateState::new(DataFormat::Raw);
                if total_written > 0 {
                    return Ok(total_written);
                }
                continue;
            }
            return Ok(total_written); // true EOF
        }

        if n_in == 0 && res.bytes_consumed == 0 && res.bytes_written == 0 {
            return Ok(total_written);
        }
    }
}

fn build_index(path: &Path, spacing: u64) -> Result<GzipSeekIndex> {
    let mut file = File::open(path)?;
    let file_len = file.metadata()?.len();
    let mut checkpoints = Vec::new();
    let mut uncompressed_total = 0u64;
    let mut compressed_at = 0u64;

    // Multi-member loop
    while compressed_at < file_len {
        let header_end = match parse_gzip_header(&mut file, compressed_at)? {
            Some(h) => h,
            None => break, // padding / EOF
        };
        compressed_at = header_end;

        let mut state = Box::new(InflateState::new(DataFormat::Raw));
        // Checkpoint at start of each member (cheap restart).
        checkpoints.push(Checkpoint {
            compressed_offset: compressed_at,
            uncompressed_offset: uncompressed_total,
            state: state.clone(),
        });
        let mut next_cp_at = uncompressed_total + spacing;
        let mut in_buf = [0u8; 64 * 1024];
        let mut out_buf = vec![0u8; 256 * 1024];

        loop {
            file.seek(SeekFrom::Start(compressed_at))?;
            let n_in = file.read(&mut in_buf)?;
            let input = if n_in == 0 { &[][..] } else { &in_buf[..n_in] };
            let res = inflate(
                state.as_mut(),
                input,
                &mut out_buf,
                if n_in == 0 {
                    MZFlush::Finish
                } else {
                    MZFlush::None
                },
            );
            match res.status {
                Ok(_) => {}
                Err(e) => {
                    return Err(CompressError::Msg(format!(
                        "gzip inflate during index build: {e:?}"
                    )));
                }
            }
            compressed_at += res.bytes_consumed as u64;
            uncompressed_total += res.bytes_written as u64;

            while uncompressed_total >= next_cp_at {
                checkpoints.push(Checkpoint {
                    compressed_offset: compressed_at,
                    uncompressed_offset: uncompressed_total,
                    state: state.clone(),
                });
                next_cp_at += spacing;
            }

            if matches!(res.status, Ok(MZStatus::StreamEnd)) {
                // Skip trailer.
                compressed_at = skip_gzip_trailer(&mut file, compressed_at)?;
                break;
            }
            if n_in == 0 && res.bytes_consumed == 0 {
                return Err(CompressError::Msg(
                    "gzip stream ended unexpectedly during index build".into(),
                ));
            }
        }
    }

    if checkpoints.is_empty() {
        // Empty file: one dummy checkpoint.
        checkpoints.push(Checkpoint {
            compressed_offset: 0,
            uncompressed_offset: 0,
            state: Box::new(InflateState::new(DataFormat::Raw)),
        });
    }

    Ok(GzipSeekIndex {
        checkpoints,
        uncompressed_size: uncompressed_total,
        spacing,
    })
}

/// Parse gzip member header at `offset`; returns absolute offset of first deflate byte.
fn parse_gzip_header(file: &mut File, offset: u64) -> Result<Option<u64>> {
    file.seek(SeekFrom::Start(offset))?;
    let mut fixed = [0u8; 10];
    let n = file.read(&mut fixed)?;
    if n == 0 {
        return Ok(None);
    }
    if n < 10 {
        return Err(CompressError::Msg("truncated gzip header".into()));
    }
    if fixed[0] != 0x1f || fixed[1] != 0x8b {
        // Not a gzip header (e.g. zero padding after last member).
        return Ok(None);
    }
    if fixed[2] != 8 {
        return Err(CompressError::Msg(format!(
            "unsupported gzip CM {}",
            fixed[2]
        )));
    }
    let flg = fixed[3];
    let mut pos = offset + 10;

    // FEXTRA
    if flg & 0x04 != 0 {
        file.seek(SeekFrom::Start(pos))?;
        let mut xlen = [0u8; 2];
        file.read_exact(&mut xlen)?;
        let xlen = u16::from_le_bytes(xlen) as u64;
        pos += 2 + xlen;
    }
    // FNAME
    if flg & 0x08 != 0 {
        pos = skip_c_string(file, pos)?;
    }
    // FCOMMENT
    if flg & 0x10 != 0 {
        pos = skip_c_string(file, pos)?;
    }
    // FHCRC
    if flg & 0x02 != 0 {
        pos += 2;
    }
    Ok(Some(pos))
}

fn skip_c_string(file: &mut File, mut pos: u64) -> Result<u64> {
    file.seek(SeekFrom::Start(pos))?;
    let mut b = [0u8; 1];
    loop {
        file.read_exact(&mut b)?;
        pos += 1;
        if b[0] == 0 {
            break;
        }
    }
    Ok(pos)
}

fn skip_gzip_trailer(_file: &mut File, offset: u64) -> Result<u64> {
    // CRC32 + ISIZE
    Ok(offset + 8)
}

fn skip_trailer_and_next_header(file: &mut File, after_deflate: u64) -> io::Result<Option<u64>> {
    let after_trailer = after_deflate + 8;
    match parse_gzip_header(file, after_trailer) {
        Ok(Some(h)) => Ok(Some(h)),
        Ok(None) => Ok(None),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
    }
}

/// Convenience: open gzip as a seekable reader (builds index).
pub fn open_seekable_gzip(path: &Path, spacing: u64) -> Result<SeekableGzipReader> {
    let g = SeekableGzip::open(path, spacing)?;
    g.reader().map_err(CompressError::from)
}

/// Shared gzip body used by TAR mounts (random access without materialize).
pub struct SharedSeekableGzip {
    inner: Arc<SeekableGzip>,
    /// Serialise concurrent FUSE opens that share inflate work — each open still
    /// gets its own reader via [`Self::reader`].
    _lock: Mutex<()>,
}

impl SharedSeekableGzip {
    pub fn open(path: &Path, spacing: u64) -> Result<Arc<Self>> {
        let inner = SeekableGzip::open(path, spacing)?;
        Ok(Arc::new(Self {
            inner,
            _lock: Mutex::new(()),
        }))
    }

    pub fn size(&self) -> u64 {
        self.inner.uncompressed_size()
    }

    pub fn reader(&self) -> io::Result<SeekableGzipReader> {
        self.inner.reader()
    }

    pub fn path(&self) -> &Path {
        self.inner.path()
    }

    pub fn checkpoint_count(&self) -> usize {
        self.inner.checkpoint_count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn py_test(name: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        PathBuf::from(root).join("tests").join(name)
    }

    #[test]
    fn simple_gz_random_access() {
        let path = py_test("simple.gz");
        if !path.exists() {
            eprintln!("skip missing simple.gz");
            return;
        }
        let g = SeekableGzip::open(&path, 1024).unwrap();
        assert_eq!(g.uncompressed_size(), 12);
        let mut r = g.reader().unwrap();
        let mut buf = String::new();
        r.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "foo fighter\n");

        r.seek(SeekFrom::Start(4)).unwrap();
        let mut mid = String::new();
        r.read_to_string(&mut mid).unwrap();
        assert_eq!(mid, "fighter\n");

        r.seek(SeekFrom::Start(0)).unwrap();
        let mut b = [0u8; 3];
        r.read_exact(&mut b).unwrap();
        assert_eq!(&b, b"foo");
    }

    #[test]
    fn roundtrip_generated_gzip() {
        let dir = tempfile::tempdir().unwrap();
        let gz = dir.path().join("t.gz");
        // ~200 KiB compressible payload
        let mut raw = Vec::new();
        for i in 0..2000 {
            writeln!(&mut raw, "line {i:05} {}", "x".repeat(80)).unwrap();
        }
        {
            use flate2::write::GzEncoder;
            use flate2::Compression;
            let f = File::create(&gz).unwrap();
            let mut enc = GzEncoder::new(f, Compression::default());
            enc.write_all(&raw).unwrap();
            enc.finish().unwrap();
        }
        let g = SeekableGzip::open(&gz, 16 * 1024).unwrap();
        assert!(g.checkpoint_count() >= 2, "expected intermediate checkpoints");
        assert_eq!(g.uncompressed_size(), raw.len() as u64);
        let mut r = g.reader().unwrap();
        // Seek near end
        let off = raw.len() as u64 - 50;
        r.seek(SeekFrom::Start(off)).unwrap();
        let mut tail = vec![0u8; 50];
        r.read_exact(&mut tail).unwrap();
        assert_eq!(tail, raw[raw.len() - 50..]);
        // Full read
        r.seek(SeekFrom::Start(0)).unwrap();
        let mut all = Vec::new();
        r.read_to_end(&mut all).unwrap();
        assert_eq!(all, raw);
    }
}
