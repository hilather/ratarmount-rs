//! Seekable gzip (G3 Tier B + C): checkpoints via `miniz_oxide` state clones.
//!
//! ## Tier B — rebuild-on-open
//! On first open we scan the compressed stream once, cloning inflate state every
//! `spacing` uncompressed bytes. Random access restores the nearest checkpoint and
//! decodes forward (at most ~spacing work per seek).
//!
//! ## Tier C — seek-index blob import/export
//! A versioned pure-Rust blob (`RGZI`) stores the checkpoint list
//! `(compressed_offset, uncompressed_offset)` plus spacing / uncompressed size.
//! The index crate can persist these bytes; this module only understands the blob
//! layout (no dependency on `ratarmount-index`).
//!
//! On import, inflate state is **rehydrated in one forward pass** at the imported
//! offsets (mid-stream resume needs `miniz_oxide` state that is not itself
//! serializable). That skips spacing-based point discovery and enables round-trip
//! remount when a blob is available. Future format flags may embed window bits for
//! zero-scan import interop with indexed_gzip / rapidgzip.
//!
//! Thread hint (`open_seekable_gzip_with_threads` / Python `-P` gzip backend):
//! * Seek-index construction is inherently sequential (inflate state chain).
//! * When `threads > 1` and the file is a **concatenation of independent gzip
//!   members**, members can be fully decoded in parallel
//!   ([`try_parallel_multi_member_decode`]) — best-effort multi-member parallel
//!   path matching rapidgzip-style member independence.
//!
//! Open paths:
//! * **Path-based** — reopen independent FDs per reader (`File::open`).
//! * **Reader-based** — any `Read + Seek + Send` (e.g. HTTP Range / in-memory
//!   `Cursor`); shared under a mutex so random Range reads drive inflate.
//! * **Imported index** — [`SeekableGzip::open_with_imported_index`] hydrates from
//!   an [`export_seek_index_blob`] payload.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

use miniz_oxide::inflate::stream::{inflate, InflateState};
use miniz_oxide::{DataFormat, MZFlush, MZStatus};
use ratarmount_core::ParallelizationSpec;

use crate::seekable_body::SeekRead;
use crate::{CompressError, Result};

/// Default seek-point spacing (uncompressed), matching Python CLI default (16 MiB).
pub const DEFAULT_GZIP_SEEK_SPACING: u64 = 16 * 1024 * 1024;

/// Magic for the ratarmount-rs gzip seek-index blob (`RGZI` = Ratarmount GZip Index).
pub const GZIP_SEEK_INDEX_MAGIC: &[u8; 4] = b"RGZI";

/// Current blob format version (v1 = offset pairs only, no window bits).
pub const GZIP_SEEK_INDEX_VERSION: u32 = 1;

/// Minimum blob header size: magic(4) + version(4) + flags(4) + spacing(8)
/// + uncompressed_size(8) + point_count(4).
const GZIP_SEEK_INDEX_HEADER_LEN: usize = 32;

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

/// Parsed Tier C seek-index blob (offset pairs + metadata; no inflate state).
///
/// # Binary layout (version 1, little-endian)
///
/// | Offset | Type   | Field |
/// |--------|--------|-------|
/// | 0      | `[u8;4]` | magic `RGZI` |
/// | 4      | `u32`  | version (`1`) |
/// | 8      | `u32`  | flags (reserved, must be `0` for v1) |
/// | 12     | `u64`  | spacing (uncompressed bytes between build points) |
/// | 20     | `u64`  | uncompressed_size |
/// | 28     | `u32`  | point_count |
/// | 32     | `point_count × 16` | `(compressed_offset u64, uncompressed_offset u64)` pairs |
///
/// Points are ordered by non-decreasing `uncompressed_offset`. The index crate
/// stores these bytes opaquely; only this module interprets them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GzipSeekIndexBlob {
    pub version: u32,
    pub flags: u32,
    pub spacing: u64,
    pub uncompressed_size: u64,
    /// `(compressed_offset, uncompressed_offset)` pairs.
    pub points: Vec<(u64, u64)>,
}

/// Encode a Tier C seek-index blob from spacing, size, and seek points.
pub fn encode_gzip_seek_index_blob(
    spacing: u64,
    uncompressed_size: u64,
    points: &[(u64, u64)],
) -> Vec<u8> {
    let count = u32::try_from(points.len()).unwrap_or(u32::MAX);
    let n = count as usize;
    let mut out = Vec::with_capacity(GZIP_SEEK_INDEX_HEADER_LEN + n * 16);
    out.extend_from_slice(GZIP_SEEK_INDEX_MAGIC);
    out.extend_from_slice(&GZIP_SEEK_INDEX_VERSION.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes()); // flags
    out.extend_from_slice(&spacing.to_le_bytes());
    out.extend_from_slice(&uncompressed_size.to_le_bytes());
    out.extend_from_slice(&count.to_le_bytes());
    for &(c, u) in points.iter().take(n) {
        out.extend_from_slice(&c.to_le_bytes());
        out.extend_from_slice(&u.to_le_bytes());
    }
    out
}

/// Parse a Tier C seek-index blob. Does not touch the compressed stream.
pub fn parse_gzip_seek_index_blob(blob: &[u8]) -> Result<GzipSeekIndexBlob> {
    if blob.len() < GZIP_SEEK_INDEX_HEADER_LEN {
        return Err(CompressError::Msg(format!(
            "gzip seek-index blob too short ({} < {GZIP_SEEK_INDEX_HEADER_LEN})",
            blob.len()
        )));
    }
    if &blob[0..4] != GZIP_SEEK_INDEX_MAGIC.as_slice() {
        return Err(CompressError::Msg(format!(
            "gzip seek-index bad magic: {:02x?}",
            &blob[0..4]
        )));
    }
    let version = u32::from_le_bytes(blob[4..8].try_into().unwrap());
    if version == 0 || version > GZIP_SEEK_INDEX_VERSION {
        return Err(CompressError::Msg(format!(
            "gzip seek-index unsupported version {version} (max {GZIP_SEEK_INDEX_VERSION})"
        )));
    }
    let flags = u32::from_le_bytes(blob[8..12].try_into().unwrap());
    if flags != 0 {
        return Err(CompressError::Msg(format!(
            "gzip seek-index unknown flags 0x{flags:x} (v1 requires 0)"
        )));
    }
    let spacing = u64::from_le_bytes(blob[12..20].try_into().unwrap());
    let uncompressed_size = u64::from_le_bytes(blob[20..28].try_into().unwrap());
    let point_count = u32::from_le_bytes(blob[28..32].try_into().unwrap()) as usize;
    let need = GZIP_SEEK_INDEX_HEADER_LEN
        .checked_add(point_count.checked_mul(16).ok_or_else(|| {
            CompressError::Msg("gzip seek-index point_count overflow".into())
        })?)
        .ok_or_else(|| CompressError::Msg("gzip seek-index size overflow".into()))?;
    if blob.len() < need {
        return Err(CompressError::Msg(format!(
            "gzip seek-index truncated: have {} need {need} for {point_count} points",
            blob.len()
        )));
    }
    let mut points = Vec::with_capacity(point_count);
    let mut off = GZIP_SEEK_INDEX_HEADER_LEN;
    for _ in 0..point_count {
        let c = u64::from_le_bytes(blob[off..off + 8].try_into().unwrap());
        let u = u64::from_le_bytes(blob[off + 8..off + 16].try_into().unwrap());
        points.push((c, u));
        off += 16;
    }
    // Enforce non-decreasing uncompressed offsets.
    for w in points.windows(2) {
        if w[1].1 < w[0].1 {
            return Err(CompressError::Msg(
                "gzip seek-index points not sorted by uncompressed_offset".into(),
            ));
        }
    }
    Ok(GzipSeekIndexBlob {
        version,
        flags,
        spacing,
        uncompressed_size,
        points,
    })
}

/// How compressed bytes are re-opened for independent inflate cursors.
enum GzipBackend {
    /// Local path: each reader opens its own `File`.
    Path(PathBuf),
    /// Shared seekable stream (HTTP Range, Cursor, etc.).
    Shared(Arc<Mutex<Box<dyn SeekRead>>>),
}

/// Shared seekable gzip file (index + backend). Readers open independent handles
/// (path) or share the compressed stream under a mutex (reader backend).
pub struct SeekableGzip {
    /// Label for logs / index metadata (filesystem path, URL, or virtual name).
    path: PathBuf,
    backend: GzipBackend,
    index: GzipSeekIndex,
}

impl SeekableGzip {
    /// Open and build (or rebuild) a seek index for `path`.
    pub fn open(path: impl AsRef<Path>, spacing: u64) -> Result<Arc<Self>> {
        Self::open_with_threads(path, spacing, 1)
    }

    /// Open with a thread hint (Python `-P` / gzip backend).
    ///
    /// `threads == 0` means “use CPU count”. The seek index is still built
    /// sequentially (inflate state chain). Independent multi-member parallel
    /// decode is available via [`try_parallel_multi_member_decode`] when a full
    /// buffer is preferred over random-access checkpoints.
    pub fn open_with_threads(
        path: impl AsRef<Path>,
        spacing: u64,
        threads: u32,
    ) -> Result<Arc<Self>> {
        let path = path.as_ref().to_path_buf();
        let spacing = spacing.max(64 * 1024); // avoid pathological tiny spacing
        // Resolve for -P 0 parity / future concurrent index builders; index path
        // does not currently fan out workers.
        let _threads = ParallelizationSpec::resolve_zero(threads).max(1);
        let mut file = File::open(&path)?;
        let index = build_index(&mut file, spacing)?;
        Ok(Arc::new(Self {
            path: path.clone(),
            backend: GzipBackend::Path(path),
            index,
        }))
    }

    /// Open using a Tier C seek-index blob (skips spacing-based point discovery).
    ///
    /// Inflate states are rehydrated in one forward pass at the imported offsets.
    /// `spacing` is only used if the blob's spacing is zero (clamped to ≥ 64 KiB);
    /// otherwise the blob's spacing is kept for forward-decode heuristics.
    /// `threads` matches the path open API (`0` → CPU count); index rehydration
    /// remains sequential.
    pub fn open_with_imported_index(
        path: impl AsRef<Path>,
        spacing: u64,
        threads: u32,
        index_blob: &[u8],
    ) -> Result<Arc<Self>> {
        let path = path.as_ref().to_path_buf();
        let _threads = ParallelizationSpec::resolve_zero(threads).max(1);
        let parsed = parse_gzip_seek_index_blob(index_blob)?;
        let spacing = effective_import_spacing(spacing, parsed.spacing);
        let mut file = File::open(&path)?;
        let index = import_seek_points(
            &mut file,
            &parsed.points,
            spacing,
            parsed.uncompressed_size,
        )?;
        Ok(Arc::new(Self {
            path: path.clone(),
            backend: GzipBackend::Path(path),
            index,
        }))
    }

    /// Open from an already-seekable compressed stream (HTTP Range, memory, …).
    ///
    /// `archive_label` is stored for [`Self::path`] / logs (URL or virtual name).
    pub fn open_from_reader<R>(
        reader: R,
        spacing: u64,
        archive_label: impl AsRef<Path>,
    ) -> Result<Arc<Self>>
    where
        R: Read + Seek + Send + 'static,
    {
        Self::open_with_threads_from_reader(reader, spacing, 1, archive_label)
    }

    /// Like [`Self::open_from_reader`] with a thread hint (Python `-P`).
    ///
    /// Index construction remains sequential; the thread hint matches path-based
    /// openers for API parity.
    pub fn open_with_threads_from_reader<R>(
        mut reader: R,
        spacing: u64,
        threads: u32,
        archive_label: impl AsRef<Path>,
    ) -> Result<Arc<Self>>
    where
        R: Read + Seek + Send + 'static,
    {
        let path = archive_label.as_ref().to_path_buf();
        let spacing = spacing.max(64 * 1024);
        let _threads = ParallelizationSpec::resolve_zero(threads).max(1);
        let index = build_index(&mut reader, spacing)?;
        let shared: Arc<Mutex<Box<dyn SeekRead>>> = Arc::new(Mutex::new(Box::new(reader)));
        Ok(Arc::new(Self {
            path,
            backend: GzipBackend::Shared(shared),
            index,
        }))
    }

    /// Open from a seekable stream using a Tier C seek-index blob.
    ///
    /// See [`Self::open_with_imported_index`].
    pub fn open_with_imported_index_from_reader<R>(
        mut reader: R,
        spacing: u64,
        threads: u32,
        archive_label: impl AsRef<Path>,
        index_blob: &[u8],
    ) -> Result<Arc<Self>>
    where
        R: Read + Seek + Send + 'static,
    {
        let path = archive_label.as_ref().to_path_buf();
        let _threads = ParallelizationSpec::resolve_zero(threads).max(1);
        let parsed = parse_gzip_seek_index_blob(index_blob)?;
        let spacing = effective_import_spacing(spacing, parsed.spacing);
        let index = import_seek_points(
            &mut reader,
            &parsed.points,
            spacing,
            parsed.uncompressed_size,
        )?;
        let shared: Arc<Mutex<Box<dyn SeekRead>>> = Arc::new(Mutex::new(Box::new(reader)));
        Ok(Arc::new(Self {
            path,
            backend: GzipBackend::Shared(shared),
            index,
        }))
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

    /// Export a Tier C seek-index blob (offset pairs + metadata) for persistence
    /// or round-trip reopen via [`Self::open_with_imported_index`].
    pub fn export_seek_index_blob(&self) -> Vec<u8> {
        let points: Vec<(u64, u64)> = self
            .index
            .checkpoints
            .iter()
            .map(|c| (c.compressed_offset, c.uncompressed_offset))
            .collect();
        encode_gzip_seek_index_blob(
            self.index.spacing,
            self.index.uncompressed_size,
            &points,
        )
    }

    /// Independent reader (own file fd or shared stream handle + logical position).
    pub fn reader(self: &Arc<Self>) -> io::Result<SeekableGzipReader> {
        SeekableGzipReader::open(Arc::clone(self))
    }
}

fn effective_import_spacing(api_spacing: u64, blob_spacing: u64) -> u64 {
    let s = if blob_spacing > 0 {
        blob_spacing
    } else {
        api_spacing
    };
    s.max(64 * 1024)
}

/// Compressed-stream handle used during inflate (path FD or shared mutex stream).
enum CompressedHandle {
    File(File),
    Shared(Arc<Mutex<Box<dyn SeekRead>>>),
}

impl Read for CompressedHandle {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            CompressedHandle::File(f) => f.read(buf),
            CompressedHandle::Shared(inner) => inner
                .lock()
                .map_err(|_| io::Error::other("gzip backend mutex poisoned"))?
                .read(buf),
        }
    }
}

impl Seek for CompressedHandle {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match self {
            CompressedHandle::File(f) => f.seek(pos),
            CompressedHandle::Shared(inner) => inner
                .lock()
                .map_err(|_| io::Error::other("gzip backend mutex poisoned"))?
                .seek(pos),
        }
    }
}

/// Read + Seek view of a [`SeekableGzip`].
pub struct SeekableGzipReader {
    gzip: Arc<SeekableGzip>,
    file: CompressedHandle,
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
        let file = match &gzip.backend {
            GzipBackend::Path(p) => CompressedHandle::File(File::open(p)?),
            GzipBackend::Shared(shared) => CompressedHandle::Shared(Arc::clone(shared)),
        };
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
fn inflate_more<R: Read + Seek>(
    file: &mut R,
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
            if n_in == 0 {
                MZFlush::Finish
            } else {
                MZFlush::None
            },
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

fn stream_len<R: Read + Seek>(file: &mut R) -> io::Result<u64> {
    let cur = file.stream_position()?;
    let len = file.seek(SeekFrom::End(0))?;
    file.seek(SeekFrom::Start(cur))?;
    Ok(len)
}

fn build_index<R: Read + Seek>(file: &mut R, spacing: u64) -> Result<GzipSeekIndex> {
    let file_len = stream_len(file)?;
    let mut checkpoints = Vec::new();
    let mut uncompressed_total = 0u64;
    let mut compressed_at = 0u64;

    // Multi-member loop
    while compressed_at < file_len {
        let header_end = match parse_gzip_header(file, compressed_at)? {
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
                compressed_at = skip_gzip_trailer(file, compressed_at)?;
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

/// Rehydrate inflate state at imported seek points (Tier C).
///
/// Walks the compressed stream once and snapshots `miniz_oxide` state when the
/// uncompressed cursor matches each imported `(compressed_offset, uncompressed_offset)`.
/// Empty `points` falls back to a full spacing-based [`build_index`].
///
/// `expected_uncompressed_size` must match the decoded size (blob metadata check).
pub fn import_seek_points<R: Read + Seek>(
    file: &mut R,
    points: &[(u64, u64)],
    spacing: u64,
    expected_uncompressed_size: u64,
) -> Result<GzipSeekIndex> {
    let spacing = spacing.max(64 * 1024);
    if points.is_empty() {
        let index = build_index(file, spacing)?;
        if index.uncompressed_size != expected_uncompressed_size {
            return Err(CompressError::Msg(format!(
                "gzip seek-index size mismatch: blob {} vs decoded {}",
                expected_uncompressed_size, index.uncompressed_size
            )));
        }
        return Ok(index);
    }

    // Snapshot whenever we land on an imported uncompressed offset (post-inflate
    // cursor). Duplicate (c,u) pairs from dense spacing exports are preserved.
    let mut targets: Vec<(u64, u64)> = points.to_vec();
    targets.sort_by_key(|p| (p.1, p.0));

    let file_len = stream_len(file)?;
    let mut checkpoints = Vec::with_capacity(targets.len().max(1));
    let mut uncompressed_total = 0u64;
    let mut compressed_at = 0u64;
    let mut next_target = 0usize;

    let take_if_due = |compressed_at: u64,
                       uncompressed_total: u64,
                       state: &InflateState,
                       checkpoints: &mut Vec<Checkpoint>,
                       next_target: &mut usize|
     -> Result<()> {
        while *next_target < targets.len() && uncompressed_total >= targets[*next_target].1 {
            let (want_c, want_u) = targets[*next_target];
            if uncompressed_total != want_u {
                return Err(CompressError::Msg(format!(
                    "gzip seek-index cannot land on uncompressed_offset {want_u} (at {uncompressed_total})"
                )));
            }
            // Compressed cursor must match the export (deterministic inflate).
            if compressed_at != want_c {
                return Err(CompressError::Msg(format!(
                    "gzip seek-index compressed_offset mismatch at uncompressed {want_u}: \
                     blob {want_c} vs rehydrated {compressed_at}"
                )));
            }
            checkpoints.push(Checkpoint {
                compressed_offset: compressed_at,
                uncompressed_offset: uncompressed_total,
                state: Box::new(state.clone()),
            });
            *next_target += 1;
        }
        Ok(())
    };

    while compressed_at < file_len {
        let header_end = match parse_gzip_header(file, compressed_at)? {
            Some(h) => h,
            None => break,
        };
        compressed_at = header_end;

        let mut state = Box::new(InflateState::new(DataFormat::Raw));
        // Member start may be an imported point.
        take_if_due(
            compressed_at,
            uncompressed_total,
            state.as_ref(),
            &mut checkpoints,
            &mut next_target,
        )?;

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
                        "gzip inflate during seek-index import: {e:?}"
                    )));
                }
            }
            compressed_at += res.bytes_consumed as u64;
            uncompressed_total += res.bytes_written as u64;

            take_if_due(
                compressed_at,
                uncompressed_total,
                state.as_ref(),
                &mut checkpoints,
                &mut next_target,
            )?;

            if matches!(res.status, Ok(MZStatus::StreamEnd)) {
                compressed_at = skip_gzip_trailer(file, compressed_at)?;
                break;
            }
            if n_in == 0 && res.bytes_consumed == 0 {
                return Err(CompressError::Msg(
                    "gzip stream ended unexpectedly during seek-index import".into(),
                ));
            }
        }
    }

    if next_target != targets.len() {
        return Err(CompressError::Msg(format!(
            "gzip seek-index import missed {} of {} points (decoded {uncompressed_total} bytes)",
            targets.len() - next_target,
            targets.len()
        )));
    }

    if uncompressed_total != expected_uncompressed_size {
        return Err(CompressError::Msg(format!(
            "gzip seek-index size mismatch: blob {expected_uncompressed_size} vs decoded {uncompressed_total}"
        )));
    }

    if checkpoints.is_empty() {
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
fn parse_gzip_header<R: Read + Seek>(file: &mut R, offset: u64) -> Result<Option<u64>> {
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

fn skip_c_string<R: Read + Seek>(file: &mut R, mut pos: u64) -> Result<u64> {
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

fn skip_gzip_trailer<R: Read + Seek>(_file: &mut R, offset: u64) -> Result<u64> {
    // CRC32 + ISIZE
    Ok(offset + 8)
}

fn skip_trailer_and_next_header<R: Read + Seek>(
    file: &mut R,
    after_deflate: u64,
) -> io::Result<Option<u64>> {
    let after_trailer = after_deflate + 8;
    match parse_gzip_header(file, after_trailer) {
        Ok(Some(h)) => Ok(Some(h)),
        Ok(None) => Ok(None),
        Err(e) => Err(io::Error::new(io::ErrorKind::InvalidData, e.to_string())),
    }
}

/// Convenience: open gzip as a seekable reader (builds index).
pub fn open_seekable_gzip(path: &Path, spacing: u64) -> Result<SeekableGzipReader> {
    open_seekable_gzip_with_threads(path, spacing, 1)
}

/// Open seekable gzip with a thread hint (Python `-P` / gzip backend).
///
/// See [`SeekableGzip::open_with_threads`].
pub fn open_seekable_gzip_with_threads(
    path: &Path,
    spacing: u64,
    threads: u32,
) -> Result<SeekableGzipReader> {
    let g = SeekableGzip::open_with_threads(path, spacing, threads)?;
    g.reader().map_err(CompressError::from)
}

/// Open seekable gzip using a Tier C seek-index blob.
///
/// See [`SeekableGzip::open_with_imported_index`].
pub fn open_seekable_gzip_with_imported_index(
    path: &Path,
    spacing: u64,
    threads: u32,
    index_blob: &[u8],
) -> Result<SeekableGzipReader> {
    let g = SeekableGzip::open_with_imported_index(path, spacing, threads, index_blob)?;
    g.reader().map_err(CompressError::from)
}

/// Open seekable gzip from a seekable compressed reader (builds index).
///
/// `archive_label` is used for logs / [`SeekableGzip::path`] (URL or virtual name).
pub fn open_seekable_gzip_from_reader<R>(
    reader: R,
    spacing: u64,
    archive_label: impl AsRef<Path>,
) -> Result<SeekableGzipReader>
where
    R: Read + Seek + Send + 'static,
{
    open_seekable_gzip_with_threads_from_reader(reader, spacing, 1, archive_label)
}

/// Open seekable gzip from a seekable compressed reader with a thread hint.
///
/// See [`SeekableGzip::open_with_threads_from_reader`].
pub fn open_seekable_gzip_with_threads_from_reader<R>(
    reader: R,
    spacing: u64,
    threads: u32,
    archive_label: impl AsRef<Path>,
) -> Result<SeekableGzipReader>
where
    R: Read + Seek + Send + 'static,
{
    let g = SeekableGzip::open_with_threads_from_reader(reader, spacing, threads, archive_label)?;
    g.reader().map_err(CompressError::from)
}

/// Open seekable gzip from a seekable reader using a Tier C seek-index blob.
///
/// See [`SeekableGzip::open_with_imported_index_from_reader`].
pub fn open_seekable_gzip_with_imported_index_from_reader<R>(
    reader: R,
    spacing: u64,
    threads: u32,
    archive_label: impl AsRef<Path>,
    index_blob: &[u8],
) -> Result<SeekableGzipReader>
where
    R: Read + Seek + Send + 'static,
{
    let g = SeekableGzip::open_with_imported_index_from_reader(
        reader,
        spacing,
        threads,
        archive_label,
        index_blob,
    )?;
    g.reader().map_err(CompressError::from)
}

/// Best-effort parallel decode of independent concatenated gzip members.
///
/// Returns concatenated uncompressed bytes when ≥2 members are found and each
/// segment decodes on its own. Single-member inputs return an error so callers
/// can fall back to sequential `MultiGzDecoder` / seek-index paths.
pub fn try_parallel_multi_member_decode(compressed: &[u8], threads: u32) -> Result<Vec<u8>> {
    let threads = ParallelizationSpec::resolve_zero(threads).max(1);
    let parts = split_gzip_member_slices(compressed)
        .ok_or_else(|| CompressError::Msg("single gzip member; sequential path".into()))?;
    if parts.len() < 2 {
        return Err(CompressError::Msg("single gzip member; sequential path".into()));
    }
    parallel_map_decode_gzip_members(&parts, threads)
}

fn is_gzip_magic(data: &[u8]) -> bool {
    data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b
}

/// Locate gzip member header offsets (`1f 8b`).
fn find_gzip_magic_offsets(data: &[u8]) -> Vec<usize> {
    let mut markers = Vec::new();
    let mut i = 0usize;
    while i + 2 <= data.len() {
        if data[i] == 0x1f && data[i + 1] == 0x8b {
            markers.push(i);
            i += 2;
        } else {
            i += 1;
        }
    }
    markers
}

/// Split multi-member gzip at header magics. Each slice is one member candidate
/// (through the next magic or EOF). Callers decode in parallel; false mid-stream
/// magics cause decode errors and should fall back to sequential.
fn split_gzip_member_slices(compressed: &[u8]) -> Option<Vec<&[u8]>> {
    if !is_gzip_magic(compressed) {
        return None;
    }
    let markers = find_gzip_magic_offsets(compressed);
    if markers.len() < 2 {
        return None;
    }
    let mut ends = markers;
    ends.push(compressed.len());
    let mut parts = Vec::with_capacity(ends.len() - 1);
    for w in ends.windows(2) {
        let start = w[0];
        let end = w[1];
        if end <= start + 10 {
            return None;
        }
        parts.push(&compressed[start..end]);
    }
    Some(parts)
}

fn decode_one_gzip_member(member: &[u8]) -> Result<Vec<u8>> {
    use flate2::read::GzDecoder;
    let mut dec = GzDecoder::new(member);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)
        .map_err(|e| CompressError::Msg(format!("gzip member decode: {e}")))?;
    Ok(out)
}

fn parallel_map_decode_gzip_members(parts: &[&[u8]], threads: u32) -> Result<Vec<u8>> {
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
                    outs.push(decode_one_gzip_member(p));
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
            r.ok_or_else(|| CompressError::Msg("gzip parallel worker missing".into()))??,
        );
    }
    Ok(out)
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
        Self::open_with_threads(path, spacing, 1)
    }

    /// Open with a thread hint (Python `-P` / gzip backend).
    pub fn open_with_threads(path: &Path, spacing: u64, threads: u32) -> Result<Arc<Self>> {
        let inner = SeekableGzip::open_with_threads(path, spacing, threads)?;
        Ok(Arc::new(Self {
            inner,
            _lock: Mutex::new(()),
        }))
    }

    /// Open with a Tier C seek-index blob (see [`SeekableGzip::open_with_imported_index`]).
    pub fn open_with_imported_index(
        path: &Path,
        spacing: u64,
        threads: u32,
        index_blob: &[u8],
    ) -> Result<Arc<Self>> {
        let inner = SeekableGzip::open_with_imported_index(path, spacing, threads, index_blob)?;
        Ok(Arc::new(Self {
            inner,
            _lock: Mutex::new(()),
        }))
    }

    /// Open from a seekable compressed reader (HTTP Range, memory, …).
    ///
    /// `archive_label` is stored for [`Self::path`] / logs.
    pub fn open_from_reader<R>(
        reader: R,
        spacing: u64,
        archive_label: impl AsRef<Path>,
    ) -> Result<Arc<Self>>
    where
        R: Read + Seek + Send + 'static,
    {
        Self::open_with_threads_from_reader(reader, spacing, 1, archive_label)
    }

    /// Like [`Self::open_from_reader`] with a thread hint.
    pub fn open_with_threads_from_reader<R>(
        reader: R,
        spacing: u64,
        threads: u32,
        archive_label: impl AsRef<Path>,
    ) -> Result<Arc<Self>>
    where
        R: Read + Seek + Send + 'static,
    {
        let inner =
            SeekableGzip::open_with_threads_from_reader(reader, spacing, threads, archive_label)?;
        Ok(Arc::new(Self {
            inner,
            _lock: Mutex::new(()),
        }))
    }

    /// Open from a seekable reader with a Tier C seek-index blob.
    pub fn open_with_imported_index_from_reader<R>(
        reader: R,
        spacing: u64,
        threads: u32,
        archive_label: impl AsRef<Path>,
        index_blob: &[u8],
    ) -> Result<Arc<Self>>
    where
        R: Read + Seek + Send + 'static,
    {
        let inner = SeekableGzip::open_with_imported_index_from_reader(
            reader,
            spacing,
            threads,
            archive_label,
            index_blob,
        )?;
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

    /// Export Tier C seek-index blob (see [`SeekableGzip::export_seek_index_blob`]).
    pub fn export_seek_index_blob(&self) -> Vec<u8> {
        self.inner.export_seek_index_blob()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read, Write};

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
        assert!(
            g.checkpoint_count() >= 2,
            "expected intermediate checkpoints"
        );
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

    fn encode_gz(data: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let mut enc = GzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn parallel_multi_member_equals_sequential() {
        let a = b"member-A-payload-aaaa";
        let b = b"member-B-payload-bbbb-EXTRA";
        let mut compressed = encode_gz(a);
        compressed.extend_from_slice(&encode_gz(b));

        let parts = split_gzip_member_slices(&compressed).expect("split members");
        assert!(parts.len() >= 2, "expected ≥2 members, got {}", parts.len());

        use flate2::read::MultiGzDecoder;
        let mut seq = Vec::new();
        MultiGzDecoder::new(&compressed[..])
            .read_to_end(&mut seq)
            .unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(a);
        expected.extend_from_slice(b);
        assert_eq!(seq, expected);

        let par = try_parallel_multi_member_decode(&compressed, 4).unwrap();
        assert_eq!(par, seq);
    }

    #[test]
    fn with_threads_equals_single_thread_gzip() {
        let dir = tempfile::tempdir().unwrap();
        let gz = dir.path().join("multi.gz");
        let a = b"alpha-gzip-member";
        let b = b"beta-gzip-member!!";
        let mut compressed = encode_gz(a);
        compressed.extend_from_slice(&encode_gz(b));
        std::fs::write(&gz, &compressed).unwrap();

        let mut one = Vec::new();
        open_seekable_gzip_with_threads(&gz, 1024, 1)
            .unwrap()
            .read_to_end(&mut one)
            .unwrap();
        let mut many = Vec::new();
        open_seekable_gzip_with_threads(&gz, 1024, 4)
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
    fn threads_zero_means_cpu_count_gzip() {
        let path = py_test("simple.gz");
        if !path.exists() {
            return;
        }
        let mut r = open_seekable_gzip_with_threads(&path, 1024, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "foo fighter\n");
    }

    #[test]
    fn from_reader_cursor_random_access_equals_path() {
        let dir = tempfile::tempdir().unwrap();
        let gz = dir.path().join("cursor.gz");
        let mut raw = Vec::new();
        for i in 0..1500 {
            writeln!(&mut raw, "line {i:05} {}", "y".repeat(64)).unwrap();
        }
        let compressed = encode_gz(&raw);
        std::fs::write(&gz, &compressed).unwrap();

        let path_g = SeekableGzip::open(&gz, 8 * 1024).unwrap();
        let reader_g = SeekableGzip::open_with_threads_from_reader(
            Cursor::new(compressed.clone()),
            8 * 1024,
            1,
            Path::new("memory://cursor.gz"),
        )
        .unwrap();

        assert_eq!(path_g.uncompressed_size(), reader_g.uncompressed_size());
        assert_eq!(path_g.checkpoint_count(), reader_g.checkpoint_count());
        assert_eq!(reader_g.path(), Path::new("memory://cursor.gz"));

        let mut path_r = path_g.reader().unwrap();
        let mut mem_r = reader_g.reader().unwrap();

        // Full sequential read
        let mut path_all = Vec::new();
        let mut mem_all = Vec::new();
        path_r.read_to_end(&mut path_all).unwrap();
        mem_r.read_to_end(&mut mem_all).unwrap();
        assert_eq!(path_all, raw);
        assert_eq!(mem_all, raw);

        // Random seeks across the payload
        let offsets = [
            0u64,
            17,
            raw.len() as u64 / 3,
            raw.len() as u64 / 2,
            raw.len() as u64 - 40,
        ];
        for &off in &offsets {
            path_r.seek(SeekFrom::Start(off)).unwrap();
            mem_r.seek(SeekFrom::Start(off)).unwrap();
            let mut pb = [0u8; 32];
            let mut mb = [0u8; 32];
            let pn = path_r.read(&mut pb).unwrap();
            let mn = mem_r.read(&mut mb).unwrap();
            assert_eq!(pn, mn, "offset {off}");
            assert_eq!(&pb[..pn], &mb[..mn], "offset {off}");
        }

        // Free-function + SharedSeekableGzip reader path
        let mut free_r = open_seekable_gzip_with_threads_from_reader(
            Cursor::new(compressed.clone()),
            8 * 1024,
            2,
            Path::new("label.gz"),
        )
        .unwrap();
        free_r.seek(SeekFrom::Start(100)).unwrap();
        let mut free_chunk = [0u8; 16];
        free_r.read_exact(&mut free_chunk).unwrap();
        assert_eq!(&free_chunk, &raw[100..116]);

        let shared = SharedSeekableGzip::open_with_threads_from_reader(
            Cursor::new(compressed),
            8 * 1024,
            1,
            Path::new("shared://cursor.gz"),
        )
        .unwrap();
        assert_eq!(shared.size(), raw.len() as u64);
        assert_eq!(shared.path(), Path::new("shared://cursor.gz"));
        let mut sr = shared.reader().unwrap();
        sr.seek(SeekFrom::End(-20)).unwrap();
        let mut tail = vec![0u8; 20];
        sr.read_exact(&mut tail).unwrap();
        assert_eq!(tail, raw[raw.len() - 20..]);
    }

    #[test]
    fn from_reader_open_without_threads_api() {
        let payload = b"hello from reader API\n";
        let compressed = encode_gz(payload);
        let g = SeekableGzip::open_from_reader(
            Cursor::new(compressed.clone()),
            1024,
            Path::new("virt.gz"),
        )
        .unwrap();
        let mut r = g.reader().unwrap();
        let mut out = Vec::new();
        r.read_to_end(&mut out).unwrap();
        assert_eq!(out, payload);

        let mut r2 = open_seekable_gzip_from_reader(Cursor::new(compressed), 1024, "virt.gz")
            .unwrap();
        let mut out2 = Vec::new();
        r2.read_to_end(&mut out2).unwrap();
        assert_eq!(out2, payload);

        let shared =
            SharedSeekableGzip::open_from_reader(Cursor::new(encode_gz(payload)), 1024, "s.gz")
                .unwrap();
        assert_eq!(shared.size(), payload.len() as u64);
    }

    #[test]
    fn seek_index_blob_roundtrip_parse() {
        let points = vec![(10, 0), (100, 16_384), (200, 32_768)];
        let blob = encode_gzip_seek_index_blob(16 * 1024, 40_000, &points);
        assert!(blob.starts_with(GZIP_SEEK_INDEX_MAGIC));
        let parsed = parse_gzip_seek_index_blob(&blob).unwrap();
        assert_eq!(parsed.version, GZIP_SEEK_INDEX_VERSION);
        assert_eq!(parsed.flags, 0);
        assert_eq!(parsed.spacing, 16 * 1024);
        assert_eq!(parsed.uncompressed_size, 40_000);
        assert_eq!(parsed.points, points);

        assert!(parse_gzip_seek_index_blob(b"nope").is_err());
        assert!(parse_gzip_seek_index_blob(&blob[..10]).is_err());
        let mut bad_ver = blob.clone();
        bad_ver[4..8].copy_from_slice(&99u32.to_le_bytes());
        assert!(parse_gzip_seek_index_blob(&bad_ver).is_err());
    }

    #[test]
    fn export_import_blob_random_access_equals_rebuild() {
        let dir = tempfile::tempdir().unwrap();
        let gz = dir.path().join("tierc.gz");
        let mut raw = Vec::new();
        for i in 0..2500 {
            writeln!(&mut raw, "line {i:05} {}", "z".repeat(72)).unwrap();
        }
        let compressed = encode_gz(&raw);
        std::fs::write(&gz, &compressed).unwrap();

        let spacing = 8 * 1024u64;
        let built = SeekableGzip::open(&gz, spacing).unwrap();
        assert!(built.checkpoint_count() >= 2);
        let blob = built.export_seek_index_blob();
        assert!(blob.len() >= GZIP_SEEK_INDEX_HEADER_LEN + 16);
        let parsed = parse_gzip_seek_index_blob(&blob).unwrap();
        assert_eq!(parsed.uncompressed_size, raw.len() as u64);
        assert_eq!(parsed.points.len(), built.checkpoint_count());

        // Path import
        let imported =
            SeekableGzip::open_with_imported_index(&gz, spacing, 1, &blob).unwrap();
        assert_eq!(imported.uncompressed_size(), built.uncompressed_size());
        assert_eq!(imported.checkpoint_count(), built.checkpoint_count());
        assert_eq!(imported.spacing(), built.spacing());

        let mut r_built = built.reader().unwrap();
        let mut r_imp = imported.reader().unwrap();

        // Full sequential
        let mut all_b = Vec::new();
        let mut all_i = Vec::new();
        r_built.read_to_end(&mut all_b).unwrap();
        r_imp.read_to_end(&mut all_i).unwrap();
        assert_eq!(all_b, raw);
        assert_eq!(all_i, raw);

        // Random access across the payload
        let offsets = [
            0u64,
            1,
            100,
            raw.len() as u64 / 4,
            raw.len() as u64 / 2,
            raw.len() as u64 * 3 / 4,
            raw.len() as u64 - 64,
        ];
        for &off in &offsets {
            r_built.seek(SeekFrom::Start(off)).unwrap();
            r_imp.seek(SeekFrom::Start(off)).unwrap();
            let mut bb = [0u8; 48];
            let mut ib = [0u8; 48];
            let bn = r_built.read(&mut bb).unwrap();
            let inn = r_imp.read(&mut ib).unwrap();
            assert_eq!(bn, inn, "offset {off}");
            assert_eq!(&bb[..bn], &ib[..inn], "offset {off}");
            assert_eq!(&bb[..bn], &raw[off as usize..off as usize + bn]);
        }

        // Free-function import path
        let mut free_r =
            open_seekable_gzip_with_imported_index(&gz, spacing, 2, &blob).unwrap();
        free_r.seek(SeekFrom::Start(200)).unwrap();
        let mut chunk = [0u8; 24];
        free_r.read_exact(&mut chunk).unwrap();
        assert_eq!(&chunk, &raw[200..224]);

        // SharedSeekableGzip import + export
        let shared = SharedSeekableGzip::open_with_imported_index(&gz, spacing, 1, &blob).unwrap();
        assert_eq!(shared.size(), raw.len() as u64);
        assert_eq!(shared.export_seek_index_blob(), blob);
        let mut sr = shared.reader().unwrap();
        sr.seek(SeekFrom::End(-30)).unwrap();
        let mut tail = vec![0u8; 30];
        sr.read_exact(&mut tail).unwrap();
        assert_eq!(tail, raw[raw.len() - 30..]);

        // Reader-backend import (Cursor)
        let imp_reader = SeekableGzip::open_with_imported_index_from_reader(
            Cursor::new(compressed.clone()),
            spacing,
            1,
            Path::new("mem://tierc.gz"),
            &blob,
        )
        .unwrap();
        assert_eq!(imp_reader.checkpoint_count(), built.checkpoint_count());
        let mut rr = imp_reader.reader().unwrap();
        rr.seek(SeekFrom::Start(raw.len() as u64 / 3)).unwrap();
        let mut mid = [0u8; 16];
        rr.read_exact(&mut mid).unwrap();
        let off = raw.len() / 3;
        assert_eq!(&mid, &raw[off..off + 16]);

        let mut free_mem = open_seekable_gzip_with_imported_index_from_reader(
            Cursor::new(compressed),
            spacing,
            1,
            "virt-tierc.gz",
            &blob,
        )
        .unwrap();
        let mut full = Vec::new();
        free_mem.read_to_end(&mut full).unwrap();
        assert_eq!(full, raw);

        let shared_mem = SharedSeekableGzip::open_with_imported_index_from_reader(
            Cursor::new(encode_gz(&raw)),
            spacing,
            1,
            "shared-tierc.gz",
            &blob,
        )
        .unwrap();
        assert_eq!(shared_mem.size(), raw.len() as u64);
    }

    #[test]
    fn import_seek_points_rejects_stale_offsets() {
        let dir = tempfile::tempdir().unwrap();
        let gz = dir.path().join("stale.gz");
        let raw = b"hello stale index payload that is long enough for a few points!!!!\n";
        std::fs::write(&gz, encode_gz(raw)).unwrap();
        let g = SeekableGzip::open(&gz, 1024).unwrap();
        let mut blob = g.export_seek_index_blob();
        // Corrupt first point's compressed offset.
        if blob.len() >= GZIP_SEEK_INDEX_HEADER_LEN + 8 {
            blob[GZIP_SEEK_INDEX_HEADER_LEN] ^= 0xff;
        }
        let err = match SeekableGzip::open_with_imported_index(&gz, 1024, 1, &blob) {
            Ok(_) => panic!("expected stale index to fail"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("mismatch") || msg.contains("seek-index"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn import_seek_points_direct_api() {
        let payload = b"direct import_seek_points API\n";
        let compressed = encode_gz(payload);
        let mut cur = Cursor::new(compressed.clone());
        let idx = build_index(&mut cur, 64 * 1024).unwrap();
        let points: Vec<(u64, u64)> = idx
            .checkpoints
            .iter()
            .map(|c| (c.compressed_offset, c.uncompressed_offset))
            .collect();
        let mut cur2 = Cursor::new(compressed);
        let hydrated =
            import_seek_points(&mut cur2, &points, 64 * 1024, payload.len() as u64).unwrap();
        assert_eq!(hydrated.uncompressed_size, payload.len() as u64);
        assert_eq!(hydrated.checkpoints.len(), points.len());
    }
}
