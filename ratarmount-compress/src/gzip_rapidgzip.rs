//! Gzip via `rapidgzip-core` (Tier D).
//!
//! Builds a random-access [`GzipIndex`] once (full verified decode to a sink with
//! `keep_index`, or imported GZIDX / auto-detect via [`read_gzip_index`]), then
//! serves concurrent FUSE opens with independent [`IndexedReader`]s (in-process;
//! no worker-thread IPC).
//!
//! **`IndexedReader` is not auto-`Send`** (zlib-rs inflate holds raw pointers).
//! [`RapidgzipReader`] asserts `Send` unsafely under the exclusive-ownership
//! contract used by FUSE file handles: each reader is never accessed from more
//! than one thread at a time (it may be moved between threads between requests).
//!
//! **Backends**
//! * **Path** — local file; each reader opens its own FD (`File` implements
//!   [`ReadAt`] natively).
//! * **Shared reader** — nested / HTTP Range / in-memory `Cursor` wrapped as
//!   [`SeekReadAt`] (`Arc<Mutex<Box<dyn SeekRead>>>` + seek+read under lock).
//!   Parallel decode workers and concurrent readers **serialize on this mutex**
//!   (nested thruput residual).
//!
//! **GZIDX** — [`SharedRapidgzip::export_gzidx_blob`] writes Python
//! `indexed_gzip` format; import skips the full keep_index rebuild.
//!
//! **Enable at open time** (feature `gzip-rapidgzip` must be compiled in):
//! * env `RATARMOUNT_GZIP_BACKEND=rapidgzip`
//! * or `--use-backend rapidgzip` / `rapidgzip-gzip` in `use_backends`

use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rapidgzip_core::{
    read_gzip_index, write_indexed_gzip_index, Decoder, Format, GzipIndex, IndexedReader, ReadAt,
};
use ratarmount_core::ParallelizationSpec;

use crate::seekable_body::{SeekRead, SeekableBody};
use crate::{CompressError, Result, DEFAULT_GZIP_SEEK_SPACING};

/// Env var that selects the rapidgzip path backend when set to [`RAPIDGZIP_BACKEND_VALUE`].
pub const RAPIDGZIP_BACKEND_ENV: &str = "RATARMOUNT_GZIP_BACKEND";

/// Value for [`RAPIDGZIP_BACKEND_ENV`] / `--use-backend` that selects this POC.
pub const RAPIDGZIP_BACKEND_VALUE: &str = "rapidgzip";

/// Kind string reported by [`SeekableBody::kind`].
pub const RAPIDGZIP_BODY_KIND: &str = "gzip-rapidgzip";

/// Whether open paths should prefer the rapidgzip backend (feature compiled in).
///
/// True when `RATARMOUNT_GZIP_BACKEND=rapidgzip` (ASCII case-insensitive) or when
/// `use_backends` contains `rapidgzip` or `rapidgzip-gzip`.
pub fn prefer_rapidgzip_gzip_backend(use_backends: &[String]) -> bool {
    prefer_rapidgzip_gzip_backend_with_env(
        use_backends,
        std::env::var(RAPIDGZIP_BACKEND_ENV).ok().as_deref(),
    )
}

/// Same as [`prefer_rapidgzip_gzip_backend`] with an injectable env value (tests).
pub fn prefer_rapidgzip_gzip_backend_with_env(
    use_backends: &[String],
    env_value: Option<&str>,
) -> bool {
    if let Some(v) = env_value {
        if v.eq_ignore_ascii_case(RAPIDGZIP_BACKEND_VALUE)
            || v.eq_ignore_ascii_case("rapidgzip-gzip")
        {
            return true;
        }
    }
    use_backends.iter().any(|b| {
        let l = b.to_ascii_lowercase();
        l == RAPIDGZIP_BACKEND_VALUE || l == "rapidgzip-gzip"
    })
}

/// Positional [`ReadAt`] adapter over a shared seekable compressed stream.
///
/// Parallel rapidgzip decode/seek workers call [`ReadAt::read_at`] concurrently;
/// every access **serializes on the inner mutex** (nested / Range thruput residual).
/// Length is fixed at construction (seek End) and must remain stable.
struct SeekReadAt {
    inner: Arc<Mutex<Box<dyn SeekRead>>>,
    len: u64,
}

impl SeekReadAt {
    fn new(inner: Arc<Mutex<Box<dyn SeekRead>>>, len: u64) -> Self {
        Self { inner, len }
    }

    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, Box<dyn SeekRead>>> {
        self.inner
            .lock()
            .map_err(|_| io::Error::other("rapidgzip shared compressed reader mutex poisoned"))
    }
}

impl ReadAt for SeekReadAt {
    fn len(&self) -> io::Result<u64> {
        Ok(self.len)
    }

    fn read_at(&self, offset: u64, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if offset >= self.len {
            return Ok(0);
        }
        let mut guard = self.lock()?;
        guard.seek(SeekFrom::Start(offset))?;
        let max = buffer.len().min((self.len - offset) as usize);
        guard.read(&mut buffer[..max])
    }
}

/// Compressed-source backend for multi-open seekable gzip.
enum RapidgzipBackend {
    /// Local path: each reader opens its own `File`.
    Path(PathBuf),
    /// Shared seekable stream (nested Range, Cursor, …).
    Shared {
        reader: Arc<Mutex<Box<dyn SeekRead>>>,
        compressed_len: u64,
    },
}

/// Shared rapidgzip index + path/reader backend for multi-open seekable gzip.
pub struct SharedRapidgzip {
    /// Local path or virtual archive label for logs / [`SeekableBody::path`].
    path: PathBuf,
    backend: RapidgzipBackend,
    index: GzipIndex,
    size: u64,
    /// Decoder configuration (threads, cache, spacing) used for every reader.
    decoder: Decoder,
}

impl SharedRapidgzip {
    /// Build index from `path` and return a shared seekable body.
    ///
    /// `spacing` is the soft uncompressed checkpoint spacing (0 → default 16 MiB).
    /// `threads` is the decoder worker budget (`0` → CPU count), matching `-P`.
    pub fn open_with_threads(path: &Path, spacing: u64, threads: u32) -> Result<Arc<Self>> {
        let path = path.to_path_buf();
        let decoder = make_decoder(spacing, threads, /* keep_index */ true)?;

        let file = File::open(&path)?;
        // Full decode once to collect the index; payload discarded (same cost class
        // as G3 checkpoint scan, but can use parallel workers).
        let mut sink = io::sink();
        let report = decoder
            .decode(&file, &mut sink)
            .map_err(|e| CompressError::Msg(format!("rapidgzip index build: {e}")))?;
        let index = report
            .index
            .ok_or_else(|| CompressError::Msg("rapidgzip keep_index returned no index".into()))?;
        let size = validate_index(&index)?;
        drop(file);

        Ok(Arc::new(Self {
            path: path.clone(),
            backend: RapidgzipBackend::Path(path),
            index,
            size,
            decoder,
        }))
    }

    /// Build index from a seekable compressed reader (nested / Range / Cursor).
    ///
    /// The reader is held under a mutex and exposed to rapidgzip as [`SeekReadAt`].
    /// Parallel workers serialize on that mutex (nested thruput residual).
    ///
    /// `archive_label` is stored for logs / [`SeekableBody::path`].
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
        let compressed_len = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;

        let shared: Arc<Mutex<Box<dyn SeekRead>>> = Arc::new(Mutex::new(Box::new(reader)));
        let source = SeekReadAt::new(Arc::clone(&shared), compressed_len);
        let decoder = make_decoder(spacing, threads, /* keep_index */ true)?;

        let mut sink = io::sink();
        let report = decoder
            .decode(&source, &mut sink)
            .map_err(|e| CompressError::Msg(format!("rapidgzip index build: {e}")))?;
        let index = report
            .index
            .ok_or_else(|| CompressError::Msg("rapidgzip keep_index returned no index".into()))?;
        let size = validate_index(&index)?;

        Ok(Arc::new(Self {
            path,
            backend: RapidgzipBackend::Shared {
                reader: shared,
                compressed_len,
            },
            index,
            size,
            decoder,
        }))
    }

    /// Open a path using a prebuilt index blob (GZIDX / auto-detect).
    ///
    /// Skips the full keep_index rebuild. `spacing` still configures the reader
    /// decoder (import uses blob checkpoints as-is).
    pub fn open_with_imported_index(
        path: &Path,
        spacing: u64,
        threads: u32,
        index_blob: &[u8],
    ) -> Result<Arc<Self>> {
        let path = path.to_path_buf();
        let compressed_len = File::open(&path)?.metadata()?.len();
        let index = import_index_blob(index_blob, Some(compressed_len))?;
        let size = validate_index(&index)?;
        // No keep_index: index already provided.
        let decoder = make_decoder(spacing, threads, /* keep_index */ false)?;

        Ok(Arc::new(Self {
            path: path.clone(),
            backend: RapidgzipBackend::Path(path),
            index,
            size,
            decoder,
        }))
    }

    /// Open from a seekable reader using a prebuilt index blob (GZIDX / auto-detect).
    ///
    /// Skips the full keep_index rebuild.
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
        let compressed_len = reader.seek(SeekFrom::End(0))?;
        reader.seek(SeekFrom::Start(0))?;
        let index = import_index_blob(index_blob, Some(compressed_len))?;
        let size = validate_index(&index)?;
        let decoder = make_decoder(spacing, threads, /* keep_index */ false)?;
        let shared: Arc<Mutex<Box<dyn SeekRead>>> = Arc::new(Mutex::new(Box::new(reader)));

        Ok(Arc::new(Self {
            path,
            backend: RapidgzipBackend::Shared {
                reader: shared,
                compressed_len,
            },
            index,
            size,
            decoder,
        }))
    }

    /// Export this index as Python `indexed_gzip` (`GZIDX`) bytes.
    pub fn export_gzidx_blob(&self) -> Result<Vec<u8>> {
        let mut buf = Vec::new();
        write_indexed_gzip_index(&self.index, &mut buf)
            .map_err(|e| CompressError::Msg(format!("rapidgzip GZIDX export: {e}")))?;
        Ok(buf)
    }

    /// Uncompressed payload size.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Archive path or virtual label.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Number of random-access checkpoints.
    pub fn checkpoint_count(&self) -> usize {
        self.index.checkpoint_count()
    }

    /// Independent seekable reader (new FD or shared-stream handle + in-process inflate).
    pub fn reader(&self) -> io::Result<RapidgzipReader> {
        let inner = match &self.backend {
            RapidgzipBackend::Path(path) => {
                let file = File::open(path)?;
                let ir = self
                    .decoder
                    .reader_with_index(file, self.index.clone())
                    .map_err(|e| io::Error::other(format!("rapidgzip reader_with_index: {e}")))?;
                RapidgzipReaderInner::Path(ir)
            }
            RapidgzipBackend::Shared {
                reader,
                compressed_len,
            } => {
                let source = SeekReadAt::new(Arc::clone(reader), *compressed_len);
                let ir = self
                    .decoder
                    .reader_with_index(source, self.index.clone())
                    .map_err(|e| io::Error::other(format!("rapidgzip reader_with_index: {e}")))?;
                RapidgzipReaderInner::Shared(ir)
            }
        };
        Ok(RapidgzipReader { inner })
    }
}

/// Reader backend: path FD or shared mutex stream.
enum RapidgzipReaderInner {
    Path(IndexedReader<File>),
    Shared(IndexedReader<SeekReadAt>),
}

/// [`Read`] + [`Seek`] + [`Send`] over uncompressed gzip output.
///
/// Holds [`IndexedReader`] **in-process** (no worker-thread IPC). See module
/// docs for the `Send` safety contract.
pub struct RapidgzipReader {
    inner: RapidgzipReaderInner,
}

// SAFETY: `IndexedReader` is not auto-`Send` because zlib-rs inflate state
// contains raw pointers (`*mut c_void` in `z_stream`). Those pointers are
// exclusive to this reader — not shared across threads. FUSE may move a file
// handle between threads *between* requests, but never calls into the same
// handle concurrently from two threads. Exclusive ownership + no concurrent
// access makes moving this value across threads sound.
//
// Shared-backend variant: the compressed `SeekReadAt` is `Send + Sync`; the
// inflate session remains exclusive to this handle under the same contract.
unsafe impl Send for RapidgzipReader {}

impl Read for RapidgzipReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match &mut self.inner {
            RapidgzipReaderInner::Path(r) => r.read(buf),
            RapidgzipReaderInner::Shared(r) => r.read(buf),
        }
    }
}

impl Seek for RapidgzipReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        match &mut self.inner {
            RapidgzipReaderInner::Path(r) => r.seek(pos),
            RapidgzipReaderInner::Shared(r) => r.seek(pos),
        }
    }
}

impl SeekableBody for SharedRapidgzip {
    fn path(&self) -> &Path {
        &self.path
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn open_reader(&self) -> io::Result<Box<dyn SeekRead>> {
        Ok(Box::new(self.reader()?))
    }

    fn kind(&self) -> &'static str {
        RAPIDGZIP_BODY_KIND
    }

    fn checkpoint_count(&self) -> usize {
        self.index.checkpoint_count()
    }
}

/// Open path-backed rapidgzip seekable body (thread-aware).
pub fn open_seekable_gzip_rapidgzip(
    path: &Path,
    spacing: u64,
    threads: u32,
) -> Result<Arc<dyn SeekableBody>> {
    let body = SharedRapidgzip::open_with_threads(path, spacing, threads)?;
    Ok(body as Arc<dyn SeekableBody>)
}

/// Open rapidgzip seekable body from a seekable compressed reader.
///
/// See [`SharedRapidgzip::open_with_threads_from_reader`].
pub fn open_seekable_gzip_rapidgzip_from_reader<R>(
    reader: R,
    spacing: u64,
    threads: u32,
    archive_label: impl AsRef<Path>,
) -> Result<Arc<dyn SeekableBody>>
where
    R: Read + Seek + Send + 'static,
{
    let body =
        SharedRapidgzip::open_with_threads_from_reader(reader, spacing, threads, archive_label)?;
    Ok(body as Arc<dyn SeekableBody>)
}

/// Open path-backed rapidgzip using an imported index blob (skips keep_index rebuild).
///
/// See [`SharedRapidgzip::open_with_imported_index`].
pub fn open_seekable_gzip_rapidgzip_with_imported_index(
    path: &Path,
    spacing: u64,
    threads: u32,
    index_blob: &[u8],
) -> Result<Arc<dyn SeekableBody>> {
    let body = SharedRapidgzip::open_with_imported_index(path, spacing, threads, index_blob)?;
    Ok(body as Arc<dyn SeekableBody>)
}

/// Open rapidgzip from a reader using an imported index blob (skips keep_index rebuild).
///
/// See [`SharedRapidgzip::open_with_imported_index_from_reader`].
pub fn open_seekable_gzip_rapidgzip_with_imported_index_from_reader<R>(
    reader: R,
    spacing: u64,
    threads: u32,
    archive_label: impl AsRef<Path>,
    index_blob: &[u8],
) -> Result<Arc<dyn SeekableBody>>
where
    R: Read + Seek + Send + 'static,
{
    let body = SharedRapidgzip::open_with_imported_index_from_reader(
        reader,
        spacing,
        threads,
        archive_label,
        index_blob,
    )?;
    Ok(body as Arc<dyn SeekableBody>)
}

fn make_decoder(spacing: u64, threads: u32, keep_index: bool) -> Result<Decoder> {
    let threads = ParallelizationSpec::resolve_zero(threads).max(1) as usize;
    let spacing = if spacing == 0 {
        DEFAULT_GZIP_SEEK_SPACING as usize
    } else {
        spacing as usize
    };

    Decoder::builder()
        .decoder_threads(threads)
        .keep_index(keep_index)
        .checkpoint_spacing(spacing)
        .format(Format::Gzip)
        .seek_readahead(true)
        // Warm a couple of windows ahead for sequential FUSE cats.
        .seek_prefetch_windows(2)
        .build()
        .map_err(|e| CompressError::Msg(format!("rapidgzip decoder config: {e}")))
}

fn validate_index(index: &GzipIndex) -> Result<u64> {
    let size = index.uncompressed_size_in_bytes;
    if size == u64::MAX {
        return Err(CompressError::Msg(
            "rapidgzip index has unknown uncompressed size".into(),
        ));
    }
    if index.checkpoints.is_empty() {
        return Err(CompressError::Msg(
            "rapidgzip index has no checkpoints".into(),
        ));
    }
    Ok(size)
}

/// Import GZIDX (or auto-detected gztool / BGZI) via `read_gzip_index`.
fn import_index_blob(blob: &[u8], archive_size: Option<u64>) -> Result<GzipIndex> {
    read_gzip_index(&mut Cursor::new(blob), archive_size)
        .map_err(|e| CompressError::Msg(format!("rapidgzip index import: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::GzEncoder;
    use flate2::Compression;
    use std::io::Write;

    fn encode_gz(payload: &[u8]) -> Vec<u8> {
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(payload).unwrap();
        e.finish().unwrap()
    }

    fn write_temp_gz(payload: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("poc.gz");
        std::fs::write(&path, encode_gz(payload)).unwrap();
        (dir, path)
    }

    fn sample_payload() -> Vec<u8> {
        let mut payload = Vec::new();
        for i in 0..40u32 {
            payload.extend(format!("block-{i:04}-").repeat(64).into_bytes());
            payload.push(b'\n');
        }
        payload
    }

    #[test]
    fn prefer_backend_env_and_use_backends_list() {
        assert!(!prefer_rapidgzip_gzip_backend_with_env(&[], None));
        assert!(!prefer_rapidgzip_gzip_backend_with_env(&[], Some("g3")));
        assert!(prefer_rapidgzip_gzip_backend_with_env(
            &[],
            Some("rapidgzip")
        ));
        assert!(prefer_rapidgzip_gzip_backend_with_env(
            &[],
            Some("RapidGzip-Gzip")
        ));
        assert!(prefer_rapidgzip_gzip_backend_with_env(
            &["rapidgzip".into()],
            None
        ));
        assert!(prefer_rapidgzip_gzip_backend_with_env(
            &["RapidGzip-Gzip".into()],
            None
        ));
        assert!(!prefer_rapidgzip_gzip_backend_with_env(
            &["indexed_gzip".into()],
            None
        ));
        assert!(prefer_rapidgzip_gzip_backend_with_env(
            &["rapidgzip".into()],
            Some("g3")
        ));
    }

    #[test]
    fn open_random_seek_and_full_read() {
        let payload = sample_payload();
        let (_dir, path) = write_temp_gz(&payload);
        let body = SharedRapidgzip::open_with_threads(&path, 1024, 2).expect("open rapidgzip");
        assert_eq!(body.size(), payload.len() as u64);
        assert!(
            body.checkpoint_count() >= 2,
            "expected multiple checkpoints, got {}",
            body.checkpoint_count()
        );
        assert_eq!(body.kind(), RAPIDGZIP_BODY_KIND);

        let mut r = body.reader().unwrap();
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, payload);

        let mid = payload.len() / 2;
        let mut a = body.reader().unwrap();
        let mut b = body.reader().unwrap();
        a.seek(SeekFrom::Start(mid as u64)).unwrap();
        b.seek(SeekFrom::Start((mid / 2) as u64)).unwrap();
        let mut ta = [0u8; 32];
        let mut tb = [0u8; 32];
        a.read_exact(&mut ta).unwrap();
        b.read_exact(&mut tb).unwrap();
        assert_eq!(&ta, &payload[mid..mid + 32]);
        assert_eq!(&tb, &payload[mid / 2..mid / 2 + 32]);
    }

    #[test]
    fn seekable_body_open_reader_trait() {
        let payload = b"hello rapidgzip poc\n".repeat(100);
        let (_dir, path) = write_temp_gz(&payload);
        let body: Arc<dyn SeekableBody> =
            open_seekable_gzip_rapidgzip(&path, 4096, 1).expect("open");
        let mut r = body.open_reader().unwrap();
        r.seek(SeekFrom::End(-5)).unwrap();
        let mut tail = [0u8; 5];
        r.read_exact(&mut tail).unwrap();
        assert_eq!(&tail, &payload[payload.len() - 5..]);
    }

    /// Regression: multi-open (FUSE-style) must not interleave after in-process Send.
    #[test]
    fn concurrent_readers_full_payload() {
        let payload: Vec<u8> = (0..50_000u32).flat_map(|i| i.to_le_bytes()).collect();
        let (_dir, path) = write_temp_gz(&payload);
        let body = SharedRapidgzip::open_with_threads(&path, 8192, 4).unwrap();

        let body_a = Arc::clone(&body);
        let body_b = Arc::clone(&body);
        let expected = payload.clone();
        let h1 = std::thread::spawn(move || {
            // Move Send reader across threads (FUSE-style).
            let mut r = body_a.reader().unwrap();
            let mut out = Vec::new();
            r.read_to_end(&mut out).unwrap();
            out
        });
        let h2 = std::thread::spawn(move || {
            let mut r = body_b.reader().unwrap();
            let mut out = Vec::new();
            r.read_to_end(&mut out).unwrap();
            out
        });
        assert_eq!(h1.join().unwrap(), expected);
        assert_eq!(h2.join().unwrap(), expected);
    }

    /// Regression: reader remains usable after move across threads (Send contract).
    #[test]
    fn reader_send_across_threads_then_seek() {
        let payload = b"send-me-across\n".repeat(2000);
        let (_dir, path) = write_temp_gz(&payload);
        let body = SharedRapidgzip::open_with_threads(&path, 2048, 2).unwrap();
        let mut r = body.reader().unwrap();
        r.seek(SeekFrom::Start(10)).unwrap();
        let r = std::thread::spawn(move || {
            let mut r = r;
            let mut buf = [0u8; 8];
            r.read_exact(&mut buf).unwrap();
            buf
        })
        .join()
        .unwrap();
        assert_eq!(&r, &payload[10..18]);
    }

    /// Regression: from_reader Cursor random seek equals path open payload.
    #[test]
    fn from_reader_cursor_random_seek_equals_path() {
        let payload = sample_payload();
        let compressed = encode_gz(&payload);
        let (_dir, path) = write_temp_gz(&payload);

        let path_body = SharedRapidgzip::open_with_threads(&path, 1024, 2).unwrap();
        let reader_body = SharedRapidgzip::open_with_threads_from_reader(
            Cursor::new(compressed.clone()),
            1024,
            2,
            "virt.gz",
        )
        .expect("from_reader open");

        assert_eq!(reader_body.size(), path_body.size());
        assert_eq!(reader_body.size(), payload.len() as u64);
        assert_eq!(reader_body.kind(), RAPIDGZIP_BODY_KIND);
        assert!(reader_body.checkpoint_count() >= 1);

        let mid = payload.len() / 2;
        let mut rp = path_body.reader().unwrap();
        let mut rr = reader_body.reader().unwrap();
        rp.seek(SeekFrom::Start(mid as u64)).unwrap();
        rr.seek(SeekFrom::Start(mid as u64)).unwrap();
        let mut tp = [0u8; 48];
        let mut tr = [0u8; 48];
        rp.read_exact(&mut tp).unwrap();
        rr.read_exact(&mut tr).unwrap();
        assert_eq!(tp, tr);
        assert_eq!(&tr, &payload[mid..mid + 48]);

        // Free-function wrapper.
        let free: Arc<dyn SeekableBody> = open_seekable_gzip_rapidgzip_from_reader(
            Cursor::new(compressed),
            1024,
            1,
            Path::new("free.gz"),
        )
        .unwrap();
        let mut fr = free.open_reader().unwrap();
        let mut full = Vec::new();
        fr.read_to_end(&mut full).unwrap();
        assert_eq!(full, payload);
    }

    /// Regression: concurrent from_reader handles do not interleave on shared mutex.
    #[test]
    fn concurrent_readers_from_reader() {
        let payload: Vec<u8> = (0..40_000u32).flat_map(|i| i.to_le_bytes()).collect();
        let compressed = encode_gz(&payload);
        let body = SharedRapidgzip::open_with_threads_from_reader(
            Cursor::new(compressed),
            4096,
            2,
            "concurrent.gz",
        )
        .unwrap();

        let body_a = Arc::clone(&body);
        let body_b = Arc::clone(&body);
        let expected = payload.clone();
        let h1 = std::thread::spawn(move || {
            let mut r = body_a.reader().unwrap();
            let mut out = Vec::new();
            r.read_to_end(&mut out).unwrap();
            out
        });
        let h2 = std::thread::spawn(move || {
            let mut r = body_b.reader().unwrap();
            r.seek(SeekFrom::Start(100)).unwrap();
            let mut buf = [0u8; 64];
            r.read_exact(&mut buf).unwrap();
            buf
        });
        assert_eq!(h1.join().unwrap(), expected);
        assert_eq!(&h2.join().unwrap(), &expected[100..164]);
    }

    /// Regression: GZIDX export → re-import → seek matches (path + from_reader).
    #[test]
    fn gzidx_export_reimport_seek_roundtrip() {
        let payload = sample_payload();
        let compressed = encode_gz(&payload);
        let (_dir, path) = write_temp_gz(&payload);

        let built = SharedRapidgzip::open_with_threads(&path, 1024, 2).unwrap();
        let blob = built.export_gzidx_blob().expect("export GZIDX");
        assert!(
            blob.starts_with(b"GZIDX"),
            "expected GZIDX magic, got {:?}",
            &blob[..blob.len().min(8)]
        );

        let imported =
            SharedRapidgzip::open_with_imported_index(&path, 1024, 2, &blob).expect("import path");
        assert_eq!(imported.size(), built.size());
        assert!(imported.checkpoint_count() >= 1);

        let mid = payload.len() / 2;
        let mut a = built.reader().unwrap();
        let mut b = imported.reader().unwrap();
        a.seek(SeekFrom::Start(mid as u64)).unwrap();
        b.seek(SeekFrom::Start(mid as u64)).unwrap();
        let mut ta = [0u8; 40];
        let mut tb = [0u8; 40];
        a.read_exact(&mut ta).unwrap();
        b.read_exact(&mut tb).unwrap();
        assert_eq!(ta, tb);
        assert_eq!(&tb, &payload[mid..mid + 40]);

        // from_reader import + free wrappers.
        let mem = SharedRapidgzip::open_with_imported_index_from_reader(
            Cursor::new(compressed.clone()),
            1024,
            1,
            "import-mem.gz",
            &blob,
        )
        .expect("import from_reader");
        let mut mr = mem.reader().unwrap();
        mr.seek(SeekFrom::Start(0)).unwrap();
        let mut head = [0u8; 16];
        mr.read_exact(&mut head).unwrap();
        assert_eq!(&head, &payload[..16]);

        let free_path: Arc<dyn SeekableBody> =
            open_seekable_gzip_rapidgzip_with_imported_index(&path, 1024, 1, &blob).unwrap();
        assert_eq!(free_path.size(), payload.len() as u64);

        let free_mem: Arc<dyn SeekableBody> =
            open_seekable_gzip_rapidgzip_with_imported_index_from_reader(
                Cursor::new(compressed),
                1024,
                1,
                "free-import.gz",
                &blob,
            )
            .unwrap();
        let mut fr = free_mem.open_reader().unwrap();
        let mut full = Vec::new();
        fr.read_to_end(&mut full).unwrap();
        assert_eq!(full, payload);

        // Re-export from imported body should remain GZIDX.
        let re = imported.export_gzidx_blob().unwrap();
        assert!(re.starts_with(b"GZIDX"));
    }

    /// Regression: invalid index blob errors cleanly (no panic).
    #[test]
    fn imported_invalid_blob_errors_cleanly() {
        let payload = b"tiny\n".repeat(50);
        let compressed = encode_gz(&payload);
        let (_dir, path) = write_temp_gz(&payload);

        let bad = b"not-a-valid-index-blob!!!!";
        let err = match SharedRapidgzip::open_with_imported_index(&path, 1024, 1, bad) {
            Ok(_) => panic!("expected import error for garbage blob"),
            Err(e) => e,
        };
        let msg = err.to_string();
        assert!(
            msg.contains("rapidgzip index import") || msg.contains("index"),
            "unexpected error: {msg}"
        );

        let err2 = match SharedRapidgzip::open_with_imported_index_from_reader(
            Cursor::new(compressed),
            1024,
            1,
            "bad.gz",
            b"",
        ) {
            Ok(_) => panic!("expected import error for empty blob"),
            Err(e) => e,
        };
        assert!(!err2.to_string().is_empty());

        // Truncated GZIDX magic prefix.
        let err3 = match SharedRapidgzip::open_with_imported_index(&path, 1024, 1, b"GZID") {
            Ok(_) => panic!("expected import error for truncated GZIDX"),
            Err(e) => e,
        };
        assert!(err3.to_string().contains("import") || err3.to_string().contains("index"));
    }
}
