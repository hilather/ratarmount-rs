//! Path-backed gzip via `rapidgzip-core` (Tier D POC).
//!
//! Builds a random-access [`GzipIndex`] once (full verified decode to a sink with
//! `keep_index`), then serves concurrent FUSE opens with independent
//! [`IndexedReader`]s (in-process; no worker-thread IPC).
//!
//! **`IndexedReader` is not auto-`Send`** (zlib-rs inflate holds raw pointers).
//! [`RapidgzipReader`] asserts `Send` unsafely under the exclusive-ownership
//! contract used by FUSE file handles: each reader is never accessed from more
//! than one thread at a time (it may be moved between threads between requests).
//!
//! **Scope (POC):** local path only. Nested / `from_reader` / HTTP Range stay on
//! G3 (`gzip_seek`). Multi-thread index build uses parallel marker/window paths
//! when the file and thread budget allow.
//!
//! **Enable at open time** (feature `gzip-rapidgzip` must be compiled in):
//! * env `RATARMOUNT_GZIP_BACKEND=rapidgzip`
//! * or `--use-backend rapidgzip` / `rapidgzip-gzip` in `use_backends`

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use rapidgzip_core::{Decoder, Format, GzipIndex, IndexedReader};
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

/// Shared rapidgzip index + path for multi-open seekable gzip.
pub struct SharedRapidgzip {
    path: PathBuf,
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
        let threads = ParallelizationSpec::resolve_zero(threads).max(1) as usize;
        let spacing = if spacing == 0 {
            DEFAULT_GZIP_SEEK_SPACING as usize
        } else {
            spacing as usize
        };

        let decoder = Decoder::builder()
            .decoder_threads(threads)
            .keep_index(true)
            .checkpoint_spacing(spacing)
            .format(Format::Gzip)
            .seek_readahead(true)
            // Warm a couple of windows ahead for sequential FUSE cats.
            .seek_prefetch_windows(2)
            .build()
            .map_err(|e| CompressError::Msg(format!("rapidgzip decoder config: {e}")))?;

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

        // Drop the FD used for index build; each reader reopens.
        drop(file);

        Ok(Arc::new(Self {
            path,
            index,
            size,
            decoder,
        }))
    }

    /// Uncompressed payload size.
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Archive path (compressed file).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Number of random-access checkpoints.
    pub fn checkpoint_count(&self) -> usize {
        self.index.checkpoint_count()
    }

    /// Independent seekable reader (new FD + in-process inflate session).
    pub fn reader(&self) -> io::Result<RapidgzipReader> {
        let file = File::open(&self.path)?;
        let inner = self
            .decoder
            .reader_with_index(file, self.index.clone())
            .map_err(|e| io::Error::other(format!("rapidgzip reader_with_index: {e}")))?;
        Ok(RapidgzipReader { inner })
    }
}

/// [`Read`] + [`Seek`] + [`Send`] over uncompressed gzip output (path-backed).
///
/// Holds [`IndexedReader`] **in-process** (no worker-thread IPC). See module
/// docs for the `Send` safety contract.
pub struct RapidgzipReader {
    inner: IndexedReader<File>,
}

// SAFETY: `IndexedReader` is not auto-`Send` because zlib-rs inflate state
// contains raw pointers (`*mut c_void` in `z_stream`). Those pointers are
// exclusive to this reader — not shared across threads. FUSE may move a file
// handle between threads *between* requests, but never calls into the same
// handle concurrently from two threads. Exclusive ownership + no concurrent
// access makes moving this value across threads sound.
unsafe impl Send for RapidgzipReader {}

impl Read for RapidgzipReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Seek for RapidgzipReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
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
        let mut payload = Vec::new();
        for i in 0..40u32 {
            payload.extend(format!("block-{i:04}-").repeat(64).into_bytes());
            payload.push(b'\n');
        }
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
}
