//! Seekable LZMA Alone (`.lzma`) — one-shot decompress into [`DecodedBody`].
//!
//! Thread hint ([`open_seekable_lzma_with_threads`] / Python `-P` lzma backend):
//! LZMA Alone is a single sequential stream, so decode is always one-shot
//! sequential. The `threads` parameter is clamped (`0` → CPU count) for API
//! parity with other codecs; extra workers are unused for now.

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use ratarmount_core::ParallelizationSpec;

use crate::seekable_body::{DecodedBody, SeekableBody, DEFAULT_MEMORY_CAP};
use crate::{CompressError, Result};

/// Open an LZMA Alone (`.lzma`) file as a seekable body (single-thread open).
pub fn open_seekable_lzma(path: impl AsRef<Path>) -> Result<Arc<dyn SeekableBody>> {
    open_seekable_lzma_with_threads(path, 1)
}

/// Open LZMA Alone with a thread hint (Python `-P` / lzma backend).
///
/// `threads == 0` means “use CPU count”. Decode is always sequential (single
/// LZMA stream); `threads` is accepted so factory code can pass
/// `options.threads_for("lzma")` without API churn.
pub fn open_seekable_lzma_with_threads(
    path: impl AsRef<Path>,
    threads: u32,
) -> Result<Arc<dyn SeekableBody>> {
    let path = path.as_ref();
    let _threads = ParallelizationSpec::resolve_zero(threads).max(1);

    let file = File::open(path)?;
    let mut input = BufReader::new(file);
    let mut output = Vec::new();
    lzma_rs::lzma_decompress(&mut input, &mut output)
        .map_err(|e| CompressError::Msg(format!("failed to decompress .lzma: {e}")))?;
    if output.len() as u64 <= DEFAULT_MEMORY_CAP {
        Ok(DecodedBody::from_bytes(path, "lzma", output) as Arc<dyn SeekableBody>)
    } else {
        let body = DecodedBody::from_decoder(
            path,
            "lzma",
            std::io::Cursor::new(output),
            DEFAULT_MEMORY_CAP,
        )?;
        Ok(body as Arc<dyn SeekableBody>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::path::PathBuf;

    fn py_test(name: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        PathBuf::from(root).join("tests").join(name)
    }

    #[test]
    fn simple_lzma() {
        let path = py_test("simple.lzma");
        if !path.exists() {
            return;
        }
        let body = open_seekable_lzma(&path).unwrap();
        assert_eq!(body.size(), 12);
        let mut r = body.open_reader().unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "foo fighter\n");
    }

    #[test]
    fn open_seekable_lzma_with_threads_equals_single() {
        let path = py_test("simple.lzma");
        if !path.exists() {
            return;
        }
        let body1 = open_seekable_lzma_with_threads(&path, 1).unwrap();
        let body4 = open_seekable_lzma_with_threads(&path, 4).unwrap();
        assert_eq!(body1.size(), body4.size());
        let mut a = Vec::new();
        body1.open_reader().unwrap().read_to_end(&mut a).unwrap();
        let mut b = Vec::new();
        body4.open_reader().unwrap().read_to_end(&mut b).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, b"foo fighter\n");
    }

    #[test]
    fn threads_zero_means_cpu_count_lzma() {
        let path = py_test("simple.lzma");
        if !path.exists() {
            return;
        }
        let body = open_seekable_lzma_with_threads(&path, 0).unwrap();
        assert_eq!(body.size(), 12);
    }
}
