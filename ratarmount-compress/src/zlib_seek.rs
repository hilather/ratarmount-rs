//! Seekable zlib (RFC 1950) via one-shot inflate into [`DecodedBody`].
//!
//! Thread hint ([`open_seekable_zlib_with_threads`] / Python `-P` zlib backend):
//! zlib is a single deflate stream (sequential dictionary), so decode is always
//! one-shot sequential. The `threads` parameter is clamped (`0` → CPU count) for
//! API parity with other codecs; extra workers are unused for now.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use flate2::read::ZlibDecoder;
use ratarmount_core::ParallelizationSpec;

use crate::seekable_body::{DecodedBody, SeekableBody, DEFAULT_MEMORY_CAP};
use crate::{CompressError, Result};

/// True if the first two bytes form a valid zlib header without a preset dictionary.
pub fn looks_like_zlib_header(header: &[u8]) -> bool {
    if header.len() < 2 {
        return false;
    }
    let cmf = header[0];
    let flags = header[1];
    // CM must be 8 (deflate); CINFO (window) max 7.
    if cmf & 0x0f != 8 {
        return false;
    }
    if cmf >> 4 > 7 {
        return false;
    }
    if ((u16::from(cmf) << 8) + u16::from(flags)) % 31 != 0 {
        return false;
    }
    // FDICT bit must be clear (Python `_check_zlib_header`).
    if (flags >> 5) & 1 != 0 {
        return false;
    }
    true
}

/// Open a zlib-wrapped deflate stream as a seekable body (single-thread open).
pub fn open_seekable_zlib(path: impl AsRef<Path>) -> Result<Arc<dyn SeekableBody>> {
    open_seekable_zlib_with_threads(path, 1)
}

/// Open zlib with a thread hint (Python `-P` / zlib backend).
///
/// `threads == 0` means “use CPU count”. Decode is always sequential (single
/// deflate stream); `threads` is accepted so factory code can pass
/// `options.threads_for("zlib")` without API churn.
pub fn open_seekable_zlib_with_threads(
    path: impl AsRef<Path>,
    threads: u32,
) -> Result<Arc<dyn SeekableBody>> {
    let path = path.as_ref();
    let _threads = ParallelizationSpec::resolve_zero(threads).max(1);

    let mut file = File::open(path)?;
    let mut raw = Vec::new();
    file.read_to_end(&mut raw)?;
    if !looks_like_zlib_header(&raw) {
        return Err(CompressError::Msg("not a zlib stream".into()));
    }
    let mut decoder = ZlibDecoder::new(&raw[..]);
    let mut plain = Vec::new();
    decoder
        .read_to_end(&mut plain)
        .map_err(|e| CompressError::Msg(format!("zlib inflate failed: {e}")))?;
    if plain.len() as u64 <= DEFAULT_MEMORY_CAP {
        Ok(DecodedBody::from_bytes(path, "zlib", plain) as Arc<dyn SeekableBody>)
    } else {
        let cursor = std::io::Cursor::new(plain);
        let body = DecodedBody::from_decoder(path, "zlib", cursor, DEFAULT_MEMORY_CAP)?;
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
    fn simple_zlib() {
        let path = py_test("simple.zlib");
        if !path.exists() {
            return;
        }
        assert!(looks_like_zlib_header(&std::fs::read(&path).unwrap()[..2]));
        let body = open_seekable_zlib(&path).unwrap();
        assert_eq!(body.size(), 12);
        let mut r = body.open_reader().unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "foo fighter\n");
    }

    #[test]
    fn open_seekable_zlib_with_threads_equals_single() {
        let path = py_test("simple.zlib");
        if !path.exists() {
            return;
        }
        let body1 = open_seekable_zlib_with_threads(&path, 1).unwrap();
        let body4 = open_seekable_zlib_with_threads(&path, 4).unwrap();
        assert_eq!(body1.size(), body4.size());
        let mut a = Vec::new();
        body1.open_reader().unwrap().read_to_end(&mut a).unwrap();
        let mut b = Vec::new();
        body4.open_reader().unwrap().read_to_end(&mut b).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, b"foo fighter\n");
    }

    #[test]
    fn threads_zero_means_cpu_count_zlib() {
        let path = py_test("simple.zlib");
        if !path.exists() {
            return;
        }
        let body = open_seekable_zlib_with_threads(&path, 0).unwrap();
        assert_eq!(body.size(), 12);
    }
}
