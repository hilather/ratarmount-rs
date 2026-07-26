//! Seekable zlib (RFC 1950) via one-shot inflate into [`DecodedBody`].

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use flate2::read::ZlibDecoder;

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

/// Open a zlib-wrapped deflate stream as a seekable body.
pub fn open_seekable_zlib(path: impl AsRef<Path>) -> Result<Arc<dyn SeekableBody>> {
    let path = path.as_ref();
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

    #[test]
    fn simple_zlib() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let path = PathBuf::from(root).join("tests/simple.zlib");
        if !path.exists() {
            return;
        }
        assert!(looks_like_zlib_header(
            &std::fs::read(&path).unwrap()[..2]
        ));
        let body = open_seekable_zlib(&path).unwrap();
        assert_eq!(body.size(), 12);
        let mut r = body.open_reader().unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "foo fighter\n");
    }
}
