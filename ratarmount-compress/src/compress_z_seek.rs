//! Seekable Unix compress (`.Z`) via one-shot LZW decompress into [`DecodedBody`].

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use crate::seekable_body::{DecodedBody, SeekableBody, DEFAULT_MEMORY_CAP};
use crate::{CompressError, Result};

/// Open a Unix compress (`.Z`) file as a seekable body.
pub fn open_seekable_compress_z(path: impl AsRef<Path>) -> Result<Arc<dyn SeekableBody>> {
    let path = path.as_ref();
    let mut file = File::open(path)?;
    let mut raw = Vec::new();
    file.read_to_end(&mut raw)?;
    if raw.len() < 3 || !(raw[0] == 0x1f && (raw[1] == 0x9d || raw[1] == 0xa0)) {
        return Err(CompressError::Msg("not a Unix compress (.Z) file".into()));
    }
    let plain = lzw_z::decompress_slice(&raw).map_err(|e| CompressError::Msg(e.to_string()))?;
    if plain.len() as u64 <= DEFAULT_MEMORY_CAP {
        Ok(DecodedBody::from_bytes(path, "compress-z", plain) as Arc<dyn SeekableBody>)
    } else {
        // Spill large bodies via from_decoder path.
        let cursor = std::io::Cursor::new(plain);
        let body = DecodedBody::from_decoder(path, "compress-z", cursor, DEFAULT_MEMORY_CAP)?;
        Ok(body as Arc<dyn SeekableBody>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::path::PathBuf;

    #[test]
    fn simple_z() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let path = PathBuf::from(root).join("tests/simple.Z");
        if !path.exists() {
            return;
        }
        let body = open_seekable_compress_z(&path).unwrap();
        assert_eq!(body.size(), 12);
        let mut r = body.open_reader().unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "foo fighter\n");
    }
}
