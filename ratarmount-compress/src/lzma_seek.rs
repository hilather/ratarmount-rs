//! Seekable LZMA Alone (`.lzma`) — one-shot decompress into [`DecodedBody`].

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use std::sync::Arc;

use crate::seekable_body::{DecodedBody, SeekableBody, DEFAULT_MEMORY_CAP};
use crate::{CompressError, Result};

/// Open an LZMA Alone (`.lzma`) file as a seekable body.
pub fn open_seekable_lzma(path: impl AsRef<Path>) -> Result<Arc<dyn SeekableBody>> {
    let path = path.as_ref();
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

    #[test]
    fn simple_lzma() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let path = PathBuf::from(root).join("tests/simple.lzma");
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
}
