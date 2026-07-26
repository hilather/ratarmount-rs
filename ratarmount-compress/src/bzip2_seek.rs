//! Seekable bzip2: full decode into RAM/temp (Tier B lite).
//!
//! True mid-stream block restart needs bit-aligned block decoding (indexed_bzip2 class).
//! Until that lands, we decode once into a [`DecodedBody`] so TAR mounts avoid a
//! long-lived materialised path and share the same seekable backend trait.

use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use bzip2::read::BzDecoder;

use crate::seekable_body::{DecodedBody, SeekableBody, DEFAULT_MEMORY_CAP};
use crate::Result;

/// Open bzip2 as a seekable body (one-shot decode, memory or temp spill).
pub fn open_seekable_bzip2(path: impl AsRef<Path>) -> Result<Arc<dyn SeekableBody>> {
    let path = path.as_ref();
    let file = File::open(path)?;
    let dec = BzDecoder::new(file);
    let body = DecodedBody::from_decoder(path, "bzip2", dec, DEFAULT_MEMORY_CAP)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::path::PathBuf;

    #[test]
    fn simple_bz2() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let path = PathBuf::from(root).join("tests/simple.bz2");
        if !path.exists() {
            return;
        }
        let body = open_seekable_bzip2(&path).unwrap();
        assert_eq!(body.size(), 12);
        let mut r = body.open_reader().unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "foo fighter\n");
    }
}
