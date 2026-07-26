//! Seekable xz: full decode into RAM/temp (Tier B lite).
//!
//! Multi-block xz streams embed an index for constant-time block seek; wiring
//! liblzma stream indexes is a follow-up. For now we match bzip2: one decode into
//! [`DecodedBody`] so mounts share the seekable trait and avoid permanent sidecars.

use std::fs::File;
use std::path::Path;
use std::sync::Arc;

use xz2::read::XzDecoder;

use crate::seekable_body::{DecodedBody, SeekableBody, DEFAULT_MEMORY_CAP};
use crate::Result;

/// Open xz as a seekable body (one-shot decode, memory or temp spill).
pub fn open_seekable_xz(path: impl AsRef<Path>) -> Result<Arc<dyn SeekableBody>> {
    let path = path.as_ref();
    let file = File::open(path)?;
    // Multi-decoder handles concatenated xz streams.
    let dec = XzDecoder::new_multi_decoder(file);
    let body = DecodedBody::from_decoder(path, "xz", dec, DEFAULT_MEMORY_CAP)?;
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::path::PathBuf;

    #[test]
    fn simple_xz() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let path = PathBuf::from(root).join("tests/simple.xz");
        if !path.exists() {
            return;
        }
        let body = open_seekable_xz(&path).unwrap();
        assert_eq!(body.size(), 12);
        let mut r = body.open_reader().unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "foo fighter\n");
    }
}
