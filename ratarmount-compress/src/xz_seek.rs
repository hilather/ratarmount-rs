//! Seekable xz: full decode into RAM/temp (Tier B lite).
//!
//! Multi-block xz streams embed an index for constant-time block seek; wiring
//! liblzma stream indexes is a follow-up. For now we match bzip2: one decode into
//! [`DecodedBody`] so mounts share the seekable trait and avoid permanent sidecars.
//!
//! When `threads > 1` and the file is a **concatenation of independent xz streams**
//! (multi-stream `.xz`), each stream is decoded in parallel (Python `-P` / xz backend).
//! Single-stream files stay single-threaded; the `threads` parameter is accepted for
//! future block-index parallel decode.

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::thread;

use ratarmount_core::ParallelizationSpec;
use xz2::read::XzDecoder;

use crate::seekable_body::{DecodedBody, SeekableBody, DEFAULT_MEMORY_CAP};
use crate::{CompressError, Result};

/// xz stream header magic (`FD 37 7A 58 5A 00`).
const XZ_MAGIC: [u8; 6] = [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];

/// Open xz as a seekable body (one-shot decode, memory or temp spill).
pub fn open_seekable_xz(path: impl AsRef<Path>) -> Result<Arc<dyn SeekableBody>> {
    open_seekable_xz_with_threads(path, 1)
}

/// Open xz using up to `threads` workers for multi-stream parallel decode.
///
/// `threads == 0` means “use CPU count” (Python `-P 0` semantics).
///
/// * **Multi-stream** (concatenated independent xz streams): streams are split and
///   decompressed in parallel when `threads > 1`.
/// * **Single-stream**: decoded sequentially; `threads` is accepted for API parity
///   and future multi-block index parallelization (liblzma block seek).
pub fn open_seekable_xz_with_threads(
    path: impl AsRef<Path>,
    threads: u32,
) -> Result<Arc<dyn SeekableBody>> {
    let path = path.as_ref();
    let threads = ParallelizationSpec::resolve_zero(threads).max(1);

    let mut file = File::open(path)?;
    let mut compressed = Vec::new();
    file.read_to_end(&mut compressed)?;
    if compressed.len() < 6 || compressed[..6] != XZ_MAGIC {
        return Err(CompressError::Msg("not an xz stream".into()));
    }

    let decoded = if threads > 1 {
        match try_parallel_multi_stream(&compressed, threads) {
            Ok(data) => data,
            Err(_) => decode_sequential(&compressed)?,
        }
    } else {
        decode_sequential(&compressed)?
    };

    if decoded.len() as u64 <= DEFAULT_MEMORY_CAP {
        Ok(DecodedBody::from_bytes(path, "xz", decoded))
    } else {
        let cursor = std::io::Cursor::new(decoded);
        let body = DecodedBody::from_decoder(path, "xz", cursor, DEFAULT_MEMORY_CAP)?;
        Ok(body)
    }
}

/// Multi-decoder handles concatenated xz streams (and optional zero padding).
fn decode_sequential(compressed: &[u8]) -> Result<Vec<u8>> {
    let mut dec = XzDecoder::new_multi_decoder(compressed);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)
        .map_err(|e| CompressError::Msg(format!("xz decode: {e}")))?;
    Ok(out)
}

fn decode_one_stream(compressed: &[u8]) -> Result<Vec<u8>> {
    let mut dec = XzDecoder::new(compressed);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)
        .map_err(|e| CompressError::Msg(format!("xz stream decode: {e}")))?;
    Ok(out)
}

fn is_xz_magic(data: &[u8]) -> bool {
    data.len() >= 6 && data[..6] == XZ_MAGIC
}

/// Locate stream-header magic offsets (including the start at 0).
fn find_xz_magic_offsets(data: &[u8]) -> Vec<usize> {
    let mut markers = Vec::new();
    let mut i = 0usize;
    while i + 6 <= data.len() {
        if is_xz_magic(&data[i..]) {
            markers.push(i);
            i += 6;
        } else {
            i += 1;
        }
    }
    markers
}

/// Try to split multi-stream xz at header magics into independent compressed slices.
///
/// Does **not** fully decode: only checks magic layout. Callers decode slices
/// (in parallel when desired). Mid-stream false magics are rejected when a slice
/// fails to decode as a complete single stream.
fn split_xz_stream_slices(compressed: &[u8]) -> Option<Vec<&[u8]>> {
    if !is_xz_magic(compressed) {
        return None;
    }
    let markers = find_xz_magic_offsets(compressed);
    if markers.len() < 2 {
        return None;
    }
    let mut ends = markers;
    ends.push(compressed.len());
    let mut parts = Vec::with_capacity(ends.len() - 1);
    for w in ends.windows(2) {
        let start = w[0];
        let end = w[1];
        if end <= start + 12 {
            return None;
        }
        // Include possible stream-padding NULs before the next magic; the single-stream
        // decoder stops at stream end and ignores trailing padding.
        parts.push(&compressed[start..end]);
    }
    Some(parts)
}

/// Parallel decode of independent multi-stream xz (one decode pass, N workers).
fn try_parallel_multi_stream(compressed: &[u8], threads: u32) -> Result<Vec<u8>> {
    let parts = split_xz_stream_slices(compressed)
        .ok_or_else(|| CompressError::Msg("single xz stream; sequential path".into()))?;
    if parts.len() < 2 {
        return Err(CompressError::Msg("single xz stream; sequential path".into()));
    }
    parallel_map_decode_slices(&parts, threads)
}

fn parallel_map_decode_slices(parts: &[&[u8]], threads: u32) -> Result<Vec<u8>> {
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
                    outs.push(decode_one_stream(p));
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
            r.ok_or_else(|| CompressError::Msg("xz parallel worker missing".into()))??,
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::path::PathBuf;

    use xz2::write::XzEncoder;

    fn py_test(name: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        PathBuf::from(root).join("tests").join(name)
    }

    fn encode_xz(data: &[u8]) -> Vec<u8> {
        let mut enc = XzEncoder::new(Vec::new(), 6);
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn simple_xz() {
        let path = py_test("simple.xz");
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

    #[test]
    fn parallel_concatenated_streams() {
        let a = b"stream-A-payload-aaaa";
        let b = b"stream-B-payload-bbbb-EXTRA";
        let mut compressed = encode_xz(a);
        compressed.extend_from_slice(&encode_xz(b));

        let streams = split_xz_stream_slices(&compressed).expect("split streams");
        assert!(
            streams.len() >= 2,
            "expected ≥2 streams, got {}",
            streams.len()
        );

        let seq = decode_sequential(&compressed).unwrap();
        let mut expected = Vec::new();
        expected.extend_from_slice(a);
        expected.extend_from_slice(b);
        assert_eq!(seq, expected);

        let par = try_parallel_multi_stream(&compressed, 4).unwrap();
        assert_eq!(par, seq);

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("multi-stream.xz");
        std::fs::write(&path, &compressed).unwrap();
        let body = open_seekable_xz_with_threads(&path, 4).unwrap();
        let mut r = body.open_reader().unwrap();
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn threads_zero_means_cpu_count() {
        let path = py_test("simple.xz");
        if !path.exists() {
            return;
        }
        let body = open_seekable_xz_with_threads(&path, 0).unwrap();
        assert_eq!(body.size(), 12);
    }

    #[test]
    fn sequential_still_works_with_threads() {
        let data = b"hello xz parallelization";
        let compressed = encode_xz(data);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("one.xz");
        std::fs::write(&path, &compressed).unwrap();
        let body = open_seekable_xz_with_threads(&path, 8).unwrap();
        let mut r = body.open_reader().unwrap();
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn with_threads_equals_single_thread() {
        let a = b"alpha-xz-member";
        let b = b"beta-xz-member!!";
        let mut compressed = encode_xz(a);
        compressed.extend_from_slice(&encode_xz(b));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("eq.xz");
        std::fs::write(&path, &compressed).unwrap();

        let mut one = Vec::new();
        open_seekable_xz_with_threads(&path, 1)
            .unwrap()
            .open_reader()
            .unwrap()
            .read_to_end(&mut one)
            .unwrap();
        let mut many = Vec::new();
        open_seekable_xz_with_threads(&path, 4)
            .unwrap()
            .open_reader()
            .unwrap()
            .read_to_end(&mut many)
            .unwrap();
        assert_eq!(one, many);
    }
}
