//! Content hashing for index xattrs (`user.hash.<algo>`), Python `hashing.py` subset.
//!
//! Supported algorithms: `crc32`, `md5`, `sha1`, `sha256`.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use crc32fast::Hasher as Crc32Hasher;
use log::warn;
use md5::Md5;
use sha1::{Digest, Sha1};
use sha2::Sha256;

use crate::{IndexError, Result, SqliteIndex};

/// Algorithms implemented by this crate (Python CLI names).
pub const SUPPORTED_HASH_ALGORITHMS: &[&str] = &["crc32", "md5", "sha1", "sha256"];

/// Scratch size for streaming SHA-256 / content-hash fill (64 KiB).
pub const HASH_STREAM_CHUNK: usize = 64 * 1024;

/// Lowercase hex SHA-256 of `data` (same as [`hash_hex`] `"sha256"`).
pub fn sha256_hex(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

/// Stream `reader` until EOF (`n == 0`), hashing whatever was read (no `max_bytes`).
///
/// Short reads are not an error: the digest covers bytes received, matching
/// today's `read_to_end` then `Sha256::digest`. Never materializes a body `Vec`.
pub fn sha256_hex_stream<R: Read>(reader: &mut R) -> std::io::Result<String> {
    let mut hasher = Sha256::new();
    let mut buf = [0u8; HASH_STREAM_CHUNK];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// `read_exact` `window_len` bytes into `buf` and hash `&buf[..window_len]` only.
pub(crate) fn sha256_hex_window<R: Read>(
    reader: &mut R,
    buf: &mut [u8],
    window_len: usize,
) -> std::io::Result<String> {
    if window_len > 0 {
        reader.read_exact(&mut buf[..window_len])?;
    }
    Ok(sha256_hex(&buf[..window_len]))
}

/// Normalize a user/CLI algorithm name to a canonical supported name.
pub fn normalize_algorithm(name: &str) -> Option<&'static str> {
    // Accept Python-style underscores (`sha_256`) and hyphens (`sha-256`).
    let key = name.trim().to_ascii_lowercase().replace(['_', '-'], "");
    match key.as_str() {
        "crc32" => Some("crc32"),
        "md5" => Some("md5"),
        "sha1" => Some("sha1"),
        "sha256" => Some("sha256"),
        _ => None,
    }
}

/// Hex digest of `data` for a single algorithm (canonical name or CLI alias).
pub fn hash_hex(algorithm: &str, data: &[u8]) -> Option<String> {
    let algo = normalize_algorithm(algorithm)?;
    Some(match algo {
        "crc32" => {
            let mut h = Crc32Hasher::new();
            h.update(data);
            format!("{:08x}", h.finalize())
        }
        "md5" => {
            let mut h = Md5::new();
            h.update(data);
            format!("{:x}", h.finalize())
        }
        "sha1" => {
            let mut h = Sha1::new();
            h.update(data);
            format!("{:x}", h.finalize())
        }
        "sha256" => sha256_hex(data),
        _ => return None,
    })
}

/// Multi-hasher for streaming archive payloads.
struct MultiHasher {
    names: Vec<&'static str>,
    crc32: Option<Crc32Hasher>,
    md5: Option<Md5>,
    sha1: Option<Sha1>,
    sha256: Option<Sha256>,
}

impl MultiHasher {
    fn new(algorithms: &[String]) -> Self {
        let mut names = Vec::new();
        let mut crc32 = None;
        let mut md5 = None;
        let mut sha1 = None;
        let mut sha256 = None;
        for raw in algorithms {
            let Some(algo) = normalize_algorithm(raw) else {
                if !raw.trim().is_empty() {
                    warn!("Unsupported hash algorithm: {raw}");
                }
                continue;
            };
            if names.contains(&algo) {
                continue;
            }
            names.push(algo);
            match algo {
                "crc32" => crc32 = Some(Crc32Hasher::new()),
                "md5" => md5 = Some(Md5::new()),
                "sha1" => sha1 = Some(Sha1::new()),
                "sha256" => sha256 = Some(Sha256::new()),
                _ => {}
            }
        }
        Self {
            names,
            crc32,
            md5,
            sha1,
            sha256,
        }
    }

    fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    fn update(&mut self, chunk: &[u8]) {
        if let Some(h) = self.crc32.as_mut() {
            h.update(chunk);
        }
        if let Some(h) = self.md5.as_mut() {
            h.update(chunk);
        }
        if let Some(h) = self.sha1.as_mut() {
            h.update(chunk);
        }
        if let Some(h) = self.sha256.as_mut() {
            h.update(chunk);
        }
    }

    /// Returns `(algorithm, hex_digest)` pairs in request order.
    fn finalize(self) -> Vec<(String, String)> {
        let mut out = Vec::with_capacity(self.names.len());
        for name in &self.names {
            let hex = match *name {
                "crc32" => format!(
                    "{:08x}",
                    self.crc32.as_ref().expect("crc32").clone().finalize()
                ),
                "md5" => format!("{:x}", self.md5.as_ref().expect("md5").clone().finalize()),
                "sha1" => format!("{:x}", self.sha1.as_ref().expect("sha1").clone().finalize()),
                "sha256" => {
                    format!(
                        "{:x}",
                        self.sha256.as_ref().expect("sha256").clone().finalize()
                    )
                }
                _ => continue,
            };
            out.push(((*name).to_string(), hex));
        }
        out
    }
}

/// Hash up to `size` bytes from `reader` for the given algorithms.
pub fn compute_hashes_limited<R: Read>(
    reader: &mut R,
    size: u64,
    algorithms: &[String],
) -> std::io::Result<Vec<(String, String)>> {
    let mut hasher = MultiHasher::new(algorithms);
    if hasher.is_empty() {
        return Ok(Vec::new());
    }
    let mut remaining = size;
    let mut buf = [0u8; HASH_STREAM_CHUNK];
    while remaining > 0 {
        let want = std::cmp::min(remaining as usize, buf.len());
        let n = reader.read(&mut buf[..want])?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        remaining -= n as u64;
    }
    Ok(hasher.finalize())
}

/// Query regular files with size > 0 and compute content hashes into index xattrs.
///
/// For each eligible `files` row, seeks the archive to `offset` and hashes `size` bytes
/// (sparse best-effort: raw bytes from the archive, not expanded sparse layout).
/// Results are stored as `user.hash.<algo>` via the `xattrs` view.
///
/// The index must be writable. Compressed / non-seekable archives are best-effort only;
/// callers should prefer path-backed uncompressed TAR-like archives.
pub fn fill_content_hashes(
    index: &SqliteIndex,
    archive_path: &Path,
    algorithms: &[String],
) -> Result<()> {
    if algorithms.is_empty() {
        return Ok(());
    }
    if index.is_read_only() {
        return Err(IndexError::Invalid(
            "cannot store content hashes on a read-only index".into(),
        ));
    }

    let hasher_probe = MultiHasher::new(algorithms);
    if hasher_probe.is_empty() {
        return Ok(());
    }
    // Keep only supported names for storage keys.
    let algos: Vec<String> = hasher_probe
        .names
        .iter()
        .map(|s| (*s).to_string())
        .collect();

    let rows = index.regular_file_payloads()?;
    if rows.is_empty() {
        return Ok(());
    }

    let mut archive = File::open(archive_path)?;
    let mut pending: Vec<(i64, String, Vec<u8>)> = Vec::new();

    for (offsetheader, offset, size) in rows {
        if let Err(e) = archive.seek(SeekFrom::Start(offset as u64)) {
            warn!(
                "Failed to seek archive {} to offset {offset} for hash: {e}",
                archive_path.display()
            );
            continue;
        }
        let digests = match compute_hashes_limited(&mut archive, size, &algos) {
            Ok(d) => d,
            Err(e) => {
                warn!(
                    "Failed to hash file at offsetheader={offsetheader} in {}: {e}",
                    archive_path.display()
                );
                continue;
            }
        };
        for (name, hex) in digests {
            let key = format!("user.hash.{name}");
            pending.push((offsetheader, key, hex.into_bytes()));
        }
        if pending.len() >= 256 {
            index.insert_xattrs_batch(&pending)?;
            pending.clear();
        }
    }
    if !pending.is_empty() {
        index.insert_xattrs_batch(&pending)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_vector_abc() {
        let data = b"abc";
        assert_eq!(hash_hex("crc32", data).as_deref(), Some("352441c2"));
        assert_eq!(
            hash_hex("md5", data).as_deref(),
            Some("900150983cd24fb0d6963f7d28e17f72")
        );
        assert_eq!(
            hash_hex("sha1", data).as_deref(),
            Some("a9993e364706816aba3e25717850c26c9cd0d89d")
        );
        assert_eq!(
            hash_hex("sha256", data).as_deref(),
            Some("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        );
    }

    #[test]
    fn known_vector_foo_newline() {
        // Python single-file.tar /bar content
        let data = b"foo\n";
        assert_eq!(hash_hex("crc32", data).as_deref(), Some("7e3265a8"));
        assert_eq!(
            hash_hex("sha256", data).as_deref(),
            Some("b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c")
        );
    }

    #[test]
    fn normalize_aliases() {
        assert_eq!(normalize_algorithm("SHA256"), Some("sha256"));
        assert_eq!(normalize_algorithm("sha_1"), Some("sha1"));
        assert_eq!(normalize_algorithm("sha-256"), Some("sha256"));
        assert_eq!(normalize_algorithm("nope"), None);
    }

    #[test]
    fn stream_matches_one_shot() {
        let data = b"hello world for streaming hash test";
        let mut cursor = std::io::Cursor::new(data);
        let streamed = compute_hashes_limited(
            &mut cursor,
            data.len() as u64,
            &["crc32".into(), "sha256".into()],
        )
        .unwrap();
        assert_eq!(streamed.len(), 2);
        assert_eq!(streamed[0].1, hash_hex("crc32", data).unwrap());
        assert_eq!(streamed[1].1, hash_hex("sha256", data).unwrap());
    }

    /// Rejects `read` requests larger than [`HASH_STREAM_CHUNK`].
    struct ChunkCapped<R> {
        inner: R,
    }

    impl<R: Read> Read for ChunkCapped<R> {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            if buf.len() > HASH_STREAM_CHUNK {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "read request larger than HASH_STREAM_CHUNK",
                ));
            }
            self.inner.read(buf)
        }
    }

    /// Regression: `sha256_hex_stream` hashes until EOF in ≤64 KiB reads (no body `Vec`).
    #[test]
    fn regression_archive_full_hash_stream_rejects_oversize_read() {
        let payload: Vec<u8> = (0..(HASH_STREAM_CHUNK + 4096))
            .map(|i| (i % 251) as u8)
            .collect();
        let expected = hash_hex("sha256", &payload).unwrap();
        let mut capped = ChunkCapped {
            inner: std::io::Cursor::new(payload.clone()),
        };
        let got = sha256_hex_stream(&mut capped).unwrap();
        assert_eq!(got, expected);
        assert_eq!(sha256_hex(b""), hash_hex("sha256", b"").unwrap());
        let mut empty = std::io::Cursor::new(&b""[..]);
        assert_eq!(sha256_hex_stream(&mut empty).unwrap(), sha256_hex(b""));
    }

    /// Regression: `compute_hashes_limited` multi-chunk equals one-shot; does not hash past `size`.
    #[test]
    fn regression_compute_hashes_limited_multi_chunk() {
        let mut payload: Vec<u8> = (0..(HASH_STREAM_CHUNK + 200))
            .map(|i| (i % 251) as u8)
            .collect();
        let size = payload.len() as u64;
        payload.extend_from_slice(&[0xFF; 1024]);
        let member = &payload[..size as usize];
        let mut cursor = std::io::Cursor::new(&payload);
        let streamed =
            compute_hashes_limited(&mut cursor, size, &["crc32".into(), "sha256".into()]).unwrap();
        assert_eq!(streamed.len(), 2);
        assert_eq!(streamed[0].1, hash_hex("crc32", member).unwrap());
        assert_eq!(streamed[1].1, hash_hex("sha256", member).unwrap());
        assert_ne!(
            streamed[1].1,
            hash_hex("sha256", &payload).unwrap(),
            "must not hash past the TAR member size"
        );
    }
}
