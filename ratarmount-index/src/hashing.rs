//! Content hashing for index xattrs (`user.hash.<algo>`), Python `hashing.py` subset.
//!
//! Supported algorithms: `crc32`, `md5`, `sha1`, `sha256`.

use std::collections::{HashMap, HashSet};
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

thread_local! {
    static SHA256_STREAM_CALLS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// Whole-stream hashes started on this thread (test instrumentation: lets a
/// test prove an operation hashed no file content).
pub fn sha256_stream_calls_this_thread() -> u64 {
    SHA256_STREAM_CALLS.with(std::cell::Cell::get)
}

/// Stream `reader` until EOF (`n == 0`), hashing whatever was read (no `max_bytes`).
///
/// Short reads are not an error: the digest covers bytes received, matching
/// today's `read_to_end` then `Sha256::digest`. Never materializes a body `Vec`.
pub fn sha256_hex_stream<R: Read + ?Sized>(reader: &mut R) -> std::io::Result<String> {
    SHA256_STREAM_CALLS.with(|c| c.set(c.get() + 1));
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
pub(crate) fn sha256_hex_window<R: Read + ?Sized>(
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

/// Fill missing content-hash keys from decoded archive content, keeping stored
/// values byte-identical. ZIP late filling requires a verified unencrypted Stored
/// entry; 7z is build-time only. Sparse, shared-slot and libarchive rows are skipped.
/// Other backends require true payload offsets into the decoded stream.
pub fn fill_content_hashes(
    index: &SqliteIndex,
    archive_path: &Path,
    algorithms: &[String],
) -> Result<()> {
    let mut fill = prepare_fill(index, algorithms)?;
    if fill.rows.iter().all(|row| row.algos.is_empty()) {
        return Ok(());
    }
    // Keep this acquisition's compiler owner and reviewed inventory unchanged.
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-B0422-M01","item":"ratarmount_index::hashing::fill_content_hashes","disposition":"managed-read","regression":"regression_content_hashes_keep_aliased_database_lock","category":"managed-read","reason":"Use the reviewed managed reader under the existing lock guarantee.","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
    )]
    let mut archive = crate::managed_read::ManagedReadCursor::open(archive_path)?;
    archive.seek(SeekFrom::Start(0))?;
    fill_content_hashes_report(index, archive_path, archive, &mut fill).map(|_| ())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct FillReport {
    pub filled: usize,
    pub kept_existing: usize,
    pub unverifiable: usize,
}

struct HashRow {
    oh: i64,
    offset: i64,
    size: u64,
    unverifiable: bool,
    algos: Vec<String>,
}

pub(crate) struct FillState {
    rows: Vec<HashRow>,
    algos: String,
    report: FillReport,
    kept: HashSet<usize>,
    filled: HashSet<usize>,
}

// Reporting is scoped across *all* returns, including open/detection/setup errors.
impl Drop for FillState {
    fn drop(&mut self) {
        log::info!(
            "content hashes: filled={}, kept_existing={}, unverifiable={}",
            self.report.filled,
            self.report.kept_existing,
            self.report.unverifiable
        );
        if self.report.kept_existing > 0 {
            warn!("{} members already had stored hashes that were kept unchanged; older versions may have stored wrong hashes; rebuild with --recreate-index --hashes {}",
                self.report.kept_existing, self.algos);
        }
        if self.report.unverifiable > 0 {
            warn!("{} members have unverifiable content locations or unsupported late hashes; rebuild with --recreate-index --hashes {}",
                self.report.unverifiable, self.algos);
        }
    }
}

fn prepare_fill(index: &SqliteIndex, algorithms: &[String]) -> Result<FillState> {
    let mut fill = FillState {
        rows: Vec::new(),
        algos: String::new(),
        report: FillReport::default(),
        kept: HashSet::new(),
        filled: HashSet::new(),
    };
    if algorithms.is_empty() {
        return Ok(fill);
    }
    if index.is_read_only() {
        return Err(IndexError::Invalid(
            "cannot store content hashes on a read-only index".into(),
        ));
    }
    let algos: Vec<String> = MultiHasher::new(algorithms)
        .names
        .into_iter()
        .map(str::to_owned)
        .collect();
    fill.algos = algos.join(",");
    if algos.is_empty() {
        return Ok(fill);
    }
    let rows = index.regular_file_payloads()?;
    // Retain the established candidate query (including nested/PAX rows). Load
    // sparse flags and existing keys before any detection or decoder acquisition.
    let (sparse, shared, existing) = index.with_conn(|conn| {
        let mut stmt = conn.prepare("SELECT offsetheader FROM files WHERE issparse")?;
        let sparse = stmt
            .query_map([], |r| r.get::<_, i64>(0))?
            .collect::<std::result::Result<HashSet<_>, _>>()?;
        // Every row owns its xattr slot, even empty/generated/non-regular rows
        // excluded from the payload candidates.
        let mut stmt = conn.prepare(
            "SELECT offsetheader FROM files WHERE offsetheader IS NOT NULL
             GROUP BY offsetheader HAVING COUNT(*) > 1",
        )?;
        let shared = stmt
            .query_map([], |r| r.get::<_, i64>(0))?
            .collect::<std::result::Result<HashSet<_>, _>>()?;
        let mut stmt =
            conn.prepare("SELECT offsetheader, key FROM xattrs WHERE key LIKE 'user.hash.%'")?;
        let existing = stmt
            .query_map([], |r| Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?)))?
            .collect::<std::result::Result<HashSet<_>, _>>()?;
        Ok((sparse, shared, existing))
    })?;
    for (i, (oh, offset, size)) in rows.into_iter().enumerate() {
        let missing: Vec<_> = algos
            .iter()
            .filter(|a| !existing.contains(&(oh, format!("user.hash.{a}"))))
            .cloned()
            .collect();
        if missing.len() != algos.len() {
            fill.kept.insert(i);
        }
        fill.rows.push(HashRow {
            oh,
            offset,
            size,
            algos: missing,
            unverifiable: sparse.contains(&oh) || shared.contains(&oh),
        });
    }
    fill.report.kept_existing = fill.kept.len();
    Ok(fill)
}

#[derive(PartialEq)]
enum HashBackend {
    Offsets,
    Zip,
    SevenZip,
    Libarchive,
}

fn read_probe<R: Read + ?Sized>(reader: &mut R, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut count = 0;
    while count < buf.len() {
        match reader.read(&mut buf[count..]) {
            Ok(0) => break,
            Ok(n) => count += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(count)
}

fn classify(
    stream: &mut dyn ratarmount_compress::SeekRead,
    head: &[u8],
    first: &HashRow,
) -> std::io::Result<HashBackend> {
    // Envelope evidence precedes member structures, including TAR-shaped Copy 7z.
    if head.starts_with(b"7z\xbc\xaf\x27\x1c") {
        stream.seek(SeekFrom::Start(0))?;
        let mut envelope = [0; 32];
        if stream.read_exact(&mut envelope).is_ok()
            && crc32fast::hash(&envelope[12..])
                == u32::from_le_bytes(envelope[8..12].try_into().unwrap())
        {
            return Ok(HashBackend::SevenZip);
        }
    }
    let mut local = [0; 30];
    let n = if first.oh == 0 {
        local[..head.len()].copy_from_slice(head);
        head.len()
    } else if first.oh >= 0 {
        stream.seek(SeekFrom::Start(first.oh as u64))?;
        read_probe(stream, &mut local)?
    } else {
        0
    };
    if n >= 4 && local[..4] == *b"PK\x03\x04" {
        stream.seek(SeekFrom::Start(first.oh as u64))?;
        if stream.read_exact(&mut local).is_ok() {
            let data = first.oh.checked_add(
                30 + i64::from(u16::from_le_bytes([local[26], local[27]]))
                    + i64::from(u16::from_le_bytes([local[28], local[29]])),
            );
            if first.offset == 0 || data == Some(first.offset) {
                return Ok(HashBackend::Zip);
            }
        }
    }
    // TAR and raw-offset modes have identical fill-only semantics. No header walk
    // or header-size validation: indexed sizes already include PAX overrides.
    Ok(HashBackend::Offsets)
}

pub(crate) fn fill_content_hashes_report(
    index: &SqliteIndex,
    path: &Path,
    mut archive: crate::managed_read::ManagedReadCursor,
    fill: &mut FillState,
) -> Result<FillReport> {
    use ratarmount_compress::{
        detect_compression_head, open_decompressed_reader, CompressionFormat,
    };
    let mut head = [0; 16];
    let n = read_probe(&mut archive, &mut head)?;
    let setup = (|| {
        let format = detect_compression_head(&head[..n], &mut archive, path)?;
        let mut stream: Box<dyn ratarmount_compress::SeekRead> =
            if format == CompressionFormat::None {
                Box::new(archive)
            } else {
                open_decompressed_reader(archive, path, format)?
            };
        let mut decoded_head = head;
        let count = if format == CompressionFormat::None {
            n
        } else {
            stream.seek(SeekFrom::Start(0))?;
            read_probe(&mut *stream, &mut decoded_head)?
        };
        Ok::<_, ratarmount_compress::CompressError>((stream, decoded_head, count))
    })();
    let (mut stream, head, n) = setup.map_err(|e| {
        warn!("Failed to decode {} for content hashes: {e}; rebuild with --recreate-index --hashes {}", path.display(), fill.algos);
        IndexError::Invalid(e.to_string())
    })?;
    let meta = index.metadata()?;
    let backend = match meta.get("backendName").map(String::as_str) {
        Some("ZipMountSource") => HashBackend::Zip,
        Some("SevenZipMountSource") => HashBackend::SevenZip,
        Some("LibarchiveMountSource") => HashBackend::Libarchive,
        Some(_) => HashBackend::Offsets,
        None => classify(&mut *stream, &head[..n], &fill.rows[0])?,
    };
    let mut zip_windows = HashMap::new();
    if backend == HashBackend::Zip && !meta.contains_key("zipMultipartParts") {
        // Central directory is authoritative; no member decompression or path open.
        match zip::ZipArchive::new(&mut stream) {
            Ok(mut zip) => {
                for i in 0..zip.len() {
                    if let Ok(entry) = zip.by_index_raw(i) {
                        let window = (entry.compression() == zip::CompressionMethod::Stored
                            && !entry.encrypted())
                        .then_some((entry.data_start(), entry.size()));
                        // Duplicate identities cannot prove a unique content location.
                        zip_windows
                            .entry(entry.header_start())
                            .and_modify(|v| *v = None)
                            .or_insert(window);
                    }
                }
            }
            Err(e) => warn!(
                "Cannot verify ZIP content locations in {}: {e}",
                path.display()
            ),
        }
    }
    let mut order: Vec<_> = (0..fill.rows.len()).collect();
    order.sort_by_key(|&i| (fill.rows[i].offset, fill.rows[i].oh));
    let mut pending = Vec::new();
    for i in order {
        let row = &fill.rows[i];
        if row.algos.is_empty() {
            continue;
        }
        let offset = if backend == HashBackend::Zip {
            zip_windows
                .get(&(row.oh as u64))
                .copied()
                .flatten()
                .and_then(|(data, size)| {
                    (size == row.size
                        && (row.offset == 0 || u64::try_from(row.offset).ok() == Some(data)))
                    .then_some(data)
                })
        } else {
            u64::try_from(row.offset).ok()
        };
        if row.unverifiable
            || matches!(backend, HashBackend::SevenZip | HashBackend::Libarchive)
            || offset.is_none()
        {
            fill.report.unverifiable += 1;
            continue;
        }
        let result = (|| {
            stream.seek(SeekFrom::Start(offset.unwrap()))?;
            let mut limited = (&mut stream).take(row.size);
            let digests = compute_hashes_limited(&mut limited, row.size, &row.algos)?;
            if limited.limit() != 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
            }
            Ok::<_, std::io::Error>(digests)
        })();
        match result {
            Ok(digests) => {
                for (name, hex) in digests {
                    pending.push((i, row.oh, format!("user.hash.{name}"), hex.into_bytes()));
                }
            }
            Err(e) => {
                fill.report.unverifiable += 1;
                warn!(
                    "Failed to hash offsetheader={} in {}: {e}",
                    row.oh,
                    path.display()
                );
            }
        }
        if pending.len() >= 256 {
            insert_missing_batch(index, &pending, fill)?;
            pending.clear();
        }
    }
    if !pending.is_empty() {
        insert_missing_batch(index, &pending, fill)?;
    }
    Ok(fill.report)
}

type PendingHash = (usize, i64, String, Vec<u8>);

fn insert_missing_batch(
    index: &SqliteIndex,
    pending: &[PendingHash],
    fill: &mut FillState,
) -> Result<()> {
    let mut kept = HashSet::new();
    let result = index.with_conn(|conn| {
        conn.execute_batch("SAVEPOINT fill_hashes")?;
        let result = (|| {
            let mut stmt = conn.prepare_cached(
                r#"INSERT INTO "xattrs" (offsetheader, key, value)
                SELECT ?1, ?2, ?3 WHERE NOT EXISTS
                (SELECT 1 FROM "xattrs" WHERE offsetheader = ?1 AND key = ?2)"#,
            )?;
            let mut filled = HashSet::new();
            for (i, oh, key, value) in pending {
                // sqlite3_changes excludes INSTEAD OF trigger writes; total_changes
                // includes them and also works for legacy plain xattrs tables.
                let before = conn.total_changes();
                stmt.execute(rusqlite::params![oh, key, value])?;
                if conn.total_changes() == before {
                    kept.insert(*i);
                } else {
                    filled.insert(*i);
                }
            }
            conn.execute_batch("RELEASE fill_hashes")?;
            Ok(filled)
        })();
        if result.is_err() {
            let rollback = conn.execute_batch("ROLLBACK TO fill_hashes");
            let release = conn.execute_batch("RELEASE fill_hashes");
            rollback?;
            release?;
        }
        result
    });
    // Rollback preserves keys that already existed before this batch.
    fill.kept.extend(kept);
    fill.report.kept_existing = fill.kept.len();
    fill.filled.extend(result?);
    fill.report.filled = fill.filled.len();
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
                    std::io::ErrorKind::InvalidInput,
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

    use std::io::{Cursor, Write};

    fn algorithms() -> Vec<String> {
        vec!["sha256".into(), "crc32".into()]
    }

    fn payloads() -> Vec<Vec<u8>> {
        let mut state = 303u32;
        [8193, HASH_STREAM_CHUNK + 17, 1_010_000]
            .into_iter()
            .map(|n| {
                (0..n)
                    .map(|_| {
                        state ^= state << 13;
                        state ^= state >> 17;
                        state ^= state << 5;
                        state as u8
                    })
                    .collect()
            })
            .collect()
    }

    fn checksum(header: &mut [u8]) {
        header[148..156].fill(b' ');
        let sum: u32 = header[..512].iter().map(|&v| u32::from(v)).sum();
        header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    }

    fn tar_bytes(parts: &[Vec<u8>]) -> (Vec<u8>, Vec<(i64, i64, u64)>) {
        let mut tar = Vec::new();
        let mut rows = Vec::new();
        for (i, content) in parts.iter().enumerate() {
            let oh = tar.len();
            let mut h = [0u8; 512];
            h[..2].copy_from_slice(&[b'a' + i as u8, 0]);
            h[100..108].copy_from_slice(b"0000644\0");
            h[124..136].copy_from_slice(format!("{:011o}\0", content.len()).as_bytes());
            h[156] = b'0';
            h[257..263].copy_from_slice(b"ustar\0");
            checksum(&mut h);
            tar.extend(h);
            rows.push((oh as i64, tar.len() as i64, content.len() as u64));
            tar.extend(content);
            tar.resize(tar.len().div_ceil(512) * 512, 0);
        }
        tar.resize(tar.len() + 1024, 0);
        (tar, rows)
    }

    pub(super) fn encoded(data: &[u8], codec: &str) -> Vec<u8> {
        match codec {
            "tar" => data.to_vec(),
            "zst" => zstd::encode_all(data, 1).unwrap(),
            "gz" => {
                let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
                e.write_all(data).unwrap();
                e.finish().unwrap()
            }
            "zlib" => {
                let mut e =
                    flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
                e.write_all(data).unwrap();
                e.finish().unwrap()
            }
            "bz2" => {
                let mut e = bzip2::write::BzEncoder::new(Vec::new(), bzip2::Compression::fast());
                e.write_all(data).unwrap();
                e.finish().unwrap()
            }
            "xz" | "lzma" => {
                let stream = if codec == "xz" {
                    xz2::stream::Stream::new_easy_encoder(1, xz2::stream::Check::Crc64).unwrap()
                } else {
                    xz2::stream::Stream::new_lzma_encoder(
                        &xz2::stream::LzmaOptions::new_preset(1).unwrap(),
                    )
                    .unwrap()
                };
                let mut e = xz2::write::XzEncoder::new_stream(Vec::new(), stream);
                e.write_all(data).unwrap();
                e.finish().unwrap()
            }
            _ => unreachable!(),
        }
    }

    fn make_index(
        path: Option<&Path>,
        rows: &[(i64, i64, u64)],
        backend: Option<&str>,
    ) -> SqliteIndex {
        let idx = SqliteIndex::create_writable(path).unwrap();
        for (i, &(oh, off, size)) in rows.iter().enumerate() {
            idx.insert_file(
                "",
                &format!("m{i}"),
                oh,
                off,
                size as i64,
                0.0,
                0o100644,
                0,
                "",
                0,
                0,
                true,
                false,
                false,
                0,
            )
            .unwrap();
        }
        if let Some(backend) = backend {
            idx.store_metadata_key_value("backendName", backend)
                .unwrap();
        }
        idx
    }

    fn report_fill(idx: &SqliteIndex, path: &Path) -> (FillReport, Result<FillReport>) {
        let mut fill = prepare_fill(idx, &algorithms()).unwrap();
        let result = if fill.rows.iter().all(|r| r.algos.is_empty()) {
            Ok(fill.report)
        } else {
            let cursor = crate::managed_read::ManagedReadCursor::open(path).unwrap();
            fill_content_hashes_report(idx, path, cursor, &mut fill)
        };
        (fill.report, result)
    }

    fn assert_hash(idx: &SqliteIndex, oh: i64, algo: &str, data: &[u8]) {
        assert_eq!(
            idx.get_xattr(oh, &format!("user.hash.{algo}")).unwrap(),
            Some(hash_hex(algo, data).unwrap().into_bytes()),
            "offsetheader={oh}, {algo}"
        );
    }

    // Capture actual emitted warnings/reports on this test thread only.
    thread_local! { static MESSAGES: std::cell::RefCell<Vec<String>> = const { std::cell::RefCell::new(Vec::new()) }; }
    struct TestLog;
    impl log::Log for TestLog {
        fn enabled(&self, _: &log::Metadata<'_>) -> bool {
            true
        }
        fn log(&self, record: &log::Record<'_>) {
            MESSAGES.with(|m| m.borrow_mut().push(record.args().to_string()));
        }
        fn flush(&self) {}
    }
    fn capture_logs() {
        static INIT: std::sync::Once = std::sync::Once::new();
        INIT.call_once(|| {
            log::set_logger(&TestLog).unwrap();
            log::set_max_level(log::LevelFilter::Info);
        });
        MESSAGES.with(|m| m.borrow_mut().clear());
    }
    fn assert_remedy() {
        MESSAGES.with(|m| {
            assert!(
                m.borrow()
                    .iter()
                    .any(|s| s.contains("--recreate-index --hashes sha256,crc32")),
                "{:?}",
                m.borrow()
            )
        });
    }

    /// Regression: outer compression must not change any member digest.
    #[test]
    fn regression_303_compressed_tar_hashes_decoded_content() {
        let parts = payloads();
        let (tar, rows) = tar_bytes(&parts);
        let dir = tempfile::tempdir().unwrap();
        for codec in ["tar", "gz", "bz2", "xz", "zst", "lzma", "zlib"] {
            let path = dir.path().join(format!("A.tar.{codec}"));
            std::fs::write(&path, encoded(&tar, codec)).unwrap();
            let idx = make_index(None, &rows, Some("SQLiteIndexedTar"));
            let (report, result) = report_fill(&idx, &path);
            result.unwrap_or_else(|e| panic!("{codec}: {e}"));
            assert_eq!(report.filled, 3, "{codec}");
            for (i, part) in parts.iter().enumerate() {
                for algo in algorithms() {
                    assert_hash(&idx, rows[i].0, &algo, part);
                }
            }
        }
    }

    /// Regression: members crossing concatenated streams/frames keep their bytes.
    #[test]
    fn regression_303_codec_variants() {
        let parts = vec![payloads().remove(1)];
        let (tar, rows) = tar_bytes(&parts);
        let dir = tempfile::tempdir().unwrap();
        for codec in ["gz", "bz2", "xz", "zst", "skippable", "seek-table"] {
            let split = tar.len() / 2;
            let encoder = if matches!(codec, "skippable" | "seek-table") {
                "zst"
            } else {
                codec
            };
            let first = encoded(&tar[..split], encoder);
            let second = encoded(&tar[split..], encoder);
            let mut bytes = first.clone();
            bytes.extend(&second);
            if codec == "skippable" {
                bytes.splice(..0, [0x50, 0x2a, 0x4d, 0x18, 3, 0, 0, 0, 1, 2, 3]);
            }
            if codec == "seek-table" {
                bytes.extend(ratarmount_compress::build_seek_table_skippable(&[
                    (first.len() as u32, split as u32),
                    (second.len() as u32, (tar.len() - split) as u32),
                ]));
            }
            let path = dir.path().join(format!("A.{encoder}"));
            std::fs::write(&path, bytes).unwrap();
            let idx = make_index(None, &rows, Some("SQLiteIndexedTar"));
            report_fill(&idx, &path).1.unwrap();
            assert_hash(&idx, rows[0].0, "sha256", &parts[0]);
        }
    }

    /// Regression: even known-wrong compressed-window hashes are fill-only.
    #[test]
    fn regression_303_existing_wrong_hash_untouched() {
        capture_logs();
        let parts = vec![vec![b'x'; 8193], vec![b'y'; 2048]];
        let (tar, rows) = tar_bytes(&parts);
        let dir = tempfile::tempdir().unwrap();
        for codec in ["zst", "gz"] {
            let path = dir.path().join(format!("A.{codec}"));
            let compressed = encoded(&tar, codec);
            let start = (rows[0].1 as usize).min(compressed.len());
            let wrong = sha256_hex(&compressed[start..]).into_bytes();
            assert_ne!(wrong, sha256_hex(&parts[0]).into_bytes());
            std::fs::write(&path, compressed).unwrap();
            let idx = make_index(None, &rows, Some("SQLiteIndexedTar"));
            idx.insert_xattr(rows[0].0, "user.hash.sha256", &wrong)
                .unwrap();
            let (report, result) = report_fill(&idx, &path);
            result.unwrap();
            assert_eq!(report.kept_existing, 1);
            assert_eq!(
                idx.get_xattr(rows[0].0, "user.hash.sha256").unwrap(),
                Some(wrong)
            );
            assert_hash(&idx, rows[0].0, "crc32", &parts[0]);
            for algo in algorithms() {
                assert_hash(&idx, rows[1].0, &algo, &parts[1]);
            }
            assert_remedy();
        }
    }

    /// Regression: ambiguous metadata and inferred TAR never authorize replacement.
    #[test]
    fn regression_303_ambiguous_row_keeps_hash() {
        let dir = tempfile::tempdir().unwrap();
        for (backend, tar, sparse, zip) in [
            (None, false, false, false),
            (Some("SomeUnknownMountSource"), false, false, false),
            (None, false, false, true),
            (Some("SQLiteIndexedTar"), true, true, false),
            (None, true, false, false),
        ] {
            let data = vec![42; 700];
            let (mut bytes, mut rows) = if tar {
                tar_bytes(std::slice::from_ref(&data))
            } else {
                (data.clone(), vec![(0, 0, 700)])
            };
            if zip {
                bytes[..4].copy_from_slice(b"PK\x03\x04");
                rows[0].1 = 0;
            }
            let path = dir.path().join("A.tar");
            std::fs::write(&path, &bytes).unwrap();
            let idx = make_index(None, &rows, backend);
            if sparse {
                idx.with_conn(|c| {
                    c.execute("UPDATE files SET issparse=1", [])?;
                    Ok(())
                })
                .unwrap();
            }
            idx.insert_xattr(0, "user.hash.sha256", b"deadbeef")
                .unwrap();
            let (report, result) = report_fill(&idx, &path);
            result.unwrap();
            assert_eq!(report.kept_existing, 1);
            assert_eq!(
                idx.get_xattr(0, "user.hash.sha256").unwrap().unwrap(),
                b"deadbeef"
            );
            if sparse || zip {
                assert_eq!(report.unverifiable, 1);
                assert!(idx.get_xattr(0, "user.hash.crc32").unwrap().is_none());
            } else {
                assert_hash(&idx, 0, "crc32", if tar { &data } else { &bytes });
            }
        }
    }

    /// Regression: physical TAR size zero must not discard effective PAX size 700.
    #[test]
    fn regression_303_pax_effective_size_filled() {
        let data = vec![b'p'; 700];
        let (mut tar, rows) = tar_bytes(std::slice::from_ref(&data));
        tar[124..136].copy_from_slice(b"00000000000\0");
        checksum(&mut tar[..512]);
        let (mut pax, _) = tar_bytes(&[b"12 size=700\n".to_vec()]);
        pax[156] = b'x';
        checksum(&mut pax[..512]);
        pax.truncate(1024);
        pax.extend(tar);
        for codec in ["tar", "zst"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(format!("A.{codec}"));
            std::fs::write(&path, encoded(&pax, codec)).unwrap();
            let idx = make_index(
                None,
                &[(1024, rows[0].1 + 1024, 700)],
                Some("SQLiteIndexedTar"),
            );
            report_fill(&idx, &path).1.unwrap();
            for algo in algorithms() {
                assert_hash(&idx, 1024, &algo, &data);
            }
        }
    }

    /// Regression: flattened nested rows use absolute outer-stream offsets.
    #[test]
    fn regression_303_nested_member_filled() {
        let content = vec![b'n'; 700];
        let (inner, _) = tar_bytes(std::slice::from_ref(&content));
        let (outer, _) = tar_bytes(&[inner]);
        for codec in ["tar", "zst"] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join(format!("A.{codec}"));
            std::fs::write(&path, encoded(&outer, codec)).unwrap();
            let idx = make_index(None, &[(512, 1024, 700)], Some("SQLiteIndexedTar"));
            idx.with_conn(|c| {
                c.execute("UPDATE files SET recursiondepth=1", [])?;
                Ok(())
            })
            .unwrap();
            report_fill(&idx, &path).1.unwrap();
            for algo in algorithms() {
                assert_hash(&idx, 512, &algo, &content);
            }
        }
    }

    /// Regression: shared xattr slots and libarchive entry numbers are not offsets.
    #[test]
    fn regression_303_shared_slot_and_libarchive_unverifiable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("A.bin");
        std::fs::write(&path, vec![9; 100]).unwrap();
        for backend in [None, Some("LibarchiveMountSource")] {
            let rows = if backend.is_none() {
                vec![(0, 0, 20), (0, 20, 20)]
            } else {
                vec![(1, 0, 20), (2, 0, 20)]
            };
            let idx = make_index(None, &rows, backend);
            let (report, result) = report_fill(&idx, &path);
            result.unwrap();
            assert_eq!(report.unverifiable, 2);
            assert_eq!(report.filled, 0);
            for row in rows {
                assert!(idx.list_xattr_keys(row.0).unwrap().is_empty());
            }
        }
    }

    /// Regression: an empty or otherwise ineligible sibling still shares its slot.
    #[test]
    fn regression_303_shared_slot_with_empty_sibling_unverifiable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("A.asar");
        std::fs::write(&path, [9; 40]).unwrap();
        for (mode, generated, size) in [
            (0o100644, false, 0),
            (0o040755, false, 0),
            (0o120777, false, 0),
            (0o100644, true, 20),
        ] {
            let idx = make_index(None, &[(0, 0, 20), (0, 20, size)], Some("ASARMountSource"));
            idx.with_conn(|c| {
                c.execute(
                    "UPDATE files SET mode=?1, isgenerated=?2 WHERE name='m1'",
                    rusqlite::params![mode, generated],
                )?;
                Ok(())
            })
            .unwrap();
            assert_eq!(idx.regular_file_payloads().unwrap().len(), 1);
            let (report, result) = report_fill(&idx, &path);
            result.unwrap();
            assert_eq!(
                report,
                FillReport {
                    unverifiable: 1,
                    ..FillReport::default()
                }
            );
            assert!(idx.list_xattr_keys(0).unwrap().is_empty());
        }
    }

    /// Regression: decoder failures report kept hashes before returning the error.
    #[test]
    fn regression_303_decode_failure_stores_nothing() {
        capture_logs();
        let dir = tempfile::tempdir().unwrap();
        for (name, bytes) in [
            ("A.tar.gz", vec![0x1f, 0x8b, 8]),
            ("A.tar.lzma", vec![]),
            ("B.tar.lzma", vec![0x5d]),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, bytes).unwrap();
            let idx = make_index(None, &[(0, 512, 700)], Some("SQLiteIndexedTar"));
            idx.insert_xattr(0, "user.hash.sha256", b"kept").unwrap();
            let (report, result) = report_fill(&idx, &path);
            assert!(result.is_err(), "{name}");
            assert_eq!(report.kept_existing, 1);
            assert_eq!(
                idx.get_xattr(0, "user.hash.sha256").unwrap().unwrap(),
                b"kept"
            );
            assert!(idx.get_xattr(0, "user.hash.crc32").unwrap().is_none());
            assert_remedy();
            MESSAGES.with(|m| assert!(m.borrow().iter().any(|s| s.contains("kept_existing=1"))));
            // A fully populated row returns before even opening this broken source.
            idx.insert_xattr(0, "user.hash.crc32", b"kept too").unwrap();
            fill_content_hashes(&idx, &dir.path().join("missing"), &algorithms()).unwrap();
        }
    }

    /// Regression: legacy indexes still decode outer compression.
    #[test]
    fn regression_303_legacy_index_without_backend_name() {
        let data = vec![b'l'; 700];
        let (tar, rows) = tar_bytes(std::slice::from_ref(&data));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("A.zst");
        std::fs::write(&path, encoded(&tar, "zst")).unwrap();
        let idx = make_index(None, &rows, None);
        report_fill(&idx, &path).1.unwrap();
        assert_hash(&idx, 0, "sha256", &data);
    }

    /// Regression: short members must never finalize a partial/empty digest.
    #[test]
    fn regression_303_truncated_member_stores_no_digest() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("A.bin");
        std::fs::write(&path, [9; 20]).unwrap();
        let idx = make_index(None, &[(0, 10, 20), (1, 100, 20)], Some("SQLiteIndexedTar"));
        let (report, result) = report_fill(&idx, &path);
        result.unwrap();
        assert_eq!(report.unverifiable, 2);
        assert_eq!(report.filled, 0);
        for oh in [0, 1] {
            assert!(idx.list_xattr_keys(oh).unwrap().is_empty());
        }
    }

    type ZipFixture = (Vec<u8>, Vec<(i64, i64, u64)>, Vec<Vec<u8>>);

    fn zip_bytes(encrypted: bool, long_name: bool) -> ZipFixture {
        use zip::unstable::write::FileOptionsExt;
        use zip::write::SimpleFileOptions;
        let parts = vec![vec![b's'; 700], vec![b'd'; 700]];
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (i, part) in parts.iter().enumerate() {
            let mut options =
                SimpleFileOptions::default().compression_method(if (i == 0) != long_name {
                    zip::CompressionMethod::Stored
                } else {
                    zip::CompressionMethod::Deflated
                });
            if encrypted {
                options = options.with_deprecated_encryption(b"password");
            }
            let name = if long_name {
                "x".repeat(481)
            } else {
                format!("m{i}")
            };
            writer.start_file(format!("{name}{i}"), options).unwrap();
            writer.write_all(part).unwrap();
        }
        let bytes = writer.finish().unwrap().into_inner();
        let mut zip = zip::ZipArchive::new(Cursor::new(&bytes)).unwrap();
        let rows = (0..zip.len())
            .map(|i| {
                let e = zip.by_index_raw(i).unwrap();
                (e.header_start() as i64, e.data_start() as i64, e.size())
            })
            .collect();
        (bytes, rows, parts)
    }

    fn check_zip(
        bytes: &[u8],
        rows: &[(i64, i64, u64)],
        parts: &[Vec<u8>],
        backend: Option<&str>,
        compressed: bool,
        multipart: bool,
        stored_fill: bool,
    ) {
        capture_logs();
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join(if compressed { "A.zip.zst" } else { "A.zip" });
        std::fs::write(
            &path,
            if compressed {
                encoded(bytes, "zst")
            } else {
                bytes.to_vec()
            },
        )
        .unwrap();
        let idx = make_index(None, rows, backend);
        idx.insert_xattr(
            rows[1].0,
            "user.hash.sha256",
            sha256_hex(&parts[1]).as_bytes(),
        )
        .unwrap();
        if multipart {
            idx.store_metadata_key_value("zipMultipartParts", "[]")
                .unwrap();
        }
        let (report, result) = report_fill(&idx, &path);
        result.unwrap();
        assert_eq!(report.kept_existing, 1);
        assert_hash(&idx, rows[1].0, "sha256", &parts[1]);
        assert!(idx
            .get_xattr(rows[1].0, "user.hash.crc32")
            .unwrap()
            .is_none());
        if stored_fill {
            for algo in algorithms() {
                assert_hash(&idx, rows[0].0, &algo, &parts[0]);
            }
        } else {
            assert!(idx.list_xattr_keys(rows[0].0).unwrap().is_empty());
        }
        assert_remedy();
    }

    /// Regression: ZIP preservation and late filling use central-directory evidence.
    #[test]
    fn regression_303_zip_digests_not_overwritten() {
        let (bytes, rows, parts) = zip_bytes(false, false);
        for backend in [Some("ZipMountSource"), None] {
            check_zip(&bytes, &rows, &parts, backend, false, false, true);
            check_zip(&bytes, &rows, &parts, backend, false, true, false);
            let mut patched = bytes.clone();
            let oh = rows[1].0 as usize;
            patched[oh + 8..oh + 10].copy_from_slice(&0u16.to_le_bytes());
            check_zip(&patched, &rows, &parts, backend, false, false, true);
            // find's late-fill function on an index with no hashes at all.
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("A.zip");
            std::fs::write(&path, &bytes).unwrap();
            let idx = make_index(None, &rows, backend);
            fill_content_hashes(&idx, &path, &algorithms()).unwrap();
            assert_hash(&idx, rows[0].0, "sha256", &parts[0]);
            let (encrypted, rows, _) = zip_bytes(true, false);
            std::fs::write(&path, &encrypted).unwrap();
            let idx = make_index(None, &rows, backend);
            let start = rows[0].1 as usize;
            let wrong = sha256_hex(&encrypted[start..start + rows[0].2 as usize]);
            idx.insert_xattr(rows[0].0, "user.hash.sha256", wrong.as_bytes())
                .unwrap();
            let (report, result) = report_fill(&idx, &path);
            result.unwrap();
            assert_eq!(report.unverifiable, 2);
            assert_eq!(report.kept_existing, 1);
            assert_eq!(
                idx.get_xattr(rows[0].0, "user.hash.sha256")
                    .unwrap()
                    .unwrap(),
                wrong.as_bytes()
            );
            assert!(idx
                .get_xattr(rows[0].0, "user.hash.crc32")
                .unwrap()
                .is_none());
            assert_remedy();
        }
    }

    /// Regression: Python's offset=0 sentinel resolves through the central directory.
    #[test]
    fn regression_303_legacy_python_zip_offset_zero() {
        let (bytes, mut rows, parts) = zip_bytes(false, false);
        for row in &mut rows {
            row.1 = 0;
        }
        check_zip(&bytes, &rows, &parts, None, false, false, true);
    }

    /// Regression: probes must inspect the decoded ZIP, never the compressed head.
    #[test]
    fn regression_303_compressed_legacy_zip() {
        let (bytes, rows, parts) = zip_bytes(false, false);
        check_zip(&bytes, &rows, &parts, None, true, false, true);
    }

    /// Regression: short/Interrupted probe reads accumulate through EOF.
    #[test]
    fn regression_303_probe_short_reads_and_interruptions() {
        struct Probe(bool, Cursor<&'static [u8]>);
        impl Read for Probe {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if !self.0 {
                    self.0 = true;
                    return Err(std::io::ErrorKind::Interrupted.into());
                }
                self.1.read(&mut buf[..1])
            }
        }
        let mut reader = Probe(false, Cursor::new(b"abc"));
        let mut buf = [0; 4];
        assert_eq!(read_probe(&mut reader, &mut buf).unwrap(), 3);
        assert_eq!(&buf[..3], b"abc");
    }

    /// Regression: ZIP prefix/local-header signatures may cross zstd frames.
    #[test]
    fn regression_303_short_decoded_probes_verify_legacy_zip() {
        let (mut bytes, rows, parts) = zip_bytes(false, false);
        // A raw-offset fallback must have enough bytes to produce a wrong digest.
        bytes.extend([0; 700]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("A.zip.zst");
        for nonzero_header in [false, true] {
            let split = if nonzero_header {
                rows[1].0 as usize + 1
            } else {
                1
            };
            let mut compressed = encoded(&bytes[..split], "zst");
            compressed.extend(encoded(&bytes[split..], "zst"));
            std::fs::write(&path, compressed).unwrap();
            let candidates = if nonzero_header {
                vec![rows[1]]
            } else {
                rows.iter().map(|&(oh, _, size)| (oh, 0, size)).collect()
            };
            let idx = make_index(None, &candidates, None);
            let (report, result) = report_fill(&idx, &path);
            result.unwrap();
            assert_eq!(report.filled, usize::from(!nonzero_header));
            assert_eq!(report.unverifiable, 1);
            assert!(idx.list_xattr_keys(rows[1].0).unwrap().is_empty());
            if !nonzero_header {
                for algo in algorithms() {
                    assert_hash(&idx, rows[0].0, &algo, &parts[0]);
                }
            }
        }
    }

    /// Regression: a TAR with ZIP-shaped prefix fails closed without an EOCD.
    #[test]
    fn regression_303_legacy_tar_named_like_zip_header() {
        capture_logs();
        let (mut tar, rows) = tar_bytes(&[vec![42; 700]]);
        tar[..4].copy_from_slice(b"PK\x03\x04");
        tar[26..30].copy_from_slice(&[0x71, 1, 0x71, 0]);
        checksum(&mut tar[..512]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("A.tar");
        std::fs::write(&path, tar).unwrap();
        let idx = make_index(None, &rows, None);
        idx.insert_xattr(0, "user.hash.sha256", b"keep").unwrap();
        let (report, result) = report_fill(&idx, &path);
        result.unwrap();
        assert_eq!(report.unverifiable, 1);
        assert_eq!(report.kept_existing, 1);
        assert_eq!(
            idx.get_xattr(0, "user.hash.sha256").unwrap().unwrap(),
            b"keep"
        );
        assert!(idx.get_xattr(0, "user.hash.crc32").unwrap().is_none());
        assert_remedy();
    }

    /// Regression: ZIP structure wins when its first 512 bytes also pass TAR checksum.
    #[test]
    fn regression_303_legacy_zip_with_tar_checksum_extra() {
        capture_logs();
        let (mut bytes, rows, parts) = zip_bytes(false, true);
        assert_eq!(rows[0].1, 512);
        bytes[156] = b'0';
        bytes[257..263].copy_from_slice(b"ustar\0");
        checksum(&mut bytes[..512]);
        let stored_sum =
            u32::from_str_radix(std::str::from_utf8(&bytes[148..154]).unwrap(), 8).unwrap();
        assert_eq!(
            stored_sum,
            bytes[..512]
                .iter()
                .enumerate()
                .map(|(i, &v)| if (148..156).contains(&i) {
                    32
                } else {
                    u32::from(v)
                })
                .sum::<u32>()
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("A.zip");
        std::fs::write(&path, bytes).unwrap();
        let idx = make_index(None, &rows, None);
        idx.insert_xattr(0, "user.hash.sha256", sha256_hex(&parts[0]).as_bytes())
            .unwrap();
        let (report, result) = report_fill(&idx, &path);
        result.unwrap();
        assert_eq!(report.kept_existing, 1);
        assert_eq!(report.unverifiable, 1);
        assert_hash(&idx, 0, "sha256", &parts[0]);
        assert!(idx.get_xattr(0, "user.hash.crc32").unwrap().is_none());
        assert_remedy();
    }

    /// Regression: named 7z never receives late raw-window hashes.
    #[test]
    fn regression_303_sevenzip_digests_not_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("A.7z");
        std::fs::write(&path, [9; 100]).unwrap();
        let idx = make_index(None, &[(32, 0, 100)], Some("SevenZipMountSource"));
        idx.insert_xattr(32, "user.hash.sha256", b"keep").unwrap();
        let (report, result) = report_fill(&idx, &path);
        result.unwrap();
        assert_eq!(report.kept_existing, 1);
        assert_eq!(report.unverifiable, 1);
        assert_eq!(
            idx.get_xattr(32, "user.hash.sha256").unwrap().unwrap(),
            b"keep"
        );
        assert!(idx.get_xattr(32, "user.hash.crc32").unwrap().is_none());
    }

    fn copy_7z_bytes(payload: &[u8]) -> Vec<u8> {
        // Real one-folder Copy stream + one UTF-16 filename, no timestamps.
        // 7z's variable uint encoding uses two bytes for these small fixtures.
        let n = payload.len() as u16;
        let size = [0x80 | (n >> 8) as u8, n as u8];
        let mut next = vec![1, 4, 6, 0, 1, 9];
        next.extend(size);
        next.extend([0, 7, 11, 1, 0, 1, 1, 0, 12]);
        next.extend(size);
        next.extend([0, 8, 10, 1]);
        next.extend(crc32fast::hash(payload).to_le_bytes());
        next.extend([0, 0, 5, 1, 17, 5, 0, b'a', 0, 0, 0, 0, 0]);
        let mut envelope = vec![0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c, 0, 4, 0, 0, 0, 0];
        envelope.extend((payload.len() as u64).to_le_bytes());
        envelope.extend((next.len() as u64).to_le_bytes());
        envelope.extend(crc32fast::hash(&next).to_le_bytes());
        let crc = crc32fast::hash(&envelope[12..32]);
        envelope[8..12].copy_from_slice(&crc.to_le_bytes());
        envelope.extend(payload);
        envelope.extend(next);
        envelope
    }

    /// Regression: a split decoded 7z signature must never enable raw-offset fills.
    #[test]
    fn regression_303_short_decoded_probe_preserves_legacy_7z() {
        let payload = vec![7; 700];
        let bytes = copy_7z_bytes(&payload);
        let mut compressed = encoded(&bytes[..1], "zst");
        compressed.extend(encoded(&bytes[1..], "zst"));
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("A.7z.zst");
        std::fs::write(&path, compressed).unwrap();
        let idx = make_index(None, &[(32, 0, payload.len() as u64)], None);
        let (report, result) = report_fill(&idx, &path);
        result.unwrap();
        assert_eq!(
            report,
            FillReport {
                unverifiable: 1,
                ..FillReport::default()
            }
        );
        assert!(idx.list_xattr_keys(32).unwrap().is_empty());
    }

    /// Regression: a Copy 7z containing TAR cannot fill a second absent algorithm.
    #[test]
    fn regression_303_legacy_copy_7z_with_tar_member() {
        let (tar, _) = tar_bytes(&[vec![42; 700]]);
        for payload in [tar.clone(), vec![7; 700]] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("A.7z");
            std::fs::write(&path, copy_7z_bytes(&payload)).unwrap();
            let idx = make_index(None, &[(32, 0, payload.len() as u64)], None);
            idx.insert_xattr(32, "user.hash.sha256", sha256_hex(&payload).as_bytes())
                .unwrap();
            let (report, result) = report_fill(&idx, &path);
            result.unwrap();
            assert_eq!(report.kept_existing, 1);
            assert_eq!(report.unverifiable, 1);
            assert_hash(&idx, 32, "sha256", &payload);
            assert!(idx.get_xattr(32, "user.hash.crc32").unwrap().is_none());
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("A.tar");
        std::fs::write(&path, &tar).unwrap();
        let idx = make_index(None, &[(0, 512, 700)], None);
        report_fill(&idx, &path).1.unwrap();
        assert_hash(&idx, 0, "sha256", &[42; 700]);
    }

    /// Regression: a key added after inventory is kept, including legacy xattrs tables.
    #[test]
    fn regression_303_conditional_insert_keeps_late_hash() {
        capture_logs();
        for legacy in [false, true] {
            let idx = make_index(None, &[(0, 0, 20)], None);
            if legacy {
                idx.with_conn(|c| { c.execute_batch("DROP VIEW xattrs; CREATE TABLE xattrs(offsetheader INTEGER, key TEXT, value BLOB, PRIMARY KEY(offsetheader,key));")?; Ok(()) }).unwrap();
            }
            let mut fill = prepare_fill(&idx, &algorithms()).unwrap();
            idx.insert_xattr(0, "user.hash.sha256", b"late value")
                .unwrap();
            insert_missing_batch(
                &idx,
                &[
                    (0, 0, "user.hash.sha256".into(), b"replacement".to_vec()),
                    (0, 0, "user.hash.crc32".into(), b"new".to_vec()),
                ],
                &mut fill,
            )
            .unwrap();
            assert_eq!(fill.report.kept_existing, 1);
            assert_eq!(fill.report.filled, 1);
            assert_eq!(
                idx.get_xattr(0, "user.hash.sha256").unwrap().unwrap(),
                b"late value"
            );
            assert_eq!(
                idx.get_xattr(0, "user.hash.crc32").unwrap().unwrap(),
                b"new"
            );
            drop(fill);
            assert_remedy();
        }
    }

    fn published_index(db: &Path, rows: &[(i64, i64, u64)]) -> SqliteIndex {
        let mut idx = make_index(Some(db), rows, None);
        idx.store_versions(env!("CARGO_PKG_VERSION")).unwrap();
        idx.publish_tmp().unwrap();
        drop(idx);
        SqliteIndex::open_writable(db).unwrap()
    }

    fn transaction_fill(caller: bool) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("A.bin");
        let db = dir.path().join("index.sqlite");
        std::fs::write(&path, [9; 100]).unwrap();
        let idx = published_index(&db, &[(0, 0, 100)]);
        if caller {
            idx.begin_write().unwrap();
        }
        fill_content_hashes(&idx, &path, &algorithms()).unwrap();
        assert_eq!(idx.with_conn(|c| Ok(c.is_autocommit())).unwrap(), !caller);
        if caller {
            idx.commit_write().unwrap();
        }
        drop(idx);
        let idx = SqliteIndex::open_writable(&db).unwrap();
        assert_hash(&idx, 0, "sha256", &[9; 100]);
    }

    /// Regression R1: a fill inside begin_write leaves commit to the caller.
    #[test]
    fn regression_303_r1_fill_inside_caller_transaction() {
        transaction_fill(true);
    }
    /// Regression R2: an outermost savepoint persists a standalone fill.
    #[test]
    fn regression_303_r2_standalone_fill_persists() {
        transaction_fill(false);
    }
    /// Regression R3: failed batch rolls back its inserts, preserving caller writes.
    #[test]
    fn regression_303_r3_failed_fill_preserves_caller_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("A.bin");
        let db = dir.path().join("index.sqlite");
        std::fs::write(&path, [9; 100]).unwrap();
        let idx = published_index(&db, &[(0, 0, 20), (32, 20, 20)]);
        idx.with_conn(|c| { c.execute_batch("CREATE TRIGGER fail_hash BEFORE INSERT ON xattrsdata WHEN NEW.offsetheader=32 BEGIN SELECT RAISE(ABORT, 'injected hash failure'); END;")?; Ok(()) }).unwrap();
        idx.begin_write().unwrap();
        idx.insert_xattr(999, "user.caller", b"earlier").unwrap();
        let err = fill_content_hashes(&idx, &path, &algorithms()).unwrap_err();
        assert!(err.to_string().contains("injected hash failure"));
        assert!(!idx.with_conn(|c| Ok(c.is_autocommit())).unwrap());
        assert!(idx.list_xattr_keys(0).unwrap().is_empty());
        assert_eq!(
            idx.get_xattr(999, "user.caller").unwrap().unwrap(),
            b"earlier"
        );
        idx.commit_write().unwrap();
        drop(idx);
        let idx = SqliteIndex::open_writable(&db).unwrap();
        assert!(idx.list_xattr_keys(0).unwrap().is_empty());
        assert_eq!(
            idx.get_xattr(999, "user.caller").unwrap().unwrap(),
            b"earlier"
        );
    }

    /// Regression: batch rollback preserves late-kept accounting and its warning.
    #[test]
    fn regression_303_failed_batch_reports_late_kept_hash() {
        capture_logs();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("A.bin");
        let db = dir.path().join("index.sqlite");
        std::fs::write(&path, [9; 100]).unwrap();
        let idx = published_index(&db, &[(0, 0, 20), (32, 20, 20)]);
        idx.with_conn(|c| { c.execute_batch("CREATE TRIGGER fail_hash BEFORE INSERT ON xattrsdata WHEN NEW.offsetheader=32 BEGIN SELECT RAISE(ABORT, 'injected hash failure'); END;")?; Ok(()) }).unwrap();
        idx.begin_write().unwrap();
        idx.insert_xattr(999, "user.caller", b"earlier").unwrap();
        let mut fill = prepare_fill(&idx, &algorithms()).unwrap();
        assert_eq!(fill.report.kept_existing, 0);
        idx.insert_xattr(0, "user.hash.sha256", b"late value")
            .unwrap();
        let cursor = crate::managed_read::ManagedReadCursor::open(&path).unwrap();
        let err = fill_content_hashes_report(&idx, &path, cursor, &mut fill).unwrap_err();
        assert!(err.to_string().contains("injected hash failure"));
        assert_eq!(
            fill.report,
            FillReport {
                kept_existing: 1,
                ..FillReport::default()
            }
        );
        assert!(!idx.with_conn(|c| Ok(c.is_autocommit())).unwrap());
        assert_eq!(
            idx.get_xattr(0, "user.hash.sha256").unwrap().unwrap(),
            b"late value"
        );
        assert!(idx.get_xattr(0, "user.hash.crc32").unwrap().is_none());
        assert!(idx.list_xattr_keys(32).unwrap().is_empty());
        drop(fill);
        assert_remedy();
        MESSAGES.with(|m| {
            assert!(m
                .borrow()
                .iter()
                .any(|s| s.contains("filled=0, kept_existing=1")))
        });
        idx.commit_write().unwrap();
        drop(idx);
        let idx = SqliteIndex::open_writable(&db).unwrap();
        assert_eq!(
            idx.get_xattr(0, "user.hash.sha256").unwrap().unwrap(),
            b"late value"
        );
        assert!(idx.get_xattr(0, "user.hash.crc32").unwrap().is_none());
        assert!(idx.list_xattr_keys(32).unwrap().is_empty());
        assert_eq!(
            idx.get_xattr(999, "user.caller").unwrap().unwrap(),
            b"earlier"
        );
    }
}
