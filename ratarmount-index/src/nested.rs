//! Durable nested archive indexes (warm remount of embedded ZIP/TAR/7z).
//!
//! Nested mounts stay **compact-only** at runtime. When the outer archive has a
//! writable on-disk SQLite index, a successful nested open can **export** the
//! compact MemIndex into a side table; the next open **imports** it after a
//! fingerprint check instead of rebuilding the nested file table from scratch.

use std::io::{Read, Seek, SeekFrom};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::mem::{MemIndex, MemIndexBuilder};
use crate::{FileRow, IndexError, Result};

/// Schema version for [`DurableNestedBlob`].
pub const NESTED_BLOB_VERSION: u32 = 1;

/// Side-table name on the outer SQLite index (Rust-only extension).
pub const NESTED_INDEXES_TABLE: &str = "nestedindexes";

/// Bytes sampled from nested body head/tail for fingerprinting.
pub const NESTED_FINGERPRINT_SAMPLE: usize = 4096;

/// Format tags stored with the blob.
pub const NESTED_FORMAT_ZIP: &str = "zip";
pub const NESTED_FORMAT_TAR: &str = "tar";
pub const NESTED_FORMAT_SEVENZIP: &str = "7z";
pub const NESTED_FORMAT_CPIO: &str = "cpio";
pub const NESTED_FORMAT_AR: &str = "ar";

/// DDL for the outer-index side table.
pub const CREATE_NESTED_INDEXES_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS "nestedindexes" (
    "member_key" TEXT PRIMARY KEY,
    "body_size" INTEGER NOT NULL,
    "prefix_sha256" TEXT NOT NULL,
    "suffix_sha256" TEXT NOT NULL,
    "mid_sha256" TEXT NOT NULL DEFAULT '',
    "format" TEXT NOT NULL,
    "schema_version" INTEGER NOT NULL,
    "blob" BLOB NOT NULL
);
"#;

/// Identity of a nested member for durable lookup (stable across remounts).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NestedMemberKey {
    /// Parent-relative path of the nested archive (e.g. `inner.zip` or `dir/inner.tar`).
    pub member_path: String,
    /// Outer index `offsetheader` when available (unique within TAR/ZIP/7z parent).
    pub offsetheader: Option<i64>,
    /// Nested body size in bytes (uncompressed member size from parent).
    pub body_size: u64,
}

impl NestedMemberKey {
    pub fn storage_key(&self) -> String {
        match self.offsetheader {
            Some(oh) => format!("{}|oh={oh}|sz={}", self.member_path, self.body_size),
            None => format!("{}|sz={}", self.member_path, self.body_size),
        }
    }
}

/// Content fingerprint of the nested member body (seekable store/copy range).
///
/// For bodies larger than [`NESTED_FINGERPRINT_SAMPLE`], samples head, tail, and
/// mid-body windows (not a full-content hash — residual for same-size edits outside
/// sampled windows on multi-GB members). Bodies ≤ sample size are hashed in full
/// via the prefix window.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NestedBodyFingerprint {
    pub body_size: u64,
    pub prefix_sha256: String,
    pub suffix_sha256: String,
    /// Mid-window hash (empty string on schema v1 blobs that only had head/tail).
    #[serde(default)]
    pub mid_sha256: String,
}

impl NestedBodyFingerprint {
    /// Sample head / mid / tail of a seekable nested body and rewind to 0.
    pub fn from_seekable_body<R: Read + Seek + ?Sized>(
        reader: &mut R,
        body_size: u64,
    ) -> std::io::Result<Self> {
        let sample = NESTED_FINGERPRINT_SAMPLE as u64;
        let prefix_len = sample.min(body_size) as usize;
        let mut prefix = vec![0u8; prefix_len];
        reader.seek(SeekFrom::Start(0))?;
        reader.read_exact(&mut prefix)?;

        let suffix = if body_size > sample {
            let mut buf = vec![0u8; NESTED_FINGERPRINT_SAMPLE];
            reader.seek(SeekFrom::Start(body_size - sample))?;
            reader.read_exact(&mut buf)?;
            buf
        } else {
            prefix.clone()
        };

        // Mid sample catches same-size edits far from head/tail (ZIP local data, etc.).
        let mid = if body_size > sample * 2 {
            let mid_start = body_size / 2;
            let take = sample.min(body_size - mid_start);
            let mut buf = vec![0u8; take as usize];
            reader.seek(SeekFrom::Start(mid_start))?;
            reader.read_exact(&mut buf)?;
            buf
        } else {
            prefix.clone()
        };
        reader.seek(SeekFrom::Start(0))?;

        Ok(Self {
            body_size,
            prefix_sha256: hex_sha256(&prefix),
            suffix_sha256: hex_sha256(&suffix),
            mid_sha256: hex_sha256(&mid),
        })
    }

    /// Size + head sample only (no mid/tail seeks).
    ///
    /// Use when the nested body is a progressive/compressed stream: seeking
    /// to mid or tail would fully decompress the member.
    pub fn from_head_only<R: Read + Seek + ?Sized>(
        reader: &mut R,
        body_size: u64,
    ) -> std::io::Result<Self> {
        let sample = NESTED_FINGERPRINT_SAMPLE as u64;
        let prefix_len = sample.min(body_size) as usize;
        let mut prefix = vec![0u8; prefix_len];
        reader.seek(SeekFrom::Start(0))?;
        if prefix_len > 0 {
            reader.read_exact(&mut prefix)?;
        }
        reader.seek(SeekFrom::Start(0))?;
        Ok(Self {
            body_size,
            prefix_sha256: hex_sha256(&prefix),
            suffix_sha256: String::new(),
            mid_sha256: String::new(),
        })
    }

    pub fn matches(&self, other: &Self) -> bool {
        self.body_size == other.body_size
            && self.prefix_sha256 == other.prefix_sha256
            && self.suffix_sha256 == other.suffix_sha256
            // Empty mid on either side (legacy blob) falls back to head/tail only.
            && (self.mid_sha256.is_empty()
                || other.mid_sha256.is_empty()
                || self.mid_sha256 == other.mid_sha256)
    }
}

fn hex_sha256(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(data);
    format!("{:x}", h.finalize())
}

/// Serializable file row (mirrors [`FileRow`] for nested blobs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurableFileRow {
    pub path: String,
    pub name: String,
    pub offsetheader: i64,
    pub offset: i64,
    pub size: i64,
    pub mtime: f64,
    pub mode: i64,
    pub typeflag: i64,
    pub linkname: String,
    pub uid: i64,
    pub gid: i64,
    pub istar: bool,
    pub issparse: bool,
    pub isgenerated: bool,
    pub recursiondepth: i64,
}

impl From<&FileRow> for DurableFileRow {
    fn from(r: &FileRow) -> Self {
        Self {
            path: r.path.clone(),
            name: r.name.clone(),
            offsetheader: r.offsetheader,
            offset: r.offset,
            size: r.size,
            mtime: r.mtime,
            mode: r.mode,
            typeflag: r.typeflag,
            linkname: r.linkname.clone(),
            uid: r.uid,
            gid: r.gid,
            istar: r.istar,
            issparse: r.issparse,
            isgenerated: r.isgenerated,
            recursiondepth: r.recursiondepth,
        }
    }
}

impl DurableFileRow {
    pub fn to_file_row(&self) -> FileRow {
        FileRow::new(
            self.path.clone(),
            self.name.clone(),
            self.offsetheader,
            self.offset,
            self.size,
            self.mtime,
            self.mode,
            self.typeflag,
            self.linkname.clone(),
            self.uid,
            self.gid,
            self.istar,
            self.issparse,
            self.isgenerated,
            self.recursiondepth,
        )
    }
}

/// Optional ZIP open sidecars (method / compressed size / CD index).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurableZipMember {
    pub offsetheader: u64,
    pub data_start: u64,
    pub compressed_size: u64,
    pub method: u16,
    pub encrypted: bool,
    pub index: usize,
    pub name: String,
}

/// 7z coder chain entry (mirrors formats-sevenzip `Coder`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurableSevenZipCoder {
    pub method: Vec<u8>,
    pub num_in_streams: u64,
    pub num_out_streams: u64,
    pub properties: Option<Vec<u8>>,
}

/// 7z folder (mirrors formats-sevenzip `Folder`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurableSevenZipFolder {
    pub coders: Vec<DurableSevenZipCoder>,
    pub bind_pairs: Vec<(u64, u64)>,
    pub packed_indices: Vec<u64>,
    pub unpack_sizes: Vec<u64>,
    pub has_crc: bool,
    pub crc: u32,
}

/// 7z pack stream table (mirrors formats-sevenzip `PackInfo`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurableSevenZipPackInfo {
    pub pack_pos: u64,
    pub pack_sizes: Vec<u64>,
    pub crcs: Vec<Option<u32>>,
}

/// 7z member open cookies (mirrors formats-sevenzip `SevenZipFileEntry`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurableSevenZipFileEntry {
    pub path: String,
    pub size: u64,
    pub mtime: f64,
    pub mode: u32,
    pub is_dir: bool,
    pub is_empty_stream: bool,
    pub is_empty_file: bool,
    pub folder_index: Option<usize>,
    pub unpack_offset: u64,
    pub pack_offset: u64,
    pub pack_size: u64,
    pub pack_stream_index: usize,
}

/// Full 7z archive structure for warm remount without header re-parse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurableSevenZipArchive {
    pub after_header: u64,
    pub pack_pos_base: u64,
    pub folders: Vec<DurableSevenZipFolder>,
    pub pack_info: Option<DurableSevenZipPackInfo>,
    pub files: Vec<DurableSevenZipFileEntry>,
    pub solid: bool,
}

/// Versioned durable nested index blob (JSON for simplicity / debugability).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurableNestedBlob {
    pub schema_version: u32,
    pub format: String,
    pub fingerprint: NestedBodyFingerprint,
    pub rows: Vec<DurableFileRow>,
    #[serde(default)]
    pub zip_members: Vec<DurableZipMember>,
    /// When set (nested 7z), warm open rebuilds archive structure without header parse.
    #[serde(default)]
    pub sevenzip: Option<DurableSevenZipArchive>,
}

impl DurableNestedBlob {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| IndexError::Invalid(format!("nested blob encode: {e}")))
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let b: Self = serde_json::from_slice(data)
            .map_err(|e| IndexError::Invalid(format!("nested blob decode: {e}")))?;
        if b.schema_version != NESTED_BLOB_VERSION {
            return Err(IndexError::Invalid(format!(
                "nested blob schema {} != {NESTED_BLOB_VERSION}",
                b.schema_version
            )));
        }
        Ok(b)
    }

    /// Build MemIndex from durable rows (compact-only live store).
    pub fn to_mem_index(&self) -> MemIndex {
        let mut builder = MemIndexBuilder::new();
        for r in &self.rows {
            builder.push_row(&r.to_file_row());
        }
        builder.finish()
    }

    pub fn from_mem_index(
        format: &str,
        fingerprint: NestedBodyFingerprint,
        mem: &MemIndex,
        zip_members: Vec<DurableZipMember>,
    ) -> Self {
        Self::from_mem_index_with_sidecars(format, fingerprint, mem, zip_members, None)
    }

    pub fn from_mem_index_with_sidecars(
        format: &str,
        fingerprint: NestedBodyFingerprint,
        mem: &MemIndex,
        zip_members: Vec<DurableZipMember>,
        sevenzip: Option<DurableSevenZipArchive>,
    ) -> Self {
        Self {
            schema_version: NESTED_BLOB_VERSION,
            format: format.to_string(),
            fingerprint,
            rows: mem
                .export_file_rows()
                .iter()
                .map(DurableFileRow::from)
                .collect(),
            zip_members,
            sevenzip,
        }
    }

    /// True when fingerprint matches and format tag agrees.
    pub fn is_valid_for(&self, format: &str, fp: &NestedBodyFingerprint) -> bool {
        self.format == format && self.fingerprint.matches(fp)
    }

    /// True when this blob carries 7z structure sidecars for parse-free warm open.
    pub fn has_sevenzip_structure(&self) -> bool {
        self.sevenzip
            .as_ref()
            .is_some_and(|a| !a.files.is_empty() || !a.folders.is_empty())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read, Seek, SeekFrom};

    #[test]
    fn fingerprint_roundtrip_and_mismatch() {
        let body = b"hello nested body payload for fingerprinting!!";
        let mut c = Cursor::new(body.to_vec());
        let fp = NestedBodyFingerprint::from_seekable_body(&mut c, body.len() as u64).unwrap();
        assert_eq!(fp.body_size, body.len() as u64);
        assert!(!fp.prefix_sha256.is_empty());
        let mut c2 = Cursor::new(body.to_vec());
        let fp2 = NestedBodyFingerprint::from_seekable_body(&mut c2, body.len() as u64).unwrap();
        assert!(fp.matches(&fp2));
        let mut other = body.to_vec();
        other[0] ^= 0xff;
        let mut c3 = Cursor::new(other);
        let fp3 = NestedBodyFingerprint::from_seekable_body(&mut c3, body.len() as u64).unwrap();
        assert!(!fp.matches(&fp3));
    }

    /// Regression: head-only fingerprint must not seek mid or tail.
    #[test]
    fn regression_head_only_fingerprint_does_not_seek_mid_tail() {
        struct SeekLog {
            data: Vec<u8>,
            pos: u64,
            seeks: Vec<u64>,
        }
        impl Read for SeekLog {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let start = self.pos as usize;
                if start >= self.data.len() {
                    return Ok(0);
                }
                let n = buf.len().min(self.data.len() - start);
                buf[..n].copy_from_slice(&self.data[start..start + n]);
                self.pos += n as u64;
                Ok(n)
            }
        }
        impl Seek for SeekLog {
            fn seek(&mut self, from: SeekFrom) -> std::io::Result<u64> {
                let new = match from {
                    SeekFrom::Start(o) => o as i64,
                    SeekFrom::End(o) => self.data.len() as i64 + o,
                    SeekFrom::Current(o) => self.pos as i64 + o,
                };
                assert!(new >= 0);
                self.pos = new as u64;
                self.seeks.push(self.pos);
                Ok(self.pos)
            }
        }

        let body = vec![7u8; 1024 * 1024];
        let mut log = SeekLog {
            data: body.clone(),
            pos: 0,
            seeks: Vec::new(),
        };
        let fp = NestedBodyFingerprint::from_head_only(&mut log, body.len() as u64).unwrap();
        assert_eq!(fp.body_size, body.len() as u64);
        assert!(!fp.prefix_sha256.is_empty());
        assert!(fp.suffix_sha256.is_empty());
        assert!(fp.mid_sha256.is_empty());
        let sample = NESTED_FINGERPRINT_SAMPLE as u64;
        assert!(
            log.seeks.iter().all(|&p| p == 0 || p <= sample),
            "head-only must not seek mid/tail: {:?}",
            log.seeks
        );

        let mut cheap = SeekLog {
            data: body,
            pos: 0,
            seeks: Vec::new(),
        };
        let _ = NestedBodyFingerprint::from_seekable_body(&mut cheap, 1024 * 1024).unwrap();
        assert!(
            cheap.seeks.iter().any(|&p| p > sample * 2),
            "cheap path still samples mid/tail: {:?}",
            cheap.seeks
        );
    }

    #[test]
    fn blob_export_import_memindex() {
        let mut b = MemIndexBuilder::new();
        b.push_row(&FileRow::new(
            "/d", "a.txt", 10, 42, 4, 1.0, 0o100644, 0, "", 0, 0, false, false, false, 0,
        ));
        let mem = b.finish();
        let fp = NestedBodyFingerprint {
            body_size: 100,
            prefix_sha256: "aa".into(),
            suffix_sha256: "bb".into(),
            mid_sha256: "cc".into(),
        };
        let blob = DurableNestedBlob::from_mem_index(NESTED_FORMAT_ZIP, fp.clone(), &mem, vec![]);
        let bytes = blob.to_bytes().unwrap();
        let loaded = DurableNestedBlob::from_bytes(&bytes).unwrap();
        assert!(loaded.is_valid_for(NESTED_FORMAT_ZIP, &fp));
        let mem2 = loaded.to_mem_index();
        assert_eq!(mem2.count(), 1);
        assert!(mem2.lookup("/d", "a.txt", 0).is_some());
    }
}
