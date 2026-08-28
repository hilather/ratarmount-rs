//! Durable nested archive indexes (warm remount of embedded ZIP/TAR/7z).
//!
//! Nested mounts stay **compact-only** at runtime. When the outer archive has a
//! writable on-disk SQLite index, a successful nested open can **export** the
//! compact MemIndex into a side table; the next open **imports** it after a
//! fingerprint check instead of rebuilding the nested file table from scratch.

use std::io::{Read, Seek, SeekFrom};

use serde::{Deserialize, Serialize};

use crate::hashing::sha256_hex_window;
use crate::mem::{MemIndex, MemIndexBuilder};
use crate::{FileRow, IndexError, Result};

/// Schema version for [`DurableNestedBlob`].
///
/// v1 was JSON (`{...}`). v2 is versioned little-endian columnar binary with
/// [`NESTED_BLOB_MAGIC`]. [`DurableNestedBlob::from_bytes`] still dual-decodes
/// legacy v1 JSON so existing warm indexes import; encode is always v2.
pub const NESTED_BLOB_VERSION: u32 = 2;

/// Magic prefix for v2+ binary nested blobs (`RNIB` = ratarmount nested index blob).
/// JSON `{` can never be mistaken for this format.
pub const NESTED_BLOB_MAGIC: &[u8; 4] = b"RNIB";

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
        let mut buf = [0u8; NESTED_FINGERPRINT_SAMPLE];
        reader.seek(SeekFrom::Start(0))?;
        let prefix_sha256 = sha256_hex_window(reader, &mut buf, prefix_len)?;

        // Small body: suffix/mid hex equal prefix (same bytes). Do not clone the window.
        let suffix_sha256 = if body_size > sample {
            reader.seek(SeekFrom::Start(body_size - sample))?;
            sha256_hex_window(reader, &mut buf, NESTED_FINGERPRINT_SAMPLE)?
        } else {
            prefix_sha256.clone()
        };

        // Mid sample catches same-size edits far from head/tail (ZIP local data, etc.).
        let mid_sha256 = if body_size > sample * 2 {
            let mid_start = body_size / 2;
            let take = sample.min(body_size - mid_start) as usize;
            reader.seek(SeekFrom::Start(mid_start))?;
            sha256_hex_window(reader, &mut buf, take)?
        } else {
            prefix_sha256.clone()
        };
        reader.seek(SeekFrom::Start(0))?;

        Ok(Self {
            body_size,
            prefix_sha256,
            suffix_sha256,
            mid_sha256,
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
        let mut buf = [0u8; NESTED_FINGERPRINT_SAMPLE];
        reader.seek(SeekFrom::Start(0))?;
        let prefix_sha256 = sha256_hex_window(reader, &mut buf, prefix_len)?;
        reader.seek(SeekFrom::Start(0))?;
        Ok(Self {
            body_size,
            prefix_sha256,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

/// Versioned durable nested index blob (binary/columnar on disk; JSON debug optional).
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
    /// Encode as versioned little-endian columnar binary (magic [`NESTED_BLOB_MAGIC`]).
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        binfmt::encode(self)
    }

    /// Decode binary v2, or dual-decode legacy JSON v1. Fail-closed on corrupt /
    /// truncated / unsupported version so callers cold-rebuild.
    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        if data.starts_with(NESTED_BLOB_MAGIC) {
            return binfmt::decode(data);
        }
        if data.first() == Some(&b'{') {
            return decode_legacy_json_v1(data);
        }
        Err(IndexError::Invalid(
            "nested blob: missing RNIB magic and not legacy JSON".into(),
        ))
    }

    /// Optional JSON dump for triage (not the default on-disk encoding).
    pub fn to_json_debug(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|e| IndexError::Invalid(format!("nested blob JSON debug encode: {e}")))
    }

    /// Decode a JSON debug dump (any schema the serde struct accepts).
    pub fn from_json_debug(data: &[u8]) -> Result<Self> {
        serde_json::from_slice(data)
            .map_err(|e| IndexError::Invalid(format!("nested blob JSON debug decode: {e}")))
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

fn decode_legacy_json_v1(data: &[u8]) -> Result<DurableNestedBlob> {
    let b: DurableNestedBlob = serde_json::from_slice(data)
        .map_err(|e| IndexError::Invalid(format!("nested blob legacy JSON: {e}")))?;
    if b.schema_version != 1 {
        return Err(IndexError::Invalid(format!(
            "nested blob JSON schema {} unsupported (want v1)",
            b.schema_version
        )));
    }
    Ok(b)
}

/// Little-endian columnar encoding for [`DurableNestedBlob`] v2.
mod binfmt {
    use super::*;

    struct W(Vec<u8>);

    impl W {
        fn u8(&mut self, v: u8) {
            self.0.push(v);
        }
        fn u16(&mut self, v: u16) {
            self.0.extend_from_slice(&v.to_le_bytes());
        }
        fn u32(&mut self, v: u32) {
            self.0.extend_from_slice(&v.to_le_bytes());
        }
        fn u64(&mut self, v: u64) {
            self.0.extend_from_slice(&v.to_le_bytes());
        }
        fn i64(&mut self, v: i64) {
            self.0.extend_from_slice(&v.to_le_bytes());
        }
        fn f64(&mut self, v: f64) {
            self.0.extend_from_slice(&v.to_le_bytes());
        }
        fn bool(&mut self, v: bool) {
            self.u8(u8::from(v));
        }
        fn str(&mut self, s: &str) {
            self.bytes(s.as_bytes());
        }
        fn bytes(&mut self, b: &[u8]) {
            self.u32(b.len() as u32);
            self.0.extend_from_slice(b);
        }
    }

    struct R<'a>(&'a [u8]);

    impl<'a> R<'a> {
        fn take(&mut self, n: usize) -> Result<&'a [u8]> {
            if self.0.len() < n {
                return Err(IndexError::Invalid("nested blob truncated".into()));
            }
            let (h, t) = self.0.split_at(n);
            self.0 = t;
            Ok(h)
        }

        /// Reject a claimed count that cannot fit in the remaining bytes
        /// (avoids `Vec::with_capacity(u32::MAX)` on a corrupt blob).
        fn ensure_count(&self, n: usize, min_per: usize) -> Result<()> {
            let need = n
                .checked_mul(min_per)
                .ok_or_else(|| IndexError::Invalid("nested blob row count overflow".into()))?;
            if need > self.0.len() {
                return Err(IndexError::Invalid("nested blob truncated".into()));
            }
            Ok(())
        }
        fn u8(&mut self) -> Result<u8> {
            Ok(self.take(1)?[0])
        }
        fn u16(&mut self) -> Result<u16> {
            let b = self.take(2)?;
            Ok(u16::from_le_bytes([b[0], b[1]]))
        }
        fn u32(&mut self) -> Result<u32> {
            let b = self.take(4)?;
            Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        }
        fn u64(&mut self) -> Result<u64> {
            let b = self.take(8)?;
            Ok(u64::from_le_bytes([
                b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
            ]))
        }
        fn i64(&mut self) -> Result<i64> {
            Ok(self.u64()? as i64)
        }
        fn f64(&mut self) -> Result<f64> {
            Ok(f64::from_le_bytes(self.u64()?.to_le_bytes()))
        }
        fn bool(&mut self) -> Result<bool> {
            match self.u8()? {
                0 => Ok(false),
                1 => Ok(true),
                x => Err(IndexError::Invalid(format!("nested blob invalid bool {x}"))),
            }
        }
        fn bytes(&mut self) -> Result<Vec<u8>> {
            let n = self.u32()? as usize;
            Ok(self.take(n)?.to_vec())
        }
        fn str(&mut self) -> Result<String> {
            String::from_utf8(self.bytes()?)
                .map_err(|_| IndexError::Invalid("nested blob invalid utf-8".into()))
        }
        fn finish(self) -> Result<()> {
            if !self.0.is_empty() {
                return Err(IndexError::Invalid("nested blob trailing garbage".into()));
            }
            Ok(())
        }
    }

    fn encode_rows(w: &mut W, rows: &[DurableFileRow]) {
        w.u32(rows.len() as u32);
        for r in rows {
            w.str(&r.path);
        }
        for r in rows {
            w.str(&r.name);
        }
        for r in rows {
            w.i64(r.offsetheader);
        }
        for r in rows {
            w.i64(r.offset);
        }
        for r in rows {
            w.i64(r.size);
        }
        for r in rows {
            w.f64(r.mtime);
        }
        for r in rows {
            w.i64(r.mode);
        }
        for r in rows {
            w.i64(r.typeflag);
        }
        for r in rows {
            w.str(&r.linkname);
        }
        for r in rows {
            w.i64(r.uid);
        }
        for r in rows {
            w.i64(r.gid);
        }
        for r in rows {
            w.bool(r.istar);
        }
        for r in rows {
            w.bool(r.issparse);
        }
        for r in rows {
            w.bool(r.isgenerated);
        }
        for r in rows {
            w.i64(r.recursiondepth);
        }
    }

    fn decode_rows(r: &mut R<'_>) -> Result<Vec<DurableFileRow>> {
        let n = r.u32()? as usize;
        // Empty strings still cost a u32 length each (path/name/linkname) plus
        // nine i64/f64 and three bools ≈ 87 bytes/row.
        r.ensure_count(n, 87)?;
        let paths = read_n_str(r, n)?;
        let names = read_n_str(r, n)?;
        let offsetheader = read_n_i64(r, n)?;
        let offset = read_n_i64(r, n)?;
        let size = read_n_i64(r, n)?;
        let mut mtime = Vec::with_capacity(n);
        for _ in 0..n {
            mtime.push(r.f64()?);
        }
        let mode = read_n_i64(r, n)?;
        let typeflag = read_n_i64(r, n)?;
        let linkname = read_n_str(r, n)?;
        let uid = read_n_i64(r, n)?;
        let gid = read_n_i64(r, n)?;
        let mut istar = Vec::with_capacity(n);
        let mut issparse = Vec::with_capacity(n);
        let mut isgenerated = Vec::with_capacity(n);
        for _ in 0..n {
            istar.push(r.bool()?);
        }
        for _ in 0..n {
            issparse.push(r.bool()?);
        }
        for _ in 0..n {
            isgenerated.push(r.bool()?);
        }
        let recursiondepth = read_n_i64(r, n)?;
        let mut rows = Vec::with_capacity(n);
        for i in 0..n {
            rows.push(DurableFileRow {
                path: paths[i].clone(),
                name: names[i].clone(),
                offsetheader: offsetheader[i],
                offset: offset[i],
                size: size[i],
                mtime: mtime[i],
                mode: mode[i],
                typeflag: typeflag[i],
                linkname: linkname[i].clone(),
                uid: uid[i],
                gid: gid[i],
                istar: istar[i],
                issparse: issparse[i],
                isgenerated: isgenerated[i],
                recursiondepth: recursiondepth[i],
            });
        }
        Ok(rows)
    }

    fn read_n_str(r: &mut R<'_>, n: usize) -> Result<Vec<String>> {
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(r.str()?);
        }
        Ok(v)
    }

    fn read_n_i64(r: &mut R<'_>, n: usize) -> Result<Vec<i64>> {
        let mut v = Vec::with_capacity(n);
        for _ in 0..n {
            v.push(r.i64()?);
        }
        Ok(v)
    }

    fn encode_zip(w: &mut W, z: &[DurableZipMember]) {
        w.u32(z.len() as u32);
        for m in z {
            w.u64(m.offsetheader);
        }
        for m in z {
            w.u64(m.data_start);
        }
        for m in z {
            w.u64(m.compressed_size);
        }
        for m in z {
            w.u16(m.method);
        }
        for m in z {
            w.bool(m.encrypted);
        }
        for m in z {
            w.u64(m.index as u64);
        }
        for m in z {
            w.str(&m.name);
        }
    }

    fn decode_zip(r: &mut R<'_>) -> Result<Vec<DurableZipMember>> {
        let n = r.u32()? as usize;
        // 3×u64 + u16 + bool + u64 index + u32 name-len.
        r.ensure_count(n, 39)?;
        let mut offsetheader = Vec::with_capacity(n);
        let mut data_start = Vec::with_capacity(n);
        let mut compressed_size = Vec::with_capacity(n);
        for _ in 0..n {
            offsetheader.push(r.u64()?);
        }
        for _ in 0..n {
            data_start.push(r.u64()?);
        }
        for _ in 0..n {
            compressed_size.push(r.u64()?);
        }
        let mut method = Vec::with_capacity(n);
        for _ in 0..n {
            method.push(r.u16()?);
        }
        let mut encrypted = Vec::with_capacity(n);
        for _ in 0..n {
            encrypted.push(r.bool()?);
        }
        let mut index = Vec::with_capacity(n);
        for _ in 0..n {
            index.push(r.u64()? as usize);
        }
        let names = read_n_str(r, n)?;
        let mut out = Vec::with_capacity(n);
        for i in 0..n {
            out.push(DurableZipMember {
                offsetheader: offsetheader[i],
                data_start: data_start[i],
                compressed_size: compressed_size[i],
                method: method[i],
                encrypted: encrypted[i],
                index: index[i],
                name: names[i].clone(),
            });
        }
        Ok(out)
    }

    fn encode_sevenzip(w: &mut W, a: &DurableSevenZipArchive) {
        w.u64(a.after_header);
        w.u64(a.pack_pos_base);
        w.bool(a.solid);
        w.u32(a.folders.len() as u32);
        for f in &a.folders {
            w.u32(f.coders.len() as u32);
            for c in &f.coders {
                w.bytes(&c.method);
                w.u64(c.num_in_streams);
                w.u64(c.num_out_streams);
                match &c.properties {
                    Some(p) => {
                        w.bool(true);
                        w.bytes(p);
                    }
                    None => w.bool(false),
                }
            }
            w.u32(f.bind_pairs.len() as u32);
            for &(x, y) in &f.bind_pairs {
                w.u64(x);
                w.u64(y);
            }
            w.u32(f.packed_indices.len() as u32);
            for &x in &f.packed_indices {
                w.u64(x);
            }
            w.u32(f.unpack_sizes.len() as u32);
            for &x in &f.unpack_sizes {
                w.u64(x);
            }
            w.bool(f.has_crc);
            w.u32(f.crc);
        }
        match &a.pack_info {
            Some(p) => {
                w.bool(true);
                w.u64(p.pack_pos);
                w.u32(p.pack_sizes.len() as u32);
                for &x in &p.pack_sizes {
                    w.u64(x);
                }
                w.u32(p.crcs.len() as u32);
                for c in &p.crcs {
                    match c {
                        Some(v) => {
                            w.bool(true);
                            w.u32(*v);
                        }
                        None => w.bool(false),
                    }
                }
            }
            None => w.bool(false),
        }
        w.u32(a.files.len() as u32);
        for f in &a.files {
            w.str(&f.path);
            w.u64(f.size);
            w.f64(f.mtime);
            w.u32(f.mode);
            w.bool(f.is_dir);
            w.bool(f.is_empty_stream);
            w.bool(f.is_empty_file);
            match f.folder_index {
                Some(i) => {
                    w.bool(true);
                    w.u64(i as u64);
                }
                None => w.bool(false),
            }
            w.u64(f.unpack_offset);
            w.u64(f.pack_offset);
            w.u64(f.pack_size);
            w.u64(f.pack_stream_index as u64);
        }
    }

    fn decode_sevenzip(r: &mut R<'_>) -> Result<DurableSevenZipArchive> {
        let after_header = r.u64()?;
        let pack_pos_base = r.u64()?;
        let solid = r.bool()?;
        let n_folders = r.u32()? as usize;
        r.ensure_count(n_folders, 4)?;
        let mut folders = Vec::with_capacity(n_folders);
        for _ in 0..n_folders {
            let n_coders = r.u32()? as usize;
            r.ensure_count(n_coders, 4)?;
            let mut coders = Vec::with_capacity(n_coders);
            for _ in 0..n_coders {
                let method = r.bytes()?;
                let num_in_streams = r.u64()?;
                let num_out_streams = r.u64()?;
                let properties = if r.bool()? { Some(r.bytes()?) } else { None };
                coders.push(DurableSevenZipCoder {
                    method,
                    num_in_streams,
                    num_out_streams,
                    properties,
                });
            }
            let n_bind = r.u32()? as usize;
            r.ensure_count(n_bind, 16)?;
            let mut bind_pairs = Vec::with_capacity(n_bind);
            for _ in 0..n_bind {
                bind_pairs.push((r.u64()?, r.u64()?));
            }
            let n_packed = r.u32()? as usize;
            r.ensure_count(n_packed, 8)?;
            let mut packed_indices = Vec::with_capacity(n_packed);
            for _ in 0..n_packed {
                packed_indices.push(r.u64()?);
            }
            let n_unpack = r.u32()? as usize;
            r.ensure_count(n_unpack, 8)?;
            let mut unpack_sizes = Vec::with_capacity(n_unpack);
            for _ in 0..n_unpack {
                unpack_sizes.push(r.u64()?);
            }
            let has_crc = r.bool()?;
            let crc = r.u32()?;
            folders.push(DurableSevenZipFolder {
                coders,
                bind_pairs,
                packed_indices,
                unpack_sizes,
                has_crc,
                crc,
            });
        }
        let pack_info = if r.bool()? {
            let pack_pos = r.u64()?;
            let n_sizes = r.u32()? as usize;
            r.ensure_count(n_sizes, 8)?;
            let mut pack_sizes = Vec::with_capacity(n_sizes);
            for _ in 0..n_sizes {
                pack_sizes.push(r.u64()?);
            }
            let n_crcs = r.u32()? as usize;
            r.ensure_count(n_crcs, 1)?;
            let mut crcs = Vec::with_capacity(n_crcs);
            for _ in 0..n_crcs {
                crcs.push(if r.bool()? { Some(r.u32()?) } else { None });
            }
            Some(DurableSevenZipPackInfo {
                pack_pos,
                pack_sizes,
                crcs,
            })
        } else {
            None
        };
        let n_files = r.u32()? as usize;
        r.ensure_count(n_files, 4)?;
        let mut files = Vec::with_capacity(n_files);
        for _ in 0..n_files {
            files.push(DurableSevenZipFileEntry {
                path: r.str()?,
                size: r.u64()?,
                mtime: r.f64()?,
                mode: r.u32()?,
                is_dir: r.bool()?,
                is_empty_stream: r.bool()?,
                is_empty_file: r.bool()?,
                folder_index: if r.bool()? {
                    Some(r.u64()? as usize)
                } else {
                    None
                },
                unpack_offset: r.u64()?,
                pack_offset: r.u64()?,
                pack_size: r.u64()?,
                pack_stream_index: r.u64()? as usize,
            });
        }
        Ok(DurableSevenZipArchive {
            after_header,
            pack_pos_base,
            folders,
            pack_info,
            files,
            solid,
        })
    }

    pub(super) fn encode(blob: &DurableNestedBlob) -> Result<Vec<u8>> {
        let mut w = W(Vec::new());
        w.0.extend_from_slice(NESTED_BLOB_MAGIC);
        w.u32(NESTED_BLOB_VERSION);
        w.u32(NESTED_BLOB_VERSION);
        w.str(&blob.format);
        w.u64(blob.fingerprint.body_size);
        w.str(&blob.fingerprint.prefix_sha256);
        w.str(&blob.fingerprint.suffix_sha256);
        w.str(&blob.fingerprint.mid_sha256);
        encode_rows(&mut w, &blob.rows);
        encode_zip(&mut w, &blob.zip_members);
        match &blob.sevenzip {
            Some(a) => {
                w.bool(true);
                encode_sevenzip(&mut w, a);
            }
            None => w.bool(false),
        }
        Ok(w.0)
    }

    pub(super) fn decode(data: &[u8]) -> Result<DurableNestedBlob> {
        if data.len() < 8 {
            return Err(IndexError::Invalid("nested blob truncated magic".into()));
        }
        if &data[..4] != NESTED_BLOB_MAGIC {
            return Err(IndexError::Invalid("nested blob bad magic".into()));
        }
        let ver = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
        if ver != NESTED_BLOB_VERSION {
            return Err(IndexError::Invalid(format!(
                "nested blob schema {ver} unsupported (want {NESTED_BLOB_VERSION})"
            )));
        }
        let mut r = R(&data[8..]);
        let schema_version = r.u32()?;
        if schema_version != NESTED_BLOB_VERSION {
            return Err(IndexError::Invalid(format!(
                "nested blob inner schema {schema_version} != {NESTED_BLOB_VERSION}"
            )));
        }
        let format = r.str()?;
        let fingerprint = NestedBodyFingerprint {
            body_size: r.u64()?,
            prefix_sha256: r.str()?,
            suffix_sha256: r.str()?,
            mid_sha256: r.str()?,
        };
        let rows = decode_rows(&mut r)?;
        let zip_members = decode_zip(&mut r)?;
        let sevenzip = if r.bool()? {
            Some(decode_sevenzip(&mut r)?)
        } else {
            None
        };
        r.finish()?;
        Ok(DurableNestedBlob {
            schema_version,
            format,
            fingerprint,
            rows,
            zip_members,
            sevenzip,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hashing::sha256_hex;
    use std::io::{Cursor, Read, Seek, SeekFrom};

    fn patterned_body(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i % 251) as u8).collect()
    }

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

    /// Regression: seekable fingerprint reads only the three windows (no body-sized `Vec`).
    #[test]
    fn regression_fingerprint_large_body_byte_budget() {
        struct Budget {
            data: Vec<u8>,
            pos: u64,
            bytes_read: usize,
            seeks: Vec<u64>,
        }
        impl Read for Budget {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                let start = self.pos as usize;
                if start >= self.data.len() {
                    return Ok(0);
                }
                // Short reads so a full-buffer `read_exact(4096)` still works,
                // while a mistaken body-sized slurp is counted.
                let n = buf.len().min(self.data.len() - start).min(1024);
                buf[..n].copy_from_slice(&self.data[start..start + n]);
                self.pos += n as u64;
                self.bytes_read += n;
                Ok(n)
            }
        }
        impl Seek for Budget {
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

        let sample = NESTED_FINGERPRINT_SAMPLE;
        let body = patterned_body(1024 * 1024);
        let body_size = body.len() as u64;
        let mid_start = body_size / 2;
        let tail_start = body_size - sample as u64;
        let mut log = Budget {
            data: body.clone(),
            pos: 0,
            bytes_read: 0,
            seeks: Vec::new(),
        };
        let fp = NestedBodyFingerprint::from_seekable_body(&mut log, body_size).unwrap();
        assert!(
            log.bytes_read <= 3 * sample,
            "read {} payload bytes, want ≤ {}",
            log.bytes_read,
            3 * sample
        );
        assert!(
            log.seeks
                .iter()
                .all(|&p| p == 0 || p == mid_start || p == tail_start),
            "seeks must be 0 / mid / tail / rewind only: {:?}",
            log.seeks
        );
        assert_eq!(fp.prefix_sha256, sha256_hex(&body[..sample]));
        assert_eq!(fp.suffix_sha256, sha256_hex(&body[tail_start as usize..]));
        assert_eq!(
            fp.mid_sha256,
            sha256_hex(&body[mid_start as usize..mid_start as usize + sample])
        );
        assert_eq!(log.pos, 0, "must rewind to 0");
    }

    /// Regression: small / 4096 / 8192 boundaries hash `&buf[..window_len]` only.
    #[test]
    fn regression_fingerprint_small_and_boundary_bodies() {
        let sample = NESTED_FINGERPRINT_SAMPLE;
        // < 4096 and == 4096: prefix is the whole body; suffix == mid == prefix.
        for n in [1usize, 100, sample - 1, sample] {
            let body = patterned_body(n);
            let mut c = Cursor::new(body.clone());
            let fp = NestedBodyFingerprint::from_seekable_body(&mut c, n as u64).unwrap();
            let whole = sha256_hex(&body);
            assert_eq!(fp.prefix_sha256, whole, "n={n} prefix");
            assert_eq!(fp.suffix_sha256, whole, "n={n} suffix==prefix");
            assert_eq!(fp.mid_sha256, whole, "n={n} mid==prefix");
            assert_eq!(c.position(), 0);
        }

        // == 8192: mid is still prefix (body_size ≤ 2 * sample); tail is last 4096.
        let body = patterned_body(2 * sample);
        let mut c = Cursor::new(body.clone());
        let fp = NestedBodyFingerprint::from_seekable_body(&mut c, body.len() as u64).unwrap();
        let prefix = sha256_hex(&body[..sample]);
        let suffix = sha256_hex(&body[sample..]);
        assert_eq!(fp.prefix_sha256, prefix);
        assert_eq!(fp.suffix_sha256, suffix);
        assert_eq!(fp.mid_sha256, prefix, "mid stays prefix at 2 * sample");
        assert_ne!(suffix, prefix, "precondition: tail window differs");
        assert_eq!(c.position(), 0);

        // > 8192: three distinct windows.
        let body = patterned_body(2 * sample + 1);
        let mut c = Cursor::new(body.clone());
        let fp = NestedBodyFingerprint::from_seekable_body(&mut c, body.len() as u64).unwrap();
        let prefix = sha256_hex(&body[..sample]);
        let suffix = sha256_hex(&body[body.len() - sample..]);
        let mid_start = body.len() / 2;
        let mid = sha256_hex(&body[mid_start..mid_start + sample]);
        assert_eq!(fp.prefix_sha256, prefix);
        assert_eq!(fp.suffix_sha256, suffix);
        assert_eq!(fp.mid_sha256, mid);
        assert_ne!(fp.prefix_sha256, fp.suffix_sha256);
        assert_ne!(fp.prefix_sha256, fp.mid_sha256);
        assert_ne!(fp.suffix_sha256, fp.mid_sha256);
        assert_eq!(c.position(), 0);
    }

    /// Regression: seekable empty hashes sha256(""); head-only empty leaves suffix/mid blank.
    #[test]
    fn regression_fingerprint_empty_seekable_vs_head_only() {
        let empty = sha256_hex(b"");
        let mut c = Cursor::new(Vec::<u8>::new());
        let seekable = NestedBodyFingerprint::from_seekable_body(&mut c, 0).unwrap();
        assert_eq!(seekable.prefix_sha256, empty);
        assert_eq!(seekable.suffix_sha256, empty);
        assert_eq!(seekable.mid_sha256, empty);
        assert_eq!(c.position(), 0);

        let mut c = Cursor::new(Vec::<u8>::new());
        let head = NestedBodyFingerprint::from_head_only(&mut c, 0).unwrap();
        assert_eq!(head.prefix_sha256, empty);
        assert!(head.suffix_sha256.is_empty());
        assert!(head.mid_sha256.is_empty());
        assert_eq!(c.position(), 0);
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

    fn sample_fp() -> NestedBodyFingerprint {
        NestedBodyFingerprint {
            body_size: 100,
            prefix_sha256: "aa".into(),
            suffix_sha256: "bb".into(),
            mid_sha256: "cc".into(),
        }
    }

    /// Regression: MemIndex → binary blob → MemIndex keeps names/modes/sizes/lookup.
    #[test]
    fn regression_binary_nested_blob_roundtrip_names_modes_sizes() {
        let mut b = MemIndexBuilder::new();
        b.push_row(&FileRow::new(
            "/d", "a.txt", 10, 42, 4, 1.0, 0o100644, 0, "", 0, 0, false, false, false, 0,
        ));
        b.push_row(&FileRow::new(
            "/d", "b.bin", 20, 80, 16, 2.0, 0o100755, 0, "tgt", 1, 2, true, false, false, 1,
        ));
        let mem = b.finish();
        let zip_members = vec![DurableZipMember {
            offsetheader: 10,
            data_start: 42,
            compressed_size: 4,
            method: 0,
            encrypted: false,
            index: 0,
            name: "a.txt".into(),
        }];
        let blob = DurableNestedBlob::from_mem_index(
            NESTED_FORMAT_ZIP,
            sample_fp(),
            &mem,
            zip_members.clone(),
        );
        assert_eq!(blob.schema_version, NESTED_BLOB_VERSION);
        let bytes = blob.to_bytes().unwrap();
        assert!(
            bytes.starts_with(NESTED_BLOB_MAGIC),
            "v2 blob must start with RNIB, not JSON"
        );
        assert_ne!(bytes.first().copied(), Some(b'{'));
        let loaded = DurableNestedBlob::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.schema_version, NESTED_BLOB_VERSION);
        assert_eq!(loaded.zip_members, zip_members);
        assert!(loaded.is_valid_for(NESTED_FORMAT_ZIP, &sample_fp()));
        let mem2 = loaded.to_mem_index();
        assert_eq!(mem2.count(), mem.count());
        let listed = mem.list("/d").unwrap();
        let listed2 = mem2.list("/d").unwrap();
        assert_eq!(listed.len(), listed2.len());
        for (name, fi) in &listed {
            let fi2 = listed2.get(name).expect("name");
            assert_eq!(fi.mode, fi2.mode);
            assert_eq!(fi.size, fi2.size);
            assert!(mem2.lookup("/d", name, 0).is_some());
        }
    }

    /// Regression: corrupt / truncated / wrong-version nested blobs fail closed.
    #[test]
    fn regression_corrupt_truncated_wrong_version_nested_blob_fail_closed() {
        assert!(
            DurableNestedBlob::from_bytes(&[0, 1, 2]).is_err(),
            "garbage"
        );
        assert!(
            DurableNestedBlob::from_bytes(b"RNIB").is_err(),
            "truncated magic only"
        );
        let mut truncated = NESTED_BLOB_MAGIC.to_vec();
        truncated.extend_from_slice(&NESTED_BLOB_VERSION.to_le_bytes());
        assert!(
            DurableNestedBlob::from_bytes(&truncated).is_err(),
            "header only, no body"
        );
        let mut wrong_ver = NESTED_BLOB_MAGIC.to_vec();
        wrong_ver.extend_from_slice(&99u32.to_le_bytes());
        wrong_ver.extend_from_slice(&[0u8; 16]);
        let err = DurableNestedBlob::from_bytes(&wrong_ver).unwrap_err();
        assert!(
            matches!(err, IndexError::Invalid(_)),
            "wrong version must be Invalid so callers cold-rebuild"
        );
        let mut b = MemIndexBuilder::new();
        b.push_row(&FileRow::new(
            "/d", "a.txt", 10, 42, 4, 1.0, 0o100644, 0, "", 0, 0, false, false, false, 0,
        ));
        let blob =
            DurableNestedBlob::from_mem_index(NESTED_FORMAT_TAR, sample_fp(), &b.finish(), vec![]);
        let mut good = blob.to_bytes().unwrap();
        let cut = good.len() / 2;
        good.truncate(cut.max(8));
        assert!(
            DurableNestedBlob::from_bytes(&good).is_err(),
            "truncated body"
        );
        let mut corrupt = blob.to_bytes().unwrap();
        let last = corrupt.len() - 1;
        corrupt[last] ^= 0xff;
        assert!(
            DurableNestedBlob::from_bytes(&corrupt).is_err(),
            "flipped tail"
        );

        // Claimed row count that cannot fit remaining bytes must fail closed
        // (not Vec::with_capacity(u32::MAX)).
        let mut count_bomb = NESTED_BLOB_MAGIC.to_vec();
        count_bomb.extend_from_slice(&NESTED_BLOB_VERSION.to_le_bytes());
        count_bomb.extend_from_slice(&NESTED_BLOB_VERSION.to_le_bytes());
        count_bomb.extend_from_slice(&3u32.to_le_bytes());
        count_bomb.extend_from_slice(b"tar");
        count_bomb.extend_from_slice(&0u64.to_le_bytes());
        for _ in 0..3 {
            count_bomb.extend_from_slice(&0u32.to_le_bytes());
        }
        count_bomb.extend_from_slice(&u32::MAX.to_le_bytes());
        let err = DurableNestedBlob::from_bytes(&count_bomb).unwrap_err();
        assert!(
            matches!(err, IndexError::Invalid(_)),
            "huge row count must fail closed, got {err:?}"
        );
    }

    /// Regression: legacy JSON schema v1 still imports (dual-decode).
    #[test]
    fn regression_legacy_json_v1_nested_blob_still_imports() {
        let mut b = MemIndexBuilder::new();
        b.push_row(&FileRow::new(
            "/d", "a.txt", 10, 42, 4, 1.0, 0o100644, 0, "", 0, 0, false, false, false, 0,
        ));
        let mem = b.finish();
        let mut blob =
            DurableNestedBlob::from_mem_index(NESTED_FORMAT_ZIP, sample_fp(), &mem, vec![]);
        blob.schema_version = 1;
        let json = blob.to_json_debug().unwrap();
        assert_eq!(json.first().copied(), Some(b'{'));
        let loaded = DurableNestedBlob::from_bytes(&json).unwrap();
        assert_eq!(loaded.schema_version, 1);
        let mem2 = loaded.to_mem_index();
        assert!(mem2.lookup("/d", "a.txt", 0).is_some());
        assert_eq!(mem2.lookup("/d", "a.txt", 0).unwrap().size, 4);
    }
}
