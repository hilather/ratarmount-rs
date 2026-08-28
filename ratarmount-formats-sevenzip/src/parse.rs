//! 7z header parser with real pack-stream offsets (port of Python `sevenzip.py`).

use std::io::{self, Read, Seek, SeekFrom};

use thiserror::Error;

pub const MAGIC_7Z: &[u8; 6] = b"7z\xBC\xAF'\x1C";
pub const SIGNATURE_HEADER_SIZE: u64 = 32;

pub const PROP_END: u8 = 0x00;
pub const PROP_HEADER: u8 = 0x01;
pub const PROP_MAIN_STREAMS_INFO: u8 = 0x04;
pub const PROP_FILES_INFO: u8 = 0x05;
pub const PROP_PACK_INFO: u8 = 0x06;
pub const PROP_UNPACK_INFO: u8 = 0x07;
pub const PROP_SUBSTREAMS_INFO: u8 = 0x08;
pub const PROP_SIZE: u8 = 0x09;
pub const PROP_CRC: u8 = 0x0A;
pub const PROP_FOLDER: u8 = 0x0B;
pub const PROP_CODERS_UNPACK_SIZE: u8 = 0x0C;
pub const PROP_NUM_UNPACK_STREAM: u8 = 0x0D;
pub const PROP_EMPTY_STREAM: u8 = 0x0E;
pub const PROP_EMPTY_FILE: u8 = 0x0F;
pub const PROP_ANTI: u8 = 0x10;
pub const PROP_NAME: u8 = 0x11;
pub const PROP_CREATION_TIME: u8 = 0x12;
pub const PROP_LAST_ACCESS_TIME: u8 = 0x13;
pub const PROP_LAST_WRITE_TIME: u8 = 0x14;
pub const PROP_ATTRIBUTES: u8 = 0x15;
pub const PROP_ENCODED_HEADER: u8 = 0x17;
pub const PROP_START_POS: u8 = 0x18;
pub const PROP_DUMMY: u8 = 0x19;

pub const METHOD_COPY: &[u8] = &[0x00];
pub const METHOD_LZMA: &[u8] = &[0x03, 0x01, 0x01];
pub const METHOD_LZMA2: &[u8] = &[0x21];
pub const METHOD_BCJ: &[u8] = &[0x03, 0x03, 0x01, 0x03];
pub const METHOD_BCJ2: &[u8] = &[0x03, 0x03, 0x01, 0x1b];
pub const METHOD_DELTA: &[u8] = &[0x03];
pub const METHOD_AES: &[u8] = &[0x06, 0xf1, 0x07, 0x01];
pub const METHOD_BZIP2: &[u8] = &[0x04, 0x02, 0x02];
pub const METHOD_DEFLATE: &[u8] = &[0x04, 0x01, 0x08];
pub const METHOD_BCJ_X86: &[u8] = &[0x04];
pub const METHOD_BCJ_PPC: &[u8] = &[0x03, 0x03, 0x02, 0x05];
pub const METHOD_BCJ_IA64: &[u8] = &[0x03, 0x03, 0x04, 0x01];
pub const METHOD_BCJ_ARM: &[u8] = &[0x03, 0x03, 0x05, 0x01];
pub const METHOD_BCJ_ARMT: &[u8] = &[0x03, 0x03, 0x07, 0x01];
pub const METHOD_BCJ_SPARC: &[u8] = &[0x03, 0x03, 0x08, 0x05];

/// Windows FILETIME → Unix: seconds between 1601-01-01 and 1970-01-01, in
/// **100-nanosecond** ticks (`11_644_473_600 * 10_000_000`).
///
/// (A previous constant used `* 1_000_000_000` and was 100× too large, so every
/// 7z mtime became a huge negative and FUSE displayed Dec 31 1969 / epoch.)
const FILETIME_UNIX_DELTA: u64 = 116_444_736_000_000_000;
const WINDOWS_DIRECTORY_ATTR: u32 = 0x10;
const WINDOWS_UNIX_ATTR_MASK: u32 = 0xFFFF_0000;

#[derive(Debug, Error)]
pub enum SevenZipError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, SevenZipError>;

fn err(msg: impl Into<String>) -> SevenZipError {
    SevenZipError::Msg(msg.into())
}

#[derive(Debug, Clone)]
pub struct Coder {
    pub method: Vec<u8>,
    pub num_in_streams: u64,
    pub num_out_streams: u64,
    pub properties: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct Folder {
    pub coders: Vec<Coder>,
    pub bind_pairs: Vec<(u64, u64)>,
    pub packed_indices: Vec<u64>,
    pub unpack_sizes: Vec<u64>,
    pub has_crc: bool,
    pub crc: u32,
}

impl Folder {
    pub fn get_unpack_size(&self) -> u64 {
        self.unpack_sizes.last().copied().unwrap_or(0)
    }

    pub fn total_in_streams(&self) -> u64 {
        self.coders.iter().map(|c| c.num_in_streams).sum()
    }

    pub fn total_out_streams(&self) -> u64 {
        self.coders.iter().map(|c| c.num_out_streams).sum()
    }

    pub fn is_copy_only(&self) -> bool {
        self.coders.len() == 1 && self.coders[0].method.as_slice() == METHOD_COPY
    }

    pub fn is_encrypted(&self) -> bool {
        self.coders
            .iter()
            .any(|c| c.method.as_slice() == METHOD_AES)
    }

    pub fn content_coders(&self) -> &[Coder] {
        if self
            .coders
            .first()
            .is_some_and(|c| c.method.as_slice() == METHOD_AES)
        {
            &self.coders[1..]
        } else {
            &self.coders
        }
    }

    pub fn has_bcj2(&self) -> bool {
        self.coders
            .iter()
            .any(|c| c.method.as_slice() == METHOD_BCJ2)
    }

    pub fn is_supported_for_open(&self, allow_encrypted: bool) -> bool {
        if self.coders.is_empty() {
            return false;
        }
        if self.is_encrypted() && !allow_encrypted {
            return false;
        }
        let coders = self.content_coders();
        if coders.is_empty() {
            return self.is_encrypted() && allow_encrypted;
        }
        if coders.len() == 1 {
            let m = coders[0].method.as_slice();
            return m == METHOD_COPY
                || m == METHOD_LZMA
                || m == METHOD_LZMA2
                || m == METHOD_BZIP2
                || m == METHOD_DEFLATE
                || is_native_lzma_filter_method(m);
        }
        if coders_are_native_lzma_chain(coders) {
            return true;
        }
        if coders.iter().any(|c| c.method.as_slice() == METHOD_BCJ2) {
            for c in coders {
                if c.method.as_slice() == METHOD_BCJ2 {
                    if c.num_in_streams != 4 || c.num_out_streams != 1 {
                        return false;
                    }
                } else {
                    let m = c.method.as_slice();
                    let ok = m == METHOD_COPY
                        || m == METHOD_LZMA
                        || m == METHOD_LZMA2
                        || m == METHOD_BZIP2
                        || m == METHOD_DEFLATE
                        || is_native_lzma_filter_method(m);
                    if !ok {
                        return false;
                    }
                }
            }
            return true;
        }
        false
    }
}

pub fn is_native_lzma_filter_method(method: &[u8]) -> bool {
    method == METHOD_LZMA
        || method == METHOD_LZMA2
        || method == METHOD_DELTA
        || method == METHOD_BCJ
        || method == METHOD_BCJ_X86
        || method == METHOD_BCJ_PPC
        || method == METHOD_BCJ_IA64
        || method == METHOD_BCJ_ARM
        || method == METHOD_BCJ_ARMT
        || method == METHOD_BCJ_SPARC
}

pub fn coders_are_native_lzma_chain(coders: &[Coder]) -> bool {
    if coders.is_empty() {
        return false;
    }
    let has_compressor = coders
        .iter()
        .any(|c| c.method.as_slice() == METHOD_LZMA || c.method.as_slice() == METHOD_LZMA2);
    has_compressor
        && coders
            .iter()
            .all(|c| is_native_lzma_filter_method(c.method.as_slice()))
}

#[derive(Debug, Clone, Default)]
pub struct PackInfo {
    pub pack_pos: u64,
    pub pack_sizes: Vec<u64>,
    pub crcs: Vec<Option<u32>>,
}

impl PackInfo {
    pub fn pack_positions(&self) -> Vec<u64> {
        let mut positions = Vec::with_capacity(self.pack_sizes.len());
        let mut cur = 0u64;
        for &size in &self.pack_sizes {
            positions.push(cur);
            cur += size;
        }
        positions
    }
}

#[derive(Debug, Clone, Default)]
pub struct SubstreamsInfo {
    pub num_unpack_streams: Vec<u64>,
    pub unpack_sizes: Vec<u64>,
    pub digests: Vec<Option<u32>>,
}

#[derive(Debug, Clone, Default)]
pub struct StreamsInfo {
    pub pack_info: Option<PackInfo>,
    pub folders: Vec<Folder>,
    pub substreams: Option<SubstreamsInfo>,
}

#[derive(Debug, Clone)]
pub struct SevenZipFileEntry {
    /// Member path; after index build may share the compact index string pool (`Arc` identity).
    pub path: std::sync::Arc<str>,
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
    /// Index of the first pack stream for this folder in PackInfo.
    pub pack_stream_index: usize,
    /// File-level CRC from SubstreamsInfo (used when the folder has no CRC).
    pub crc: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct SevenZipArchiveInfo {
    pub after_header: u64,
    pub pack_pos_base: u64,
    pub folders: Vec<Folder>,
    pub pack_info: Option<PackInfo>,
    pub files: Vec<SevenZipFileEntry>,
    pub solid: bool,
}

struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_exact(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.remaining() < n {
            return Err(err(format!(
                "Unexpected end of 7z data (wanted {n}, got {})",
                self.remaining()
            )));
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn read_byte(&mut self) -> Result<u8> {
        Ok(self.read_exact(1)?[0])
    }

    fn read_uint64(&mut self) -> Result<u64> {
        let first = self.read_byte()?;
        if first == 0xFF {
            let b = self.read_exact(8)?;
            return Ok(u64::from_le_bytes(b.try_into().unwrap()));
        }
        let mut mask = 0x80u8;
        let mut extra = 0usize;
        while mask != 0 && (first & mask) != 0 {
            extra += 1;
            mask >>= 1;
        }
        if extra == 0 {
            return Ok(u64::from(first));
        }
        let value_bytes = self.read_exact(extra)?;
        let mut value = 0u64;
        for (i, &b) in value_bytes.iter().enumerate() {
            value |= u64::from(b) << (8 * i);
        }
        let high_bits = if mask != 0 {
            u64::from(first & (mask - 1))
        } else {
            0
        };
        if extra < 7 {
            value |= high_bits << (extra * 8);
        }
        Ok(value)
    }

    fn read_bools(&mut self, count: usize, check_all: bool) -> Result<Vec<bool>> {
        if check_all {
            let all_defined = self.read_byte()?;
            if all_defined != 0 {
                return Ok(vec![true; count]);
            }
        }
        let mut result = Vec::with_capacity(count);
        let mut bit = 0u8;
        let mut byte = 0u8;
        for _ in 0..count {
            if bit == 0 {
                byte = self.read_byte()?;
                bit = 0x80;
            }
            result.push((byte & bit) != 0);
            bit >>= 1;
        }
        Ok(result)
    }

    #[allow(clippy::chunks_exact_to_as_chunks)] // MSRV 1.74: `as_chunks` is 1.88+
    fn read_utf16z(&mut self) -> Result<String> {
        let mut chars = Vec::new();
        loop {
            let pair = self.read_exact(2)?;
            if pair == [0, 0] {
                break;
            }
            chars.extend_from_slice(pair);
        }
        Ok(String::from_utf16_lossy(
            &chars
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect::<Vec<_>>(),
        ))
    }
}

/// IEEE CRC-32 (zlib/7z). Used for password-trial verification of folder digests.
pub(crate) fn crc32(data: &[u8]) -> u32 {
    crc32fast::hash(data)
}

/// Alias for password-trial call sites (keeps trial code readable).
pub(crate) fn crc32_for_password_trial(data: &[u8]) -> u32 {
    crc32(data)
}

fn filetime_to_unix(filetime: u64) -> f64 {
    if filetime == 0 {
        return 0.0;
    }
    // Subtract in integer space first so we do not depend on f64 precision near 1e17.
    if filetime >= FILETIME_UNIX_DELTA {
        (filetime - FILETIME_UNIX_DELTA) as f64 / 10_000_000.0
    } else {
        -((FILETIME_UNIX_DELTA - filetime) as f64) / 10_000_000.0
    }
}

fn parse_pack_info(c: &mut Cursor<'_>) -> Result<PackInfo> {
    let mut info = PackInfo {
        pack_pos: c.read_uint64()?,
        ..Default::default()
    };
    let num_streams = c.read_uint64()?;
    if num_streams > 1_000_000 {
        return Err(err(format!("Unreasonable pack streams: {num_streams}")));
    }
    let mut prop = c.read_byte()?;
    if prop == PROP_SIZE {
        info.pack_sizes = (0..num_streams)
            .map(|_| c.read_uint64())
            .collect::<Result<_>>()?;
        prop = c.read_byte()?;
        if prop == PROP_CRC {
            let defined = c.read_bools(num_streams as usize, true)?;
            for is_defined in defined {
                if is_defined {
                    let b = c.read_exact(4)?;
                    info.crcs
                        .push(Some(u32::from_le_bytes(b.try_into().unwrap())));
                } else {
                    info.crcs.push(None);
                }
            }
            prop = c.read_byte()?;
        } else {
            info.crcs = vec![None; num_streams as usize];
        }
    } else {
        info.pack_sizes = vec![0; num_streams as usize];
        info.crcs = vec![None; num_streams as usize];
    }
    if prop != PROP_END {
        return Err(err(format!(
            "Expected END after PackInfo, got 0x{prop:02x}"
        )));
    }
    Ok(info)
}

fn parse_folder(c: &mut Cursor<'_>) -> Result<Folder> {
    let mut folder = Folder {
        coders: Vec::new(),
        bind_pairs: Vec::new(),
        packed_indices: Vec::new(),
        unpack_sizes: Vec::new(),
        has_crc: false,
        crc: 0,
    };
    let num_coders = c.read_uint64()?;
    if num_coders == 0 || num_coders > 64 {
        return Err(err(format!("Unreasonable coders: {num_coders}")));
    }
    let mut total_in = 0u64;
    let mut total_out = 0u64;
    for _ in 0..num_coders {
        let flags = c.read_byte()?;
        let method_size = (flags & 0x0F) as usize;
        let is_complex = (flags & 0x10) != 0;
        let has_attrs = (flags & 0x20) != 0;
        if (flags & 0x80) != 0 {
            return Err(err("Unsupported coder flag bit 0x80"));
        }
        let method = if method_size == 0 {
            METHOD_COPY.to_vec()
        } else {
            c.read_exact(method_size)?.to_vec()
        };
        let (num_in, num_out) = if is_complex {
            (c.read_uint64()?, c.read_uint64()?)
        } else {
            (1, 1)
        };
        let properties = if has_attrs {
            let prop_size = c.read_uint64()? as usize;
            Some(c.read_exact(prop_size)?.to_vec())
        } else {
            None
        };
        folder.coders.push(Coder {
            method,
            num_in_streams: num_in,
            num_out_streams: num_out,
            properties,
        });
        total_in += num_in;
        total_out += num_out;
    }
    let num_bind_pairs = total_out.saturating_sub(1);
    for _ in 0..num_bind_pairs {
        folder.bind_pairs.push((c.read_uint64()?, c.read_uint64()?));
    }
    let num_packed = total_in.saturating_sub(num_bind_pairs);
    if num_packed == 1 {
        let used: std::collections::HashSet<u64> =
            folder.bind_pairs.iter().map(|(a, _)| *a).collect();
        for i in 0..total_in {
            if !used.contains(&i) {
                folder.packed_indices.push(i);
                break;
            }
        }
    } else {
        for _ in 0..num_packed {
            folder.packed_indices.push(c.read_uint64()?);
        }
    }
    Ok(folder)
}

fn parse_unpack_info(c: &mut Cursor<'_>) -> Result<Vec<Folder>> {
    let prop = c.read_byte()?;
    if prop != PROP_FOLDER {
        return Err(err(format!("Expected FOLDER, got 0x{prop:02x}")));
    }
    let num_folders = c.read_uint64()?;
    if num_folders > 1_000_000 {
        return Err(err(format!("Unreasonable folders: {num_folders}")));
    }
    let external = c.read_byte()?;
    if external != 0 {
        return Err(err("External folder data is not supported"));
    }
    let mut folders = Vec::with_capacity(num_folders as usize);
    for _ in 0..num_folders {
        folders.push(parse_folder(c)?);
    }
    let prop = c.read_byte()?;
    if prop != PROP_CODERS_UNPACK_SIZE {
        return Err(err(format!(
            "Expected CODERS_UNPACK_SIZE, got 0x{prop:02x}"
        )));
    }
    for folder in &mut folders {
        for coder in &folder.coders.clone() {
            for _ in 0..coder.num_out_streams {
                folder.unpack_sizes.push(c.read_uint64()?);
            }
        }
    }
    let mut prop = c.read_byte()?;
    if prop == PROP_CRC {
        let defined = c.read_bools(num_folders as usize, true)?;
        for (i, folder) in folders.iter_mut().enumerate() {
            if defined[i] {
                folder.has_crc = true;
                let b = c.read_exact(4)?;
                folder.crc = u32::from_le_bytes(b.try_into().unwrap());
            }
        }
        prop = c.read_byte()?;
    }
    if prop != PROP_END {
        return Err(err(format!(
            "Expected END after UnpackInfo, got 0x{prop:02x}"
        )));
    }
    Ok(folders)
}

fn parse_substreams_info(c: &mut Cursor<'_>, folders: &[Folder]) -> Result<SubstreamsInfo> {
    let mut info = SubstreamsInfo::default();
    let num_folders = folders.len();
    let mut prop = c.read_byte()?;
    if prop == PROP_NUM_UNPACK_STREAM {
        info.num_unpack_streams = (0..num_folders)
            .map(|_| c.read_uint64())
            .collect::<Result<_>>()?;
        prop = c.read_byte()?;
    } else {
        info.num_unpack_streams = vec![1; num_folders];
    }
    if prop == PROP_SIZE {
        for (folder_index, &num_streams) in info.num_unpack_streams.iter().enumerate() {
            let mut sizes = Vec::new();
            let mut total = 0u64;
            for _ in 0..num_streams.saturating_sub(1) {
                let size = c.read_uint64()?;
                sizes.push(size);
                total += size;
            }
            sizes.push(
                folders[folder_index]
                    .get_unpack_size()
                    .saturating_sub(total),
            );
            info.unpack_sizes.extend(sizes);
        }
        prop = c.read_byte()?;
    } else {
        for (folder_index, &num_streams) in info.num_unpack_streams.iter().enumerate() {
            if num_streams == 1 {
                info.unpack_sizes
                    .push(folders[folder_index].get_unpack_size());
            } else {
                return Err(err("Missing Substreams SIZE for multi-stream folder"));
            }
        }
    }
    let mut num_digests = 0usize;
    for (i, &num_streams) in info.num_unpack_streams.iter().enumerate() {
        if num_streams != 1 || !folders[i].has_crc {
            num_digests += num_streams as usize;
        }
    }
    if prop == PROP_CRC {
        let defined = c.read_bools(num_digests, true)?;
        let mut crcs = Vec::new();
        for d in defined {
            if d {
                let b = c.read_exact(4)?;
                crcs.push(Some(u32::from_le_bytes(b.try_into().unwrap())));
            } else {
                crcs.push(None);
            }
        }
        let mut digest_index = 0usize;
        for (i, &num_streams) in info.num_unpack_streams.iter().enumerate() {
            if num_streams == 1 && folders[i].has_crc {
                info.digests.push(Some(folders[i].crc));
            } else {
                for _ in 0..num_streams {
                    info.digests.push(crcs[digest_index]);
                    digest_index += 1;
                }
            }
        }
        prop = c.read_byte()?;
    } else {
        let total: u64 = info.num_unpack_streams.iter().sum();
        info.digests = vec![None; total as usize];
    }
    if prop != PROP_END {
        return Err(err(format!(
            "Expected END after SubstreamsInfo, got 0x{prop:02x}"
        )));
    }
    Ok(info)
}

fn parse_streams_info(c: &mut Cursor<'_>) -> Result<StreamsInfo> {
    let mut streams = StreamsInfo::default();
    let mut prop = c.read_byte()?;
    if prop == PROP_PACK_INFO {
        streams.pack_info = Some(parse_pack_info(c)?);
        prop = c.read_byte()?;
    }
    if prop == PROP_UNPACK_INFO {
        streams.folders = parse_unpack_info(c)?;
        prop = c.read_byte()?;
    }
    if prop == PROP_SUBSTREAMS_INFO {
        streams.substreams = Some(parse_substreams_info(c, &streams.folders)?);
        prop = c.read_byte()?;
    } else if !streams.folders.is_empty() {
        streams.substreams = Some(SubstreamsInfo {
            num_unpack_streams: vec![1; streams.folders.len()],
            unpack_sizes: streams
                .folders
                .iter()
                .map(|f| f.get_unpack_size())
                .collect(),
            digests: streams
                .folders
                .iter()
                .map(|f| if f.has_crc { Some(f.crc) } else { None })
                .collect(),
        });
    }
    if prop != PROP_END {
        return Err(err(format!(
            "Expected END after StreamsInfo, got 0x{prop:02x}"
        )));
    }
    Ok(streams)
}

#[derive(Default, Clone)]
struct RawFile {
    emptystream: bool,
    filename: String,
    mtime: u64,
    attributes: Option<u32>,
}

fn parse_files_info(c: &mut Cursor<'_>) -> Result<(Vec<RawFile>, Vec<bool>, Vec<bool>)> {
    let num_files = c.read_uint64()? as usize;
    if num_files > 10_000_000 {
        return Err(err(format!("Unreasonable files: {num_files}")));
    }
    let mut files = vec![RawFile::default(); num_files];
    let mut empty_files: Vec<bool> = Vec::new();
    let mut anti_files: Vec<bool> = Vec::new();

    loop {
        let prop = c.read_byte()?;
        if prop == PROP_END {
            break;
        }
        let size = c.read_uint64()? as usize;
        let payload = c.read_exact(size)?.to_vec();
        let mut p = Cursor::new(&payload);

        match prop {
            PROP_DUMMY => {}
            PROP_EMPTY_STREAM => {
                let defined = p.read_bools(num_files, false)?;
                let mut num_empty = 0usize;
                for (i, is_empty) in defined.into_iter().enumerate() {
                    files[i].emptystream = is_empty;
                    if is_empty {
                        num_empty += 1;
                    }
                }
                empty_files = vec![false; num_empty];
                anti_files = vec![false; num_empty];
            }
            PROP_EMPTY_FILE => {
                let n = files.iter().filter(|f| f.emptystream).count();
                empty_files = p.read_bools(n, false)?;
            }
            PROP_ANTI => {
                let n = files.iter().filter(|f| f.emptystream).count();
                anti_files = p.read_bools(n, false)?;
            }
            PROP_NAME => {
                let external = p.read_byte()?;
                if external != 0 {
                    return Err(err("External file names not supported"));
                }
                for f in &mut files {
                    f.filename = p.read_utf16z()?.replace('\\', "/");
                }
            }
            PROP_LAST_WRITE_TIME | PROP_CREATION_TIME | PROP_LAST_ACCESS_TIME => {
                let defined = p.read_bools(num_files, true)?;
                let external = p.read_byte()?;
                if external != 0 {
                    return Err(err("External timestamps not supported"));
                }
                for (i, is_defined) in defined.into_iter().enumerate() {
                    if is_defined {
                        let b = p.read_exact(8)?;
                        let ft = u64::from_le_bytes(b.try_into().unwrap());
                        if prop == PROP_LAST_WRITE_TIME {
                            files[i].mtime = ft;
                        }
                    }
                }
            }
            PROP_ATTRIBUTES => {
                let defined = p.read_bools(num_files, true)?;
                let external = p.read_byte()?;
                if external != 0 {
                    return Err(err("External attributes not supported"));
                }
                for (i, is_defined) in defined.into_iter().enumerate() {
                    if is_defined {
                        let b = p.read_exact(4)?;
                        files[i].attributes = Some(u32::from_le_bytes(b.try_into().unwrap()));
                    }
                }
            }
            PROP_START_POS => {
                let defined = p.read_bools(num_files, true)?;
                let external = p.read_byte()?;
                if external != 0 {
                    return Err(err("External start pos not supported"));
                }
                for is_defined in defined {
                    if is_defined {
                        let _ = p.read_exact(8)?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok((files, empty_files, anti_files))
}

fn attributes_to_mode(attributes: Option<u32>, is_dir: bool) -> u32 {
    if let Some(attrs) = attributes {
        if attrs & WINDOWS_UNIX_ATTR_MASK != 0 {
            let unix_full = (attrs >> 16) & 0o7777;
            let file_type = (attrs >> 16) & 0o170000;
            if file_type == 0o120000 {
                return ((attrs >> 16) & 0o777) | ratarmount_core::S_IFLNK;
            }
            if unix_full != 0 {
                let ft = if is_dir {
                    ratarmount_core::S_IFDIR
                } else {
                    ratarmount_core::S_IFREG
                };
                return (unix_full & 0o7777) | ft;
            }
        }
    }
    if is_dir {
        ratarmount_core::S_IFDIR | 0o755
    } else {
        ratarmount_core::S_IFREG | 0o644
    }
}

fn is_directory_entry(
    filename: &str,
    attributes: Option<u32>,
    is_empty_stream: bool,
    is_empty_file: bool,
) -> bool {
    if let Some(a) = attributes {
        if a & WINDOWS_DIRECTORY_ATTR != 0 {
            return true;
        }
    }
    if filename.ends_with('/') {
        return true;
    }
    is_empty_stream && !is_empty_file
}

fn build_file_entries(
    raw_files: &[RawFile],
    empty_files: &[bool],
    anti_files: &[bool],
    streams: Option<&StreamsInfo>,
    after_header: u64,
) -> Result<(Vec<SevenZipFileEntry>, bool)> {
    let Some(streams) = streams else {
        let mut entries = Vec::new();
        let mut empty_index = 0usize;
        for raw in raw_files {
            let is_empty_stream = raw.emptystream;
            let is_empty_file = if is_empty_stream {
                let v = empty_files.get(empty_index).copied().unwrap_or(false);
                empty_index += 1;
                v
            } else {
                false
            };
            let is_dir = is_directory_entry(
                &raw.filename,
                raw.attributes,
                is_empty_stream,
                is_empty_file,
            );
            entries.push(SevenZipFileEntry {
                path: std::sync::Arc::from(raw.filename.trim_end_matches('/')),
                size: 0,
                mtime: filetime_to_unix(raw.mtime),
                mode: attributes_to_mode(raw.attributes, is_dir),
                is_dir,
                is_empty_stream,
                is_empty_file,
                folder_index: None,
                unpack_offset: 0,
                pack_offset: 0,
                pack_size: 0,
                pack_stream_index: 0,
                crc: None,
            });
        }
        return Ok((entries, false));
    };

    let Some(pack_info) = streams.pack_info.as_ref() else {
        return build_file_entries(raw_files, empty_files, anti_files, None, after_header);
    };
    let folders = &streams.folders;
    let substreams = streams
        .substreams
        .as_ref()
        .ok_or_else(|| err("missing substreams"))?;

    // folder_idx, unpack_offset, size, pack_stream_index
    let mut stream_map: Vec<(usize, u64, u64, usize)> = Vec::new();
    let mut pack_stream_cursor = 0usize;
    let mut unpack_size_cursor = 0usize;
    let mut solid = false;

    for (folder_index, folder) in folders.iter().enumerate() {
        let num_streams = substreams.num_unpack_streams[folder_index] as usize;
        if num_streams > 1 {
            solid = true;
        }
        let mut unpack_offset = 0u64;
        let folder_pack_streams = if folder.packed_indices.is_empty() {
            1
        } else {
            folder.packed_indices.len()
        };
        for _ in 0..num_streams {
            let size = substreams.unpack_sizes[unpack_size_cursor];
            stream_map.push((folder_index, unpack_offset, size, pack_stream_cursor));
            unpack_offset += size;
            unpack_size_cursor += 1;
        }
        pack_stream_cursor += folder_pack_streams;
    }

    let pack_base = after_header + pack_info.pack_pos;
    let pack_positions = pack_info.pack_positions();

    let mut entries = Vec::new();
    let mut empty_index = 0usize;
    let mut stream_index = 0usize;

    for raw in raw_files {
        let is_empty_stream = raw.emptystream;
        let (is_empty_file, _is_anti) = if is_empty_stream {
            let ef = empty_files.get(empty_index).copied().unwrap_or(false);
            let af = anti_files.get(empty_index).copied().unwrap_or(false);
            empty_index += 1;
            (ef, af)
        } else {
            (false, false)
        };
        let is_dir = is_directory_entry(
            &raw.filename,
            raw.attributes,
            is_empty_stream,
            is_empty_file,
        );
        let mtime = filetime_to_unix(raw.mtime);

        if is_empty_stream || is_dir {
            let dir = is_dir || (is_empty_stream && !is_empty_file);
            entries.push(SevenZipFileEntry {
                path: std::sync::Arc::from(raw.filename.trim_end_matches('/')),
                size: 0,
                mtime,
                mode: attributes_to_mode(raw.attributes, dir),
                is_dir: dir,
                is_empty_stream,
                is_empty_file,
                folder_index: None,
                unpack_offset: 0,
                pack_offset: 0,
                pack_size: 0,
                pack_stream_index: 0,
                crc: None,
            });
            continue;
        }

        if stream_index >= stream_map.len() {
            return Err(err("More non-empty files than unpack streams"));
        }
        let (folder_index, unpack_offset, size, pack_stream_index) = stream_map[stream_index];
        let crc = substreams.digests.get(stream_index).copied().flatten();
        stream_index += 1;
        let folder = &folders[folder_index];
        let folder_pack_count = if folder.packed_indices.is_empty() {
            1
        } else {
            folder.packed_indices.len()
        };
        let pack_offset = pack_base + pack_positions[pack_stream_index];
        let pack_size: u64 = pack_info.pack_sizes
            [pack_stream_index..pack_stream_index + folder_pack_count]
            .iter()
            .sum();

        entries.push(SevenZipFileEntry {
            path: std::sync::Arc::from(raw.filename.trim_end_matches('/')),
            size,
            mtime,
            mode: attributes_to_mode(raw.attributes, false),
            is_dir: false,
            is_empty_stream: false,
            is_empty_file: false,
            folder_index: Some(folder_index),
            unpack_offset,
            pack_offset,
            pack_size,
            pack_stream_index,
            crc,
        });
    }

    Ok((entries, solid))
}

type UnpackedHeader = (Option<StreamsInfo>, Vec<RawFile>, Vec<bool>, Vec<bool>);

fn parse_unpacked_header(c: &mut Cursor<'_>) -> Result<UnpackedHeader> {
    let mut streams = None;
    let mut raw_files = Vec::new();
    let mut empty_files = Vec::new();
    let mut anti_files = Vec::new();

    let mut prop = c.read_byte()?;
    if prop == PROP_MAIN_STREAMS_INFO {
        streams = Some(parse_streams_info(c)?);
        prop = c.read_byte()?;
    }
    if prop == PROP_FILES_INFO {
        let (rf, ef, af) = parse_files_info(c)?;
        raw_files = rf;
        empty_files = ef;
        anti_files = af;
        prop = c.read_byte()?;
    }
    if prop != PROP_END {
        return Err(err(format!(
            "Expected END at end of Header, got 0x{prop:02x}"
        )));
    }
    Ok((streams, raw_files, empty_files, anti_files))
}

/// Parse a 7z archive from a seekable reader. `decompress_folder` is injected
/// to avoid a circular module dependency for encoded headers.
pub fn parse_7z_archive<R, F>(file: &mut R, mut decompress_folder: F) -> Result<SevenZipArchiveInfo>
where
    R: Read + Seek,
    F: FnMut(&Folder, &[u8]) -> Result<Vec<u8>>,
{
    file.seek(SeekFrom::Start(0))?;
    let mut magic = [0u8; 6];
    file.read_exact(&mut magic)?;
    if &magic != MAGIC_7Z {
        return Err(err(format!("Not a 7z archive (bad magic: {magic:?})")));
    }
    let mut ver = [0u8; 2];
    file.read_exact(&mut ver)?;
    if ver[0] != 0 {
        return Err(err(format!(
            "Unsupported 7z major version: {}.{}",
            ver[0], ver[1]
        )));
    }
    let mut start_header_crc_b = [0u8; 4];
    file.read_exact(&mut start_header_crc_b)?;
    let start_header_crc = u32::from_le_bytes(start_header_crc_b);
    let mut next_header_offset_b = [0u8; 8];
    file.read_exact(&mut next_header_offset_b)?;
    let next_header_offset = u64::from_le_bytes(next_header_offset_b);
    let mut next_header_size_b = [0u8; 8];
    file.read_exact(&mut next_header_size_b)?;
    let next_header_size = u64::from_le_bytes(next_header_size_b);
    let mut next_header_crc_b = [0u8; 4];
    file.read_exact(&mut next_header_crc_b)?;
    let next_header_crc = u32::from_le_bytes(next_header_crc_b);

    let mut start_data = Vec::with_capacity(20);
    start_data.extend_from_slice(&next_header_offset.to_le_bytes());
    start_data.extend_from_slice(&next_header_size.to_le_bytes());
    start_data.extend_from_slice(&next_header_crc.to_le_bytes());
    if crc32(&start_data) != start_header_crc {
        return Err(err("Invalid 7z StartHeader CRC"));
    }

    let after_header = SIGNATURE_HEADER_SIZE;
    if next_header_size == 0 {
        return Ok(SevenZipArchiveInfo {
            after_header,
            pack_pos_base: after_header,
            folders: vec![],
            pack_info: None,
            files: vec![],
            solid: false,
        });
    }

    file.seek(SeekFrom::Start(after_header + next_header_offset))?;
    let mut header_data = vec![0u8; next_header_size as usize];
    file.read_exact(&mut header_data)?;
    if crc32(&header_data) != next_header_crc {
        return Err(err("Invalid 7z NextHeader CRC"));
    }

    let (streams, raw_files, empty_files, anti_files) =
        parse_header_buffer(&header_data, file, after_header, &mut decompress_folder)?;
    let (files, solid) = build_file_entries(
        &raw_files,
        &empty_files,
        &anti_files,
        streams.as_ref(),
        after_header,
    )?;
    let pack_info = streams.as_ref().and_then(|s| s.pack_info.clone());
    let folders = streams
        .as_ref()
        .map(|s| s.folders.clone())
        .unwrap_or_default();
    let pack_pos_base = after_header + pack_info.as_ref().map(|p| p.pack_pos).unwrap_or(0);

    Ok(SevenZipArchiveInfo {
        after_header,
        pack_pos_base,
        folders,
        pack_info,
        files,
        solid,
    })
}

fn parse_header_buffer<R, F>(
    header_data: &[u8],
    archive_file: &mut R,
    after_header: u64,
    decompress_folder: &mut F,
) -> Result<UnpackedHeader>
where
    R: Read + Seek,
    F: FnMut(&Folder, &[u8]) -> Result<Vec<u8>>,
{
    let mut c = Cursor::new(header_data);
    if c.remaining() == 0 {
        return Ok((None, vec![], vec![], vec![]));
    }
    let prop_id = c.read_byte()?;
    if prop_id == PROP_HEADER {
        return parse_unpacked_header(&mut c);
    }
    if prop_id != PROP_ENCODED_HEADER {
        return Err(err(format!("Unknown header property 0x{prop_id:02x}")));
    }

    let mut streams = StreamsInfo::default();
    let next_prop = c.read_byte()?;
    if next_prop != PROP_PACK_INFO {
        return Err(err("Encoded header missing PackInfo"));
    }
    streams.pack_info = Some(parse_pack_info(&mut c)?);
    let next_prop = c.read_byte()?;
    if next_prop != PROP_UNPACK_INFO {
        return Err(err("Encoded header missing UnpackInfo"));
    }
    streams.folders = parse_unpack_info(&mut c)?;
    let next_prop = c.read_byte()?;
    if next_prop != PROP_END {
        return Err(err(format!(
            "Expected END in encoded header streams, got 0x{next_prop:02x}"
        )));
    }

    let pack_info = streams.pack_info.as_ref().unwrap();
    if streams.folders.is_empty() {
        return Err(err("Encoded header has no folders"));
    }
    let pack_base = after_header + pack_info.pack_pos;
    let positions = pack_info.pack_positions();
    let mut decoded = Vec::new();
    let mut pack_index = 0usize;
    for folder in &streams.folders {
        let folder_pack_count = if folder.packed_indices.is_empty() {
            1
        } else {
            folder.packed_indices.len()
        };
        let pack_offset = pack_base + positions[pack_index];
        let pack_size: u64 = pack_info.pack_sizes[pack_index..pack_index + folder_pack_count]
            .iter()
            .sum();
        archive_file.seek(SeekFrom::Start(pack_offset))?;
        let mut packed = vec![0u8; pack_size as usize];
        archive_file.read_exact(&mut packed)?;
        decoded.extend(decompress_folder(folder, &packed)?);
        pack_index += folder_pack_count;
    }

    let mut decoded_c = Cursor::new(&decoded);
    let header_byte = decoded_c.read_byte()?;
    if header_byte != PROP_HEADER {
        return Err(err(format!(
            "Decoded header does not start with HEADER, got 0x{header_byte:02x}"
        )));
    }
    parse_unpacked_header(&mut decoded_c)
}

pub fn looks_like_7z(path: &std::path::Path) -> bool {
    let mut f = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(_) => return false,
    };
    let mut magic = [0u8; 6];
    if f.read_exact(&mut magic).is_err() {
        return false;
    }
    &magic == MAGIC_7Z
}

#[cfg(test)]
mod filetime_tests {
    use super::filetime_to_unix;

    #[test]
    fn filetime_zero_is_unix_zero() {
        assert_eq!(filetime_to_unix(0), 0.0);
    }

    #[test]
    fn filetime_unix_epoch_is_zero() {
        // 1970-01-01 00:00:00 UTC in 100ns ticks from 1601
        let ft = 116_444_736_000_000_000u64;
        assert!((filetime_to_unix(ft) - 0.0).abs() < 1e-6);
    }

    #[test]
    fn filetime_2020_06_15_noon_utc() {
        // 2020-06-15 12:00:00 UTC = 1592222400
        let unix = 1_592_222_400u64;
        let ft = unix * 10_000_000 + 116_444_736_000_000_000;
        let got = filetime_to_unix(ft);
        assert!((got - unix as f64).abs() < 1.0, "got {got} expected {unix}");
    }

    #[test]
    fn wrong_ns_delta_must_not_be_used() {
        // Guard against reintroducing *1e9 instead of *1e7 on the 1601→1970 gap.
        let unix = 1_592_222_400u64;
        let ft = unix * 10_000_000 + 116_444_736_000_000_000;
        let got = filetime_to_unix(ft);
        assert!(got > 0.0, "must be after Unix epoch, got {got}");
        assert!(
            got < 2.0e9,
            "must not be a multi-millennium offset, got {got}"
        );
    }

    /// Document the exact wrong-delta formula that produced Dec 31 1969 on FUSE.
    #[test]
    fn historical_wrong_delta_produces_huge_negative() {
        let unix = 1_592_222_400u64;
        let ft = unix * 10_000_000 + 116_444_736_000_000_000;
        // Bug: used 11_644_473_600 * 1_000_000_000 instead of * 10_000_000.
        let wrong_delta = 11_644_473_600u64.saturating_mul(1_000_000_000);
        let bad = (ft as f64 - wrong_delta as f64) / 10_000_000.0;
        assert!(
            bad < -1.0e9,
            "wrong delta should yield huge negative (got {bad})"
        );
        let good = filetime_to_unix(ft);
        assert!((good - unix as f64).abs() < 1.0);
        assert!(good > 0.0);
    }
}

#[cfg(test)]
mod crc32_tests {
    use super::{crc32, crc32_for_password_trial};

    /// Regression: 7z parse CRC must stay IEEE / zlib (ISO-HDLC) after the
    /// crc32fast swap. Hardcoded check vector; do not compare to
    /// `crc32fast::hash` (tautological once `parse::crc32` is a wrapper).
    #[test]
    fn crc32_ieee_check_string_123456789() {
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32_for_password_trial(b"123456789"), 0xCBF4_3926);
    }

    /// Regression: empty and one-byte IEEE vectors catch init / final-xor
    /// mistakes that the 9-byte check string can miss.
    #[test]
    fn crc32_ieee_empty_and_one_byte() {
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
    }
}
