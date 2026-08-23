//! Decompress 7z folders: Copy / LZMA / LZMA2 / Deflate / BZip2 / AES / BCJ chains / BCJ2.
//!
//! Pack data can be served from file regions (and AES range-decrypt) so multi-GB solid
//! folders need not fully load into RAM.

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, Mutex};

use aes::Aes256;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use ratarmount_compress::SeekRead;
use sha2::{Digest, Sha256};

use crate::parse::{
    coders_are_native_lzma_chain, Coder, Folder, Result, SevenZipError, METHOD_AES, METHOD_BCJ,
    METHOD_BCJ2, METHOD_BCJ_ARM, METHOD_BCJ_ARMT, METHOD_BCJ_IA64, METHOD_BCJ_PPC,
    METHOD_BCJ_SPARC, METHOD_BCJ_X86, METHOD_BZIP2, METHOD_COPY, METHOD_DEFLATE, METHOD_DELTA,
    METHOD_LZMA, METHOD_LZMA2,
};

/// Shared seekable archive body (path-backed `File` or nested `Read+Seek` without temp spool).
pub type SharedArchiveIo = Arc<Mutex<Box<dyn SeekRead>>>;

type Aes256CbcDec = cbc::Decryptor<Aes256>;

// ---------------------------------------------------------------------------
// Pack sources
// ---------------------------------------------------------------------------

pub trait PackSource: Send {
    fn size(&self) -> u64;
    fn read_at(&self, offset: u64, size: usize) -> Result<Vec<u8>>;
    fn as_bytes(&self) -> Result<Vec<u8>> {
        self.read_at(0, self.size() as usize)
    }
}

pub struct BytesPackSource {
    data: Vec<u8>,
}

impl BytesPackSource {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }
}

impl PackSource for BytesPackSource {
    fn size(&self) -> u64 {
        self.data.len() as u64
    }
    fn read_at(&self, offset: u64, size: usize) -> Result<Vec<u8>> {
        let off = offset as usize;
        if size == 0 || off >= self.data.len() {
            return Ok(vec![]);
        }
        let end = (off + size).min(self.data.len());
        Ok(self.data[off..end].to_vec())
    }
    fn as_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.data.clone())
    }
}

/// Read packed data from a file region under a shared lock.
pub struct FilePackSource {
    path: std::path::PathBuf,
    offset: u64,
    length: u64,
    file: Mutex<File>,
}

impl FilePackSource {
    #[allow(dead_code)]
    pub fn open(path: &Path, offset: u64, length: u64) -> Result<Self> {
        let file = File::open(path).map_err(SevenZipError::Io)?;
        Ok(Self {
            path: path.to_path_buf(),
            offset,
            length,
            file: Mutex::new(file),
        })
    }

    #[allow(dead_code)]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl PackSource for FilePackSource {
    fn size(&self) -> u64 {
        self.length
    }
    fn read_at(&self, offset: u64, size: usize) -> Result<Vec<u8>> {
        if size == 0 || offset >= self.length {
            return Ok(vec![]);
        }
        let size = size.min((self.length - offset) as usize);
        let mut f = self.file.lock().unwrap();
        f.seek(SeekFrom::Start(self.offset + offset))
            .map_err(SevenZipError::Io)?;
        let mut buf = vec![0u8; size];
        f.read_exact(&mut buf).map_err(SevenZipError::Io)?;
        Ok(buf)
    }
}

/// Pack region over a shared seekable archive (nested open without materializing to tmp).
pub struct SeekPackSource {
    io: SharedArchiveIo,
    offset: u64,
    length: u64,
}

impl SeekPackSource {
    pub fn new(io: SharedArchiveIo, offset: u64, length: u64) -> Self {
        Self { io, offset, length }
    }
}

impl PackSource for SeekPackSource {
    fn size(&self) -> u64 {
        self.length
    }
    fn read_at(&self, offset: u64, size: usize) -> Result<Vec<u8>> {
        if size == 0 || offset >= self.length {
            return Ok(vec![]);
        }
        let size = size.min((self.length - offset) as usize);
        let mut g = self
            .io
            .lock()
            .map_err(|_| SevenZipError::Msg("7z archive IO lock poisoned".into()))?;
        g.seek(SeekFrom::Start(self.offset + offset))
            .map_err(SevenZipError::Io)?;
        let mut buf = vec![0u8; size];
        g.read_exact(&mut buf).map_err(SevenZipError::Io)?;
        Ok(buf)
    }
}

/// Independent logical view of `[base, base+len)` over [`SharedArchiveIo`].
pub struct SharedArchiveView {
    io: SharedArchiveIo,
    base: u64,
    len: u64,
    pos: u64,
}

impl SharedArchiveView {
    pub fn new(io: SharedArchiveIo, base: u64, len: u64) -> Self {
        Self {
            io,
            base,
            len,
            pos: 0,
        }
    }
}

impl Read for SharedArchiveView {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let max = ((self.len - self.pos) as usize).min(buf.len());
        let mut g = self.io.lock().map_err(|_| {
            log::warn!("7z SharedArchiveView: archive IO lock poisoned");
            io::Error::other("7z archive IO lock poisoned")
        })?;
        let abs = self.base + self.pos;
        if let Err(e) = g.seek(SeekFrom::Start(abs)) {
            log::debug!(
                "7z SharedArchiveView: seek base={} pos={} abs={abs} failed: {e}",
                self.base,
                self.pos
            );
            return Err(e);
        }
        match g.read(&mut buf[..max]) {
            Ok(n) => {
                self.pos += n as u64;
                Ok(n)
            }
            Err(e) => {
                log::debug!(
                    "7z SharedArchiveView: read base={} pos={} abs={abs} max={max} failed: {e}",
                    self.base,
                    self.pos
                );
                Err(e)
            }
        }
    }
}

impl Seek for SharedArchiveView {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::End(o) => self.len as i64 + o,
            SeekFrom::Current(o) => self.pos as i64 + o,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

/// `Read + Seek` view of a [`PackSource`] region via `read_at` (not a ciphertext stencil).
///
/// Used for encrypted COPY members after AES strip. Do not wrap the archive
/// [`SharedArchiveView`] around ciphertext — that would serve encrypted bytes.
pub struct PackSourceReader {
    pack: Box<dyn PackSource>,
    base: u64,
    len: u64,
    pos: u64,
}

impl PackSourceReader {
    pub fn new(pack: Box<dyn PackSource>, base: u64, len: u64) -> Self {
        Self {
            pack,
            base,
            len,
            pos: 0,
        }
    }
}

impl Read for PackSourceReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.len || buf.is_empty() {
            return Ok(0);
        }
        let want = ((self.len - self.pos) as usize).min(buf.len());
        let data = self
            .pack
            .read_at(self.base + self.pos, want)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let n = data.len().min(want);
        buf[..n].copy_from_slice(&data[..n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for PackSourceReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::End(o) => self.len as i64 + o,
            SeekFrom::Current(o) => self.pos as i64 + o,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

/// AES-CBC view over ciphertext with range decrypt (CBC IV from previous block).
pub struct AesPackSource {
    inner: Box<dyn PackSource>,
    plain_size: u64,
    key: [u8; 32],
    iv: [u8; 16],
}

impl AesPackSource {
    pub fn new(
        inner: Box<dyn PackSource>,
        properties: Option<&[u8]>,
        password: &str,
        plain_size: Option<u64>,
    ) -> Result<Self> {
        let props = parse_aes_properties(properties)?;
        let password_bytes: Vec<u8> = password
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let key = calculate_7z_key(&password_bytes, props.cycles, &props.salt)?;
        let plain_size = plain_size.unwrap_or_else(|| inner.size());
        let _ = properties;
        Ok(Self {
            inner,
            plain_size,
            key,
            iv: props.iv,
        })
    }
}

impl PackSource for AesPackSource {
    fn size(&self) -> u64 {
        self.plain_size
    }
    fn read_at(&self, offset: u64, size: usize) -> Result<Vec<u8>> {
        if size == 0 || offset >= self.plain_size {
            return Ok(vec![]);
        }
        let size = size.min((self.plain_size - offset) as usize);
        let block = 16u64;
        let start_block = offset / block;
        let end = offset + size as u64;
        let end_block = end.div_ceil(block);
        let ct_start = if start_block == 0 {
            0
        } else {
            (start_block - 1) * block
        };
        let ct_end = end_block * block;
        let mut ct = self.inner.read_at(ct_start, (ct_end - ct_start) as usize)?;
        if (ct.len() as u64) < ct_end - ct_start {
            ct.resize((ct_end - ct_start) as usize, 0);
        }
        if ct.len() % 16 != 0 {
            ct.resize(ct.len() + (16 - ct.len() % 16), 0);
        }
        let (block_iv, dec_ct, plain_off): ([u8; 16], &[u8], usize) = if start_block == 0 {
            (self.iv, &ct[..], offset as usize)
        } else {
            let mut iv = [0u8; 16];
            iv.copy_from_slice(&ct[..16]);
            (iv, &ct[16..], (offset - start_block * block) as usize)
        };
        if dec_ct.is_empty() {
            return Ok(vec![]);
        }
        let mut data = dec_ct.to_vec();
        if data.len() % 16 != 0 {
            data.resize(data.len() + (16 - data.len() % 16), 0);
        }
        let dec = Aes256CbcDec::new_from_slices(&self.key, &block_iv)
            .map_err(|e| SevenZipError::Msg(format!("AES key/iv: {e}")))?;
        let plain = dec
            .decrypt_padded_mut::<NoPadding>(&mut data)
            .map_err(|e| SevenZipError::Msg(format!("AES decrypt: {e}")))?;
        let end = (plain_off + size).min(plain.len());
        if plain_off >= plain.len() {
            return Ok(vec![]);
        }
        Ok(plain[plain_off..end].to_vec())
    }
}

pub fn make_pack_source(
    folder: &Folder,
    packed: Box<dyn PackSource>,
    password: Option<&str>,
) -> Result<(Folder, Box<dyn PackSource>)> {
    if folder.coders.is_empty() {
        return Err(SevenZipError::Msg("Folder has no coders".into()));
    }
    if folder.coders[0].method.as_slice() != METHOD_AES {
        return Ok((folder.clone(), packed));
    }
    let password = password.ok_or_else(|| {
        SevenZipError::Msg("7z archive contents are encrypted; pass --password".into())
    })?;
    let intermediate = folder
        .unpack_sizes
        .first()
        .copied()
        .unwrap_or_else(|| packed.size());
    let aes = AesPackSource::new(
        packed,
        folder.coders[0].properties.as_deref(),
        password,
        Some(intermediate),
    )?;
    let rest = &folder.coders[1..];
    if rest.is_empty() {
        let content = Folder {
            coders: vec![Coder {
                method: METHOD_COPY.to_vec(),
                num_in_streams: 1,
                num_out_streams: 1,
                properties: None,
            }],
            bind_pairs: vec![],
            packed_indices: vec![],
            unpack_sizes: vec![aes.size()],
            has_crc: folder.has_crc,
            crc: folder.crc,
        };
        return Ok((content, Box::new(aes)));
    }
    let content_unpack = if folder.unpack_sizes.len() > 1 {
        folder.unpack_sizes[1..].to_vec()
    } else {
        vec![folder.get_unpack_size()]
    };
    let aes_in = folder.coders[0].num_in_streams;
    let aes_out = folder.coders[0].num_out_streams;
    let (new_binds, new_packed) =
        if rest.len() == 1 && rest[0].num_in_streams == 1 && rest[0].num_out_streams == 1 {
            (vec![], vec![])
        } else {
            let binds = folder
                .bind_pairs
                .iter()
                .filter(|(_, oout)| *oout >= aes_out)
                .map(|(iin, oout)| (iin.saturating_sub(aes_in), oout.saturating_sub(aes_out)))
                .collect();
            let packed = folder
                .packed_indices
                .iter()
                .filter(|i| **i >= aes_in)
                .map(|i| i.saturating_sub(aes_in))
                .collect();
            (binds, packed)
        };
    let content = Folder {
        coders: rest.to_vec(),
        bind_pairs: new_binds,
        packed_indices: new_packed,
        unpack_sizes: if content_unpack.is_empty() {
            vec![folder.get_unpack_size()]
        } else {
            content_unpack
        },
        has_crc: folder.has_crc,
        crc: folder.crc,
    };
    Ok((content, Box::new(aes)))
}

// ---------------------------------------------------------------------------
// Public decompress entry points
// ---------------------------------------------------------------------------

pub fn decompress_folder(
    folder: &Folder,
    packed: &[u8],
    password: Option<&str>,
) -> Result<Vec<u8>> {
    decompress_folder_source(
        folder,
        Box::new(BytesPackSource::new(packed.to_vec())),
        password,
        None,
    )
}

pub fn decompress_folder_source(
    folder: &Folder,
    packed: Box<dyn PackSource>,
    password: Option<&str>,
    pack_stream_sizes: Option<&[u64]>,
) -> Result<Vec<u8>> {
    let (content_folder, content_source) = make_pack_source(folder, packed, password)?;
    if content_folder.coders.is_empty() {
        return Err(SevenZipError::Msg("Folder has no coders".into()));
    }
    let unpack_size = content_folder.get_unpack_size() as usize;
    let coders = &content_folder.coders;

    // Multi-coder / BCJ2 path.
    if coders.len() > 1
        && (coders.iter().any(|c| c.method.as_slice() == METHOD_BCJ2)
            || content_folder.packed_indices.len() > 1)
    {
        let blob = content_source.as_bytes()?;
        let sizes: Vec<u64> = if let Some(s) = pack_stream_sizes {
            s.to_vec()
        } else if content_folder.packed_indices.len() > 1 {
            return Err(SevenZipError::Msg(
                "pack_stream_sizes required for multi-pack folder".into(),
            ));
        } else {
            vec![blob.len() as u64]
        };
        let mut streams = Vec::new();
        let mut off = 0usize;
        for &sz in &sizes {
            let end = off + sz as usize;
            if end > blob.len() {
                return Err(SevenZipError::Msg(
                    "pack stream sizes exceed packed data".into(),
                ));
            }
            streams.push(blob[off..end].to_vec());
            off = end;
        }
        return decompress_complex_folder(&content_folder, &streams);
    }

    let content_packed = content_source.as_bytes()?;

    if coders.len() == 1 && coders[0].method.as_slice() == METHOD_COPY {
        if content_packed.len() < unpack_size {
            return Err(SevenZipError::Msg(
                "Copy-coded data shorter than unpack size".into(),
            ));
        }
        return Ok(content_packed[..unpack_size].to_vec());
    }

    if (coders.len() == 1
        && (coders[0].method.as_slice() == METHOD_LZMA
            || coders[0].method.as_slice() == METHOD_LZMA2))
        || coders_are_native_lzma_chain(coders)
    {
        return lzma_decompress_chain(coders, &content_packed, unpack_size);
    }

    if coders.len() != 1 {
        return Err(SevenZipError::Msg(format!(
            "Unsupported multi-coder folder: {:?}",
            coders
                .iter()
                .map(|c| hex::encode_simple(&c.method))
                .collect::<Vec<_>>()
        )));
    }

    let coder = &coders[0];
    let method = coder.method.as_slice();
    if method == METHOD_DEFLATE {
        let mut d = flate2::read::DeflateDecoder::new(&content_packed[..]);
        let mut buf = Vec::with_capacity(unpack_size);
        d.read_to_end(&mut buf)
            .map_err(|e| SevenZipError::Msg(format!("deflate: {e}")))?;
        buf.truncate(unpack_size);
        return Ok(buf);
    }
    if method == METHOD_BZIP2 {
        let mut d = bzip2::read::BzDecoder::new(&content_packed[..]);
        let mut buf = Vec::with_capacity(unpack_size);
        d.read_to_end(&mut buf)
            .map_err(|e| SevenZipError::Msg(format!("bzip2: {e}")))?;
        buf.truncate(unpack_size);
        return Ok(buf);
    }
    Err(SevenZipError::Msg(format!(
        "Unsupported 7z method: {:02x?}",
        method
    )))
}

/// Legacy AES strip used by header decoding.
#[allow(dead_code)]
pub fn prepare_folder_packed(
    folder: &Folder,
    packed: &[u8],
    password: Option<&str>,
) -> Result<(Folder, Vec<u8>)> {
    let (content, source) = make_pack_source(
        folder,
        Box::new(BytesPackSource::new(packed.to_vec())),
        password,
    )?;
    Ok((content, source.as_bytes()?))
}

// ---------------------------------------------------------------------------
// BCJ2 + complex folders
// ---------------------------------------------------------------------------

const BCJ2_TOP: u32 = 1 << 24;
const BCJ2_NUM_BIT_MODEL_TOTAL_BITS: u32 = 11;
const BCJ2_BIT_MODEL_TOTAL: u32 = 1 << BCJ2_NUM_BIT_MODEL_TOTAL_BITS;
const BCJ2_NUM_MOVE_BITS: u32 = 5;
const BCJ2_STREAM_MAIN: usize = 0;
const BCJ2_STREAM_CALL: usize = 1;
#[allow(dead_code)]
const BCJ2_STREAM_JUMP: usize = 2;
const BCJ2_STREAM_RC: usize = 3;

pub fn bcj2_decode(
    main: &[u8],
    call: &[u8],
    jump: &[u8],
    rc: &[u8],
    out_size: usize,
) -> Result<Vec<u8>> {
    let streams: [&[u8]; 4] = [main, call, jump, rc];
    let lims = [main.len(), call.len(), jump.len(), rc.len()];
    let mut pos = [0usize; 4];
    let mut dest = Vec::with_capacity(out_size);
    let mut ip: u32 = 0;
    let mut temp: u32 = 0;
    let mut range: u32 = 0;
    let mut code: u32 = 0;
    let mut probs = vec![BCJ2_BIT_MODEL_TOTAL >> 1; 2 + 256];

    let read_be32 = |stream: usize, pos: &mut [usize; 4]| -> Result<u32> {
        let i = pos[stream];
        if i + 4 > lims[stream] {
            return Err(SevenZipError::Msg(format!(
                "BCJ2 stream {stream} truncated"
            )));
        }
        pos[stream] = i + 4;
        Ok(u32::from_be_bytes([
            streams[stream][i],
            streams[stream][i + 1],
            streams[stream][i + 2],
            streams[stream][i + 3],
        ]))
    };

    // Init range coder from first 5 RC bytes.
    while range != 5 {
        if range == 1 && code != 0 {
            return Err(SevenZipError::Msg("BCJ2 RC data error during init".into()));
        }
        if pos[BCJ2_STREAM_RC] >= lims[BCJ2_STREAM_RC] {
            return Err(SevenZipError::Msg("BCJ2 RC truncated during init".into()));
        }
        code = (code << 8) | u32::from(streams[BCJ2_STREAM_RC][pos[BCJ2_STREAM_RC]]);
        pos[BCJ2_STREAM_RC] += 1;
        range += 1;
    }
    if code == 0xFFFF_FFFF {
        return Err(SevenZipError::Msg("BCJ2 invalid initial code".into()));
    }
    range = 0xFFFF_FFFF;

    while dest.len() < out_size {
        if range < BCJ2_TOP {
            if pos[BCJ2_STREAM_RC] >= lims[BCJ2_STREAM_RC] {
                break;
            }
            range <<= 8;
            code = (code << 8) | u32::from(streams[BCJ2_STREAM_RC][pos[BCJ2_STREAM_RC]]);
            pos[BCJ2_STREAM_RC] += 1;
        }
        if pos[BCJ2_STREAM_MAIN] >= lims[BCJ2_STREAM_MAIN] {
            break;
        }
        let b = streams[BCJ2_STREAM_MAIN][pos[BCJ2_STREAM_MAIN]];
        pos[BCJ2_STREAM_MAIN] += 1;
        dest.push(b);
        ip = ip.wrapping_add(1);
        let v = (temp << 24) | u32::from(b);
        temp = v;

        if ((b as u32).wrapping_add(0x100 - 0xE8) & 0xFE) != 0
            && (v.wrapping_sub((0x0F << 24) + 0x80) & (((1u32 << 28) - 0x1) << 4)) != 0
        {
            continue;
        }

        let c_bit = ((v.wrapping_add(0x17) >> 6) & 1) as usize;
        let prob_idx = (((0u32.wrapping_sub(c_bit as u32)) & ((v >> 24) & 0xFF))
            + c_bit as u32
            + ((v >> 5) & 1)) as usize;
        let ttt = probs[prob_idx];
        let bound = (range >> BCJ2_NUM_BIT_MODEL_TOTAL_BITS) * ttt;
        if code < bound {
            range = bound;
            probs[prob_idx] = (ttt + ((BCJ2_BIT_MODEL_TOTAL - ttt) >> BCJ2_NUM_MOVE_BITS)) & 0xFFFF;
            continue;
        }
        range -= bound;
        code -= bound;
        probs[prob_idx] = (ttt - (ttt >> BCJ2_NUM_MOVE_BITS)) & 0xFFFF;

        let cj = (((v.wrapping_add(0x57) >> 6) & 1) as usize) + BCJ2_STREAM_CALL;
        let mut val = read_be32(cj, &mut pos)?;
        val = val.wrapping_sub(ip.wrapping_add(4));
        ip = ip.wrapping_add(4);
        dest.push((val & 0xFF) as u8);
        dest.push(((val >> 8) & 0xFF) as u8);
        dest.push(((val >> 16) & 0xFF) as u8);
        dest.push(((val >> 24) & 0xFF) as u8);
        temp = val >> 24;
    }

    if dest.len() < out_size {
        return Err(SevenZipError::Msg(format!(
            "BCJ2 produced {} bytes but expected {out_size}",
            dest.len()
        )));
    }
    dest.truncate(out_size);
    Ok(dest)
}

fn decompress_single_coder(coder: &Coder, packed: &[u8], unpack_size: usize) -> Result<Vec<u8>> {
    let method = coder.method.as_slice();
    if method == METHOD_COPY {
        if packed.len() < unpack_size {
            return Err(SevenZipError::Msg(
                "Copy-coded data shorter than unpack size".into(),
            ));
        }
        return Ok(packed[..unpack_size].to_vec());
    }
    if method == METHOD_LZMA
        || method == METHOD_LZMA2
        || crate::parse::is_native_lzma_filter_method(method)
    {
        return lzma_decompress_chain(std::slice::from_ref(coder), packed, unpack_size);
    }
    if method == METHOD_DEFLATE {
        let mut d = flate2::read::DeflateDecoder::new(packed);
        let mut buf = Vec::with_capacity(unpack_size);
        d.read_to_end(&mut buf)
            .map_err(|e| SevenZipError::Msg(format!("deflate: {e}")))?;
        buf.truncate(unpack_size);
        return Ok(buf);
    }
    if method == METHOD_BZIP2 {
        let mut d = bzip2::read::BzDecoder::new(packed);
        let mut buf = Vec::with_capacity(unpack_size);
        d.read_to_end(&mut buf)
            .map_err(|e| SevenZipError::Msg(format!("bzip2: {e}")))?;
        buf.truncate(unpack_size);
        return Ok(buf);
    }
    Err(SevenZipError::Msg(format!(
        "Unsupported intermediate 7z method: {:02x?}",
        method
    )))
}

pub fn decompress_complex_folder(folder: &Folder, pack_streams: &[Vec<u8>]) -> Result<Vec<u8>> {
    if folder.coders.is_empty() {
        return Err(SevenZipError::Msg("Folder has no coders".into()));
    }
    let total_in = folder.total_in_streams() as usize;
    let total_out = folder.total_out_streams() as usize;
    let mut in_base = Vec::new();
    let mut out_base = Vec::new();
    let mut ii = 0usize;
    let mut oo = 0usize;
    for coder in &folder.coders {
        in_base.push(ii);
        out_base.push(oo);
        ii += coder.num_in_streams as usize;
        oo += coder.num_out_streams as usize;
    }

    let mut in_data: Vec<Option<Vec<u8>>> = vec![None; total_in];
    let mut out_data: Vec<Option<Vec<u8>>> = vec![None; total_out];

    let mut packed_indices: Vec<u64> = folder.packed_indices.clone();
    if packed_indices.is_empty() && pack_streams.len() == 1 {
        let used: std::collections::HashSet<u64> =
            folder.bind_pairs.iter().map(|(i, _)| *i).collect();
        for i in 0..total_in as u64 {
            if !used.contains(&i) {
                packed_indices = vec![i];
                break;
            }
        }
    }
    for (pack_i, &glob_in) in packed_indices.iter().enumerate() {
        if pack_i >= pack_streams.len() {
            return Err(SevenZipError::Msg(
                "Missing pack stream for multi-coder folder".into(),
            ));
        }
        in_data[glob_in as usize] = Some(pack_streams[pack_i].clone());
    }

    let mut remaining: std::collections::HashSet<usize> = (0..folder.coders.len()).collect();
    let mut progress = true;
    while !remaining.is_empty() && progress {
        progress = false;
        for &ci in remaining.clone().iter() {
            let coder = &folder.coders[ci];
            let mut inputs = Vec::new();
            let mut ready = true;
            for j in 0..coder.num_in_streams as usize {
                let gin = in_base[ci] + j;
                let bound_from = folder
                    .bind_pairs
                    .iter()
                    .find(|(iin, _)| *iin as usize == gin)
                    .map(|(_, oout)| *oout as usize);
                if let Some(oout) = bound_from {
                    match &out_data[oout] {
                        Some(d) => inputs.push(d.clone()),
                        None => {
                            ready = false;
                            break;
                        }
                    }
                } else {
                    match &in_data[gin] {
                        Some(d) => inputs.push(d.clone()),
                        None => {
                            ready = false;
                            break;
                        }
                    }
                }
            }
            if !ready {
                continue;
            }
            if coder.method.as_slice() == METHOD_BCJ2 {
                if inputs.len() != 4 {
                    return Err(SevenZipError::Msg(format!(
                        "BCJ2 expects 4 inputs, got {}",
                        inputs.len()
                    )));
                }
                let out_sz = folder.unpack_sizes[out_base[ci]] as usize;
                out_data[out_base[ci]] = Some(bcj2_decode(
                    &inputs[0], &inputs[1], &inputs[2], &inputs[3], out_sz,
                )?);
            } else {
                if coder.num_in_streams != 1 || coder.num_out_streams != 1 {
                    return Err(SevenZipError::Msg(format!(
                        "Unsupported complex intermediate coder {:02x?}",
                        coder.method
                    )));
                }
                let out_sz = folder.unpack_sizes[out_base[ci]] as usize;
                out_data[out_base[ci]] = Some(decompress_single_coder(coder, &inputs[0], out_sz)?);
            }
            remaining.remove(&ci);
            progress = true;
        }
    }
    if !remaining.is_empty() {
        return Err(SevenZipError::Msg(format!(
            "Could not resolve coder graph; remaining={remaining:?}"
        )));
    }
    let used_outs: std::collections::HashSet<usize> =
        folder.bind_pairs.iter().map(|(_, o)| *o as usize).collect();
    let primary = (0..total_out).find(|i| !used_outs.contains(i));
    let primary = primary
        .ok_or_else(|| SevenZipError::Msg("No primary output stream in complex folder".into()))?;
    out_data[primary]
        .take()
        .ok_or_else(|| SevenZipError::Msg("Primary output missing".into()))
}

// ---------------------------------------------------------------------------
// LZMA multi-filter chain (BCJ/Delta + LZMA/LZMA2)
// ---------------------------------------------------------------------------

// lzma-sys does not always export DELTA; value matches xz-utils api/lzma/delta.h
const LZMA_FILTER_DELTA: lzma_sys::lzma_vli = 0x03;

fn method_to_lzma_filter_id(method: &[u8]) -> Option<lzma_sys::lzma_vli> {
    if method == METHOD_LZMA2 {
        Some(lzma_sys::LZMA_FILTER_LZMA2)
    } else if method == METHOD_LZMA {
        Some(lzma_sys::LZMA_FILTER_LZMA1)
    } else if method == METHOD_DELTA {
        Some(LZMA_FILTER_DELTA)
    } else if method == METHOD_BCJ || method == METHOD_BCJ_X86 {
        Some(lzma_sys::LZMA_FILTER_X86)
    } else if method == METHOD_BCJ_PPC {
        Some(lzma_sys::LZMA_FILTER_POWERPC)
    } else if method == METHOD_BCJ_IA64 {
        Some(lzma_sys::LZMA_FILTER_IA64)
    } else if method == METHOD_BCJ_ARM {
        Some(lzma_sys::LZMA_FILTER_ARM)
    } else if method == METHOD_BCJ_ARMT {
        Some(lzma_sys::LZMA_FILTER_ARMTHUMB)
    } else if method == METHOD_BCJ_SPARC {
        Some(lzma_sys::LZMA_FILTER_SPARC)
    } else {
        None
    }
}

fn lzma_decompress_chain(coders: &[Coder], packed: &[u8], unpack_size: usize) -> Result<Vec<u8>> {
    use std::os::raw::c_void;

    // 7z pack→unpack order; liblzma wants reverse (prepend).
    let mut filter_coders: Vec<&Coder> = coders
        .iter()
        .filter(|c| c.method.as_slice() != METHOD_COPY)
        .collect();
    if filter_coders.is_empty() {
        return Err(SevenZipError::Msg("Empty native filter chain".into()));
    }
    // Prepend: reverse for liblzma
    filter_coders.reverse();

    unsafe {
        let mut filters: Vec<lzma_sys::lzma_filter> = Vec::with_capacity(filter_coders.len() + 1);
        let mut opts_ptrs: Vec<*mut c_void> = Vec::new();

        for coder in &filter_coders {
            let filter_id = method_to_lzma_filter_id(coder.method.as_slice()).ok_or_else(|| {
                SevenZipError::Msg(format!(
                    "Not a native lzma-chain coder: {:02x?}",
                    coder.method
                ))
            })?;
            let props = coder.properties.as_deref().unwrap_or(&[]);
            let mut filter = lzma_sys::lzma_filter {
                id: filter_id,
                options: std::ptr::null_mut(),
            };
            // LZMA2 folder-level props: single dict_size byte is fine for lzma_properties_decode.
            if !props.is_empty() || filter_id == lzma_sys::LZMA_FILTER_LZMA1 {
                let ret = lzma_sys::lzma_properties_decode(
                    &mut filter,
                    std::ptr::null(),
                    props.as_ptr(),
                    props.len(),
                );
                if ret != lzma_sys::LZMA_OK {
                    free_opts(&opts_ptrs);
                    return Err(SevenZipError::Msg(format!(
                        "lzma_properties_decode failed: {ret}"
                    )));
                }
            }
            if !filter.options.is_null() {
                opts_ptrs.push(filter.options);
            }
            filters.push(filter);
        }
        filters.push(lzma_sys::lzma_filter {
            id: lzma_sys::LZMA_VLI_UNKNOWN,
            options: std::ptr::null_mut(),
        });

        let mut out = vec![0u8; unpack_size.max(1)];
        let mut in_pos: usize = 0;
        let mut out_pos: usize = 0;
        let ret = lzma_sys::lzma_raw_buffer_decode(
            filters.as_ptr(),
            std::ptr::null(),
            packed.as_ptr(),
            &mut in_pos,
            packed.len(),
            out.as_mut_ptr(),
            &mut out_pos,
            out.len(),
        );
        free_opts(&opts_ptrs);
        if ret != lzma_sys::LZMA_OK && ret != lzma_sys::LZMA_STREAM_END {
            return lzma_stream_decode_chain(coders, packed, unpack_size);
        }
        out.truncate(out_pos.min(unpack_size));
        if out.len() < unpack_size {
            return lzma_stream_decode_chain(coders, packed, unpack_size);
        }
        Ok(out)
    }
}

fn free_opts(opts: &[*mut std::os::raw::c_void]) {
    for &p in opts {
        if !p.is_null() {
            unsafe {
                libc::free(p);
            }
        }
    }
}

fn lzma_stream_decode_chain(
    coders: &[Coder],
    packed: &[u8],
    unpack_size: usize,
) -> Result<Vec<u8>> {
    use std::os::raw::c_void;

    let mut filter_coders: Vec<&Coder> = coders
        .iter()
        .filter(|c| c.method.as_slice() != METHOD_COPY)
        .collect();
    filter_coders.reverse();

    unsafe {
        let mut filters: Vec<lzma_sys::lzma_filter> = Vec::with_capacity(filter_coders.len() + 1);
        let mut opts_ptrs: Vec<*mut c_void> = Vec::new();
        for coder in &filter_coders {
            let filter_id = method_to_lzma_filter_id(coder.method.as_slice()).ok_or_else(|| {
                SevenZipError::Msg(format!(
                    "Not a native lzma-chain coder: {:02x?}",
                    coder.method
                ))
            })?;
            let props = coder.properties.as_deref().unwrap_or(&[]);
            let mut filter = lzma_sys::lzma_filter {
                id: filter_id,
                options: std::ptr::null_mut(),
            };
            if !props.is_empty() || filter_id == lzma_sys::LZMA_FILTER_LZMA1 {
                let ret = lzma_sys::lzma_properties_decode(
                    &mut filter,
                    std::ptr::null(),
                    props.as_ptr(),
                    props.len(),
                );
                if ret != lzma_sys::LZMA_OK {
                    free_opts(&opts_ptrs);
                    return Err(SevenZipError::Msg(format!(
                        "lzma_properties_decode failed: {ret}"
                    )));
                }
            }
            if !filter.options.is_null() {
                opts_ptrs.push(filter.options);
            }
            filters.push(filter);
        }
        filters.push(lzma_sys::lzma_filter {
            id: lzma_sys::LZMA_VLI_UNKNOWN,
            options: std::ptr::null_mut(),
        });

        let mut stream: lzma_sys::lzma_stream = std::mem::zeroed();
        let ret = lzma_sys::lzma_raw_decoder(&mut stream, filters.as_ptr());
        if ret != lzma_sys::LZMA_OK {
            free_opts(&opts_ptrs);
            return Err(SevenZipError::Msg(format!("lzma_raw_decoder: {ret}")));
        }

        let mut out = vec![0u8; unpack_size];
        stream.next_in = packed.as_ptr();
        stream.avail_in = packed.len();
        stream.next_out = out.as_mut_ptr();
        stream.avail_out = out.len();

        let mut action = lzma_sys::LZMA_RUN;
        loop {
            let ret = lzma_sys::lzma_code(&mut stream, action);
            if ret == lzma_sys::LZMA_STREAM_END {
                break;
            }
            if ret != lzma_sys::LZMA_OK {
                lzma_sys::lzma_end(&mut stream);
                free_opts(&opts_ptrs);
                return Err(SevenZipError::Msg(format!("lzma_code: {ret}")));
            }
            if stream.avail_out == 0 {
                break;
            }
            if stream.avail_in == 0 {
                action = lzma_sys::LZMA_FINISH;
            }
        }
        let produced = stream.total_out as usize;
        lzma_sys::lzma_end(&mut stream);
        free_opts(&opts_ptrs);
        out.truncate(produced.min(unpack_size));
        if out.len() < unpack_size {
            return Err(SevenZipError::Msg(format!(
                "LZMA decompressed {} bytes but expected {unpack_size}",
                out.len()
            )));
        }
        Ok(out)
    }
}

fn start_lzma2_live_cursor(
    coders: &[Coder],
    packed_pos: u64,
    unpacked_pos: u64,
) -> Result<LiveLzma2Cursor> {
    use std::os::raw::c_void;

    let mut filter_coders: Vec<&Coder> = coders
        .iter()
        .filter(|c| c.method.as_slice() != METHOD_COPY)
        .collect();
    if filter_coders.is_empty() {
        return Err(SevenZipError::Msg("Empty native filter chain".into()));
    }
    // liblzma raw decoder wants encoder order: filters then LZMA1/2 last.
    // 7z may store BCJ-first (`-m0=BCJ -m1=LZMA2`) or pack→unpack (LZMA2 first).
    let compressor_last = filter_coders.last().is_some_and(|c| {
        let m = c.method.as_slice();
        m == METHOD_LZMA || m == METHOD_LZMA2
    });
    if !compressor_last {
        filter_coders.reverse();
    }

    unsafe {
        let mut filters: Vec<lzma_sys::lzma_filter> = Vec::with_capacity(filter_coders.len() + 1);
        let mut opts_ptrs: Vec<*mut c_void> = Vec::new();
        for c in &filter_coders {
            let filter_id = method_to_lzma_filter_id(c.method.as_slice()).ok_or_else(|| {
                SevenZipError::Msg(format!("Not a native lzma-chain coder: {:02x?}", c.method))
            })?;
            let props = c.properties.as_deref().unwrap_or(&[]);
            let mut filter = lzma_sys::lzma_filter {
                id: filter_id,
                options: std::ptr::null_mut(),
            };
            if !props.is_empty() || filter_id == lzma_sys::LZMA_FILTER_LZMA1 {
                let ret = lzma_sys::lzma_properties_decode(
                    &mut filter,
                    std::ptr::null(),
                    props.as_ptr(),
                    props.len(),
                );
                if ret != lzma_sys::LZMA_OK {
                    free_opts(&opts_ptrs);
                    return Err(SevenZipError::Msg(format!(
                        "lzma_properties_decode failed: {ret}"
                    )));
                }
            }
            if !filter.options.is_null() {
                opts_ptrs.push(filter.options);
            }
            filters.push(filter);
        }
        filters.push(lzma_sys::lzma_filter {
            id: lzma_sys::LZMA_VLI_UNKNOWN,
            options: std::ptr::null_mut(),
        });

        let mut stream: lzma_sys::lzma_stream = std::mem::zeroed();
        let ret = lzma_sys::lzma_raw_decoder(&mut stream, filters.as_ptr());
        if ret != lzma_sys::LZMA_OK {
            free_opts(&opts_ptrs);
            return Err(SevenZipError::Msg(format!("lzma_raw_decoder: {ret}")));
        }
        Ok(LiveLzma2Cursor {
            stream,
            opts_ptrs,
            unpacked_pos,
            abs_packed_pos: packed_pos,
        })
    }
}

// ---------------------------------------------------------------------------
// LZMA2 chunk-indexed random access (Python Lzma2RandomAccessDecoder parity)
// ---------------------------------------------------------------------------

/// One LZMA2 chunk in a folder's packed stream.
#[derive(Debug, Clone)]
#[allow(dead_code)] // packed_size / control / is_lzma used by indexer + tests
pub struct Lzma2ChunkIndex {
    pub index: usize,
    pub packed_offset: usize,
    pub packed_size: usize,
    pub unpacked_offset: u64,
    pub unpacked_size: usize,
    pub control: u8,
    pub is_lzma: bool,
    /// Dictionary reset: may be decoded independently.
    pub independent: bool,
}

fn coder_is_bcj_or_delta(coder: &Coder) -> bool {
    let m = coder.method.as_slice();
    m == METHOD_DELTA
        || m == METHOD_BCJ
        || m == METHOD_BCJ_X86
        || m == METHOD_BCJ_PPC
        || m == METHOD_BCJ_IA64
        || m == METHOD_BCJ_ARM
        || m == METHOD_BCJ_ARMT
        || m == METHOD_BCJ_SPARC
}

/// AES-stripped content is a single LZMA2 coder or a native BCJ/Delta+LZMA2 chain.
fn lzma2_progressive_content_coders(coders: &[Coder]) -> bool {
    if coders.is_empty() {
        return false;
    }
    if coders.iter().any(|c| c.method.as_slice() == METHOD_BCJ2) {
        return false;
    }
    if !coders.iter().any(|c| c.method.as_slice() == METHOD_LZMA2) {
        return false;
    }
    if coders.len() == 1 {
        return true;
    }
    coders_are_native_lzma_chain(coders)
}

/// True when the folder (after AES strip) can use [`Lzma2RandomAccessDecoder`].
///
/// Size is not considered: small folders still use the decoder with a full
/// unpack cache. BCJ2 / multi-pack remain residual.
pub fn lzma2_folder_can_use_decoder(folder: &Folder) -> bool {
    if folder.has_bcj2() || folder.packed_indices.len() > 1 {
        return false;
    }
    lzma2_progressive_content_coders(folder.content_coders())
}

/// True when `open` should return a progressive [`Lzma2MemberReader`].
///
/// AES+LZMA2 and native BCJ/Delta+LZMA2 (LZMA2 compressor, not LZMA1-only)
/// above [`SMALL_FOLDER_FULL_CACHE`]. BCJ2 / multi-pack stay full-folder.
pub fn lzma2_folder_uses_progressive(folder: &Folder, folder_unpack: u64) -> bool {
    lzma2_folder_can_use_decoder(folder) && folder_unpack > SMALL_FOLDER_FULL_CACHE
}

/// Sliding packed-input window (never treat this boundary as pack EOF).
pub const PACKED_INPUT_WINDOW: usize = 64 * 1024;

/// Walk an LZMA2 packed stream and record chunk boundaries without decompressing.
#[allow(dead_code)] // tests + `Lzma2RandomAccessDecoder::with_chunk_size` Vec wrapper
pub fn index_lzma2_chunks(packed: &[u8]) -> Result<Vec<Lzma2ChunkIndex>> {
    struct SlicePack<'a>(&'a [u8]);
    impl PackSource for SlicePack<'_> {
        fn size(&self) -> u64 {
            self.0.len() as u64
        }
        fn read_at(&self, offset: u64, size: usize) -> Result<Vec<u8>> {
            let off = offset as usize;
            if size == 0 || off >= self.0.len() {
                return Ok(vec![]);
            }
            let end = (off + size).min(self.0.len());
            Ok(self.0[off..end].to_vec())
        }
    }
    index_lzma2_chunks_from_pack(&SlicePack(packed))
}

/// Index LZMA2 chunks from a pack via 64 KiB windows (never `as_bytes` of the pack).
pub fn index_lzma2_chunks_from_pack(pack: &dyn PackSource) -> Result<Vec<Lzma2ChunkIndex>> {
    struct PackCursor<'a> {
        pack: &'a dyn PackSource,
        pack_size: u64,
        abs: u64,
        window: Vec<u8>,
        win_start: u64,
    }
    impl PackCursor<'_> {
        fn remaining_in_window(&self) -> usize {
            if self.abs < self.win_start {
                return 0;
            }
            let off = (self.abs - self.win_start) as usize;
            self.window.len().saturating_sub(off)
        }
        fn ensure(&mut self, n: usize) -> Result<()> {
            if self.abs >= self.pack_size {
                return Ok(());
            }
            if self.remaining_in_window() >= n {
                return Ok(());
            }
            let have = self.remaining_in_window();
            if have > 0 {
                let off = (self.abs - self.win_start) as usize;
                let mut rest = self.window.split_off(off);
                let more = self
                    .pack
                    .read_at(self.abs + rest.len() as u64, PACKED_INPUT_WINDOW)?;
                rest.extend_from_slice(&more);
                self.window = rest;
                self.win_start = self.abs;
            } else {
                let nread = ((self.pack_size - self.abs) as usize).min(PACKED_INPUT_WINDOW);
                self.window = self.pack.read_at(self.abs, nread)?;
                self.win_start = self.abs;
            }
            Ok(())
        }
        fn read_u8(&mut self) -> Result<Option<u8>> {
            if self.abs >= self.pack_size {
                return Ok(None);
            }
            self.ensure(1)?;
            let off = (self.abs - self.win_start) as usize;
            if off >= self.window.len() {
                return Ok(None);
            }
            let b = self.window[off];
            self.abs += 1;
            Ok(Some(b))
        }
        fn read_exact(&mut self, n: usize) -> Result<Vec<u8>> {
            self.ensure(n)?;
            let off = (self.abs - self.win_start) as usize;
            if off + n > self.window.len() {
                return Err(SevenZipError::Msg("Truncated LZMA2 chunk header".into()));
            }
            let bytes = self.window[off..off + n].to_vec();
            self.abs += n as u64;
            Ok(bytes)
        }
        fn skip(&mut self, n: usize) -> Result<()> {
            let new_abs = self.abs.saturating_add(n as u64);
            if new_abs > self.pack_size {
                return Err(SevenZipError::Msg("Truncated LZMA2 compressed data".into()));
            }
            self.abs = new_abs;
            Ok(())
        }
    }

    let mut cur = PackCursor {
        pack,
        pack_size: pack.size(),
        abs: 0,
        window: Vec::new(),
        win_start: 0,
    };
    let mut unpacked_pos = 0u64;
    let mut chunks = Vec::new();
    let mut need_dict_reset = true;
    let mut chunk_index = 0usize;

    loop {
        let chunk_start = cur.abs as usize;
        let Some(control) = cur.read_u8()? else {
            break;
        };
        if control == 0 {
            break;
        }

        let dict_reset = control >= 0xe0 || control == 0x01;
        if !dict_reset && need_dict_reset {
            return Err(SevenZipError::Msg(format!(
                "LZMA2 stream missing dictionary reset at offset {chunk_start}"
            )));
        }
        if dict_reset {
            need_dict_reset = false;
        }

        if control >= 0x80 {
            let hdr = cur.read_exact(4)?;
            let unpacked_size = (((control & 0x1f) as usize) << 16)
                + ((hdr[0] as usize) << 8)
                + hdr[1] as usize
                + 1;
            let compressed_size = ((hdr[2] as usize) << 8) + hdr[3] as usize + 1;
            if control >= 0xc0 {
                let _props = cur.read_exact(1)?;
            }
            cur.skip(compressed_size)?;
            let independent = control >= 0xe0 || control == 0x01;
            chunks.push(Lzma2ChunkIndex {
                index: chunk_index,
                packed_offset: chunk_start,
                packed_size: cur.abs as usize - chunk_start,
                unpacked_offset: unpacked_pos,
                unpacked_size,
                control,
                is_lzma: true,
                independent,
            });
            unpacked_pos += unpacked_size as u64;
        } else if control == 1 || control == 2 {
            let hdr = cur.read_exact(2)?;
            let copy_size = ((hdr[0] as usize) << 8) + hdr[1] as usize + 1;
            cur.skip(copy_size)?;
            chunks.push(Lzma2ChunkIndex {
                index: chunk_index,
                packed_offset: chunk_start,
                packed_size: cur.abs as usize - chunk_start,
                unpacked_offset: unpacked_pos,
                unpacked_size: copy_size,
                control,
                is_lzma: false,
                independent: control == 1,
            });
            unpacked_pos += copy_size as u64;
        } else {
            return Err(SevenZipError::Msg(format!(
                "Invalid LZMA2 control byte 0x{control:02x} at offset {chunk_start}"
            )));
        }
        chunk_index += 1;
    }
    Ok(chunks)
}

/// Incremental liblzma raw decoder that can continue from `unpacked_pos`.
///
/// `lzma_stream` holds pointers into the current sliding packed window only for
/// the duration of [`Lzma2RandomAccessDecoder::live_decode_into`]; those are
/// rebound each call. A window `avail_in == 0` is **not** pack EOF.
struct LiveLzma2Cursor {
    stream: lzma_sys::lzma_stream,
    opts_ptrs: Vec<*mut std::os::raw::c_void>,
    unpacked_pos: u64,
    /// Absolute packed offset of the next unused input byte.
    abs_packed_pos: u64,
}

// The raw pointers are only used while this cursor is exclusively owned by
// `Lzma2RandomAccessDecoder` (itself behind a Mutex when shared).
unsafe impl Send for LiveLzma2Cursor {}

impl Drop for LiveLzma2Cursor {
    fn drop(&mut self) {
        unsafe {
            lzma_sys::lzma_end(&mut self.stream);
        }
        free_opts(&self.opts_ptrs);
    }
}

/// Serve random unpacked ranges from an LZMA2 folder.
///
/// Port of Python `Lzma2RandomAccessDecoder` (hilather a0bc76e):
/// always decode with the **folder-level** filter chain (never re-bind
/// per-chunk property filters for multi-chunk solid chains).
///
/// Packed input is a [`PackSource`] plus a **sliding window**. `lzma_code` is
/// given `LZMA_FINISH` only at true pack EOF (`abs_packed_pos >= pack.size()`);
/// exhausting a 64 KiB window mid-pack refills via `read_at` and continues
/// `LZMA_RUN`.
///
/// **Small folders** (≤ `SMALL_FOLDER_FULL_CACHE`) keep a full unpack cache
/// after the first decode for repeated random access.
///
/// **Large folders** keep a live liblzma cursor: sequential reads continue
/// from `bytes_produced` (O(range) work). Pure LZMA2 (including AES-stripped)
/// backward / random reads resume at the latest independent dict-reset chunk.
/// Native BCJ/Delta+LZMA2 disables independent resume (BCJ IP is decoder-
/// relative) and always restarts from unpacked 0. A bounded LRU of unpacked
/// windows still amortizes local re-reads.
///
/// **Non-solid / single-member** folders set [`Self::set_retain_from_zero`]:
/// a decode that walks from unpacked 0 (typical nested 7z header-at-end)
/// keeps that prefix so the next earlier-range read does not restart.
pub struct Lzma2RandomAccessDecoder {
    pack: Box<dyn PackSource>,
    /// AES-stripped coder chain (BCJ/Delta+LZMA2 or a single LZMA2 coder).
    coders: Vec<Coder>,
    /// False when any BCJ/Delta filter is in the chain (resume at `(0, 0)`).
    allow_independent_resume: bool,
    /// Sliding packed input for the live cursor (not a full-pack buffer).
    packed_window: Vec<u8>,
    /// Pack offset of `packed_window[0]`.
    packed_window_start: u64,
    /// Indexed LZMA2 stream chunk map (independent chunks are resume points).
    chunks: Vec<Lzma2ChunkIndex>,
    unpack_size: u64,
    full: Option<Vec<u8>>,
    /// When true, first full decode is retained for subsequent ranges.
    cache_full: bool,
    /// Unpacked window size for the progressive LRU cache.
    chunk_size: usize,
    max_cached_chunks: usize,
    /// Window index → decoded unpacked bytes for that window.
    window_cache: HashMap<usize, Vec<u8>>,
    /// LRU order: oldest window index at the front.
    window_lru: Vec<usize>,
    live: Option<LiveLzma2Cursor>,
    /// Contiguous unpack prefix from 0 (non-solid retain path).
    prefix_from_zero: Vec<u8>,
    retain_from_zero: bool,
    /// New decompressor started at unpacked offset 0.
    prefix_from_zero_starts: u64,
    /// New decompressor started (any resume point).
    decoder_starts: u64,
    /// Unpacked bytes emitted by the decompressor (including skip).
    bytes_decompressed: u64,
    /// Last resume unpacked offset used to start a decompressor.
    last_resume_unpacked: u64,
}

/// Folders at or below this unpack size keep a full decode cache.
pub const SMALL_FOLDER_FULL_CACHE: u64 = 4 * 1024 * 1024;

/// Default unpacked window size for progressive solid decode cache (1 MiB).
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;
/// Default max windows retained in the progressive LRU cache.
pub const DEFAULT_MAX_CACHED_CHUNKS: usize = 64;

impl Lzma2RandomAccessDecoder {
    /// Wrap a fully buffered pack (`BytesPackSource`) — kept for existing tests.
    pub fn new(folder: &Folder, packed: Vec<u8>, max_cached_chunks: usize) -> Result<Self> {
        Self::from_pack(
            folder,
            Box::new(BytesPackSource::new(packed)),
            max_cached_chunks,
        )
    }

    #[allow(dead_code)] // Vec wrapper kept for existing tests
    pub fn with_chunk_size(
        folder: &Folder,
        packed: Vec<u8>,
        chunk_size: usize,
        max_cached_chunks: usize,
    ) -> Result<Self> {
        Self::from_pack_with_chunk_size(
            folder,
            Box::new(BytesPackSource::new(packed)),
            chunk_size,
            max_cached_chunks,
        )
    }

    pub fn from_pack(
        folder: &Folder,
        pack: Box<dyn PackSource>,
        max_cached_chunks: usize,
    ) -> Result<Self> {
        Self::from_pack_with_chunk_size(folder, pack, DEFAULT_CHUNK_SIZE, max_cached_chunks.max(1))
    }

    pub fn from_pack_with_chunk_size(
        folder: &Folder,
        pack: Box<dyn PackSource>,
        chunk_size: usize,
        max_cached_chunks: usize,
    ) -> Result<Self> {
        if folder.has_bcj2() || folder.packed_indices.len() > 1 {
            return Err(SevenZipError::Msg(
                "Lzma2RandomAccessDecoder does not support BCJ2 / multi-pack folders".into(),
            ));
        }
        let content = folder.content_coders();
        if !lzma2_progressive_content_coders(content) {
            return Err(SevenZipError::Msg(
                "Lzma2RandomAccessDecoder requires LZMA2 or native BCJ/Delta+LZMA2".into(),
            ));
        }
        let chunks = index_lzma2_chunks_from_pack(pack.as_ref())?;
        let unpack_size = folder.get_unpack_size();
        let allow_independent_resume = !content.iter().any(coder_is_bcj_or_delta);
        Ok(Self {
            pack,
            coders: content.to_vec(),
            allow_independent_resume,
            packed_window: Vec::new(),
            packed_window_start: 0,
            chunks,
            unpack_size,
            full: None,
            cache_full: unpack_size <= SMALL_FOLDER_FULL_CACHE,
            chunk_size: chunk_size.max(4096),
            max_cached_chunks: max_cached_chunks.max(1),
            window_cache: HashMap::new(),
            window_lru: Vec::new(),
            live: None,
            prefix_from_zero: Vec::new(),
            retain_from_zero: false,
            prefix_from_zero_starts: 0,
            decoder_starts: 0,
            bytes_decompressed: 0,
            last_resume_unpacked: 0,
        })
    }

    /// Keep a contiguous unpack prefix from 0 (non-solid / single-member folders).
    ///
    /// After a header-at-end decode that walks from unpacked 0, the next earlier
    /// member read hits this prefix instead of restarting the decompressor.
    pub fn set_retain_from_zero(&mut self, retain: bool) {
        self.retain_from_zero = retain;
    }

    #[allow(dead_code)] // shipped decode-pass counters (tests + diagnostics)
    pub fn prefix_from_zero_starts(&self) -> u64 {
        self.prefix_from_zero_starts
    }

    #[allow(dead_code)]
    pub fn decoder_starts(&self) -> u64 {
        self.decoder_starts
    }

    #[allow(dead_code)]
    pub fn bytes_decompressed(&self) -> u64 {
        self.bytes_decompressed
    }

    #[allow(dead_code)]
    pub fn last_resume_unpacked(&self) -> u64 {
        self.last_resume_unpacked
    }

    #[cfg(test)]
    pub fn allow_independent_resume(&self) -> bool {
        self.allow_independent_resume
    }

    fn ensure_packed_window(&mut self, abs: u64) -> Result<()> {
        let pack_size = self.pack.size();
        if abs >= pack_size {
            return Ok(());
        }
        let win_end = self
            .packed_window_start
            .saturating_add(self.packed_window.len() as u64);
        if abs >= self.packed_window_start && abs < win_end {
            return Ok(());
        }
        let n = ((pack_size - abs) as usize).min(PACKED_INPUT_WINDOW);
        self.packed_window = self.pack.read_at(abs, n)?;
        self.packed_window_start = abs;
        Ok(())
    }

    /// Decode into `out` from the live cursor, refilling the packed window as needed.
    ///
    /// `LZMA_FINISH` is used only at true pack EOF. A window `avail_in == 0`
    /// while `abs_packed_pos < pack.size()` refills and continues `LZMA_RUN`.
    fn live_decode_into(&mut self, out: &mut [u8]) -> Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let pack_size = self.pack.size();
        let mut produced_total = 0usize;
        loop {
            if produced_total == out.len() {
                break;
            }
            let abs = self
                .live
                .as_ref()
                .map(|c| c.abs_packed_pos)
                .unwrap_or(pack_size);
            if abs < pack_size {
                self.ensure_packed_window(abs)?;
            }
            let (produced, ret, avail_in_after, at_pack_eof) = {
                let live = self
                    .live
                    .as_mut()
                    .ok_or_else(|| SevenZipError::Msg("LZMA2 live cursor missing".into()))?;
                let win_end = self
                    .packed_window_start
                    .saturating_add(self.packed_window.len() as u64);
                let in_slice: &[u8] = if live.abs_packed_pos >= self.packed_window_start
                    && live.abs_packed_pos < win_end
                {
                    let off = (live.abs_packed_pos - self.packed_window_start) as usize;
                    &self.packed_window[off..]
                } else {
                    &[]
                };
                let at_pack_eof = live.abs_packed_pos >= pack_size;
                unsafe {
                    let dest = &mut out[produced_total..];
                    live.stream.next_out = dest.as_mut_ptr();
                    live.stream.avail_out = dest.len();
                    if in_slice.is_empty() {
                        live.stream.next_in = std::ptr::null();
                        live.stream.avail_in = 0;
                    } else {
                        live.stream.next_in = in_slice.as_ptr();
                        live.stream.avail_in = in_slice.len();
                    }
                    let action = if at_pack_eof {
                        lzma_sys::LZMA_FINISH
                    } else {
                        lzma_sys::LZMA_RUN
                    };
                    let orig_avail_in = live.stream.avail_in;
                    let orig_avail_out = live.stream.avail_out;
                    let ret = lzma_sys::lzma_code(&mut live.stream, action);
                    let consumed = orig_avail_in - live.stream.avail_in;
                    live.abs_packed_pos += consumed as u64;
                    let produced = orig_avail_out - live.stream.avail_out;
                    live.unpacked_pos += produced as u64;
                    (produced, ret, live.stream.avail_in, at_pack_eof)
                }
            };
            produced_total += produced;
            if ret == lzma_sys::LZMA_STREAM_END {
                break;
            }
            if ret != lzma_sys::LZMA_OK {
                return Err(SevenZipError::Msg(format!("lzma_code (live LZMA2): {ret}")));
            }
            if produced_total == out.len() {
                break;
            }
            if avail_in_after == 0 {
                if !at_pack_eof {
                    // Mid-pack window exhausted: refill, never FINISH.
                    continue;
                }
                // True pack EOF already finished (or stall).
                if produced == 0 {
                    break;
                }
                continue;
            }
            // Input remains unused and no more output this step: stall.
            if produced == 0 {
                break;
            }
        }
        Ok(produced_total)
    }

    fn ensure_full(&mut self) -> Result<()> {
        if self.full.is_some() {
            return Ok(());
        }
        if self.prefix_from_zero.len() as u64 >= self.unpack_size && self.unpack_size > 0 {
            let mut full = std::mem::take(&mut self.prefix_from_zero);
            full.truncate(self.unpack_size as usize);
            self.full = Some(full);
            return Ok(());
        }
        // Folder-level chain via the live cursor (sliding pack window, no as_bytes).
        let out = self.live_decode_span(0, self.unpack_size.max(1) as usize)?;
        self.full = Some(out);
        Ok(())
    }

    /// Latest independent LZMA2 chunk with `unpacked_offset <= start` (or 0).
    ///
    /// BCJ/Delta chains always return `(0, 0)` — the filter IP is decoder-relative.
    fn resume_point(&self, start: u64) -> (usize, u64) {
        if !self.allow_independent_resume {
            return (0, 0);
        }
        let mut packed = 0usize;
        let mut unpacked = 0u64;
        for c in &self.chunks {
            if c.unpacked_offset > start {
                break;
            }
            if c.independent {
                packed = c.packed_offset;
                unpacked = c.unpacked_offset;
            }
        }
        (packed, unpacked)
    }

    fn start_live_at(&mut self, packed_pos: usize, unpacked_pos: u64) -> Result<()> {
        // Drop leftover sequential window; fill from the resume packed offset.
        self.live = None;
        self.packed_window.clear();
        self.packed_window_start = packed_pos as u64;
        let abs = packed_pos as u64;
        if abs < self.pack.size() {
            self.ensure_packed_window(abs)?;
        }
        let cursor = start_lzma2_live_cursor(&self.coders, abs, unpacked_pos)?;
        self.live = Some(cursor);
        self.decoder_starts = self.decoder_starts.saturating_add(1);
        self.last_resume_unpacked = unpacked_pos;
        if unpacked_pos == 0 {
            self.prefix_from_zero_starts = self.prefix_from_zero_starts.saturating_add(1);
        }
        Ok(())
    }

    /// Position the live cursor so the next produced byte is `start`.
    fn position_live_at(&mut self, start: u64) -> Result<()> {
        if start > self.unpack_size {
            return Ok(());
        }
        let (resume_packed, resume_unpacked) = self.resume_point(start);
        let can_continue = self
            .live
            .as_ref()
            .is_some_and(|c| c.unpacked_pos <= start && c.unpacked_pos >= resume_unpacked);
        if !can_continue {
            self.start_live_at(resume_packed, resume_unpacked)?;
        }
        let have = self.live.as_ref().map(|c| c.unpacked_pos).unwrap_or(0);
        if have < start {
            self.live_skip_to(start)?;
        }
        Ok(())
    }

    fn live_skip_to(&mut self, target: u64) -> Result<()> {
        let mut buf = vec![0u8; 64 * 1024];
        while self.live.as_ref().is_some_and(|c| c.unpacked_pos < target) {
            let want =
                (target - self.live.as_ref().map(|c| c.unpacked_pos).unwrap_or(target)) as usize;
            let take = want.min(buf.len());
            let n = self.live_decode_into(&mut buf[..take])?;
            if n == 0 {
                return Err(SevenZipError::Msg(format!(
                    "LZMA2 live skip stalled at {} want {target}",
                    self.live.as_ref().map(|c| c.unpacked_pos).unwrap_or(0)
                )));
            }
            self.bytes_decompressed = self.bytes_decompressed.saturating_add(n as u64);
            let produced_end = self.live.as_ref().map(|c| c.unpacked_pos).unwrap_or(0);
            let produced_start = produced_end.saturating_sub(n as u64);
            self.note_produced(produced_start, &buf[..n]);
        }
        Ok(())
    }

    fn live_decode_span(&mut self, start: usize, end: usize) -> Result<Vec<u8>> {
        if end <= start {
            return Ok(vec![]);
        }
        self.position_live_at(start as u64)?;
        let mut out = vec![0u8; end - start];
        let mut filled = 0usize;
        while filled < out.len() {
            let n = self.live_decode_into(&mut out[filled..])?;
            if n == 0 {
                return Err(SevenZipError::Msg(format!(
                    "LZMA2 live decode short: got {filled} want {}",
                    out.len()
                )));
            }
            self.bytes_decompressed = self.bytes_decompressed.saturating_add(n as u64);
            self.note_produced((start + filled) as u64, &out[filled..filled + n]);
            filled += n;
        }
        Ok(out)
    }

    fn note_produced(&mut self, start: u64, data: &[u8]) {
        if !self.retain_from_zero || data.is_empty() {
            return;
        }
        let start = start as usize;
        if start > self.prefix_from_zero.len() {
            return;
        }
        if start < self.prefix_from_zero.len() {
            let overlap = self.prefix_from_zero.len() - start;
            if overlap >= data.len() {
                return;
            }
            self.prefix_from_zero.extend_from_slice(&data[overlap..]);
        } else {
            self.prefix_from_zero.extend_from_slice(data);
        }
        if self.prefix_from_zero.len() as u64 >= self.unpack_size && self.full.is_none() {
            let mut full = std::mem::take(&mut self.prefix_from_zero);
            full.truncate(self.unpack_size as usize);
            self.full = Some(full);
        }
    }

    fn touch_window(&mut self, index: usize) {
        if let Some(pos) = self.window_lru.iter().position(|&i| i == index) {
            self.window_lru.remove(pos);
        }
        self.window_lru.push(index);
        while self.window_lru.len() > self.max_cached_chunks {
            let old = self.window_lru.remove(0);
            self.window_cache.remove(&old);
        }
    }

    fn store_window(&mut self, index: usize, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        self.window_cache.insert(index, data);
        self.touch_window(index);
    }

    fn assemble_from_windows(&mut self, start: usize, end: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(end.saturating_sub(start));
        let mut offset = start;
        while offset < end {
            let index = offset / self.chunk_size;
            if !self.window_cache.contains_key(&index) {
                return Err(SevenZipError::Msg(format!(
                    "LZMA2 window {index} missing after ensure (offset={offset})"
                )));
            }
            self.touch_window(index);
            let win = self.window_cache.get(&index).unwrap();
            let chunk_start = index * self.chunk_size;
            let local = offset - chunk_start;
            if local >= win.len() {
                return Err(SevenZipError::Msg(format!(
                    "Invalid window slice at {index}: local={local} len={}",
                    win.len()
                )));
            }
            let take = (end - offset).min(win.len() - local);
            out.extend_from_slice(&win[local..local + take]);
            offset += take;
        }
        Ok(out)
    }

    /// Ensure windows covering `[start, end)` are cached; live-cursor decode on miss.
    fn ensure_windows(&mut self, start: usize, end: usize) -> Result<()> {
        if end <= start {
            return Ok(());
        }
        let first = start / self.chunk_size;
        let last = (end - 1) / self.chunk_size;
        if (first..=last).all(|i| self.window_cache.contains_key(&i)) {
            for i in first..=last {
                self.touch_window(i);
            }
            return Ok(());
        }
        let need_from = (first..=last)
            .find(|i| !self.window_cache.contains_key(i))
            .map(|i| i * self.chunk_size)
            .unwrap_or(start)
            .min(start);
        let need_through = ((last + 1) * self.chunk_size).min(self.unpack_size as usize);
        let span = self.live_decode_span(need_from, need_through)?;
        self.cache_span_windows(need_from, &span, first, last);
        for i in first..=last {
            let win_start = i * self.chunk_size;
            if win_start >= self.unpack_size as usize {
                break;
            }
            if !self.window_cache.contains_key(&i) && win_start >= need_from {
                let off = win_start - need_from;
                let win_end = (win_start + self.chunk_size).min(need_from + span.len());
                if off < span.len() && win_end > win_start {
                    self.window_cache
                        .insert(i, span[off..off + (win_end - win_start)].to_vec());
                    self.touch_window(i);
                }
            }
        }
        Ok(())
    }

    /// Cache windows covered by `data` starting at unpacked `span_start`.
    fn cache_span_windows(&mut self, span_start: usize, data: &[u8], first: usize, last: usize) {
        let span_end = span_start + data.len();
        if span_end <= span_start {
            return;
        }
        for i in first..=last {
            let win_start = i * self.chunk_size;
            let win_end = (win_start + self.chunk_size).min(self.unpack_size as usize);
            if win_start >= span_start && win_end <= span_end && win_end > win_start {
                let off = win_start - span_start;
                let slice = &data[off..off + (win_end - win_start)];
                if !self.window_cache.contains_key(&i) {
                    self.store_window(i, slice.to_vec());
                } else {
                    self.touch_window(i);
                }
            }
        }
    }

    pub fn read_range(&mut self, start: u64, length: usize) -> Result<Vec<u8>> {
        if length == 0 || start >= self.unpack_size {
            return Ok(vec![]);
        }
        let end = (start as usize)
            .saturating_add(length)
            .min(self.unpack_size as usize);
        let s = start as usize;

        // Prefer full cache when already populated or folder is small.
        if self.full.is_some() || self.cache_full {
            self.ensure_full()?;
            let full = self.full.as_ref().unwrap();
            if s >= full.len() {
                return Ok(vec![]);
            }
            let e = end.min(full.len());
            return Ok(full[s..e].to_vec());
        }

        if self.retain_from_zero && self.prefix_from_zero.len() >= end {
            return Ok(self.prefix_from_zero[s..end].to_vec());
        }

        let first = s / self.chunk_size;
        let last = (end - 1) / self.chunk_size;
        let windows_needed = last - first + 1;
        // Wide request: one live-cursor pass, return the slice, warm MRU windows.
        if windows_needed > self.max_cached_chunks {
            let need_through = ((last + 1) * self.chunk_size).min(self.unpack_size as usize);
            let span = self.live_decode_span(s, need_through)?;
            self.cache_span_windows(s, &span, first, last);
            let take = (end - s).min(span.len());
            return Ok(span[..take].to_vec());
        }
        self.ensure_windows(s, end)?;
        if (first..=last).all(|i| self.window_cache.contains_key(&i)) {
            return self.assemble_from_windows(s, end);
        }
        // Partial windows (unaligned first read): decode the exact range.
        self.live_decode_span(s, end)
    }

    pub fn unpack_size(&self) -> u64 {
        self.unpack_size
    }

    #[allow(dead_code)] // used by unit tests / diagnostics
    pub fn cached_window_count(&self) -> usize {
        self.window_cache.len()
    }

    #[allow(dead_code)]
    pub fn chunk_count(&self) -> usize {
        self.chunks.len()
    }

    /// Force progressive window-cache mode even for small folders (tests).
    #[cfg(test)]
    pub fn force_progressive_for_test(&mut self) {
        self.cache_full = false;
        self.full = None;
        self.live = None;
        self.packed_window.clear();
        self.packed_window_start = 0;
        self.prefix_from_zero.clear();
    }
}

/// Shared pure-LZMA2 solid-folder decoder (multiple members / concurrent opens).
pub type SharedLzma2Decoder = Arc<Mutex<Lzma2RandomAccessDecoder>>;

/// Seekable logical view of one solid-folder member over a shared LZMA2 decoder.
///
/// Positions are relative to the member; the decoder addresses absolute offsets
/// inside the folder unpack stream (`member_start + pos`). Matches Python
/// `SevenZipStreamingMemberFile` so nested AutoMount can `seek(0)` / re-read
/// without temp spooling the outer solid member.
///
/// **Nested 7z:** outer solid members return this type (or a fully-buffered
/// `Cursor` for small folders). Either is `Read+Seek` and feeds
/// `SevenZipMountSource::open_from_reader` without materializing a host temp file.
pub struct Lzma2MemberReader {
    decoder: SharedLzma2Decoder,
    member_start: u64,
    member_size: u64,
    pos: u64,
}

impl Lzma2MemberReader {
    pub fn new(decoder: SharedLzma2Decoder, member_start: u64, member_size: u64) -> Self {
        Self {
            decoder,
            member_start,
            member_size,
            pos: 0,
        }
    }

    #[allow(dead_code)] // diagnostics / nested AutoMount sizing
    pub fn member_size(&self) -> u64 {
        self.member_size
    }
}

impl Read for Lzma2MemberReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.member_size || buf.is_empty() {
            return Ok(0);
        }
        let want = ((self.member_size - self.pos) as usize).min(buf.len());
        let abs = self.member_start + self.pos;
        let mut g = self
            .decoder
            .lock()
            .map_err(|_| io::Error::other("7z LZMA2 decoder lock poisoned"))?;
        let data = g
            .read_range(abs, want)
            .map_err(|e| io::Error::other(e.to_string()))?;
        let n = data.len().min(want);
        buf[..n].copy_from_slice(&data[..n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for Lzma2MemberReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::End(o) => self.member_size as i64 + o,
            SeekFrom::Current(o) => self.pos as i64 + o,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start of solid 7z member",
            ));
        }
        // Allow seeks past EOF (like Cursor); reads then return 0.
        self.pos = new as u64;
        Ok(self.pos)
    }
}

/// Best random-access decoder for a folder's primary codec (Python `create_folder_decoder`).
///
/// Accepts AES-stripped LZMA2 and native BCJ/Delta+LZMA2. Packed bytes are the
/// **content** pack (already decrypted if AES). Still `Err` on BCJ2 / multi-pack.
/// Open does **not** depend on this helper.
#[allow(dead_code)]
pub fn create_folder_decoder(
    folder: &Folder,
    packed: Vec<u8>,
    max_cached_chunks: usize,
) -> Result<Lzma2RandomAccessDecoder> {
    if folder.has_bcj2() {
        return Err(SevenZipError::Msg(
            "create_folder_decoder does not support BCJ2 folders".into(),
        ));
    }
    if folder.packed_indices.len() > 1 {
        return Err(SevenZipError::Msg(
            "create_folder_decoder does not support multi-pack folders".into(),
        ));
    }
    let content_coders = folder.content_coders();
    if !lzma2_progressive_content_coders(content_coders) {
        let methods: Vec<_> = folder
            .coders
            .iter()
            .map(|c| hex::encode_simple(&c.method))
            .collect();
        return Err(SevenZipError::Msg(format!(
            "create_folder_decoder currently only supports LZMA2 / native BCJ+LZMA2 (got {methods:?})"
        )));
    }
    let content = Folder {
        coders: content_coders.to_vec(),
        bind_pairs: vec![],
        packed_indices: vec![],
        unpack_sizes: vec![folder.get_unpack_size()],
        has_crc: folder.has_crc,
        crc: folder.crc,
    };
    Lzma2RandomAccessDecoder::new(
        &content,
        packed,
        max_cached_chunks.max(DEFAULT_MAX_CACHED_CHUNKS),
    )
}

// ---------------------------------------------------------------------------
// AES helpers
// ---------------------------------------------------------------------------

struct AesProps {
    cycles: u32,
    salt: Vec<u8>,
    iv: [u8; 16],
}

fn parse_aes_properties(properties: Option<&[u8]>) -> Result<AesProps> {
    let properties = properties.ok_or_else(|| SevenZipError::Msg("Missing AES props".into()))?;
    if properties.is_empty() {
        return Err(SevenZipError::Msg("Missing AES props".into()));
    }
    let first = properties[0];
    let cycles = u32::from(first & 0x3F);
    if first & 0xC0 == 0 {
        return Err(SevenZipError::Msg("Invalid AES props flags".into()));
    }
    let mut salt_size = ((first >> 7) & 1) as usize;
    let mut iv_size = ((first >> 6) & 1) as usize;
    if properties.len() < 2 {
        return Err(SevenZipError::Msg("Truncated AES props".into()));
    }
    let second = properties[1];
    salt_size += (second >> 4) as usize;
    iv_size += (second & 0x0F) as usize;
    let expected = 2 + salt_size + iv_size;
    if properties.len() < expected {
        return Err(SevenZipError::Msg(format!(
            "Truncated AES props need {expected}"
        )));
    }
    let salt = properties[2..2 + salt_size].to_vec();
    let mut iv = [0u8; 16];
    let iv_src = &properties[2 + salt_size..2 + salt_size + iv_size];
    iv[..iv_src.len()].copy_from_slice(iv_src);
    Ok(AesProps { cycles, salt, iv })
}

fn calculate_7z_key(password: &[u8], cycles: u32, salt: &[u8]) -> Result<[u8; 32]> {
    if cycles > 0x3F {
        return Err(SevenZipError::Msg(format!("Invalid AES cycles {cycles}")));
    }
    if cycles == 0x3F {
        let mut key = [0u8; 32];
        let mut combined = salt.to_vec();
        combined.extend_from_slice(password);
        combined.resize(32, 0);
        key.copy_from_slice(&combined[..32]);
        return Ok(key);
    }
    let cat_cycle = 6u32;
    let (rounds, stages) = if cycles > cat_cycle {
        (1u64 << cat_cycle, 1u64 << (cycles - cat_cycle))
    } else {
        (1u64 << cycles, 1u64)
    };
    let mut digest = Sha256::new();
    let salt_password: Vec<u8> = salt.iter().chain(password.iter()).copied().collect();
    let mut counter = 0u64;
    for _ in 0..stages {
        for i in 0..rounds {
            digest.update(&salt_password);
            digest.update((counter + i).to_le_bytes());
        }
        counter += rounds;
    }
    let out = digest.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[..32]);
    Ok(key)
}

#[allow(dead_code)]
fn aes_decrypt_7z(packed: &[u8], properties: Option<&[u8]>, password: &str) -> Result<Vec<u8>> {
    let src = BytesPackSource::new(packed.to_vec());
    let aes = AesPackSource::new(Box::new(src), properties, password, None)?;
    aes.as_bytes()
}

mod hex {
    pub fn encode_simple(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

#[cfg(test)]
mod lzma2_random_tests {
    use super::*;
    use crate::parse::{Coder, Folder, METHOD_AES, METHOD_BCJ, METHOD_BCJ2, METHOD_LZMA2};
    use std::io::{Read, Seek};
    use std::process::Command;

    fn lzma2_compress_raw(data: &[u8]) -> Option<Vec<u8>> {
        unsafe {
            let mut opt: lzma_sys::lzma_options_lzma = std::mem::zeroed();
            if lzma_sys::lzma_lzma_preset(&mut opt, 1) != 0 {
                return None;
            }
            let filters = [
                lzma_sys::lzma_filter {
                    id: lzma_sys::LZMA_FILTER_LZMA2,
                    options: std::ptr::from_mut(&mut opt).cast(),
                },
                lzma_sys::lzma_filter {
                    id: lzma_sys::LZMA_VLI_UNKNOWN,
                    options: std::ptr::null_mut(),
                },
            ];
            let cap = (data.len() * 2 + 4096).max(4096);
            let mut out = vec![0u8; cap];
            let mut stream: lzma_sys::lzma_stream = std::mem::zeroed();
            if lzma_sys::lzma_raw_encoder(&mut stream, filters.as_ptr()) != lzma_sys::LZMA_OK {
                return None;
            }
            stream.next_in = data.as_ptr();
            stream.avail_in = data.len();
            stream.next_out = out.as_mut_ptr();
            stream.avail_out = out.len();
            let ret = lzma_sys::lzma_code(&mut stream, lzma_sys::LZMA_FINISH);
            let produced = stream.total_out as usize;
            lzma_sys::lzma_end(&mut stream);
            if ret != lzma_sys::LZMA_STREAM_END && ret != lzma_sys::LZMA_OK {
                return None;
            }
            out.truncate(produced);
            if out.is_empty() {
                return None;
            }
            Some(out)
        }
    }

    fn py_lzma2_compress(data: &[u8]) -> Option<Vec<u8>> {
        if let Some(p) = lzma2_compress_raw(data) {
            return Some(p);
        }
        let status = Command::new("python3")
            .args([
                "-c",
                r#"
import lzma, sys
data = sys.stdin.buffer.read()
packed = lzma.compress(data, format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2, "preset": 1}])
sys.stdout.buffer.write(packed)
"#,
            ])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .ok()?;
        use std::io::Write;
        let mut child = status;
        child.stdin.as_mut()?.write_all(data).ok()?;
        let out = child.wait_with_output().ok()?;
        if !out.status.success() {
            return None;
        }
        Some(out.stdout)
    }

    fn lzma2_folder(unpack_size: u64, props: Option<Vec<u8>>) -> Folder {
        Folder {
            coders: vec![Coder {
                method: METHOD_LZMA2.to_vec(),
                num_in_streams: 1,
                num_out_streams: 1,
                properties: props,
            }],
            bind_pairs: vec![],
            packed_indices: vec![],
            unpack_sizes: vec![unpack_size],
            has_crc: false,
            crc: 0,
        }
    }

    fn py_fixture(name: &str) -> std::path::PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        std::path::PathBuf::from(root).join("tests").join(name)
    }

    #[test]
    fn index_lzma2_chunks_sum_unpacked_sizes() {
        // Port of Python test_index_lzma2_chunks_matches_full_decompress (structure only).
        let data: Vec<u8> = (0u8..=255).cycle().take(256 * 2000).collect();
        let Some(packed) = py_lzma2_compress(&data) else {
            eprintln!("skip: python3/lzma compress unavailable");
            return;
        };
        let chunks = index_lzma2_chunks(&packed).expect("index chunks");
        assert!(!chunks.is_empty());
        let sum: u64 = chunks.iter().map(|c| c.unpacked_size as u64).sum();
        assert_eq!(sum, data.len() as u64);
        assert!(
            chunks.iter().any(|c| c.independent),
            "need at least one reset chunk"
        );
    }

    #[test]
    fn progressive_window_cache_two_non_overlapping_ranges() {
        // Patterned data so range equality checks are meaningful.
        let data: Vec<u8> = (0u8..=255).cycle().take(768 * 1024).collect();
        let Some(packed) = py_lzma2_compress(&data) else {
            eprintln!("skip: python3/lzma compress unavailable");
            return;
        };
        // Folder-level LZMA2 dict_size prop (matches typical 7z "LZMA2:22" / 4 MiB-ish).
        let folder = lzma2_folder(data.len() as u64, Some(vec![22]));
        let mut decoder = Lzma2RandomAccessDecoder::with_chunk_size(&folder, packed, 64 * 1024, 4)
            .expect("decoder");
        // Exercise progressive window path even though unpack is under full-cache threshold.
        decoder.force_progressive_for_test();

        let r1 = decoder.read_range(0, 4096).expect("range1");
        assert_eq!(r1, data[..4096]);
        assert!(decoder.cached_window_count() > 0);

        // Non-overlapping mid-stream range (different windows).
        let mid = 400 * 1024;
        let r2 = decoder.read_range(mid as u64, 8192).expect("range2");
        assert_eq!(r2, data[mid..mid + 8192]);
        assert_ne!(r1, r2);

        // Re-read first range should hit window cache (still correct).
        let r1b = decoder.read_range(0, 4096).expect("range1b");
        assert_eq!(r1b, data[..4096]);

        // Cap on cached windows.
        assert!(decoder.cached_window_count() <= 4);
    }

    #[test]
    fn medium_fixture_two_non_overlapping_ranges() {
        let path = py_fixture("lzma2-two-files-and-medium.7z");
        if !path.exists() {
            eprintln!("skip missing {}", path.display());
            return;
        }
        let mut file = std::fs::File::open(&path).expect("open fixture");
        let archive = crate::parse::parse_7z_archive(&mut file, |folder, packed| {
            decompress_folder(folder, packed, None)
        })
        .expect("parse 7z");
        let med = archive
            .files
            .iter()
            .find(|f| f.path.ends_with("medium.bin") || f.path.as_ref() == "medium.bin")
            .expect("medium.bin entry");
        assert_eq!(med.size, 2 * 1024 * 1024);
        let fi = med.folder_index.expect("folder");
        let folder = &archive.folders[fi];
        assert_eq!(folder.coders[0].method.as_slice(), METHOD_LZMA2);

        file.seek(std::io::SeekFrom::Start(med.pack_offset))
            .expect("seek pack");
        let mut packed = vec![0u8; med.pack_size as usize];
        file.read_exact(&mut packed).expect("read pack");

        let mut decoder = Lzma2RandomAccessDecoder::with_chunk_size(
            folder,
            packed.clone(),
            256 * 1024,
            DEFAULT_MAX_CACHED_CHUNKS,
        )
        .expect("decoder");
        // Fixture folder is ~2 MiB (< 4 MiB full-cache threshold); force progressive
        // windows for the non-overlapping range check.
        decoder.force_progressive_for_test();

        let base = med.unpack_offset;
        let a = decoder.read_range(base, 4096).expect("medium head");
        let b = decoder
            .read_range(base + 1024 * 1024, 4096)
            .expect("medium mid");
        assert_eq!(a.len(), 4096);
        assert_eq!(b.len(), 4096);
        assert!(decoder.cached_window_count() > 0);
        assert!(decoder.cached_window_count() <= DEFAULT_MAX_CACHED_CHUNKS);

        // Full-folder decode cross-check on the same slices (default small-folder path).
        let mut full_dec = Lzma2RandomAccessDecoder::new(folder, packed, 64).expect("full");
        let full_a = full_dec.read_range(base, 4096).unwrap();
        let full_b = full_dec.read_range(base + 1024 * 1024, 4096).unwrap();
        assert_eq!(a, full_a);
        assert_eq!(b, full_b);
    }

    /// Regression: sequential 1 MiB-step reads of a >4 MiB LZMA2 member are
    /// linear (one prefix start), not N(N+1)/2 prefix restarts from 0.
    #[test]
    fn regression_sequential_windows_are_linear_not_quadratic() {
        const WIN: usize = 1024 * 1024;
        const N: usize = 6;
        let data: Vec<u8> = (0u32..(N * WIN) as u32)
            .map(|i| (i.wrapping_mul(1664525).wrapping_add(1013904223) >> 24) as u8)
            .collect();
        let packed = lzma2_compress_raw(&data).expect("lzma2 compress");
        let folder = lzma2_folder(data.len() as u64, Some(vec![22]));
        let mut decoder =
            Lzma2RandomAccessDecoder::with_chunk_size(&folder, packed, WIN, 8).expect("decoder");
        decoder.force_progressive_for_test();

        for i in 0..N {
            let got = decoder.read_range((i * WIN) as u64, WIN).expect("window");
            assert_eq!(got, data[i * WIN..(i + 1) * WIN], "window {i}");
        }
        assert_eq!(
            decoder.prefix_from_zero_starts(),
            1,
            "sequential windows must start the decompressor from 0 once"
        );
        assert_eq!(
            decoder.decoder_starts(),
            1,
            "sequential windows must not start extra decompressor instances"
        );
        // Old path decoded 1+2+…+N windows. New path is one pass of N windows
        // (plus at most one aligned window of slack).
        let quadratic = (N * (N + 1) / 2) * WIN;
        assert!(
            decoder.bytes_decompressed() as usize <= N * WIN + WIN,
            "decompressed {} bytes (quadratic would be {quadratic})",
            decoder.bytes_decompressed()
        );
        assert!(
            (decoder.bytes_decompressed() as usize) < quadratic / 2,
            "still in quadratic territory: {}",
            decoder.bytes_decompressed()
        );
    }

    /// Regression: mid-stream read resumes at an independent LZMA2 reset, not
    /// unpacked offset 0.
    #[test]
    fn regression_independent_chunk_resume_skips_folder_start() {
        const PART: usize = 2 * 1024 * 1024;
        let part1: Vec<u8> = (0..PART).map(|i| (i % 251) as u8).collect();
        let part2: Vec<u8> = (0..PART).map(|i| (i % 241) as u8 + 3).collect();
        let mut packed = lzma2_compress_raw(&part1).expect("compress part1");
        // A finished raw LZMA2 stream ends with a single control-0 byte; drop
        // only that so the second independent stream is visible to the indexer.
        if packed.last() == Some(&0) {
            packed.pop();
        }
        let packed2 = lzma2_compress_raw(&part2).expect("compress part2");
        packed.extend_from_slice(&packed2);
        let mut data = part1.clone();
        data.extend_from_slice(&part2);

        let chunks = index_lzma2_chunks(&packed).expect("index");
        assert!(
            chunks
                .iter()
                .any(|c| c.independent && c.unpacked_offset >= PART as u64),
            "concatenated raw LZMA2 streams must have a reset at part2"
        );

        let folder = lzma2_folder(data.len() as u64, Some(vec![22]));
        let mut decoder = Lzma2RandomAccessDecoder::with_chunk_size(
            &folder,
            packed,
            256 * 1024,
            DEFAULT_MAX_CACHED_CHUNKS,
        )
        .expect("decoder");
        decoder.force_progressive_for_test();

        let mid = PART as u64 + 4096;
        let got = decoder.read_range(mid, 8192).expect("mid range");
        assert_eq!(got, data[mid as usize..mid as usize + 8192]);
        assert_eq!(
            decoder.prefix_from_zero_starts(),
            0,
            "must not start at unpacked 0 when an independent chunk covers mid"
        );
        assert!(
            decoder.last_resume_unpacked() >= PART as u64,
            "resume at/after part2 reset, got {}",
            decoder.last_resume_unpacked()
        );
        assert!(
            decoder.bytes_decompressed() < (PART + 8192 + 256 * 1024) as u64,
            "must not decode part1 prefix: {}",
            decoder.bytes_decompressed()
        );
    }

    /// Regression: after a header-at-end read, the next earlier-range read
    /// must not pay a second full prefix from 0 (retain 0..N on non-solid).
    #[test]
    fn regression_header_at_end_retains_prefix_for_next_read() {
        const SIZE: usize = 5 * 1024 * 1024;
        let data: Vec<u8> = (0..SIZE).map(|i| (i % 199) as u8).collect();
        let packed = lzma2_compress_raw(&data).expect("compress");
        let folder = lzma2_folder(data.len() as u64, Some(vec![22]));
        let mut decoder =
            Lzma2RandomAccessDecoder::with_chunk_size(&folder, packed, 1024 * 1024, 8)
                .expect("decoder");
        decoder.force_progressive_for_test();
        decoder.set_retain_from_zero(true);

        // Nested 7z: head sample, then header-at-end, then first member near 0.
        let head0 = decoder.read_range(0, 4096).expect("head sample");
        assert_eq!(head0, data[..4096]);
        let starts_after_head = decoder.prefix_from_zero_starts();
        assert_eq!(starts_after_head, 1);

        let tail = decoder
            .read_range((SIZE - 4096) as u64, 4096)
            .expect("header-at-end");
        assert_eq!(tail, data[SIZE - 4096..]);
        assert_eq!(
            decoder.prefix_from_zero_starts(),
            starts_after_head,
            "header-at-end must continue the live cursor, not restart from 0"
        );

        let head = decoder.read_range(0, 4096).expect("first member range");
        assert_eq!(head, data[..4096]);
        assert_eq!(
            decoder.prefix_from_zero_starts(),
            starts_after_head,
            "earlier-range read must use retained prefix, not a second from-0 start"
        );
    }

    struct SpyPack {
        inner: Vec<u8>,
        max_read: std::sync::Arc<std::sync::Mutex<usize>>,
    }

    impl PackSource for SpyPack {
        fn size(&self) -> u64 {
            self.inner.len() as u64
        }
        fn read_at(&self, offset: u64, size: usize) -> Result<Vec<u8>> {
            {
                let mut m = self.max_read.lock().unwrap();
                *m = (*m).max(size);
            }
            let off = offset as usize;
            if size == 0 || off >= self.inner.len() {
                return Ok(vec![]);
            }
            let end = (off + size).min(self.inner.len());
            Ok(self.inner[off..end].to_vec())
        }
        fn as_bytes(&self) -> Result<Vec<u8>> {
            panic!("Regression: AES pack not slurped — as_bytes must not be called");
        }
    }

    fn incompressible(len: usize) -> Vec<u8> {
        let mut s = 0x853c_49e6_0da1_b516u64;
        (0..len)
            .map(|_| {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                s as u8
            })
            .collect()
    }

    fn aes_lzma2_folder(unpack_size: u64) -> Folder {
        Folder {
            coders: vec![
                Coder {
                    method: METHOD_AES.to_vec(),
                    num_in_streams: 1,
                    num_out_streams: 1,
                    properties: None,
                },
                Coder {
                    method: METHOD_LZMA2.to_vec(),
                    num_in_streams: 1,
                    num_out_streams: 1,
                    properties: Some(vec![22]),
                },
            ],
            bind_pairs: vec![],
            packed_indices: vec![],
            unpack_sizes: vec![unpack_size, unpack_size],
            has_crc: false,
            crc: 0,
        }
    }

    fn bcj_lzma2_folder(unpack_size: u64) -> Folder {
        Folder {
            coders: vec![
                Coder {
                    method: METHOD_BCJ.to_vec(),
                    num_in_streams: 1,
                    num_out_streams: 1,
                    properties: None,
                },
                Coder {
                    method: METHOD_LZMA2.to_vec(),
                    num_in_streams: 1,
                    num_out_streams: 1,
                    properties: Some(vec![22]),
                },
            ],
            bind_pairs: vec![],
            packed_indices: vec![],
            unpack_sizes: vec![unpack_size],
            has_crc: false,
            crc: 0,
        }
    }

    fn bcj_lzma2_compress_raw(data: &[u8]) -> Option<Vec<u8>> {
        unsafe {
            let mut opt: lzma_sys::lzma_options_lzma = std::mem::zeroed();
            if lzma_sys::lzma_lzma_preset(&mut opt, 1) != 0 {
                return None;
            }
            let filters = [
                lzma_sys::lzma_filter {
                    id: lzma_sys::LZMA_FILTER_X86,
                    options: std::ptr::null_mut(),
                },
                lzma_sys::lzma_filter {
                    id: lzma_sys::LZMA_FILTER_LZMA2,
                    options: std::ptr::from_mut(&mut opt).cast(),
                },
                lzma_sys::lzma_filter {
                    id: lzma_sys::LZMA_VLI_UNKNOWN,
                    options: std::ptr::null_mut(),
                },
            ];
            let cap = (data.len() * 2 + 4096).max(4096);
            let mut out = vec![0u8; cap];
            let mut stream: lzma_sys::lzma_stream = std::mem::zeroed();
            if lzma_sys::lzma_raw_encoder(&mut stream, filters.as_ptr()) != lzma_sys::LZMA_OK {
                return None;
            }
            stream.next_in = data.as_ptr();
            stream.avail_in = data.len();
            stream.next_out = out.as_mut_ptr();
            stream.avail_out = out.len();
            let ret = lzma_sys::lzma_code(&mut stream, lzma_sys::LZMA_FINISH);
            let produced = stream.total_out as usize;
            lzma_sys::lzma_end(&mut stream);
            if ret != lzma_sys::LZMA_STREAM_END && ret != lzma_sys::LZMA_OK {
                return None;
            }
            out.truncate(produced);
            if out.is_empty() {
                return None;
            }
            Some(out)
        }
    }

    /// Regression: AES pack not slurped — mock pack panics on `as_bytes` and
    /// still decodes a member past the first 64 KiB window.
    #[test]
    fn regression_aes_pack_not_slurped_decode_past_first_window() {
        let mut n = 256 * 1024;
        let (data, packed) = loop {
            let data = incompressible(n);
            let Some(packed) = lzma2_compress_raw(&data) else {
                eprintln!("skip: lzma2 compress unavailable");
                return;
            };
            if packed.len() > PACKED_INPUT_WINDOW {
                break (data, packed);
            }
            n *= 2;
            if n > 8 * 1024 * 1024 {
                eprintln!(
                    "skip: could not produce packed size > {} (got {})",
                    PACKED_INPUT_WINDOW,
                    packed.len()
                );
                return;
            }
        };
        let max_read = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        let spy = SpyPack {
            inner: packed,
            max_read: std::sync::Arc::clone(&max_read),
        };
        let folder = lzma2_folder(data.len() as u64, Some(vec![22]));
        let mut decoder = Lzma2RandomAccessDecoder::from_pack_with_chunk_size(
            &folder,
            Box::new(spy),
            16 * 1024,
            4,
        )
        .expect("decoder from spy pack");
        decoder.force_progressive_for_test();
        let start = 128 * 1024;
        let got = decoder
            .read_range(start, 8192)
            .expect("decode past first 64 KiB window");
        assert_eq!(got, data[start as usize..start as usize + 8192]);
        let max = *max_read.lock().unwrap();
        assert!(
            max > 0 && max <= PACKED_INPUT_WINDOW,
            "max(read_at length)={max} must stay window-sized (not pack.size())"
        );
    }

    /// Regression: AES+LZMA2 independent-chunk resume (AES is input-side).
    #[test]
    fn regression_aes_lzma2_independent_chunk_resume() {
        const PART: usize = 2 * 1024 * 1024;
        let part1: Vec<u8> = (0..PART).map(|i| (i % 251) as u8).collect();
        let part2: Vec<u8> = (0..PART).map(|i| (i % 241) as u8 + 3).collect();
        let mut packed = lzma2_compress_raw(&part1).expect("compress part1");
        if packed.last() == Some(&0) {
            packed.pop();
        }
        packed.extend_from_slice(&lzma2_compress_raw(&part2).expect("compress part2"));
        let mut data = part1;
        data.extend_from_slice(&part2);

        let max_read = std::sync::Arc::new(std::sync::Mutex::new(0usize));
        let spy = SpyPack {
            inner: packed,
            max_read: std::sync::Arc::clone(&max_read),
        };
        let folder = aes_lzma2_folder(data.len() as u64);
        let mut decoder = Lzma2RandomAccessDecoder::from_pack_with_chunk_size(
            &folder,
            Box::new(spy),
            256 * 1024,
            DEFAULT_MAX_CACHED_CHUNKS,
        )
        .expect("AES-stripped LZMA2 decoder");
        decoder.force_progressive_for_test();
        assert!(
            decoder.allow_independent_resume(),
            "AES+LZMA2 must allow independent-chunk resume"
        );

        let mid = PART as u64 + 4096;
        let got = decoder.read_range(mid, 8192).expect("mid range");
        assert_eq!(got, data[mid as usize..mid as usize + 8192]);
        assert_eq!(
            decoder.prefix_from_zero_starts(),
            0,
            "must not start at unpacked 0 when an independent chunk covers mid"
        );
        assert!(
            decoder.last_resume_unpacked() >= PART as u64,
            "resume at/after part2 reset, got {}",
            decoder.last_resume_unpacked()
        );
        let max = *max_read.lock().unwrap();
        assert!(
            max <= PACKED_INPUT_WINDOW,
            "max(read_at)={max} must stay window-sized"
        );
    }

    /// Regression: BCJ+LZMA2 sequential is linear (one prefix start), not quadratic.
    #[test]
    fn regression_bcj_lzma2_sequential_windows_are_linear() {
        const WIN: usize = 1024 * 1024;
        const N: usize = 6;
        let data: Vec<u8> = (0u32..(N * WIN) as u32)
            .map(|i| (i.wrapping_mul(1664525).wrapping_add(1013904223) >> 24) as u8)
            .collect();
        let Some(packed) = bcj_lzma2_compress_raw(&data) else {
            eprintln!("skip: bcj+lzma2 compress unavailable");
            return;
        };
        let folder = bcj_lzma2_folder(data.len() as u64);
        let mut decoder =
            Lzma2RandomAccessDecoder::with_chunk_size(&folder, packed, WIN, 8).expect("decoder");
        decoder.force_progressive_for_test();
        assert!(
            !decoder.allow_independent_resume(),
            "BCJ+LZMA2 must not independent-chunk resume"
        );

        for i in 0..N {
            let got = decoder.read_range((i * WIN) as u64, WIN).expect("window");
            assert_eq!(got, data[i * WIN..(i + 1) * WIN], "window {i}");
        }
        assert_eq!(
            decoder.prefix_from_zero_starts(),
            1,
            "sequential BCJ+LZMA2 windows must start the decompressor from 0 once"
        );
        assert_eq!(
            decoder.decoder_starts(),
            1,
            "sequential BCJ+LZMA2 windows must not start extra decompressor instances"
        );
        let quadratic = (N * (N + 1) / 2) * WIN;
        assert!(
            decoder.bytes_decompressed() as usize <= N * WIN + WIN,
            "decompressed {} bytes (quadratic would be {quadratic})",
            decoder.bytes_decompressed()
        );
    }

    /// Regression: BCJ+LZMA2 does not independent-chunk resume (prefix-from-0).
    #[test]
    fn regression_bcj_lzma2_does_not_independent_chunk_resume() {
        const WIN: usize = 1024 * 1024;
        const N: usize = 4;
        let data: Vec<u8> = (0u32..(N * WIN) as u32)
            .map(|i| (i.wrapping_mul(1664525).wrapping_add(1013904223) >> 24) as u8)
            .collect();
        let Some(packed) = bcj_lzma2_compress_raw(&data) else {
            eprintln!("skip: bcj+lzma2 compress unavailable");
            return;
        };
        let folder = bcj_lzma2_folder(data.len() as u64);
        let mut decoder = Lzma2RandomAccessDecoder::with_chunk_size(
            &folder,
            packed,
            256 * 1024,
            DEFAULT_MAX_CACHED_CHUNKS,
        )
        .expect("decoder");
        decoder.force_progressive_for_test();
        assert!(!decoder.allow_independent_resume());

        // Late range first: must still start at unpacked 0 (no dict-reset resume).
        let late = ((N - 1) * WIN) as u64;
        let got = decoder.read_range(late, 8192).expect("late range");
        assert_eq!(got, data[late as usize..late as usize + 8192]);
        assert_eq!(
            decoder.last_resume_unpacked(),
            0,
            "BCJ must short-circuit resume_point to unpacked 0, got {}",
            decoder.last_resume_unpacked()
        );
        assert_eq!(
            decoder.prefix_from_zero_starts(),
            1,
            "late read must start a decoder from unpacked 0"
        );
        assert!(
            decoder.bytes_decompressed() >= late,
            "must decode the prefix (no dict-reset resume): {}",
            decoder.bytes_decompressed()
        );

        // Backward seek: another from-0 start, never a mid-stream dict-reset resume.
        let head = decoder.read_range(0, 4096).expect("head after late");
        assert_eq!(head, data[..4096]);
        assert_eq!(decoder.last_resume_unpacked(), 0);
        assert!(
            decoder.prefix_from_zero_starts() >= 2,
            "backward seek must restart from unpacked 0, not an independent chunk"
        );
    }

    #[test]
    fn create_folder_decoder_aes_lzma2_ok_bcj2_err() {
        let data: Vec<u8> = (0u8..=255).cycle().take(4096).collect();
        let packed = lzma2_compress_raw(&data).expect("lzma2");
        let aes = aes_lzma2_folder(data.len() as u64);
        let mut dec = create_folder_decoder(&aes, packed.clone(), 8).expect("AES+LZMA2 Ok");
        dec.force_progressive_for_test();
        assert!(dec.allow_independent_resume());
        assert_eq!(dec.read_range(0, 16).unwrap(), data[..16]);

        let bcj2 = Folder {
            coders: vec![Coder {
                method: METHOD_BCJ2.to_vec(),
                num_in_streams: 4,
                num_out_streams: 1,
                properties: None,
            }],
            bind_pairs: vec![],
            packed_indices: vec![0, 1, 2, 3],
            unpack_sizes: vec![data.len() as u64],
            has_crc: false,
            crc: 0,
        };
        match create_folder_decoder(&bcj2, packed, 8) {
            Ok(_) => panic!("BCJ2 must stay Err"),
            Err(e) => {
                let msg = e.to_string().to_ascii_lowercase();
                assert!(
                    msg.contains("bcj2"),
                    "BCJ2 must stay Err naming the method, got {msg}"
                );
            }
        }
    }

    /// Regression: PackSourceReader mid-member range (encrypted COPY open path).
    #[test]
    fn regression_pack_source_reader_mid_member_range() {
        let data: Vec<u8> = (0..8192).map(|i| (i % 251) as u8).collect();
        let pack = BytesPackSource::new(data.clone());
        let mut r = PackSourceReader::new(Box::new(pack), 1000, 500);
        r.seek(std::io::SeekFrom::Start(50)).unwrap();
        let mut buf = [0u8; 20];
        r.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, &data[1050..1070]);
        r.seek(std::io::SeekFrom::Start(0)).unwrap();
        let mut all = Vec::new();
        r.read_to_end(&mut all).unwrap();
        assert_eq!(all, data[1000..1500]);
    }
}
