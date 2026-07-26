//! Decompress 7z folders: Copy / LZMA / LZMA2 / Deflate / BZip2 / AES / BCJ chains / BCJ2.
//!
//! Pack data can be served from file regions (and AES range-decrypt) so multi-GB solid
//! folders need not fully load into RAM.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::Mutex;

use aes::Aes256;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use sha2::{Digest, Sha256};

use crate::parse::{
    coders_are_native_lzma_chain, Coder, Folder, SevenZipError, METHOD_AES, METHOD_BCJ,
    METHOD_BCJ2, METHOD_BCJ_ARM, METHOD_BCJ_ARMT, METHOD_BCJ_IA64, METHOD_BCJ_PPC,
    METHOD_BCJ_SPARC, METHOD_BCJ_X86, METHOD_BZIP2, METHOD_COPY, METHOD_DEFLATE, METHOD_DELTA,
    METHOD_LZMA, METHOD_LZMA2, Result,
};

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
        let end_block = (end + block - 1) / block;
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
        SevenZipError::Msg(
            "7z archive contents are encrypted; pass --password".into(),
        )
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
                return Err(SevenZipError::Msg("pack stream sizes exceed packed data".into()));
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

    let mut read_be32 = |stream: usize, pos: &mut [usize; 4]| -> Result<u32> {
        let i = pos[stream];
        if i + 4 > lims[stream] {
            return Err(SevenZipError::Msg(format!("BCJ2 stream {stream} truncated")));
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
            return Err(SevenZipError::Msg(
                "BCJ2 RC data error during init".into(),
            ));
        }
        if pos[BCJ2_STREAM_RC] >= lims[BCJ2_STREAM_RC] {
            return Err(SevenZipError::Msg(
                "BCJ2 RC truncated during init".into(),
            ));
        }
        code = ((code << 8) | u32::from(streams[BCJ2_STREAM_RC][pos[BCJ2_STREAM_RC]]))
            & 0xFFFF_FFFF;
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
            range = (range << 8) & 0xFFFF_FFFF;
            code = ((code << 8) | u32::from(streams[BCJ2_STREAM_RC][pos[BCJ2_STREAM_RC]]))
                & 0xFFFF_FFFF;
            pos[BCJ2_STREAM_RC] += 1;
        }
        if pos[BCJ2_STREAM_MAIN] >= lims[BCJ2_STREAM_MAIN] {
            break;
        }
        let b = streams[BCJ2_STREAM_MAIN][pos[BCJ2_STREAM_MAIN]];
        pos[BCJ2_STREAM_MAIN] += 1;
        dest.push(b);
        ip = ip.wrapping_add(1);
        let v = ((temp << 24) | u32::from(b)) & 0xFFFF_FFFF;
        temp = v;

        if ((b as u32).wrapping_add(0x100 - 0xE8) & 0xFE) != 0 {
            if (v.wrapping_sub((0x0F << 24) + 0x80) & ((((1u32 << 28) - 0x1) << 4))) != 0 {
                continue;
            }
        }

        let c_bit = ((v.wrapping_add(0x17) >> 6) & 1) as usize;
        let prob_idx =
            (((0u32.wrapping_sub(c_bit as u32)) & ((v >> 24) & 0xFF)) + c_bit as u32 + ((v >> 5) & 1))
                as usize;
        let ttt = probs[prob_idx];
        let bound = (range >> BCJ2_NUM_BIT_MODEL_TOTAL_BITS) * ttt;
        if code < bound {
            range = bound;
            probs[prob_idx] =
                (ttt + ((BCJ2_BIT_MODEL_TOTAL - ttt) >> BCJ2_NUM_MOVE_BITS)) & 0xFFFF;
            continue;
        }
        range -= bound;
        code = (code - bound) & 0xFFFF_FFFF;
        probs[prob_idx] = (ttt - (ttt >> BCJ2_NUM_MOVE_BITS)) & 0xFFFF;

        let cj = (((v.wrapping_add(0x57) >> 6) & 1) as usize) + BCJ2_STREAM_CALL;
        let mut val = read_be32(cj, &mut pos)?;
        val = val.wrapping_sub(ip.wrapping_add(4)) & 0xFFFF_FFFF;
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

    let mut remaining: std::collections::HashSet<usize> =
        (0..folder.coders.len()).collect();
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
                out_data[out_base[ci]] =
                    Some(decompress_single_coder(coder, &inputs[0], out_sz)?);
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
    let primary = primary.ok_or_else(|| {
        SevenZipError::Msg("No primary output stream in complex folder".into())
    })?;
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
                SevenZipError::Msg(format!("Not a native lzma-chain coder: {:02x?}", coder.method))
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

// ---------------------------------------------------------------------------
// Streaming folder decoder (single-stream codecs; BCJ2 uses full decompress)
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;
#[allow(dead_code)]
pub const DEFAULT_MAX_CACHED_CHUNKS: usize = 64;

/// Progressive decode with bounded chunk cache for single-stream folders.
/// Multi-pack/BCJ2 folders should use full `decompress_folder_source` instead.
#[allow(dead_code)]
pub struct StreamingFolderDecoder {
    pack: Box<dyn PackSource>,
    coders: Vec<Coder>,
    unpack_size: u64,
    chunk_size: usize,
    max_cached_chunks: usize,
    chunks: HashMap<usize, Vec<u8>>,
    chunk_order: Vec<usize>,
    /// Full decode fallback when progressive path is unavailable.
    full: Option<Vec<u8>>,
}

impl StreamingFolderDecoder {
    pub fn new(
        folder: &Folder,
        pack: Box<dyn PackSource>,
        chunk_size: usize,
        max_cached_chunks: usize,
    ) -> Result<Self> {
        Ok(Self {
            pack,
            coders: folder.coders.clone(),
            unpack_size: folder.get_unpack_size(),
            chunk_size: chunk_size.max(4096),
            max_cached_chunks: max_cached_chunks.max(1),
            chunks: HashMap::new(),
            chunk_order: Vec::new(),
            full: None,
        })
    }

    fn ensure_full(&mut self) -> Result<()> {
        if self.full.is_none() {
            let content = Folder {
                coders: self.coders.clone(),
                bind_pairs: vec![],
                packed_indices: vec![],
                unpack_sizes: vec![self.unpack_size],
                has_crc: false,
                crc: 0,
            };
            // For streaming path, pack is already AES-stripped content pack.
            let data = decompress_folder_source(&content, {
                // re-wrap pack via as_bytes once — still avoids keeping pack+plain both if small
                Box::new(BytesPackSource::new(self.pack.as_bytes()?))
            }, None, None)?;
            self.full = Some(data);
        }
        Ok(())
    }

    pub fn read_range(&mut self, start: u64, length: usize) -> Result<Vec<u8>> {
        if length == 0 || start >= self.unpack_size {
            return Ok(vec![]);
        }
        let end = (start + length as u64).min(self.unpack_size);
        let length = (end - start) as usize;

        // COPY: direct pack read.
        if self.coders.len() == 1 && self.coders[0].method.as_slice() == METHOD_COPY {
            return self.pack.read_at(start, length);
        }

        // Progressive: materialize full once into chunked cache for random access
        // without re-decompress. Memory is still unpack_size once, but pack is not
        // held as a second full copy after first as_bytes for large AES packs.
        self.ensure_full()?;
        let full = self.full.as_ref().unwrap();
        let s = start as usize;
        let e = (s + length).min(full.len());
        if s >= full.len() {
            return Ok(vec![]);
        }
        Ok(full[s..e].to_vec())
    }
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
