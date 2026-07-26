//! Decompress 7z folders (Copy / LZMA / LZMA2 / Deflate / BZip2 / AES).

use std::io::Read;

use aes::Aes256;
use cbc::cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use sha2::{Digest, Sha256};

use crate::parse::{
    Coder, Folder, SevenZipError, METHOD_AES, METHOD_BZIP2, METHOD_COPY, METHOD_DEFLATE,
    METHOD_LZMA, METHOD_LZMA2, Result,
};

type Aes256CbcDec = cbc::Decryptor<Aes256>;

pub fn decompress_folder(
    folder: &Folder,
    packed: &[u8],
    password: Option<&str>,
) -> Result<Vec<u8>> {
    let (content_folder, content_packed) = prepare_folder_packed(folder, packed, password)?;
    if content_folder.coders.len() != 1 {
        return Err(SevenZipError::Msg(format!(
            "Unsupported multi-coder folder: {:?}",
            content_folder
                .coders
                .iter()
                .map(|c| hex::encode_simple(&c.method))
                .collect::<Vec<_>>()
        )));
    }
    let coder = &content_folder.coders[0];
    let unpack_size = content_folder.get_unpack_size() as usize;
    let method = coder.method.as_slice();

    if method == METHOD_COPY {
        if content_packed.len() < unpack_size {
            return Err(SevenZipError::Msg("Copy data shorter than unpack size".into()));
        }
        return Ok(content_packed[..unpack_size].to_vec());
    }
    if method == METHOD_LZMA || method == METHOD_LZMA2 {
        return lzma_decompress_raw(coder, &content_packed, unpack_size);
    }
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

pub fn prepare_folder_packed(
    folder: &Folder,
    packed: &[u8],
    password: Option<&str>,
) -> Result<(Folder, Vec<u8>)> {
    if folder.coders.is_empty() {
        return Err(SevenZipError::Msg("Folder has no coders".into()));
    }
    if folder.coders[0].method.as_slice() != METHOD_AES {
        return Ok((folder.clone(), packed.to_vec()));
    }
    let password = password.ok_or_else(|| {
        SevenZipError::Msg(
            "7z archive contents are encrypted; pass --password".into(),
        )
    })?;
    let mut decrypted =
        aes_decrypt_7z(packed, folder.coders[0].properties.as_deref(), password)?;
    if !folder.unpack_sizes.is_empty() {
        let intermediate = folder.unpack_sizes[0] as usize;
        if intermediate <= decrypted.len() {
            decrypted.truncate(intermediate);
        }
    }
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
            unpack_sizes: vec![decrypted.len() as u64],
            has_crc: folder.has_crc,
            crc: folder.crc,
        };
        return Ok((content, decrypted));
    }
    if rest.len() != 1 {
        return Err(SevenZipError::Msg(
            "Unsupported encrypted multi-coder chain".into(),
        ));
    }
    let content_coder = &rest[0];
    let content_unpack = if folder.unpack_sizes.len() > 1 {
        folder.unpack_sizes[1..].to_vec()
    } else {
        vec![folder.get_unpack_size()]
    };
    let content = Folder {
        coders: vec![content_coder.clone()],
        bind_pairs: vec![],
        packed_indices: vec![],
        unpack_sizes: content_unpack,
        has_crc: folder.has_crc,
        crc: folder.crc,
    };
    Ok((content, decrypted))
}

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

fn aes_decrypt_7z(packed: &[u8], properties: Option<&[u8]>, password: &str) -> Result<Vec<u8>> {
    let password_bytes: Vec<u8> = password
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let props = parse_aes_properties(properties)?;
    let key = calculate_7z_key(&password_bytes, props.cycles, &props.salt)?;
    if packed.is_empty() {
        return Ok(vec![]);
    }
    let mut data = packed.to_vec();
    if data.len() % 16 != 0 {
        data.resize(data.len() + (16 - data.len() % 16), 0);
    }
    let dec = Aes256CbcDec::new_from_slices(&key, &props.iv)
        .map_err(|e| SevenZipError::Msg(format!("AES key/iv: {e}")))?;
    let decrypted = dec
        .decrypt_padded_mut::<NoPadding>(&mut data)
        .map_err(|e| SevenZipError::Msg(format!("AES decrypt: {e}")))?;
    Ok(decrypted.to_vec())
}

fn lzma_decompress_raw(coder: &Coder, packed: &[u8], unpack_size: usize) -> Result<Vec<u8>> {
    use std::os::raw::c_void;

    let filter_id = if coder.method.as_slice() == METHOD_LZMA2 {
        lzma_sys::LZMA_FILTER_LZMA2
    } else {
        lzma_sys::LZMA_FILTER_LZMA1
    };
    let props = coder.properties.as_deref().unwrap_or(&[]);

    unsafe {
        let mut filter = lzma_sys::lzma_filter {
            id: filter_id,
            options: std::ptr::null_mut(),
        };
        let ret = lzma_sys::lzma_properties_decode(
            &mut filter,
            std::ptr::null(),
            props.as_ptr(),
            props.len(),
        );
        if ret != lzma_sys::LZMA_OK {
            return Err(SevenZipError::Msg(format!(
                "lzma_properties_decode failed: {ret}"
            )));
        }
        let filters = [
            filter,
            lzma_sys::lzma_filter {
                id: lzma_sys::LZMA_VLI_UNKNOWN,
                options: std::ptr::null_mut(),
            },
        ];
        let opts_ptr = filters[0].options;
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
        // Free options allocated by lzma_properties_decode.
        if !opts_ptr.is_null() {
            libc::free(opts_ptr as *mut c_void);
        }
        if ret != lzma_sys::LZMA_OK && ret != lzma_sys::LZMA_STREAM_END {
            // Some streams need larger intermediate; try streaming via lzma_raw_decoder.
            return lzma_stream_decode(filter_id, props, packed, unpack_size);
        }
        out.truncate(out_pos.min(unpack_size));
        if out.len() < unpack_size {
            return lzma_stream_decode(filter_id, props, packed, unpack_size);
        }
        Ok(out)
    }
}

fn lzma_stream_decode(
    filter_id: lzma_sys::lzma_vli,
    props: &[u8],
    packed: &[u8],
    unpack_size: usize,
) -> Result<Vec<u8>> {
    use std::os::raw::c_void;

    unsafe {
        let mut filter = lzma_sys::lzma_filter {
            id: filter_id,
            options: std::ptr::null_mut(),
        };
        let ret = lzma_sys::lzma_properties_decode(
            &mut filter,
            std::ptr::null(),
            props.as_ptr(),
            props.len(),
        );
        if ret != lzma_sys::LZMA_OK {
            return Err(SevenZipError::Msg(format!(
                "lzma_properties_decode failed: {ret}"
            )));
        }
        let filters = [
            filter,
            lzma_sys::lzma_filter {
                id: lzma_sys::LZMA_VLI_UNKNOWN,
                options: std::ptr::null_mut(),
            },
        ];
        let opts_ptr = filters[0].options;
        let mut stream: lzma_sys::lzma_stream = std::mem::zeroed();
        let ret = lzma_sys::lzma_raw_decoder(&mut stream, filters.as_ptr());
        if ret != lzma_sys::LZMA_OK {
            if !opts_ptr.is_null() {
                libc::free(opts_ptr as *mut c_void);
            }
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
                if !opts_ptr.is_null() {
                    libc::free(opts_ptr as *mut c_void);
                }
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
        if !opts_ptr.is_null() {
            libc::free(opts_ptr as *mut c_void);
        }
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

// Minimal hex helper without extra crate.
mod hex {
    pub fn encode_simple(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}
