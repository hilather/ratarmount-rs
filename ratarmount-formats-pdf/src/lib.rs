//! PDF MountSource (`backendName=PDFMountSource`).
//!
//! Extracts:
//! - Embedded file attachments via [`lopdf`] (Names tree + FileAttachment annotations +
//!   Filespec objects), exposed at their original attachment paths.
//! - Page XObject images under `images/pageN-imgM.<ext>` (1-based page, 0-based image index).
//!
//! Image formats:
//! - `/Filter /DCTDecode` → `.jpg` (raw JPEG bitstream, no re-encoding)
//! - `/Filter /JPXDecode` → `.jp2` (raw JPEG 2000 bitstream)
//! - Sole `/Filter /FlateDecode` or no filter, with `/ColorSpace /DeviceGray` or
//!   `/DeviceRGB` (and CalGray/CalRGB) at 1/2/4/8/16 bits/component → `.png`
//!   (samples expanded to 8-bpc and re-encoded as PNG)
//! - Sole `/Filter /FlateDecode` or no filter, `/DeviceCMYK` (and CalCMYK) at 8 bpc →
//!   `.png` (CMYK→RGB via undercolor-removal photometric formula, then PNG)
//! - `/ColorSpace [/Indexed base hival lookup]` with DeviceGray/RGB/CMYK (or ICCBased
//!   N=1/3/4) base → expand index samples via lookup table to base samples, then PNG
//! - `/ColorSpace [/ICCBased …]` with stream `/N` = 1, 3, or 4 → treat sample layout as
//!   Gray/RGB/CMYK (**ignore ICC profile**; no colorimetric transform) when BPC is
//!   supported (same as the matching Device* path)
//! - Multi-filter chains, non-8-bpc CMYK, Separation/DeviceN/Lab, unsupported Indexed
//!   bases, ICCBased N∉{1,3,4}, and other residual cases → `.bin` (stream bytes as
//!   stored; not reassembled)
//!
//! Note: lopdf refuses to run `decompressed_content` on `/Subtype /Image` streams, so
//! FlateDecode inflation and PNG reassembly are done here with `flate2` + `png`.
//!
//! Text extraction is out of scope.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use flate2::read::{DeflateDecoder, ZlibDecoder};
use lopdf::{Document, Object, ObjectId, Stream};
use ratarmount_core::{
    normpath, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions, UserData,
};
use ratarmount_index::{IndexError, SqliteIndex};
use thiserror::Error;

pub const BACKEND_NAME: &str = "PDFMountSource";

#[derive(Debug, Error)]
pub enum PdfError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, PdfError>;

pub fn looks_like_pdf(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        let mut magic = [0u8; 5];
        if f.read(&mut magic).ok() == Some(5) && &magic == b"%PDF-" {
            return true;
        }
    }
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("pdf"))
}

fn pdf_string(obj: &Object) -> Option<String> {
    match obj {
        Object::String(bytes, _) => Some(String::from_utf8_lossy(bytes).into_owned()),
        Object::Name(n) => Some(String::from_utf8_lossy(n).into_owned()),
        _ => None,
    }
}

fn resolve<'a>(doc: &'a Document, obj: &'a Object) -> Option<&'a Object> {
    match obj {
        Object::Reference(id) => doc.get_object(*id).ok(),
        other => Some(other),
    }
}

fn stream_bytes(doc: &Document, id: ObjectId) -> Option<Vec<u8>> {
    let obj = doc.get_object(id).ok()?;
    match obj {
        Object::Stream(stream) => {
            if let Ok(data) = stream.decompressed_content() {
                Some(data)
            } else {
                Some(stream.content.clone())
            }
        }
        _ => None,
    }
}

/// Source color space for image sample reassembly (before PNG encoding).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ImageColorSpace {
    Gray,
    Rgb,
    /// Converted to RGB PNG via undercolor-removal photometric formula (8 bpc only).
    Cmyk,
}

impl ImageColorSpace {
    fn channels(self) -> usize {
        match self {
            ImageColorSpace::Gray => 1,
            ImageColorSpace::Rgb => 3,
            ImageColorSpace::Cmyk => 4,
        }
    }

    /// PNG color type after conversion (CMYK becomes RGB).
    fn png_color(self) -> PngColor {
        match self {
            ImageColorSpace::Gray => PngColor::Gray,
            ImageColorSpace::Rgb | ImageColorSpace::Cmyk => PngColor::Rgb,
        }
    }
}

/// PNG-encodable color type (post conversion).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PngColor {
    Gray,
    Rgb,
}

impl PngColor {
    fn channels(self) -> usize {
        match self {
            PngColor::Gray => 1,
            PngColor::Rgb => 3,
        }
    }

    fn png_color_type(self) -> png::ColorType {
        match self {
            PngColor::Gray => png::ColorType::Grayscale,
            PngColor::Rgb => png::ColorType::Rgb,
        }
    }
}

fn dict_i64(dict: &lopdf::Dictionary, key: &[u8]) -> Option<i64> {
    dict.get(key).ok().and_then(|o| o.as_i64().ok())
}

fn image_color_from_name(name: &str) -> Option<ImageColorSpace> {
    match name {
        "DeviceGray" | "CalGray" => Some(ImageColorSpace::Gray),
        "DeviceRGB" | "CalRGB" => Some(ImageColorSpace::Rgb),
        "DeviceCMYK" | "CalCMYK" => Some(ImageColorSpace::Cmyk),
        // Separation / DeviceN / Lab / Pattern → residual .bin
        _ => None,
    }
}

/// Resolved color interpretation for sample reassembly (before PNG encoding).
#[derive(Clone, Debug)]
enum ResolvedColorSpace {
    /// Direct Device*/Cal* or ICCBased-as-N-channels samples.
    Direct(ImageColorSpace),
    /// Indexed: single-channel indices expanded via lookup into `base` samples.
    Indexed {
        base: ImageColorSpace,
        /// `(hival + 1) * base.channels()` bytes; each base component is 8-bit.
        lookup: Vec<u8>,
        hival: usize,
    },
}

/// Resolve `obj` through an optional document reference chain.
fn resolve_object<'a>(doc: Option<&'a Document>, obj: &'a Object) -> Option<&'a Object> {
    match obj {
        Object::Reference(id) => doc?.get_object(*id).ok(),
        other => Some(other),
    }
}

/// Bytes of an Indexed lookup table (string, stream, or reference thereto).
fn indexed_lookup_bytes(doc: Option<&Document>, obj: &Object) -> Option<Vec<u8>> {
    let obj = resolve_object(doc, obj)?;
    match obj {
        Object::String(bytes, _) => Some(bytes.clone()),
        Object::Stream(stream) => {
            // Lookup streams are not Image subtype; try lopdf inflate then raw/flate.
            if let Ok(data) = stream.decompressed_content() {
                return Some(data);
            }
            if let Some(data) = inflate_flate(&stream.content) {
                return Some(data);
            }
            Some(stream.content.clone())
        }
        _ => None,
    }
}

/// ICCBased: ignore the profile; use `/N` (or Alternate device name) for channel layout.
///
/// Supported: N=1 → Gray, N=3 → RGB, N=4 → CMYK. Other N values are residual `.bin`.
fn resolve_iccbased_stream(stream: &Stream) -> Option<ImageColorSpace> {
    if let Some(n) = dict_i64(&stream.dict, b"N") {
        return match n {
            1 => Some(ImageColorSpace::Gray),
            3 => Some(ImageColorSpace::Rgb),
            4 => Some(ImageColorSpace::Cmyk),
            _ => None,
        };
    }
    // Fall back to /Alternate when /N is missing.
    let alt = stream.dict.get(b"Alternate").ok()?;
    match alt {
        Object::Name(n) => image_color_from_name(&String::from_utf8_lossy(n)),
        Object::Array(arr) if !arr.is_empty() => {
            arr[0].as_name_str().ok().and_then(image_color_from_name)
        }
        _ => None,
    }
}

/// Resolve a ColorSpace object (name, array, or reference) for image sample reassembly.
///
/// `doc` is used to follow object references (Indexed lookup streams, ICCBased profile
/// streams). Inline forms work with `doc = None`.
fn resolve_image_color_space(
    doc: Option<&Document>,
    cs_obj: &Object,
) -> Option<ResolvedColorSpace> {
    let obj = resolve_object(doc, cs_obj)?;
    match obj {
        Object::Name(n) => {
            image_color_from_name(&String::from_utf8_lossy(n)).map(ResolvedColorSpace::Direct)
        }
        Object::Array(arr) if !arr.is_empty() => {
            let kind = arr[0].as_name_str().ok()?;
            match kind {
                "Indexed" => {
                    // [/Indexed base hival lookup]
                    if arr.len() < 4 {
                        return None;
                    }
                    let base = match resolve_image_color_space(doc, &arr[1])? {
                        ResolvedColorSpace::Direct(cs) => cs,
                        // Nested Indexed is not supported.
                        ResolvedColorSpace::Indexed { .. } => return None,
                    };
                    let hival = arr[2].as_i64().ok()?;
                    if hival < 0 {
                        return None;
                    }
                    let hival = hival as usize;
                    let lookup = indexed_lookup_bytes(doc, &arr[3])?;
                    let need = (hival + 1).checked_mul(base.channels())?;
                    if lookup.len() < need {
                        return None;
                    }
                    Some(ResolvedColorSpace::Indexed {
                        base,
                        lookup: lookup[..need].to_vec(),
                        hival,
                    })
                }
                "ICCBased" => {
                    // [/ICCBased stream] — profile ignored; use N channels.
                    if arr.len() < 2 {
                        return None;
                    }
                    let profile = resolve_object(doc, &arr[1])?;
                    let Object::Stream(stream) = profile else {
                        return None;
                    };
                    resolve_iccbased_stream(stream).map(ResolvedColorSpace::Direct)
                }
                // CalRGB/Lab etc. may appear as parameter arrays; use the type name.
                other => image_color_from_name(other).map(ResolvedColorSpace::Direct),
            }
        }
        // Bare ICC profile stream (unusual as ColorSpace value, but harmless).
        Object::Stream(stream) => resolve_iccbased_stream(stream).map(ResolvedColorSpace::Direct),
        _ => None,
    }
}

/// Unpack tightly packed PDF samples to one `u8` per sample **without** 0..=255 scaling.
///
/// Used for Indexed indices (1/2/4/8 bpc). Values are raw bit-field integers.
fn unpack_indices_u8(packed: &[u8], width: usize, height: usize, bpc: usize) -> Option<Vec<u8>> {
    if width == 0 || height == 0 {
        return None;
    }
    let samples_per_row = width;
    let out_len = samples_per_row.checked_mul(height)?;

    match bpc {
        8 => {
            if packed.len() < out_len {
                return None;
            }
            Some(packed[..out_len].to_vec())
        }
        1 | 2 | 4 => {
            let bytes_per_row = packed_row_bytes(width, 1, bpc)?;
            let expected = bytes_per_row.checked_mul(height)?;
            if packed.len() < expected {
                return None;
            }
            let mask = (1u32 << bpc) - 1;
            let mut out = Vec::with_capacity(out_len);
            for row in 0..height {
                let row_data = &packed[row * bytes_per_row..(row + 1) * bytes_per_row];
                let mut bit_pos = 0usize;
                for _ in 0..samples_per_row {
                    let byte_idx = bit_pos / 8;
                    let bit_offset = bit_pos % 8;
                    let available = 8 - bit_offset;
                    let sample = if available >= bpc {
                        ((row_data[byte_idx] as u32) >> (available - bpc)) & mask
                    } else {
                        let hi_bits = available;
                        let lo_bits = bpc - hi_bits;
                        let hi = (row_data[byte_idx] as u32) & ((1u32 << hi_bits) - 1);
                        let lo = (row_data[byte_idx + 1] as u32) >> (8 - lo_bits);
                        (hi << lo_bits) | lo
                    };
                    out.push(sample as u8);
                    bit_pos += bpc;
                }
            }
            Some(out)
        }
        // Indexed images use BPC 1/2/4/8 per PDF; 16-bpc indices are unsupported.
        _ => None,
    }
}

/// Expand Indexed indices through the lookup table into contiguous base-space samples.
fn expand_indexed_samples(
    indices: &[u8],
    base: ImageColorSpace,
    lookup: &[u8],
    hival: usize,
) -> Option<Vec<u8>> {
    let n = base.channels();
    let need = (hival + 1).checked_mul(n)?;
    if lookup.len() < need {
        return None;
    }
    let mut out = Vec::with_capacity(indices.len().checked_mul(n)?);
    for &idx in indices {
        let i = (idx as usize).min(hival);
        let off = i * n;
        out.extend_from_slice(&lookup[off..off + n]);
    }
    Some(out)
}

/// Inflate PDF FlateDecode data (zlib wrapper preferred; raw deflate as fallback).
fn inflate_flate(data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::with_capacity(data.len().saturating_mul(2));
    {
        let mut z = ZlibDecoder::new(data);
        if z.read_to_end(&mut out).is_ok() {
            return Some(out);
        }
    }
    out.clear();
    let mut d = DeflateDecoder::new(data);
    if d.read_to_end(&mut out).is_ok() {
        return Some(out);
    }
    None
}

/// Apply PDF `/DecodeParms` predictors after Flate inflation (PNG 10–15 and TIFF 2).
fn apply_predictor(data: Vec<u8>, params: Option<&lopdf::Dictionary>) -> Option<Vec<u8>> {
    let Some(params) = params else {
        return Some(data);
    };
    let predictor = dict_i64(params, b"Predictor").unwrap_or(1);
    if predictor == 1 {
        return Some(data);
    }

    let columns = dict_i64(params, b"Columns").unwrap_or(1).max(1) as usize;
    let colors = dict_i64(params, b"Colors").unwrap_or(1).max(1) as usize;
    let bits = dict_i64(params, b"BitsPerComponent").unwrap_or(8).max(1) as usize;

    if (10..=15).contains(&predictor) {
        // PNG filter methods: each row is filter_byte + row_bytes.
        if !bits.is_multiple_of(8) {
            return None;
        }
        let bytes_per_pixel = colors * (bits / 8);
        let bytes_per_row = bytes_per_pixel * columns;
        return decode_png_predictor_rows(&data, bytes_per_pixel, bytes_per_row);
    }

    if predictor == 2 {
        // TIFF horizontal differencing (8-bit samples only).
        if bits != 8 {
            return None;
        }
        return Some(decode_tiff_predictor(&data, columns, colors));
    }

    // Unknown predictor: leave data unchanged (best-effort).
    Some(data)
}

fn decode_png_predictor_rows(
    content: &[u8],
    bytes_per_pixel: usize,
    bytes_per_row: usize,
) -> Option<Vec<u8>> {
    if bytes_per_row == 0 {
        return Some(Vec::new());
    }
    let row_stride = bytes_per_row + 1; // filter byte + samples
    if !content.len().is_multiple_of(row_stride) {
        return None;
    }
    let mut previous = vec![0u8; bytes_per_row];
    let mut current = vec![0u8; bytes_per_row];
    let mut decoded = Vec::with_capacity(content.len());
    let bpp = bytes_per_pixel.min(bytes_per_row);

    for row in content.chunks_exact(row_stride) {
        let filter = row[0];
        current.copy_from_slice(&row[1..]);
        match filter {
            0 => {} // None
            1 => {
                // Sub
                for i in bpp..bytes_per_row {
                    current[i] = current[i].wrapping_add(current[i - bpp]);
                }
            }
            2 => {
                // Up
                for i in 0..bytes_per_row {
                    current[i] = current[i].wrapping_add(previous[i]);
                }
            }
            3 => {
                // Average: floor((left + above) / 2)
                for i in 0..bpp {
                    current[i] = current[i].wrapping_add(previous[i] / 2);
                }
                for i in bpp..bytes_per_row {
                    let avg = ((i16::from(current[i - bpp]) + i16::from(previous[i])) / 2) as u8;
                    current[i] = current[i].wrapping_add(avg);
                }
            }
            4 => {
                // Paeth
                for i in 0..bpp {
                    current[i] = current[i].wrapping_add(paeth_predict(0, previous[i], 0));
                }
                for i in bpp..bytes_per_row {
                    current[i] = current[i].wrapping_add(paeth_predict(
                        current[i - bpp],
                        previous[i],
                        previous[i - bpp],
                    ));
                }
            }
            _ => return None,
        }
        decoded.extend_from_slice(&current);
        std::mem::swap(&mut previous, &mut current);
    }
    Some(decoded)
}

fn paeth_predict(left: u8, above: u8, upperleft: u8) -> u8 {
    let a = i16::from(left);
    let b = i16::from(above);
    let c = i16::from(upperleft);
    let p = a + b - c;
    let pa = (p - a).abs();
    let pb = (p - b).abs();
    let pc = (p - c).abs();
    if pa <= pb && pa <= pc {
        left
    } else if pb <= pc {
        above
    } else {
        upperleft
    }
}

fn decode_tiff_predictor(data: &[u8], columns: usize, colors: usize) -> Vec<u8> {
    let row_len = columns * colors;
    if row_len == 0 {
        return data.to_vec();
    }
    let mut out = data.to_vec();
    for row in out.chunks_exact_mut(row_len) {
        for i in colors..row.len() {
            row[i] = row[i].wrapping_add(row[i - colors]);
        }
    }
    out
}

/// Packed sample bytes per image row (PDF pads each row to a full byte).
fn packed_row_bytes(width: usize, channels: usize, bpc: usize) -> Option<usize> {
    let bits = width.checked_mul(channels)?.checked_mul(bpc)?;
    Some(bits.div_ceil(8))
}

/// Scale a sample with `bpc` significant bits into the 0..=255 range.
fn scale_sample_to_u8(value: u32, bpc: usize) -> u8 {
    if bpc == 0 || bpc >= 8 {
        return value.min(255) as u8;
    }
    let max = (1u32 << bpc) - 1;
    value
        .checked_mul(255)
        .and_then(|n| n.checked_div(max))
        .unwrap_or(0) as u8
}

/// Expand packed PDF image samples (1/2/4/8/16 bpc) to contiguous 8-bpc samples.
///
/// PDF packs components tightly within a row and pads each row to a byte boundary
/// (ISO 32000-1 §8.9.2). Multi-byte samples are big-endian.
fn expand_samples_to_8bpc(
    packed: &[u8],
    width: usize,
    height: usize,
    channels: usize,
    bpc: usize,
) -> Option<Vec<u8>> {
    if width == 0 || height == 0 || channels == 0 {
        return None;
    }
    let samples_per_row = width.checked_mul(channels)?;
    let out_len = samples_per_row.checked_mul(height)?;

    match bpc {
        8 => {
            let expected = out_len;
            if packed.len() < expected {
                return None;
            }
            Some(packed[..expected].to_vec())
        }
        16 => {
            // Two bytes per sample, big-endian; take high byte (or full-range scale).
            let bytes_per_row = samples_per_row.checked_mul(2)?;
            let expected = bytes_per_row.checked_mul(height)?;
            if packed.len() < expected {
                return None;
            }
            let mut out = Vec::with_capacity(out_len);
            for row in 0..height {
                let base = row * bytes_per_row;
                for i in 0..samples_per_row {
                    let off = base + i * 2;
                    let hi = packed[off] as u32;
                    let lo = packed[off + 1] as u32;
                    let v = (hi << 8) | lo;
                    // Map 0..=65535 → 0..=255.
                    out.push(((v * 255) / 65535) as u8);
                }
            }
            Some(out)
        }
        1 | 2 | 4 => {
            let bytes_per_row = packed_row_bytes(width, channels, bpc)?;
            let expected = bytes_per_row.checked_mul(height)?;
            if packed.len() < expected {
                return None;
            }
            let mask = (1u32 << bpc) - 1;
            let mut out = Vec::with_capacity(out_len);
            for row in 0..height {
                let row_data = &packed[row * bytes_per_row..(row + 1) * bytes_per_row];
                let mut bit_pos = 0usize;
                for _ in 0..samples_per_row {
                    let byte_idx = bit_pos / 8;
                    let bit_offset = bit_pos % 8; // bits already consumed in this byte
                    let available = 8 - bit_offset;
                    let sample = if available >= bpc {
                        // Entire sample sits in this byte (MSB-first packing).
                        ((row_data[byte_idx] as u32) >> (available - bpc)) & mask
                    } else {
                        // Spans two bytes (rare for 1/2/4 when starting aligned, but safe).
                        let hi_bits = available;
                        let lo_bits = bpc - hi_bits;
                        let hi = (row_data[byte_idx] as u32) & ((1u32 << hi_bits) - 1);
                        let lo = (row_data[byte_idx + 1] as u32) >> (8 - lo_bits);
                        (hi << lo_bits) | lo
                    };
                    out.push(scale_sample_to_u8(sample, bpc));
                    bit_pos += bpc;
                }
            }
            Some(out)
        }
        _ => None,
    }
}

/// Convert 8-bpc DeviceCMYK samples to 8-bpc DeviceRGB using the simple
/// undercolor-removal photometric formula:
/// `R = (1-C)*(1-K)`, similarly for G/B (components in 0..=1).
fn cmyk_to_rgb(cmyk: &[u8]) -> Option<Vec<u8>> {
    if !cmyk.len().is_multiple_of(4) {
        return None;
    }
    let mut rgb = Vec::with_capacity(cmyk.len() / 4 * 3);
    for chunk in cmyk.chunks_exact(4) {
        let c = u16::from(chunk[0]);
        let m = u16::from(chunk[1]);
        let y = u16::from(chunk[2]);
        let k = u16::from(chunk[3]);
        rgb.push((((255 - c) * (255 - k)) / 255) as u8);
        rgb.push((((255 - m) * (255 - k)) / 255) as u8);
        rgb.push((((255 - y) * (255 - k)) / 255) as u8);
    }
    Some(rgb)
}

/// Encode raw 8-bpc Gray or RGB samples as a PNG file.
fn encode_png(width: u32, height: u32, color: PngColor, samples: &[u8]) -> Option<Vec<u8>> {
    let expected = (width as usize)
        .checked_mul(height as usize)?
        .checked_mul(color.channels())?;
    if samples.len() < expected {
        return None;
    }
    let samples = &samples[..expected];

    let mut buf = Vec::new();
    {
        let mut encoder = png::Encoder::new(&mut buf, width, height);
        encoder.set_color(color.png_color_type());
        encoder.set_depth(png::BitDepth::Eight);
        let mut writer = encoder.write_header().ok()?;
        writer.write_image_data(samples).ok()?;
    }
    Some(buf)
}

/// Try to reassemble FlateDecode (or raw uncompressed) Image XObject samples as PNG.
///
/// Supported:
/// - `/DeviceGray` / `/CalGray` and `/DeviceRGB` / `/CalRGB` at 1, 2, 4, 8, or 16 bpc
/// - `/DeviceCMYK` / `/CalCMYK` at 8 bpc (converted to RGB)
/// - `/Indexed` with Device*/ICCBased base (lookup expanded to base samples)
/// - `/ICCBased` with N∈{1,3,4} (profile ignored; channel layout only)
///
/// Multi-filter chains, non-8-bpc CMYK, unsupported spaces, and failed inflation fall
/// through to the caller (`.bin`).
fn try_samples_to_png(doc: Option<&Document>, stream: &Stream, inflate: bool) -> Option<Vec<u8>> {
    let width = dict_i64(&stream.dict, b"Width")? as u32;
    let height = dict_i64(&stream.dict, b"Height")? as u32;
    if width == 0 || height == 0 {
        return None;
    }
    let bpc = dict_i64(&stream.dict, b"BitsPerComponent").unwrap_or(8);
    if !matches!(bpc, 1 | 2 | 4 | 8 | 16) {
        return None;
    }
    let bpc = bpc as usize;
    let cs_obj = stream.dict.get(b"ColorSpace").ok()?;
    let resolved = resolve_image_color_space(doc, cs_obj)?;

    let samples = if inflate {
        let inflated = inflate_flate(&stream.content)?;
        let params = stream
            .dict
            .get(b"DecodeParms")
            .ok()
            .and_then(|o| o.as_dict().ok());
        apply_predictor(inflated, params)?
    } else {
        stream.content.clone()
    };

    let w = width as usize;
    let h = height as usize;

    let (expanded, color_space) = match resolved {
        ResolvedColorSpace::Direct(color_space) => {
            // CMYK only at 8 bpc (task scope).
            if color_space == ImageColorSpace::Cmyk && bpc != 8 {
                return None;
            }
            let channels = color_space.channels();
            let expanded = expand_samples_to_8bpc(&samples, w, h, channels, bpc)?;
            (expanded, color_space)
        }
        ResolvedColorSpace::Indexed {
            base,
            lookup,
            hival,
        } => {
            // Indexed: BPC applies to the index channel (1/2/4/8); base samples are 8-bit.
            if !matches!(bpc, 1 | 2 | 4 | 8) {
                return None;
            }
            // CMYK base only when base samples are 8-bpc (always true for lookup tables).
            let indices = unpack_indices_u8(&samples, w, h, bpc)?;
            let expanded = expand_indexed_samples(&indices, base, &lookup, hival)?;
            (expanded, base)
        }
    };

    let rgb_or_gray = match color_space {
        ImageColorSpace::Cmyk => cmyk_to_rgb(&expanded)?,
        ImageColorSpace::Gray | ImageColorSpace::Rgb => expanded,
    };

    encode_png(width, height, color_space.png_color(), &rgb_or_gray)
}

/// Choose file extension and payload for an Image XObject stream.
///
/// lopdf refuses to run `decompressed_content` on `/Subtype /Image` streams (pixel data is
/// not general stream content). For sole `/DCTDecode` / `/JPXDecode` the stored bytes are
/// already a usable file. Sole `/FlateDecode` or no filter with Gray/RGB (1–16 bpc),
/// CMYK (8 bpc), Indexed (supported bases), or ICCBased N∈{1,3,4} is reassembled into
/// PNG. Other cases emit raw stream content as `.bin`.
///
/// `doc` resolves ColorSpace / lookup object references; pass `None` for fully-inline
/// synthetic streams.
fn image_payload_and_ext(doc: Option<&Document>, stream: &Stream) -> (Vec<u8>, &'static str) {
    let filters = stream.filters().unwrap_or_default();
    if filters.len() == 1 {
        match filters[0].as_str() {
            "DCTDecode" => return (stream.content.clone(), "jpg"),
            "JPXDecode" => return (stream.content.clone(), "jp2"),
            "FlateDecode" => {
                if let Some(png) = try_samples_to_png(doc, stream, true) {
                    return (png, "png");
                }
            }
            _ => {}
        }
    } else if filters.is_empty() {
        if let Some(png) = try_samples_to_png(doc, stream, false) {
            return (png, "png");
        }
    }
    // Multi-filter, exotic depths/spaces, or failed reassembly: keep stored bytes.
    (stream.content.clone(), "bin")
}

/// Resolve a Resources dictionary from a page node or referenced object.
fn resources_dict<'a>(
    doc: &'a Document,
    page: &'a lopdf::Dictionary,
) -> Option<&'a lopdf::Dictionary> {
    match page.get(b"Resources").ok() {
        Some(Object::Dictionary(d)) => Some(d),
        Some(Object::Reference(id)) => doc.get_dictionary(*id).ok(),
        _ => {
            // Inherit from parent Pages nodes.
            let mut parent = page.get(b"Parent").ok().and_then(|o| o.as_reference().ok());
            let mut seen = HashSet::new();
            while let Some(pid) = parent {
                if !seen.insert(pid) {
                    break;
                }
                let Ok(pdict) = doc.get_dictionary(pid) else {
                    break;
                };
                match pdict.get(b"Resources").ok() {
                    Some(Object::Dictionary(d)) => return Some(d),
                    Some(Object::Reference(id)) => return doc.get_dictionary(*id).ok(),
                    _ => {}
                }
                parent = pdict
                    .get(b"Parent")
                    .ok()
                    .and_then(|o| o.as_reference().ok());
            }
            None
        }
    }
}

fn xobject_dict<'a>(
    doc: &'a Document,
    resources: &'a lopdf::Dictionary,
) -> Option<&'a lopdf::Dictionary> {
    match resources.get(b"XObject").ok() {
        Some(Object::Dictionary(d)) => Some(d),
        Some(Object::Reference(id)) => doc.get_dictionary(*id).ok(),
        _ => None,
    }
}

/// Collect image XObjects from page resources: `(path, stream_id, payload)`.
///
/// Paths use `images/page{N}-img{M}.{ext}` with 1-based page and 0-based image index so they
/// never collide with attachment names at the mount root.
fn gather_images(doc: &Document) -> Vec<(String, ObjectId, Vec<u8>)> {
    let mut out = Vec::new();
    let mut used_names: HashMap<String, u32> = HashMap::new();

    for (page_num, page_id) in doc.get_pages() {
        let Ok(page) = doc.get_dictionary(page_id) else {
            continue;
        };
        let Some(resources) = resources_dict(doc, page) else {
            continue;
        };
        let Some(xobjects) = xobject_dict(doc, resources) else {
            continue;
        };

        let mut img_idx: u32 = 0;
        // Stable order: iterate by name sorted for determinism.
        let mut entries: Vec<(Vec<u8>, &Object)> =
            xobjects.iter().map(|(k, v)| (k.clone(), v)).collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        for (_name, xvalue) in entries {
            let stream_id = match xvalue {
                Object::Reference(id) => *id,
                _ => continue,
            };
            let Ok(obj) = doc.get_object(stream_id) else {
                continue;
            };
            let Object::Stream(stream) = obj else {
                continue;
            };
            let is_image = stream
                .dict
                .get(b"Subtype")
                .ok()
                .and_then(|s| s.as_name().ok())
                .is_some_and(|n| n == b"Image");
            if !is_image {
                continue;
            }

            let (data, ext) = image_payload_and_ext(Some(doc), stream);
            if data.is_empty() {
                continue;
            }

            let mut name = format!("images/page{page_num}-img{img_idx}.{ext}");
            img_idx += 1;

            if let Some(n) = used_names.get_mut(&name) {
                *n += 1;
                let count = *n;
                if let Some((stem, e)) = name.rsplit_once('.') {
                    name = format!("{stem}-{count}.{e}");
                } else {
                    name = format!("{name}-{count}");
                }
            } else {
                used_names.insert(name.clone(), 0);
            }

            out.push((name, stream_id, data));
        }
    }
    out
}

/// Collect (display_name, embedded_stream_id, payload).
fn gather_attachments(doc: &Document) -> Vec<(String, ObjectId, Vec<u8>)> {
    let mut found: Vec<(String, ObjectId)> = Vec::new();
    let mut seen_streams: HashSet<ObjectId> = HashSet::new();

    // 1) Catalog -> Names -> EmbeddedFiles
    if let Ok(catalog) = doc.catalog() {
        if let Ok(names_obj) = catalog.get(b"Names") {
            if let Some(Object::Dictionary(names)) = resolve(doc, names_obj) {
                if let Ok(ef_obj) = names.get(b"EmbeddedFiles") {
                    collect_name_tree(doc, ef_obj, &mut found);
                }
            }
        }
    }

    // 2) Walk all objects for Filespec with EF, and FileAttachment annotations.
    for obj in doc.objects.values() {
        let Object::Dictionary(dict) = obj else {
            continue;
        };
        // Filespec
        if let Ok(Object::Name(t)) = dict.get(b"Type") {
            if t == b"Filespec" {
                if let Some(pair) = filespec_pair(doc, dict) {
                    found.push(pair);
                }
            }
        }
        // Annotation FileAttachment
        if let Ok(Object::Name(st)) = dict.get(b"Subtype") {
            if st == b"FileAttachment" {
                if let Ok(fs) = dict.get(b"FS") {
                    if let Some(Object::Dictionary(fsd)) = resolve(doc, fs) {
                        if let Some(pair) = filespec_pair(doc, fsd) {
                            found.push(pair);
                        }
                    }
                }
            }
        }
    }

    let mut out = Vec::new();
    let mut used_names: HashMap<String, u32> = HashMap::new();
    for (name, stream_id) in found {
        if !seen_streams.insert(stream_id) {
            continue;
        }
        let Some(data) = stream_bytes(doc, stream_id) else {
            continue;
        };
        let mut name = if name.is_empty() {
            format!("attachment-{}-{}", stream_id.0, stream_id.1)
        } else {
            name
        };
        // sanitize path separators
        name = name.replace('\\', "/");
        if let Some(n) = used_names.get_mut(&name) {
            *n += 1;
            let count = *n;
            if let Some((stem, ext)) = name.rsplit_once('.') {
                name = format!("{stem}-{count}.{ext}");
            } else {
                name = format!("{name}-{count}");
            }
        } else {
            used_names.insert(name.clone(), 0);
        }
        out.push((name, stream_id, data));
    }
    out
}

fn filespec_pair(doc: &Document, dict: &lopdf::Dictionary) -> Option<(String, ObjectId)> {
    let name = dict
        .get(b"UF")
        .ok()
        .and_then(pdf_string)
        .or_else(|| dict.get(b"F").ok().and_then(pdf_string))
        .unwrap_or_default();
    let ef = dict.get(b"EF").ok()?;
    let ef_dict = match resolve(doc, ef)? {
        Object::Dictionary(d) => d,
        _ => return None,
    };
    // Prefer /UF then /F then /DOS /Unix /Mac
    for key in [b"UF".as_slice(), b"F", b"DOS", b"Unix", b"Mac"] {
        if let Ok(obj) = ef_dict.get(key) {
            if let Object::Reference(id) = obj {
                return Some((name, *id));
            }
            if let Some(Object::Stream(_)) = resolve(doc, obj) {
                // rare inline
            }
            if let Object::Reference(id) = obj {
                return Some((name, *id));
            }
        }
    }
    None
}

fn collect_name_tree(doc: &Document, node: &Object, out: &mut Vec<(String, ObjectId)>) {
    let Some(Object::Dictionary(dict)) = resolve(doc, node) else {
        return;
    };
    if let Ok(names) = dict.get(b"Names") {
        if let Some(Object::Array(arr)) = resolve(doc, names) {
            let mut i = 0;
            while i + 1 < arr.len() {
                let name = pdf_string(&arr[i]).unwrap_or_default();
                if let Object::Reference(id) = &arr[i + 1] {
                    if let Ok(Object::Dictionary(fs)) = doc.get_object(*id) {
                        if let Some(pair) = filespec_pair(doc, fs) {
                            out.push(pair);
                        } else {
                            // filespec may use name from Names array
                            if let Some((_, sid)) =
                                filespec_pair(doc, fs).or_else(|| filespec_stream_only(doc, fs))
                            {
                                out.push((name, sid));
                            }
                        }
                    }
                } else if let Some(Object::Dictionary(fs)) = resolve(doc, &arr[i + 1]) {
                    if let Some((n, sid)) = filespec_pair(doc, fs) {
                        out.push((if name.is_empty() { n } else { name }, sid));
                    }
                }
                i += 2;
            }
        }
    }
    if let Ok(kids) = dict.get(b"Kids") {
        if let Some(Object::Array(arr)) = resolve(doc, kids) {
            for kid in arr {
                collect_name_tree(doc, kid, out);
            }
        }
    }
}

fn filespec_stream_only(doc: &Document, dict: &lopdf::Dictionary) -> Option<(String, ObjectId)> {
    filespec_pair(doc, dict)
}

pub struct PdfMountSource {
    #[allow(dead_code)]
    archive_path: PathBuf,
    index: SqliteIndex,
    payloads: Mutex<HashMap<i64, Vec<u8>>>,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl PdfMountSource {
    pub fn open(
        archive_path: impl AsRef<Path>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
        recreate: bool,
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        if !looks_like_pdf(&archive_path) {
            return Err(PdfError::Msg("Not a valid PDF file!".into()));
        }
        // Force memory index (decoded attachment payloads not stable on disk).
        let _ = (index_path, recreate);
        let mut opts = options.clone();
        opts.index_in_memory = true;
        Self::create_index(&archive_path, &opts, product_version)
    }

    fn create_index(
        archive_path: &Path,
        options: &OpenOptions,
        product_version: &str,
    ) -> Result<Self> {
        let _ = options;
        println!(
            "Creating offset dictionary for {} ...",
            archive_path.display()
        );
        let t0 = Instant::now();

        let doc = Document::load(archive_path)
            .map_err(|e| PdfError::Msg(format!("failed to load PDF: {e}")))?;
        let attachments = gather_attachments(&doc);
        let images = gather_images(&doc);

        let mtime = std::fs::metadata(archive_path)
            .map(|m| {
                use std::os::unix::fs::MetadataExt;
                m.mtime() as f64
            })
            .unwrap_or(0.0);

        let index = SqliteIndex::create_writable(None)?;
        index.begin_write()?;
        let mut payloads = HashMap::new();
        let mut generated = std::collections::BTreeSet::new();
        // Distinct payload keys for attachments vs images so object-number collisions
        // (same obj num, different role) cannot overwrite each other.
        const IMAGE_KEY_BASE: i64 = 1 << 40;

        for (name, stream_id, data) in attachments {
            let nfull = normpath(&name);
            let (path, base) = split_name(&nfull);
            ensure_parents(&index, &path, &mut generated, mtime)?;
            let key = stream_id.0 as i64;
            let mode = (ratarmount_core::S_IFREG | 0o644) as i64;
            index.insert_file(
                &path,
                &base,
                key,
                0,
                data.len() as i64,
                mtime,
                mode,
                0,
                "",
                0,
                0,
                false,
                false,
                false,
                0,
            )?;
            payloads.insert(key, data);
        }

        for (name, stream_id, data) in images {
            let nfull = normpath(&name);
            let (path, base) = split_name(&nfull);
            ensure_parents(&index, &path, &mut generated, mtime)?;
            let key = IMAGE_KEY_BASE + stream_id.0 as i64;
            let mode = (ratarmount_core::S_IFREG | 0o644) as i64;
            index.insert_file(
                &path,
                &base,
                key,
                0,
                data.len() as i64,
                mtime,
                mode,
                0,
                "",
                0,
                0,
                false,
                false,
                false,
                0,
            )?;
            // Prefer first payload if the same image stream appears on multiple pages.
            payloads.entry(key).or_insert(data);
        }

        index.store_versions(product_version)?;
        index.store_metadata_key_value("backendName", BACKEND_NAME)?;
        store_stats(&index, archive_path)?;
        index.commit_write()?;

        let secs = t0.elapsed().as_secs_f64();
        println!(
            "Creating offset dictionary for {} took {secs:.2}s",
            archive_path.display()
        );

        let index = index.into_read_only()?;
        Ok(Self {
            archive_path: archive_path.to_path_buf(),
            index,
            payloads: Mutex::new(payloads),
            options: options.clone(),
        })
    }
}

impl MountSource for PdfMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        self.index.list(path).ok().flatten().map(ListResult::Infos)
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        self.index
            .list_mode(path)
            .ok()
            .flatten()
            .map(ListModeResult::Modes)
    }

    fn lookup(&self, path: &str, file_version: i32) -> Option<FileInfo> {
        self.index.lookup(path, file_version).ok().flatten()
    }

    fn open(
        &self,
        file_info: &FileInfo,
        _buffering: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        if file_info.mode & ratarmount_core::S_IFMT == ratarmount_core::S_IFDIR {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "is a directory",
            ));
        }
        let key = file_info
            .userdata
            .iter()
            .rev()
            .find_map(|u| match u {
                UserData::Tar(t) => t.offsetheader.map(|v| v as i64),
                _ => None,
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing pdf userdata"))?;
        let map = self
            .payloads
            .lock()
            .map_err(|_| io::Error::other("pdf payload lock poisoned"))?;
        let data = map
            .get(&key)
            .cloned()
            .ok_or_else(|| io::Error::other(format!("missing pdf payload for object {key}")))?;
        Ok(Box::new(Cursor::new(data)))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

fn split_name(full: &str) -> (String, String) {
    match full.rsplit_once('/') {
        Some(("", n)) => (String::new(), n.to_string()),
        Some((p, n)) => (p.to_string(), n.to_string()),
        None => (String::new(), full.to_string()),
    }
}

fn ensure_parents(
    index: &SqliteIndex,
    path: &str,
    generated: &mut std::collections::BTreeSet<String>,
    mtime: f64,
) -> Result<()> {
    if path.is_empty() {
        return Ok(());
    }
    let parts: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|p| !p.is_empty())
        .collect();
    let mut cur = String::new();
    for (i, part) in parts.iter().enumerate() {
        let parent = if i == 0 { String::new() } else { cur.clone() };
        cur = if parent.is_empty() {
            format!("/{part}")
        } else {
            format!("{parent}/{part}")
        };
        if generated.contains(&cur) {
            continue;
        }
        generated.insert(cur.clone());
        let mode = (ratarmount_core::S_IFDIR | 0o755) as i64;
        index.insert_file(
            &parent, part, 0, 0, 0, mtime, mode, 0, "", 0, 0, false, false, true, 0,
        )?;
    }
    Ok(())
}

fn store_stats(index: &SqliteIndex, path: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::metadata(path)?;
    let json = format!(
        "{{\"st_size\":{},\"st_mtime\":{},\"st_mtime_ns\":{}}}",
        meta.size(),
        meta.mtime(),
        meta.mtime_nsec()
    );
    index.store_metadata_key_value("tarstats", &json)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn py_fixture(name: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        PathBuf::from(root).join("tests").join(name)
    }

    #[test]
    fn pypdf_minimal_attachment() {
        let path = py_fixture("pypdf-minimal-single-attachment.pdf");
        if !path.exists() {
            return;
        }
        assert!(looks_like_pdf(&path));
        let m = PdfMountSource::open(&path, None, &OpenOptions::default(), "0.1.0", true).unwrap();
        let fi = m.lookup("/test.bin", 0).expect("test.bin");
        assert_eq!(fi.size, 28);
        let mut r = m.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "This is a test embedded file");
    }

    #[test]
    fn example_pdf_attachments() {
        let path = py_fixture("example.pdf");
        if !path.exists() {
            return;
        }
        let m = PdfMountSource::open(&path, None, &OpenOptions::default(), "0.1.0", true).unwrap();
        let list = m.list("/").expect("list");
        match list {
            ListResult::Infos(map) => {
                assert!(
                    map.contains_key("example.tex") || map.keys().any(|k| k.contains("example")),
                    "keys: {:?}",
                    map.keys().collect::<Vec<_>>()
                );
                assert!(
                    map.contains_key("single-file.tar")
                        || map.keys().any(|k| k.contains("single-file")),
                    "keys: {:?}",
                    map.keys().collect::<Vec<_>>()
                );
                if let Some(fi) = map.get("example.tex") {
                    let mut r = m.open(fi, 0).unwrap();
                    let mut buf = Vec::new();
                    r.read_to_end(&mut buf).unwrap();
                    assert!(!buf.is_empty());
                }
            }
            _ => panic!("expected infos"),
        }
    }

    /// Minimal JPEG SOI…EOI used as a DCTDecode Image XObject payload.
    fn tiny_jpeg() -> Vec<u8> {
        vec![
            0xFF, 0xD8, // SOI
            0xFF, 0xE0, 0x00, 0x10, // APP0
            b'J', b'F', b'I', b'F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            0xFF, 0xDB, 0x00, 0x43, 0x00, // DQT
            0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08, 0x07, 0x07, 0x07, 0x09, 0x09, 0x08, 0x0A,
            0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C, 0x19, 0x12, 0x13, 0x0F, 0x14, 0x1D, 0x1A,
            0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20, 0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23,
            0x1C, 0x1C, 0x28, 0x37, 0x29, 0x2C, 0x30, 0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39,
            0x3D, 0x38, 0x32, 0x3C, 0x2E, 0x33, 0x34, 0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00,
            0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00, // SOF0
            0xFF, 0xC4, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, // DHT
            0xFF, 0xC4, 0x00, 0x14, 0x10, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // DHT
            0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0x7F, // SOS + ECS
            0xFF, 0xD9, // EOI
        ]
    }

    fn dict(entries: &[(&str, Object)]) -> lopdf::Dictionary {
        let mut d = lopdf::Dictionary::new();
        for (k, v) in entries {
            d.set(k.to_string(), v.clone());
        }
        d
    }

    fn jpeg_image_stream(jpeg: Vec<u8>) -> Stream {
        Stream::new(
            dict(&[
                ("Type", "XObject".into()),
                ("Subtype", "Image".into()),
                ("Width", 1.into()),
                ("Height", 1.into()),
                ("ColorSpace", "DeviceGray".into()),
                ("BitsPerComponent", 8.into()),
                ("Filter", "DCTDecode".into()),
            ]),
            jpeg,
        )
    }

    fn write_pdf_with_jpeg_image(path: &Path) {
        let jpeg = tiny_jpeg();
        let mut doc = Document::with_version("1.4");
        let pages_id = doc.new_object_id();

        let image_id = doc.add_object(jpeg_image_stream(jpeg));
        // Empty content is enough: we only walk Resources/XObject.
        let content_id = doc.add_object(Stream::new(lopdf::Dictionary::new(), Vec::new()));

        let mut xobject = lopdf::Dictionary::new();
        xobject.set("Im0", Object::Reference(image_id));
        let mut resources = lopdf::Dictionary::new();
        resources.set("XObject", Object::Dictionary(xobject));

        let page_id = doc.add_object(dict(&[
            ("Type", "Page".into()),
            ("Parent", pages_id.into()),
            (
                "MediaBox",
                vec![0.into(), 0.into(), 100.into(), 100.into()].into(),
            ),
            ("Contents", content_id.into()),
            ("Resources", Object::Dictionary(resources)),
        ]));

        doc.objects.insert(
            pages_id,
            Object::Dictionary(dict(&[
                ("Type", "Pages".into()),
                ("Kids", vec![page_id.into()].into()),
                ("Count", 1.into()),
            ])),
        );

        let catalog_id = doc.add_object(dict(&[
            ("Type", "Catalog".into()),
            ("Pages", pages_id.into()),
        ]));
        doc.trailer.set("Root", catalog_id);
        doc.save(path).expect("save synthetic pdf");
    }

    #[test]
    fn synthetic_pdf_xobject_image_mount() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("with-image.pdf");
        write_pdf_with_jpeg_image(&path);

        assert!(looks_like_pdf(&path));
        let m = PdfMountSource::open(&path, None, &OpenOptions::default(), "0.1.0", true).unwrap();

        let root = m.list("/").expect("list root");
        match &root {
            ListResult::Infos(map) => {
                assert!(
                    map.contains_key("images"),
                    "root keys: {:?}",
                    map.keys().collect::<Vec<_>>()
                );
            }
            _ => panic!("expected infos"),
        }

        let images = m.list("/images").expect("list images");
        match &images {
            ListResult::Infos(map) => {
                assert!(
                    map.contains_key("page1-img0.jpg"),
                    "image keys: {:?}",
                    map.keys().collect::<Vec<_>>()
                );
            }
            _ => panic!("expected infos"),
        }

        let fi = m.lookup("/images/page1-img0.jpg", 0).expect("lookup image");
        let jpeg = tiny_jpeg();
        assert_eq!(fi.size, jpeg.len() as u64);
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, jpeg);
        assert_eq!(&buf[..2], &[0xFF, 0xD8]);
    }

    #[test]
    fn synthetic_pdf_image_and_attachment_no_collision() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("img-and-attach.pdf");

        let jpeg = tiny_jpeg();
        let mut doc = Document::with_version("1.4");
        let pages_id = doc.new_object_id();

        let image_id = doc.add_object(jpeg_image_stream(jpeg.clone()));

        let attach_data = b"hello-attachment".to_vec();
        let embed_id = doc.add_object(Stream::new(
            dict(&[("Type", "EmbeddedFile".into())]),
            attach_data,
        ));
        let mut ef = lopdf::Dictionary::new();
        ef.set("F", Object::Reference(embed_id));
        let filespec_id = doc.add_object(dict(&[
            ("Type", "Filespec".into()),
            ("F", Object::string_literal("note.txt")),
            ("UF", Object::string_literal("note.txt")),
            ("EF", Object::Dictionary(ef)),
        ]));
        // EmbeddedFiles name tree: leaf node with /Names [name filespec …].
        let ef_tree_id = doc.add_object(dict(&[(
            "Names",
            vec![Object::string_literal("note.txt"), filespec_id.into()].into(),
        )]));
        let names_root_id =
            doc.add_object(dict(&[("EmbeddedFiles", Object::Reference(ef_tree_id))]));

        let content_id = doc.add_object(Stream::new(lopdf::Dictionary::new(), Vec::new()));
        let mut xobject = lopdf::Dictionary::new();
        xobject.set("Im0", Object::Reference(image_id));
        let mut resources = lopdf::Dictionary::new();
        resources.set("XObject", Object::Dictionary(xobject));
        let page_id = doc.add_object(dict(&[
            ("Type", "Page".into()),
            ("Parent", pages_id.into()),
            (
                "MediaBox",
                vec![0.into(), 0.into(), 100.into(), 100.into()].into(),
            ),
            ("Contents", content_id.into()),
            ("Resources", Object::Dictionary(resources)),
        ]));
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dict(&[
                ("Type", "Pages".into()),
                ("Kids", vec![page_id.into()].into()),
                ("Count", 1.into()),
            ])),
        );
        let catalog_id = doc.add_object(dict(&[
            ("Type", "Catalog".into()),
            ("Pages", pages_id.into()),
            ("Names", names_root_id.into()),
        ]));
        doc.trailer.set("Root", catalog_id);
        doc.save(&path).expect("save");

        let m = PdfMountSource::open(&path, None, &OpenOptions::default(), "0.1.0", true).unwrap();

        let attach = m.lookup("/note.txt", 0).expect("attachment");
        let mut r = m.open(&attach, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello-attachment");

        let img = m.lookup("/images/page1-img0.jpg", 0).expect("image");
        let mut r = m.open(&img, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, jpeg);
    }

    #[test]
    fn image_payload_ext_dct_and_raw() {
        let jpeg = tiny_jpeg();
        let stream = Stream::new(
            dict(&[
                ("Type", "XObject".into()),
                ("Subtype", "Image".into()),
                ("Filter", "DCTDecode".into()),
            ]),
            jpeg.clone(),
        );
        let (data, ext) = image_payload_and_ext(None, &stream);
        assert_eq!(ext, "jpg");
        assert_eq!(data, jpeg);

        // Incomplete image dict (no ColorSpace): remain .bin
        let raw = Stream::new(
            dict(&[
                ("Type", "XObject".into()),
                ("Subtype", "Image".into()),
                ("Width", 1.into()),
                ("Height", 1.into()),
            ]),
            vec![0xAB, 0xCD],
        );
        let (data, ext) = image_payload_and_ext(None, &raw);
        assert_eq!(ext, "bin");
        assert_eq!(data, vec![0xAB, 0xCD]);
    }

    fn zlib_compress(data: &[u8]) -> Vec<u8> {
        use flate2::write::ZlibEncoder;
        use flate2::Compression;
        use std::io::Write;
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::fast());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn flate_gray_image_stream(width: i64, height: i64, samples: Vec<u8>) -> Stream {
        let compressed = zlib_compress(&samples);
        Stream::new(
            dict(&[
                ("Type", "XObject".into()),
                ("Subtype", "Image".into()),
                ("Width", width.into()),
                ("Height", height.into()),
                ("ColorSpace", "DeviceGray".into()),
                ("BitsPerComponent", 8.into()),
                ("Filter", "FlateDecode".into()),
            ]),
            compressed,
        )
    }

    fn flate_rgb_image_stream(width: i64, height: i64, samples: Vec<u8>) -> Stream {
        let compressed = zlib_compress(&samples);
        Stream::new(
            dict(&[
                ("Type", "XObject".into()),
                ("Subtype", "Image".into()),
                ("Width", width.into()),
                ("Height", height.into()),
                ("ColorSpace", "DeviceRGB".into()),
                ("BitsPerComponent", 8.into()),
                ("Filter", "FlateDecode".into()),
            ]),
            compressed,
        )
    }

    fn write_pdf_with_image_stream(path: &Path, image: Stream) {
        let mut doc = Document::with_version("1.4");
        let pages_id = doc.new_object_id();
        let image_id = doc.add_object(image);
        let content_id = doc.add_object(Stream::new(lopdf::Dictionary::new(), Vec::new()));
        let mut xobject = lopdf::Dictionary::new();
        xobject.set("Im0", Object::Reference(image_id));
        let mut resources = lopdf::Dictionary::new();
        resources.set("XObject", Object::Dictionary(xobject));
        let page_id = doc.add_object(dict(&[
            ("Type", "Page".into()),
            ("Parent", pages_id.into()),
            (
                "MediaBox",
                vec![0.into(), 0.into(), 100.into(), 100.into()].into(),
            ),
            ("Contents", content_id.into()),
            ("Resources", Object::Dictionary(resources)),
        ]));
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dict(&[
                ("Type", "Pages".into()),
                ("Kids", vec![page_id.into()].into()),
                ("Count", 1.into()),
            ])),
        );
        let catalog_id = doc.add_object(dict(&[
            ("Type", "Catalog".into()),
            ("Pages", pages_id.into()),
        ]));
        doc.trailer.set("Root", catalog_id);
        doc.save(path).expect("save synthetic pdf");
    }

    #[test]
    fn image_payload_flate_devicegray_to_png() {
        // 2x2 gray: black, white, mid, max
        let samples = vec![0x00, 0xFF, 0x80, 0x40];
        let stream = flate_gray_image_stream(2, 2, samples);
        let (data, ext) = image_payload_and_ext(None, &stream);
        assert_eq!(ext, "png");
        assert!(data.starts_with(b"\x89PNG\r\n\x1a\n"), "PNG signature");
        // Round-trip decode via png crate
        let decoder = png::Decoder::new(Cursor::new(&data));
        let mut reader = decoder.read_info().expect("png info");
        let mut buf = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut buf).unwrap();
        assert_eq!(info.width, 2);
        assert_eq!(info.height, 2);
        assert_eq!(&buf[..info.buffer_size()], &[0x00, 0xFF, 0x80, 0x40]);
    }

    #[test]
    fn image_payload_flate_devicergb_to_png() {
        // 1x2 RGB: red pixel, blue pixel
        let samples = vec![255, 0, 0, 0, 0, 255];
        let stream = flate_rgb_image_stream(1, 2, samples);
        let (data, ext) = image_payload_and_ext(None, &stream);
        assert_eq!(ext, "png");
        assert_eq!(&data[..8], b"\x89PNG\r\n\x1a\n");
        let decoder = png::Decoder::new(Cursor::new(&data));
        let mut reader = decoder.read_info().expect("png info");
        let mut buf = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut buf).unwrap();
        assert_eq!(info.width, 1);
        assert_eq!(info.height, 2);
        assert_eq!(&buf[..info.buffer_size()], &[255, 0, 0, 0, 0, 255]);
    }

    #[test]
    fn image_payload_raw_devicergb_to_png() {
        let samples = vec![1, 2, 3];
        let stream = Stream::new(
            dict(&[
                ("Type", "XObject".into()),
                ("Subtype", "Image".into()),
                ("Width", 1.into()),
                ("Height", 1.into()),
                ("ColorSpace", "DeviceRGB".into()),
                ("BitsPerComponent", 8.into()),
            ]),
            samples.clone(),
        );
        let (data, ext) = image_payload_and_ext(None, &stream);
        assert_eq!(ext, "png");
        assert!(data.starts_with(b"\x89PNG"));
    }

    #[test]
    fn image_payload_cmyk_flate_to_png() {
        // 1x1 pure cyan (C=255, M=Y=K=0) → RGB (0, 255, 255)
        let samples = vec![255, 0, 0, 0];
        let compressed = zlib_compress(&samples);
        let stream = Stream::new(
            dict(&[
                ("Type", "XObject".into()),
                ("Subtype", "Image".into()),
                ("Width", 1.into()),
                ("Height", 1.into()),
                ("ColorSpace", "DeviceCMYK".into()),
                ("BitsPerComponent", 8.into()),
                ("Filter", "FlateDecode".into()),
            ]),
            compressed,
        );
        let (data, ext) = image_payload_and_ext(None, &stream);
        assert_eq!(ext, "png");
        assert!(data.starts_with(b"\x89PNG\r\n\x1a\n"), "PNG signature");
        let decoder = png::Decoder::new(Cursor::new(&data));
        let mut reader = decoder.read_info().expect("png info");
        let mut buf = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut buf).unwrap();
        assert_eq!(info.width, 1);
        assert_eq!(info.height, 1);
        assert_eq!(&buf[..info.buffer_size()], &[0, 255, 255]);
    }

    #[test]
    fn image_payload_cmyk_black_to_png() {
        // Full black key plate: C=M=Y=0, K=255 → RGB (0,0,0)
        let samples = vec![0, 0, 0, 255];
        let stream = Stream::new(
            dict(&[
                ("Type", "XObject".into()),
                ("Subtype", "Image".into()),
                ("Width", 1.into()),
                ("Height", 1.into()),
                ("ColorSpace", "DeviceCMYK".into()),
                ("BitsPerComponent", 8.into()),
            ]),
            samples,
        );
        let (data, ext) = image_payload_and_ext(None, &stream);
        assert_eq!(ext, "png");
        let decoder = png::Decoder::new(Cursor::new(&data));
        let mut reader = decoder.read_info().unwrap();
        let mut buf = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut buf).unwrap();
        assert_eq!(&buf[..info.buffer_size()], &[0, 0, 0]);
    }

    #[test]
    fn image_payload_1bpc_devicegray_to_png() {
        // 2x2 1-bpc Gray, MSB-first packing, rows padded to a byte:
        // row0: white, black → bits 1,0 → 0b10000000
        // row1: black, white → bits 0,1 → 0b01000000
        // Expanded: 255, 0, 0, 255
        let packed = vec![0b1000_0000, 0b0100_0000];
        let compressed = zlib_compress(&packed);
        let stream = Stream::new(
            dict(&[
                ("Type", "XObject".into()),
                ("Subtype", "Image".into()),
                ("Width", 2.into()),
                ("Height", 2.into()),
                ("ColorSpace", "DeviceGray".into()),
                ("BitsPerComponent", 1.into()),
                ("Filter", "FlateDecode".into()),
            ]),
            compressed,
        );
        let (data, ext) = image_payload_and_ext(None, &stream);
        assert_eq!(ext, "png");
        assert_eq!(&data[..8], b"\x89PNG\r\n\x1a\n");
        let decoder = png::Decoder::new(Cursor::new(&data));
        let mut reader = decoder.read_info().expect("png info");
        let mut buf = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut buf).unwrap();
        assert_eq!(info.width, 2);
        assert_eq!(info.height, 2);
        assert_eq!(&buf[..info.buffer_size()], &[255, 0, 0, 255]);
    }

    #[test]
    fn image_payload_4bpc_devicegray_to_png() {
        // 2x1 4-bpc: samples 0 and 15 packed as one byte 0x0F → 0 and 255
        let packed = vec![0x0F];
        let stream = Stream::new(
            dict(&[
                ("Type", "XObject".into()),
                ("Subtype", "Image".into()),
                ("Width", 2.into()),
                ("Height", 1.into()),
                ("ColorSpace", "DeviceGray".into()),
                ("BitsPerComponent", 4.into()),
            ]),
            packed,
        );
        let (data, ext) = image_payload_and_ext(None, &stream);
        assert_eq!(ext, "png");
        assert!(data.starts_with(b"\x89PNG"));
        let decoder = png::Decoder::new(Cursor::new(&data));
        let mut reader = decoder.read_info().unwrap();
        let mut buf = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut buf).unwrap();
        assert_eq!(&buf[..info.buffer_size()], &[0, 255]);
    }

    #[test]
    fn image_payload_2bpc_devicegray_to_png() {
        // 4x1 2-bpc: values 0,1,2,3 packed as 0b00_01_10_11 = 0x1B → 0,85,170,255
        let packed = vec![0x1B];
        let stream = Stream::new(
            dict(&[
                ("Type", "XObject".into()),
                ("Subtype", "Image".into()),
                ("Width", 4.into()),
                ("Height", 1.into()),
                ("ColorSpace", "DeviceGray".into()),
                ("BitsPerComponent", 2.into()),
            ]),
            packed,
        );
        let (data, ext) = image_payload_and_ext(None, &stream);
        assert_eq!(ext, "png");
        let decoder = png::Decoder::new(Cursor::new(&data));
        let mut reader = decoder.read_info().unwrap();
        let mut buf = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut buf).unwrap();
        assert_eq!(&buf[..info.buffer_size()], &[0, 85, 170, 255]);
    }

    #[test]
    fn image_payload_16bpc_devicegray_to_png() {
        // 1x1 16-bpc: 0x8000 → scale to 0x8000*255/65535 = 127 (approx mid-gray)
        let packed = vec![0x80, 0x00];
        let stream = Stream::new(
            dict(&[
                ("Type", "XObject".into()),
                ("Subtype", "Image".into()),
                ("Width", 1.into()),
                ("Height", 1.into()),
                ("ColorSpace", "DeviceGray".into()),
                ("BitsPerComponent", 16.into()),
            ]),
            packed,
        );
        let (data, ext) = image_payload_and_ext(None, &stream);
        assert_eq!(ext, "png");
        let decoder = png::Decoder::new(Cursor::new(&data));
        let mut reader = decoder.read_info().unwrap();
        let mut buf = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut buf).unwrap();
        assert_eq!(buf[0], ((0x8000u32 * 255) / 65535) as u8);
        assert_eq!(info.buffer_size(), 1);
    }

    #[test]
    fn image_payload_indexed_devicergb_to_png() {
        // 2x1 Indexed DeviceRGB: palette black/white/red, indices 0 and 2 → black, red.
        // hival=2 → 3 entries × 3 bytes.
        let lookup = vec![
            0, 0, 0, // 0 black
            255, 255, 255, // 1 white
            255, 0, 0, // 2 red
        ];
        let indices = vec![0u8, 2u8];
        let stream = Stream::new(
            dict(&[
                ("Type", "XObject".into()),
                ("Subtype", "Image".into()),
                ("Width", 2.into()),
                ("Height", 1.into()),
                (
                    "ColorSpace",
                    Object::Array(vec![
                        "Indexed".into(),
                        "DeviceRGB".into(),
                        2.into(),
                        Object::String(lookup, lopdf::StringFormat::Literal),
                    ]),
                ),
                ("BitsPerComponent", 8.into()),
            ]),
            indices,
        );
        let (data, ext) = image_payload_and_ext(None, &stream);
        assert_eq!(ext, "png");
        assert!(data.starts_with(b"\x89PNG\r\n\x1a\n"));
        let decoder = png::Decoder::new(Cursor::new(&data));
        let mut reader = decoder.read_info().unwrap();
        let mut buf = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut buf).unwrap();
        assert_eq!(&buf[..info.buffer_size()], &[0, 0, 0, 255, 0, 0]);
    }

    #[test]
    fn image_payload_indexed_1bpc_to_png() {
        // 2x1, 1 bpc indices: 0b1000_0000 → index 1, 0 with hival=1 palette gray/white.
        let lookup = vec![0x40u8, 0xC0u8]; // DeviceGray
        let packed = vec![0b1000_0000];
        let stream = Stream::new(
            dict(&[
                ("Type", "XObject".into()),
                ("Subtype", "Image".into()),
                ("Width", 2.into()),
                ("Height", 1.into()),
                (
                    "ColorSpace",
                    Object::Array(vec![
                        "Indexed".into(),
                        "DeviceGray".into(),
                        1.into(),
                        Object::String(lookup, lopdf::StringFormat::Literal),
                    ]),
                ),
                ("BitsPerComponent", 1.into()),
            ]),
            packed,
        );
        let (data, ext) = image_payload_and_ext(None, &stream);
        assert_eq!(ext, "png");
        let decoder = png::Decoder::new(Cursor::new(&data));
        let mut reader = decoder.read_info().unwrap();
        let mut buf = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut buf).unwrap();
        assert_eq!(&buf[..info.buffer_size()], &[0xC0, 0x40]);
    }

    #[test]
    fn image_payload_iccbased_n3_to_png() {
        // ICCBased N=3: ignore profile, treat as RGB sample layout.
        let samples = vec![10u8, 20, 30, 40, 50, 60]; // 2x1 RGB
        let icc = Stream::new(
            dict(&[("N", 3.into()), ("Alternate", "DeviceRGB".into())]),
            // Dummy ICC profile payload (ignored).
            b"not-a-real-icc-profile".to_vec(),
        );
        let stream = Stream::new(
            dict(&[
                ("Type", "XObject".into()),
                ("Subtype", "Image".into()),
                ("Width", 2.into()),
                ("Height", 1.into()),
                (
                    "ColorSpace",
                    Object::Array(vec!["ICCBased".into(), Object::Stream(icc)]),
                ),
                ("BitsPerComponent", 8.into()),
            ]),
            samples.clone(),
        );
        let (data, ext) = image_payload_and_ext(None, &stream);
        assert_eq!(ext, "png");
        assert!(data.starts_with(b"\x89PNG\r\n\x1a\n"));
        let decoder = png::Decoder::new(Cursor::new(&data));
        let mut reader = decoder.read_info().unwrap();
        let mut buf = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut buf).unwrap();
        assert_eq!(&buf[..info.buffer_size()], samples.as_slice());
    }

    #[test]
    fn image_payload_iccbased_n4_cmyk_to_png() {
        // ICCBased N=4 → CMYK layout → RGB PNG (undercolor removal).
        let samples = vec![0u8, 0, 0, 0]; // paper white CMYK
        let icc = Stream::new(dict(&[("N", 4.into())]), vec![0]);
        let stream = Stream::new(
            dict(&[
                ("Type", "XObject".into()),
                ("Subtype", "Image".into()),
                ("Width", 1.into()),
                ("Height", 1.into()),
                (
                    "ColorSpace",
                    Object::Array(vec!["ICCBased".into(), Object::Stream(icc)]),
                ),
                ("BitsPerComponent", 8.into()),
            ]),
            samples,
        );
        let (data, ext) = image_payload_and_ext(None, &stream);
        assert_eq!(ext, "png");
        let decoder = png::Decoder::new(Cursor::new(&data));
        let mut reader = decoder.read_info().unwrap();
        let mut buf = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut buf).unwrap();
        assert_eq!(&buf[..info.buffer_size()], &[255, 255, 255]);
    }

    #[test]
    fn image_payload_iccbased_unsupported_n_stays_bin() {
        // N=2 (e.g. some spot workflows) remains residual .bin
        let samples = vec![0u8, 1];
        let icc = Stream::new(dict(&[("N", 2.into())]), vec![0]);
        let stream = Stream::new(
            dict(&[
                ("Type", "XObject".into()),
                ("Subtype", "Image".into()),
                ("Width", 1.into()),
                ("Height", 1.into()),
                (
                    "ColorSpace",
                    Object::Array(vec!["ICCBased".into(), Object::Stream(icc)]),
                ),
                ("BitsPerComponent", 8.into()),
            ]),
            samples.clone(),
        );
        let (data, ext) = image_payload_and_ext(None, &stream);
        assert_eq!(ext, "bin");
        assert_eq!(data, samples);
    }

    #[test]
    fn image_payload_separation_stays_bin() {
        // Exotic Separation color space remains .bin
        let samples = vec![0u8];
        let stream = Stream::new(
            dict(&[
                ("Type", "XObject".into()),
                ("Subtype", "Image".into()),
                ("Width", 1.into()),
                ("Height", 1.into()),
                (
                    "ColorSpace",
                    Object::Array(vec![
                        "Separation".into(),
                        "All".into(),
                        "DeviceGray".into(),
                        Object::Dictionary(lopdf::Dictionary::new()),
                    ]),
                ),
                ("BitsPerComponent", 8.into()),
            ]),
            samples.clone(),
        );
        let (data, ext) = image_payload_and_ext(None, &stream);
        assert_eq!(ext, "bin");
        assert_eq!(data, samples);
    }

    #[test]
    fn expand_samples_helpers() {
        // Direct unit coverage for pack/expand edge cases.
        assert_eq!(packed_row_bytes(8, 1, 1), Some(1));
        assert_eq!(packed_row_bytes(9, 1, 1), Some(2));
        assert_eq!(packed_row_bytes(2, 3, 8), Some(6));
        let one_bit = expand_samples_to_8bpc(&[0xF0], 8, 1, 1, 1).unwrap();
        assert_eq!(one_bit, vec![255, 255, 255, 255, 0, 0, 0, 0]);
        let cmyk = cmyk_to_rgb(&[0, 0, 0, 0]).unwrap(); // paper white
        assert_eq!(cmyk, vec![255, 255, 255]);
    }

    #[test]
    fn synthetic_pdf_flate_rgb_image_mount() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flate-rgb.pdf");
        // 2x1: green, white
        let samples = vec![0, 255, 0, 255, 255, 255];
        write_pdf_with_image_stream(&path, flate_rgb_image_stream(2, 1, samples));

        let m = PdfMountSource::open(&path, None, &OpenOptions::default(), "0.1.0", true).unwrap();
        let images = m.list("/images").expect("list images");
        match &images {
            ListResult::Infos(map) => {
                assert!(
                    map.contains_key("page1-img0.png"),
                    "image keys: {:?}",
                    map.keys().collect::<Vec<_>>()
                );
            }
            _ => panic!("expected infos"),
        }
        let fi = m.lookup("/images/page1-img0.png", 0).expect("lookup png");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert!(
            buf.starts_with(b"\x89PNG\r\n\x1a\n"),
            "expected PNG signature, got {:?}",
            &buf[..buf.len().min(16)]
        );
        assert_eq!(fi.size, buf.len() as u64);
    }

    #[test]
    fn synthetic_pdf_flate_gray_image_mount() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flate-gray.pdf");
        let samples = vec![0x11, 0x22, 0x33, 0x44];
        write_pdf_with_image_stream(&path, flate_gray_image_stream(2, 2, samples));

        let m = PdfMountSource::open(&path, None, &OpenOptions::default(), "0.1.0", true).unwrap();
        let fi = m
            .lookup("/images/page1-img0.png", 0)
            .expect("lookup gray png");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(&buf[..8], b"\x89PNG\r\n\x1a\n");
    }

    #[test]
    fn synthetic_pdf_cmyk_image_mount() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cmyk.pdf");
        // 2x1: pure magenta, pure yellow
        let samples = vec![
            0, 255, 0, 0, // M
            0, 0, 255, 0, // Y
        ];
        let compressed = zlib_compress(&samples);
        let image = Stream::new(
            dict(&[
                ("Type", "XObject".into()),
                ("Subtype", "Image".into()),
                ("Width", 2.into()),
                ("Height", 1.into()),
                ("ColorSpace", "DeviceCMYK".into()),
                ("BitsPerComponent", 8.into()),
                ("Filter", "FlateDecode".into()),
            ]),
            compressed,
        );
        write_pdf_with_image_stream(&path, image);

        let m = PdfMountSource::open(&path, None, &OpenOptions::default(), "0.1.0", true).unwrap();
        let images = m.list("/images").expect("list images");
        match &images {
            ListResult::Infos(map) => {
                assert!(
                    map.contains_key("page1-img0.png"),
                    "image keys: {:?}",
                    map.keys().collect::<Vec<_>>()
                );
            }
            _ => panic!("expected infos"),
        }
        let fi = m
            .lookup("/images/page1-img0.png", 0)
            .expect("lookup cmyk png");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert!(
            buf.starts_with(b"\x89PNG\r\n\x1a\n"),
            "expected PNG signature, got {:?}",
            &buf[..buf.len().min(16)]
        );
        let decoder = png::Decoder::new(Cursor::new(&buf));
        let mut reader = decoder.read_info().unwrap();
        let mut pixels = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut pixels).unwrap();
        // magenta → (255,0,255), yellow → (255,255,0)
        assert_eq!(&pixels[..info.buffer_size()], &[255, 0, 255, 255, 255, 0]);
        assert_eq!(fi.size, buf.len() as u64);
    }

    #[test]
    fn synthetic_pdf_1bpc_gray_image_mount() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("1bpc-gray.pdf");
        // 4x1 checker: 1,0,1,0 → 0b10100000
        let packed = vec![0b1010_0000];
        let compressed = zlib_compress(&packed);
        let image = Stream::new(
            dict(&[
                ("Type", "XObject".into()),
                ("Subtype", "Image".into()),
                ("Width", 4.into()),
                ("Height", 1.into()),
                ("ColorSpace", "DeviceGray".into()),
                ("BitsPerComponent", 1.into()),
                ("Filter", "FlateDecode".into()),
            ]),
            compressed,
        );
        write_pdf_with_image_stream(&path, image);

        let m = PdfMountSource::open(&path, None, &OpenOptions::default(), "0.1.0", true).unwrap();
        let fi = m
            .lookup("/images/page1-img0.png", 0)
            .expect("lookup 1bpc png");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(&buf[..8], b"\x89PNG\r\n\x1a\n");
        let decoder = png::Decoder::new(Cursor::new(&buf));
        let mut reader = decoder.read_info().unwrap();
        let mut pixels = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut pixels).unwrap();
        assert_eq!(&pixels[..info.buffer_size()], &[255, 0, 255, 0]);
    }

    #[test]
    fn image_payload_predictor_png_none() {
        // Predictor 10–15: each row is filter_byte + samples. Filter 0 (None).
        // 2x2 DeviceGray: rows [0, a, b] and [0, c, d]
        let samples = vec![0x10, 0x20, 0x30, 0x40];
        let mut predicted = Vec::new();
        predicted.push(0); // filter None
        predicted.extend_from_slice(&samples[0..2]);
        predicted.push(0);
        predicted.extend_from_slice(&samples[2..4]);
        let compressed = zlib_compress(&predicted);
        let mut d = dict(&[
            ("Type", "XObject".into()),
            ("Subtype", "Image".into()),
            ("Width", 2.into()),
            ("Height", 2.into()),
            ("ColorSpace", "DeviceGray".into()),
            ("BitsPerComponent", 8.into()),
            ("Filter", "FlateDecode".into()),
        ]);
        let mut parms = lopdf::Dictionary::new();
        parms.set("Predictor", Object::Integer(15));
        parms.set("Columns", Object::Integer(2));
        parms.set("Colors", Object::Integer(1));
        parms.set("BitsPerComponent", Object::Integer(8));
        d.set("DecodeParms", Object::Dictionary(parms));
        let stream = Stream::new(d, compressed);
        let (data, ext) = image_payload_and_ext(None, &stream);
        assert_eq!(ext, "png");
        let decoder = png::Decoder::new(Cursor::new(&data));
        let mut reader = decoder.read_info().unwrap();
        let mut buf = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut buf).unwrap();
        assert_eq!(&buf[..info.buffer_size()], samples.as_slice());
    }

    #[test]
    fn synthetic_pdf_indexed_rgb_image_mount() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("indexed-rgb.pdf");
        // 2x1: palette green/blue, indices 0, 1
        let lookup = vec![0u8, 255, 0, 0, 0, 255];
        let indices = vec![0u8, 1u8];
        let compressed = zlib_compress(&indices);
        let image = Stream::new(
            dict(&[
                ("Type", "XObject".into()),
                ("Subtype", "Image".into()),
                ("Width", 2.into()),
                ("Height", 1.into()),
                (
                    "ColorSpace",
                    Object::Array(vec![
                        "Indexed".into(),
                        "DeviceRGB".into(),
                        1.into(),
                        Object::String(lookup, lopdf::StringFormat::Literal),
                    ]),
                ),
                ("BitsPerComponent", 8.into()),
                ("Filter", "FlateDecode".into()),
            ]),
            compressed,
        );
        write_pdf_with_image_stream(&path, image);

        let m = PdfMountSource::open(&path, None, &OpenOptions::default(), "0.1.0", true).unwrap();
        let images = m.list("/images").expect("list images");
        match &images {
            ListResult::Infos(map) => {
                assert!(
                    map.contains_key("page1-img0.png"),
                    "image keys: {:?}",
                    map.keys().collect::<Vec<_>>()
                );
            }
            _ => panic!("expected infos"),
        }
        let fi = m
            .lookup("/images/page1-img0.png", 0)
            .expect("lookup indexed png");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert!(
            buf.starts_with(b"\x89PNG\r\n\x1a\n"),
            "expected PNG signature, got {:?}",
            &buf[..buf.len().min(16)]
        );
        let decoder = png::Decoder::new(Cursor::new(&buf));
        let mut reader = decoder.read_info().unwrap();
        let mut pixels = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut pixels).unwrap();
        assert_eq!(&pixels[..info.buffer_size()], &[0, 255, 0, 0, 0, 255]);
        assert_eq!(fi.size, buf.len() as u64);
    }

    #[test]
    fn synthetic_pdf_iccbased_n3_image_mount() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("iccbased-n3.pdf");
        let samples = vec![1u8, 2, 3, 4, 5, 6]; // 2x1 RGB
        let compressed = zlib_compress(&samples);

        // ICC profile must be an indirect stream object so it round-trips via save/load.
        let mut doc = Document::with_version("1.4");
        let pages_id = doc.new_object_id();
        let icc_id = doc.add_object(Stream::new(
            dict(&[("N", 3.into()), ("Alternate", "DeviceRGB".into())]),
            b"dummy-icc".to_vec(),
        ));
        let image_id = doc.add_object(Stream::new(
            dict(&[
                ("Type", "XObject".into()),
                ("Subtype", "Image".into()),
                ("Width", 2.into()),
                ("Height", 1.into()),
                (
                    "ColorSpace",
                    Object::Array(vec!["ICCBased".into(), Object::Reference(icc_id)]),
                ),
                ("BitsPerComponent", 8.into()),
                ("Filter", "FlateDecode".into()),
            ]),
            compressed,
        ));
        let content_id = doc.add_object(Stream::new(lopdf::Dictionary::new(), Vec::new()));
        let mut xobject = lopdf::Dictionary::new();
        xobject.set("Im0", Object::Reference(image_id));
        let mut resources = lopdf::Dictionary::new();
        resources.set("XObject", Object::Dictionary(xobject));
        let page_id = doc.add_object(dict(&[
            ("Type", "Page".into()),
            ("Parent", pages_id.into()),
            (
                "MediaBox",
                vec![0.into(), 0.into(), 100.into(), 100.into()].into(),
            ),
            ("Contents", content_id.into()),
            ("Resources", Object::Dictionary(resources)),
        ]));
        doc.objects.insert(
            pages_id,
            Object::Dictionary(dict(&[
                ("Type", "Pages".into()),
                ("Kids", vec![page_id.into()].into()),
                ("Count", 1.into()),
            ])),
        );
        let catalog_id = doc.add_object(dict(&[
            ("Type", "Catalog".into()),
            ("Pages", pages_id.into()),
        ]));
        doc.trailer.set("Root", catalog_id);
        doc.save(&path).expect("save synthetic icc pdf");

        let m = PdfMountSource::open(&path, None, &OpenOptions::default(), "0.1.0", true).unwrap();
        let images = m.list("/images").expect("list images");
        match &images {
            ListResult::Infos(map) => {
                assert!(
                    map.contains_key("page1-img0.png"),
                    "image keys: {:?}",
                    map.keys().collect::<Vec<_>>()
                );
            }
            _ => panic!("expected infos"),
        }
        let fi = m
            .lookup("/images/page1-img0.png", 0)
            .expect("lookup icc png");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert!(
            buf.starts_with(b"\x89PNG\r\n\x1a\n"),
            "expected PNG signature, got {:?}",
            &buf[..buf.len().min(16)]
        );
        let decoder = png::Decoder::new(Cursor::new(&buf));
        let mut reader = decoder.read_info().unwrap();
        let mut pixels = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut pixels).unwrap();
        assert_eq!(&pixels[..info.buffer_size()], samples.as_slice());
        assert_eq!(fi.size, buf.len() as u64);
    }

    #[test]
    fn image_payload_flate_indexed_to_png() {
        let lookup = vec![255u8, 0, 0, 0, 255, 0]; // red, green
        let indices = vec![1u8]; // green
        let compressed = zlib_compress(&indices);
        let stream = Stream::new(
            dict(&[
                ("Type", "XObject".into()),
                ("Subtype", "Image".into()),
                ("Width", 1.into()),
                ("Height", 1.into()),
                (
                    "ColorSpace",
                    Object::Array(vec![
                        "Indexed".into(),
                        "DeviceRGB".into(),
                        1.into(),
                        Object::String(lookup, lopdf::StringFormat::Literal),
                    ]),
                ),
                ("BitsPerComponent", 8.into()),
                ("Filter", "FlateDecode".into()),
            ]),
            compressed,
        );
        let (data, ext) = image_payload_and_ext(None, &stream);
        assert_eq!(ext, "png");
        let decoder = png::Decoder::new(Cursor::new(&data));
        let mut reader = decoder.read_info().unwrap();
        let mut buf = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut buf).unwrap();
        assert_eq!(&buf[..info.buffer_size()], &[0, 255, 0]);
    }
}
