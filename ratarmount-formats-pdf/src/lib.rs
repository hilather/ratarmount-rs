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
//!   `/DeviceRGB` and 8 bits/component → `.png` (inflated samples re-encoded as PNG)
//! - CMYK, unusual bit depths, multi-filter chains, Indexed/ICCBased, and other cases →
//!   `.bin` (stream bytes as stored; not reassembled into a displayable image file)
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

/// Supported PNG-encodable color spaces (8 bpc only).
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

/// Resolve a simple ColorSpace name (`DeviceGray` / `DeviceRGB` / `DeviceCMYK`, …).
/// Array forms (`/Indexed`, `/ICCBased`, …) return the first name only for classification.
fn color_space_name(obj: &Object) -> Option<String> {
    match obj {
        Object::Name(n) => Some(String::from_utf8_lossy(n).into_owned()),
        Object::Array(arr) if !arr.is_empty() => arr[0]
            .as_name_str()
            .ok()
            .map(|s| s.to_string()),
        _ => None,
    }
}

fn png_color_from_name(name: &str) -> Option<PngColor> {
    match name {
        "DeviceGray" | "CalGray" => Some(PngColor::Gray),
        "DeviceRGB" | "CalRGB" => Some(PngColor::Rgb),
        // DeviceCMYK and others are not emitted as PNG.
        _ => None,
    }
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
                    current[i] =
                        current[i].wrapping_add(paeth_predict(0, previous[i], 0));
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
/// Only `/DeviceGray` and `/DeviceRGB` (and CalGray/CalRGB) at 8 bits/component.
/// CMYK, multi-filter, non-8-bpc, and failed inflation fall through to the caller.
fn try_samples_to_png(stream: &Stream, inflate: bool) -> Option<Vec<u8>> {
    let width = dict_i64(&stream.dict, b"Width")? as u32;
    let height = dict_i64(&stream.dict, b"Height")? as u32;
    if width == 0 || height == 0 {
        return None;
    }
    let bpc = dict_i64(&stream.dict, b"BitsPerComponent").unwrap_or(8);
    if bpc != 8 {
        return None;
    }
    let cs_obj = stream.dict.get(b"ColorSpace").ok()?;
    let cs_name = color_space_name(cs_obj)?;
    let color = png_color_from_name(&cs_name)?;

    let mut samples = if inflate {
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

    // Some producers pad the stream; trim to exact sample count if longer.
    let expected = (width as usize)
        .checked_mul(height as usize)?
        .checked_mul(color.channels())?;
    if samples.len() < expected {
        return None;
    }
    if samples.len() > expected {
        samples.truncate(expected);
    }

    encode_png(width, height, color, &samples)
}

/// Choose file extension and payload for an Image XObject stream.
///
/// lopdf refuses to run `decompressed_content` on `/Subtype /Image` streams (pixel data is
/// not general stream content). For sole `/DCTDecode` / `/JPXDecode` the stored bytes are
/// already a usable file. Sole `/FlateDecode` or no filter with DeviceGray/DeviceRGB 8-bpc
/// is reassembled into PNG. Other cases emit raw stream content as `.bin`.
fn image_payload_and_ext(stream: &Stream) -> (Vec<u8>, &'static str) {
    let filters = stream.filters().unwrap_or_default();
    if filters.len() == 1 {
        match filters[0].as_str() {
            "DCTDecode" => return (stream.content.clone(), "jpg"),
            "JPXDecode" => return (stream.content.clone(), "jp2"),
            "FlateDecode" => {
                if let Some(png) = try_samples_to_png(stream, true) {
                    return (png, "png");
                }
            }
            _ => {}
        }
    } else if filters.is_empty() {
        if let Some(png) = try_samples_to_png(stream, false) {
            return (png, "png");
        }
    }
    // Multi-filter, CMYK, unusual depths, or failed reassembly: keep stored bytes.
    (stream.content.clone(), "bin")
}

/// Resolve a Resources dictionary from a page node or referenced object.
fn resources_dict<'a>(doc: &'a Document, page: &'a lopdf::Dictionary) -> Option<&'a lopdf::Dictionary> {
    match page.get(b"Resources").ok() {
        Some(Object::Dictionary(d)) => Some(d),
        Some(Object::Reference(id)) => doc.get_dictionary(*id).ok(),
        _ => {
            // Inherit from parent Pages nodes.
            let mut parent = page
                .get(b"Parent")
                .ok()
                .and_then(|o| o.as_reference().ok());
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

fn xobject_dict<'a>(doc: &'a Document, resources: &'a lopdf::Dictionary) -> Option<&'a lopdf::Dictionary> {
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
        let mut entries: Vec<(Vec<u8>, &Object)> = xobjects.iter().map(|(k, v)| (k.clone(), v)).collect();
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

            let (data, ext) = image_payload_and_ext(stream);
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
            0x3D, 0x38, 0x32, 0x3C, 0x2E, 0x33, 0x34, 0x32,
            0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00, // SOF0
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

        let fi = m
            .lookup("/images/page1-img0.jpg", 0)
            .expect("lookup image");
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
        let (data, ext) = image_payload_and_ext(&stream);
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
        let (data, ext) = image_payload_and_ext(&raw);
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
        let (data, ext) = image_payload_and_ext(&stream);
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
        let (data, ext) = image_payload_and_ext(&stream);
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
        let (data, ext) = image_payload_and_ext(&stream);
        assert_eq!(ext, "png");
        assert!(data.starts_with(b"\x89PNG"));
    }

    #[test]
    fn image_payload_cmyk_flate_stays_bin() {
        let samples = vec![0u8; 4]; // 1x1 CMYK
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
            compressed.clone(),
        );
        let (data, ext) = image_payload_and_ext(&stream);
        assert_eq!(ext, "bin");
        assert_eq!(data, compressed);
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
        let fi = m
            .lookup("/images/page1-img0.png", 0)
            .expect("lookup png");
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
        let (data, ext) = image_payload_and_ext(&stream);
        assert_eq!(ext, "png");
        let decoder = png::Decoder::new(Cursor::new(&data));
        let mut reader = decoder.read_info().unwrap();
        let mut buf = vec![0; reader.output_buffer_size().unwrap()];
        let info = reader.next_frame(&mut buf).unwrap();
        assert_eq!(&buf[..info.buffer_size()], samples.as_slice());
    }
}
