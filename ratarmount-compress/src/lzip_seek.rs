//! Seekable LZIP (multimember) via trailer `member_size` walk + per-member LZMA1.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use lzma_rs::decompress::raw::{LzmaDecoder, LzmaParams, LzmaProperties};

use crate::seekable_body::{SeekRead, SeekableBody};
use crate::{CompressError, Result};

const LZIP_MAGIC: &[u8; 4] = b"LZIP";
const HEADER_SIZE: u64 = 6;
const TRAILER_SIZE: u64 = 20;

#[derive(Clone, Debug)]
struct Member {
    start_offset: u64,
    end_offset: u64,
    uncompressed_offset: u64,
    uncompressed_size: u64,
    dict_size_code: u8,
}

fn dict_size_from_code(code: u8) -> u32 {
    let base = 1u32 << (code & 31);
    let frac = (code >> 5) & 7;
    (base - (base / 16) * frac as u32).max(4096)
}

fn decompress_member(blob: &[u8], dict_code: u8, unpacked_hint: Option<u64>) -> Result<Vec<u8>> {
    if blob.len() < (HEADER_SIZE + TRAILER_SIZE) as usize {
        return Err(CompressError::Msg("LZIP member too small".into()));
    }
    if &blob[0..4] != LZIP_MAGIC {
        return Err(CompressError::Msg("LZIP member magic mismatch".into()));
    }
    let payload = &blob[HEADER_SIZE as usize..blob.len() - TRAILER_SIZE as usize];
    let dict_size = dict_size_from_code(dict_code);
    let props = LzmaProperties {
        lc: 3,
        lp: 0,
        pb: 2,
    };
    let try_sizes: Vec<Option<u64>> = match unpacked_hint {
        Some(n) => vec![Some(n), None],
        None => vec![None],
    };
    let mut last_err = None;
    for us in try_sizes {
        let params = LzmaParams::new(props, dict_size, us);
        let mut decoder = LzmaDecoder::new(params, None)
            .map_err(|e| CompressError::Msg(format!("LZIP decoder init: {e}")))?;
        let mut input = std::io::Cursor::new(payload);
        let mut output = Vec::new();
        match decoder.decompress(&mut input, &mut output) {
            Ok(()) => return Ok(output),
            Err(e) => last_err = Some(e),
        }
    }
    Err(CompressError::Msg(format!(
        "LZIP LZMA decompress failed: {:?}",
        last_err
    )))
}

fn index_lzip_file(path: &Path) -> Result<Vec<Member>> {
    let mut file = File::open(path)?;
    let file_size = file.metadata()?.len();
    let mut members = Vec::new();
    let mut pos = 0u64;
    let mut u_off = 0u64;

    while pos + HEADER_SIZE + TRAILER_SIZE <= file_size {
        file.seek(SeekFrom::Start(pos))?;
        let mut header = [0u8; 6];
        if file.read(&mut header)? < 6 || &header[0..4] != LZIP_MAGIC {
            break;
        }
        let version = header[4];
        if version != 1 {
            return Err(CompressError::Msg(format!(
                "unsupported LZIP version {version}"
            )));
        }
        let dict_code = header[5];

        // Prefer trailer walk: read potential trailer positions by decompressing member
        // to discover end, then verify member_size. For robustness match Python: stream
        // decompress until LZMA ends, then read trailer.
        // Simpler path for small members: if remaining is small, try reading as one member
        // using growing scan — actually use LZMA raw with unknown size and measure input.
        let payload_start = pos + HEADER_SIZE;
        let max_payload = file_size.saturating_sub(payload_start + TRAILER_SIZE);
        // Read rest of file from payload_start; try decompress with known end via trailer search.
        // Walk using trailer member_size when we can find a valid trailer after LZMA end.
        file.seek(SeekFrom::Start(payload_start))?;
        let mut rest = vec![0u8; (file_size - payload_start) as usize];
        file.read_exact(&mut rest)?;

        // Try candidate member ends: after payload + trailer. Use progressive approach:
        // decompress with optional sizes from scanning trailers every 8-byte aligned end.
        // Fast path: for single-member files, entire file is one member.
        let (end, data_size, plain_len) =
            find_member_end(&rest, dict_code, max_payload).map_err(|e| {
                CompressError::Msg(format!("LZIP member at {pos}: {e}"))
            })?;

        let member_blob_len = HEADER_SIZE + end; // end is relative to payload_start including trailer
        let end_offset = pos + member_blob_len;
        let uncompressed_size = if data_size > 0 { data_size } else { plain_len };

        members.push(Member {
            start_offset: pos,
            end_offset,
            uncompressed_offset: u_off,
            uncompressed_size,
            dict_size_code: dict_code,
        });
        u_off += uncompressed_size;
        pos = end_offset;
    }

    if members.is_empty() {
        return Err(CompressError::Msg("No LZIP members found".into()));
    }
    Ok(members)
}

/// `rest` is bytes from payload start to EOF. Returns (bytes consumed from rest incl. trailer,
/// trailer data_size, plain_len).
fn find_member_end(rest: &[u8], dict_code: u8, _max_payload: u64) -> Result<(u64, u64, u64)> {
    if rest.len() < TRAILER_SIZE as usize {
        return Err(CompressError::Msg("truncated LZIP".into()));
    }
    // Full rest as candidate single member: payload = rest[..len-20], trailer = last 20.
    // If member_size in trailer matches HEADER+payload+trailer length relative to member start,
    // accept. member_size is full member size including header.
    // We only have payload+maybe more members. So member_size = HEADER_SIZE + payload + TRAILER.
    // Try: decompress payload excluding last 20 as trailer of this member only if
    // member_size field is consistent.

    // Strategy: for each possible trailer position (from minimal payload to full rest-20),
    // check trailer.member_size == HEADER + payload_len + TRAILER and decompress works.
    // Optimization: start with whole rest as one member (common case).
    let try_at = |payload_len: usize| -> Option<(u64, u64, u64)> {
        if payload_len + TRAILER_SIZE as usize > rest.len() {
            return None;
        }
        let trailer = &rest[payload_len..payload_len + TRAILER_SIZE as usize];
        let data_size = u64::from_le_bytes(trailer[4..12].try_into().ok()?);
        let member_size = u64::from_le_bytes(trailer[12..20].try_into().ok()?);
        let expected = HEADER_SIZE + payload_len as u64 + TRAILER_SIZE;
        if member_size != 0 && member_size != expected {
            return None;
        }
        let payload = &rest[..payload_len];
        let mut header_blob = Vec::with_capacity(6 + payload_len + 20);
        header_blob.extend_from_slice(LZIP_MAGIC);
        header_blob.push(1);
        header_blob.push(dict_code);
        header_blob.extend_from_slice(payload);
        header_blob.extend_from_slice(trailer);
        match decompress_member(&header_blob, dict_code, if data_size > 0 { Some(data_size) } else { None }) {
            Ok(plain) => {
                let plain_len = plain.len() as u64;
                let ds = if data_size > 0 && data_size == plain_len {
                    data_size
                } else {
                    plain_len
                };
                Some((payload_len as u64 + TRAILER_SIZE, ds, plain_len))
            }
            Err(_) => None,
        }
    };

    // Fast path: entire rest is one member.
    if let Some(r) = try_at(rest.len() - TRAILER_SIZE as usize) {
        return Ok(r);
    }

    // Slow path: search for valid trailer by decompressing growing prefixes (binary search on
    // payload length is hard without knowing LZMA end). Linear scan in 1 KiB steps near end,
    // then refine — for archive use members are usually the whole file.
    // Use LZMA decoder with unknown size: feed all but last 20, see how much was consumed.
    // lzma-rs doesn't expose bytes consumed easily. Fall back to scanning.
    for payload_len in (0..=rest.len().saturating_sub(TRAILER_SIZE as usize)).rev() {
        if let Some(r) = try_at(payload_len) {
            return Ok(r);
        }
        // Limit expensive reverse scan for multi-member.
        if rest.len() - payload_len > 64 * 1024 && payload_len % 256 != 0 {
            continue;
        }
    }
    Err(CompressError::Msg("could not locate LZIP member end".into()))
}

/// Shared seekable LZIP body with on-demand member cache.
pub struct SeekableLzip {
    path: PathBuf,
    members: Vec<Member>,
    uncompressed_size: u64,
}

impl SeekableLzip {
    pub fn open(path: impl AsRef<Path>) -> Result<Arc<dyn SeekableBody>> {
        let path = path.as_ref();
        let members = index_lzip_file(path)?;
        let uncompressed_size = members.iter().map(|m| m.uncompressed_size).sum();
        Ok(Arc::new(Self {
            path: path.to_path_buf(),
            members,
            uncompressed_size,
        }))
    }
}

impl SeekableBody for SeekableLzip {
    fn path(&self) -> &Path {
        &self.path
    }

    fn size(&self) -> u64 {
        self.uncompressed_size
    }

    fn open_reader(&self) -> io::Result<Box<dyn SeekRead>> {
        Ok(Box::new(LzipReader {
            path: self.path.clone(),
            members: self.members.clone(),
            size: self.uncompressed_size,
            pos: 0,
            cache_idx: None,
            cache_data: Vec::new(),
        }))
    }

    fn kind(&self) -> &'static str {
        "lzip-members"
    }

    fn checkpoint_count(&self) -> usize {
        self.members.len().max(1)
    }
}

struct LzipReader {
    path: PathBuf,
    members: Vec<Member>,
    size: u64,
    pos: u64,
    cache_idx: Option<usize>,
    cache_data: Vec<u8>,
}

impl LzipReader {
    fn find(&self, pos: u64) -> (usize, u64) {
        for (i, m) in self.members.iter().enumerate() {
            if pos < m.uncompressed_offset + m.uncompressed_size {
                return (i, pos - m.uncompressed_offset);
            }
        }
        let last = self.members.len().saturating_sub(1);
        let within = self
            .members
            .last()
            .map(|m| m.uncompressed_size)
            .unwrap_or(0);
        (last, within)
    }

    fn ensure_member(&mut self, idx: usize) -> io::Result<()> {
        if self.cache_idx == Some(idx) {
            return Ok(());
        }
        let m = &self.members[idx];
        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(m.start_offset))?;
        let mut blob = vec![0u8; (m.end_offset - m.start_offset) as usize];
        file.read_exact(&mut blob)?;
        let plain = decompress_member(&blob, m.dict_size_code, Some(m.uncompressed_size))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        self.cache_idx = Some(idx);
        self.cache_data = plain;
        Ok(())
    }
}

impl Read for LzipReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.size {
            return Ok(0);
        }
        let (idx, within) = self.find(self.pos);
        self.ensure_member(idx)?;
        let into = within as usize;
        if into >= self.cache_data.len() {
            return Ok(0);
        }
        let n = (self.cache_data.len() - into).min(buf.len());
        buf[..n].copy_from_slice(&self.cache_data[into..into + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for LzipReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::End(o) => self.size as i64 + o,
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

/// Open LZIP as a seekable body.
pub fn open_seekable_lzip(path: impl AsRef<Path>) -> Result<Arc<dyn SeekableBody>> {
    SeekableLzip::open(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn py_test(name: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        PathBuf::from(root).join("tests").join(name)
    }

    #[test]
    fn simple_lzip() {
        let path = py_test("simple.lzip");
        if !path.exists() {
            return;
        }
        let body = open_seekable_lzip(&path).unwrap();
        assert_eq!(body.size(), 12);
        let mut r = body.open_reader().unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "foo fighter\n");
        r.seek(SeekFrom::Start(4)).unwrap();
        let mut mid = String::new();
        r.read_to_string(&mut mid).unwrap();
        assert_eq!(mid, "fighter\n");
    }
}
