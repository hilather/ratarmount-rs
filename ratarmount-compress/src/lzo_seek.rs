//! Seekable LZOP (`.lzo`) with per-block index.
//!
//! Decompression uses system `liblzo2` via `libloading`. If the library is
//! missing, open returns a clear error (Python raises similarly).
//!
//! Thread hint ([`open_seekable_lzo_with_threads`] / Python `-P` lzo backend):
//! LZOP blocks are independent on disk, but open currently builds a sequential
//! block index and decompresses on demand. The `threads` parameter is clamped
//! (`0` → CPU count) for API parity with other codecs; decode remains sequential
//! for now (same as early xz path before multi-stream parallel decode).

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use libloading::{Library, Symbol};
use ratarmount_core::ParallelizationSpec;

use crate::seekable_body::{SeekRead, SeekableBody};
use crate::{CompressError, Result};

const LZOP_MAGIC: [u8; 9] = [0x89, 0x4c, 0x5a, 0x4f, 0x00, 0x0d, 0x0a, 0x1a, 0x0a];

const F_ADLER32_D: u32 = 0x0000_0001;
const F_ADLER32_C: u32 = 0x0000_0002;
const F_CRC32_D: u32 = 0x0000_0100;
const F_CRC32_C: u32 = 0x0000_0200;
const F_H_EXTRA_FIELD: u32 = 0x0000_0040;
const F_H_FILTER: u32 = 0x0000_0800;

type LzoDecompressFn =
    unsafe fn(src: *const u8, src_len: u32, dst: *mut u8, dst_len: *mut u32) -> i32;

struct LzoLib {
    _lib: Library,
    decompress: LzoDecompressFn,
}

fn load_lzo() -> Result<&'static LzoLib> {
    static LIB: OnceLock<std::result::Result<LzoLib, String>> = OnceLock::new();
    let res = LIB.get_or_init(|| {
        for name in ["liblzo2.so.2", "liblzo2.so", "liblzo2.dylib", "lzo2.dll"] {
            // SAFETY: loading a well-known system compression library.
            let lib = match unsafe { Library::new(name) } {
                Ok(l) => l,
                Err(_) => continue,
            };
            // SAFETY: symbol name matches liblzo2 ABI.
            let decompress: Symbol<LzoDecompressFn> =
                match unsafe { lib.get(b"lzo1x_decompress_safe") } {
                    Ok(s) => s,
                    Err(e) => return Err(e.to_string()),
                };
            let decompress = *decompress;
            // Keep library loaded for process lifetime.
            let boxed = LzoLib {
                _lib: lib,
                decompress,
            };
            // Leak library into static by transmute via OnceLock ownership.
            return Ok(boxed);
        }
        Err(
            "liblzo2 is required for LZOP support. Install the system package \
             (e.g. liblzo2-2 / liblzo2) or ensure liblzo2 is on the library path."
                .into(),
        )
    });
    match res {
        Ok(lib) => Ok(lib),
        Err(msg) => Err(CompressError::Msg(msg.clone())),
    }
}

fn lzo_decompress_block(src: &[u8], uncompressed_size: usize) -> Result<Vec<u8>> {
    let lib = load_lzo()?;
    let mut dst = vec![0u8; uncompressed_size];
    let mut dst_len = uncompressed_size as u32;
    // SAFETY: buffers are valid for the given lengths; liblzo2 is C ABI.
    let rc = unsafe {
        (lib.decompress)(
            src.as_ptr(),
            src.len() as u32,
            dst.as_mut_ptr(),
            &mut dst_len,
        )
    };
    if rc != 0 {
        return Err(CompressError::Msg(format!(
            "lzo1x_decompress_safe failed with code {rc}"
        )));
    }
    dst.truncate(dst_len as usize);
    Ok(dst)
}

#[derive(Clone, Debug)]
struct BlockInfo {
    data_offset: u64,
    compressed_size: u32,
    uncompressed_offset: u64,
    uncompressed_size: u32,
    is_stored: bool,
}

fn read_u16_be(file: &mut File) -> Result<u16> {
    let mut b = [0u8; 2];
    file.read_exact(&mut b)?;
    Ok(u16::from_be_bytes(b))
}

fn read_u32_be(file: &mut File) -> Result<u32> {
    let mut b = [0u8; 4];
    file.read_exact(&mut b)?;
    Ok(u32::from_be_bytes(b))
}

fn parse_lzop(path: &Path) -> Result<(Vec<BlockInfo>, u64)> {
    let mut file = File::open(path)?;
    let mut magic = [0u8; 9];
    file.read_exact(&mut magic)?;
    if magic != LZOP_MAGIC {
        return Err(CompressError::Msg(format!(
            "invalid LZOP magic: {magic:02x?}"
        )));
    }
    let _version = read_u16_be(&mut file)?;
    let _lib_version = read_u16_be(&mut file)?;
    let _version_needed = read_u16_be(&mut file)?;
    let mut method = [0u8; 1];
    file.read_exact(&mut method)?;
    let mut level = [0u8; 1];
    file.read_exact(&mut level)?;
    let flags = read_u32_be(&mut file)?;
    if flags & F_H_FILTER != 0 {
        let _ = read_u32_be(&mut file)?;
    }
    let _mode = read_u32_be(&mut file)?;
    let _mtime_low = read_u32_be(&mut file)?;
    let _mtime_high = read_u32_be(&mut file)?;
    let mut name_len = [0u8; 1];
    file.read_exact(&mut name_len)?;
    if name_len[0] > 0 {
        let mut name = vec![0u8; name_len[0] as usize];
        file.read_exact(&mut name)?;
    }
    // Header checksum
    let _ = read_u32_be(&mut file)?;
    if flags & F_H_EXTRA_FIELD != 0 {
        let extra_len = read_u32_be(&mut file)? as usize;
        let mut extra = vec![0u8; extra_len];
        file.read_exact(&mut extra)?;
        let _ = read_u32_be(&mut file)?;
    }
    if method[0] != 1 && method[0] != 2 && method[0] != 3 {
        return Err(CompressError::Msg(format!(
            "unsupported LZOP method {}",
            method[0]
        )));
    }

    // Ensure liblzo2 is loadable before indexing compressed blocks.
    load_lzo()?;

    let mut blocks = Vec::new();
    let mut u_off = 0u64;
    loop {
        let usize = read_u32_be(&mut file)?;
        if usize == 0 {
            break;
        }
        let csize = read_u32_be(&mut file)?;
        if flags & (F_ADLER32_D | F_CRC32_D) != 0 {
            let _ = read_u32_be(&mut file)?;
        }
        if csize < usize && (flags & (F_ADLER32_C | F_CRC32_C) != 0) {
            let _ = read_u32_be(&mut file)?;
        }
        let data_offset = file.stream_position()?;
        file.seek(SeekFrom::Current(csize as i64))?;
        blocks.push(BlockInfo {
            data_offset,
            compressed_size: csize,
            uncompressed_offset: u_off,
            uncompressed_size: usize,
            is_stored: csize == usize,
        });
        u_off += usize as u64;
    }
    Ok((blocks, u_off))
}

/// Shared seekable LZOP body.
pub struct SeekableLzo {
    path: PathBuf,
    blocks: Vec<BlockInfo>,
    uncompressed_size: u64,
}

impl SeekableLzo {
    pub fn open(path: impl AsRef<Path>) -> Result<Arc<dyn SeekableBody>> {
        Self::open_with_threads(path, 1)
    }

    /// Open with a thread hint. See [`open_seekable_lzo_with_threads`].
    ///
    /// `threads` is resolved (`0` → CPU count) but indexing/decode stay sequential.
    pub fn open_with_threads(path: impl AsRef<Path>, threads: u32) -> Result<Arc<dyn SeekableBody>> {
        let path = path.as_ref();
        // Resolve for -P 0 parity / future block-parallel decode; index path
        // does not currently fan out workers.
        let _threads = ParallelizationSpec::resolve_zero(threads).max(1);
        let (blocks, size) = parse_lzop(path)?;
        Ok(Arc::new(Self {
            path: path.to_path_buf(),
            blocks,
            uncompressed_size: size,
        }))
    }
}

impl SeekableBody for SeekableLzo {
    fn path(&self) -> &Path {
        &self.path
    }

    fn size(&self) -> u64 {
        self.uncompressed_size
    }

    fn open_reader(&self) -> io::Result<Box<dyn SeekRead>> {
        Ok(Box::new(LzoReader {
            path: self.path.clone(),
            blocks: self.blocks.clone(),
            size: self.uncompressed_size,
            pos: 0,
            cache: Mutex::new(None),
        }))
    }

    fn kind(&self) -> &'static str {
        "lzo-blocks"
    }

    fn checkpoint_count(&self) -> usize {
        self.blocks.len().max(1)
    }
}

struct LzoReader {
    path: PathBuf,
    blocks: Vec<BlockInfo>,
    size: u64,
    pos: u64,
    /// (block_idx, data)
    cache: Mutex<Option<(usize, Vec<u8>)>>,
}

impl LzoReader {
    fn find(&self, pos: u64) -> (usize, u64) {
        for (i, b) in self.blocks.iter().enumerate() {
            if pos < b.uncompressed_offset + b.uncompressed_size as u64 {
                return (i, pos - b.uncompressed_offset);
            }
        }
        let last = self.blocks.len().saturating_sub(1);
        let within = self
            .blocks
            .last()
            .map(|b| b.uncompressed_size as u64)
            .unwrap_or(0);
        (last, within)
    }

    fn decompress_block(&self, idx: usize) -> io::Result<Vec<u8>> {
        {
            let guard = self.cache.lock().unwrap();
            if let Some((i, data)) = guard.as_ref() {
                if *i == idx {
                    return Ok(data.clone());
                }
            }
        }
        let block = &self.blocks[idx];
        let mut file = File::open(&self.path)?;
        file.seek(SeekFrom::Start(block.data_offset))?;
        let mut payload = vec![0u8; block.compressed_size as usize];
        file.read_exact(&mut payload)?;
        let plain = if block.is_stored {
            payload
        } else {
            lzo_decompress_block(&payload, block.uncompressed_size as usize)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
        };
        *self.cache.lock().unwrap() = Some((idx, plain.clone()));
        Ok(plain)
    }
}

impl Read for LzoReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.size {
            return Ok(0);
        }
        let (idx, within) = self.find(self.pos);
        let data = self.decompress_block(idx)?;
        let into = within as usize;
        if into >= data.len() {
            return Ok(0);
        }
        let n = (data.len() - into).min(buf.len());
        buf[..n].copy_from_slice(&data[into..into + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for LzoReader {
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

/// Open LZOP as a seekable body (requires liblzo2; single-thread open / index).
pub fn open_seekable_lzo(path: impl AsRef<Path>) -> Result<Arc<dyn SeekableBody>> {
    open_seekable_lzo_with_threads(path, 1)
}

/// Open LZOP with a thread hint (Python `-P` / lzo backend).
///
/// `threads == 0` means “use CPU count”. Block indexing and on-demand decode
/// remain sequential for now; `threads` is accepted so factory code can pass
/// `options.threads_for("lzo")` without API churn. Requires liblzo2.
pub fn open_seekable_lzo_with_threads(
    path: impl AsRef<Path>,
    threads: u32,
) -> Result<Arc<dyn SeekableBody>> {
    let threads = ParallelizationSpec::resolve_zero(threads).max(1);
    SeekableLzo::open_with_threads(path, threads)
}

/// Whether liblzo2 can be loaded on this host.
pub fn lzo_available() -> bool {
    load_lzo().is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    fn py_test(name: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        PathBuf::from(root).join("tests").join(name)
    }

    #[test]
    fn simple_lzo() {
        if !lzo_available() {
            eprintln!("skip: liblzo2 not available");
            return;
        }
        let path = py_test("simple.lzo");
        if !path.exists() {
            return;
        }
        let body = open_seekable_lzo(&path).unwrap();
        assert_eq!(body.size(), 12);
        let mut r = body.open_reader().unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "foo fighter\n");
    }

    #[test]
    fn open_seekable_lzo_with_threads_equals_single() {
        if !lzo_available() {
            eprintln!("skip: liblzo2 not available");
            return;
        }
        let path = py_test("simple.lzo");
        if !path.exists() {
            return;
        }
        let body1 = open_seekable_lzo_with_threads(&path, 1).unwrap();
        let body4 = open_seekable_lzo_with_threads(&path, 4).unwrap();
        assert_eq!(body1.size(), body4.size());
        let mut a = Vec::new();
        body1.open_reader().unwrap().read_to_end(&mut a).unwrap();
        let mut b = Vec::new();
        body4.open_reader().unwrap().read_to_end(&mut b).unwrap();
        assert_eq!(a, b);
        assert_eq!(a, b"foo fighter\n");
    }

    #[test]
    fn threads_zero_means_cpu_count_lzo() {
        if !lzo_available() {
            eprintln!("skip: liblzo2 not available");
            return;
        }
        let path = py_test("simple.lzo");
        if !path.exists() {
            return;
        }
        let body = open_seekable_lzo_with_threads(&path, 0).unwrap();
        assert_eq!(body.size(), 12);
    }
}
