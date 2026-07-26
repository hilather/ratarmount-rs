//! Shared seekable uncompressed body for codecs without mid-stream state clones.
//!
//! Strategy:
//! * Prefer **true restart points** (zstd frames, xz blocks) when available.
//! * Otherwise **one full decode** into RAM (under a size cap) or a temp file —
//!   still avoids leaving a permanent sidecar and unifies the TAR open path.
//! * Rebuild-on-load is fine (Python may rebuild compression tables too).

use std::fs::File;
use std::io::{self, copy, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use tempfile::NamedTempFile;

use crate::{CompressError, Result};

/// Default max uncompressed size kept fully in RAM before spilling to a temp file.
pub const DEFAULT_MEMORY_CAP: u64 = 256 * 1024 * 1024;

/// Read + Seek + Send (trait object friendly).
pub trait SeekRead: Read + Seek + Send {}
impl<T: Read + Seek + Send> SeekRead for T {}

/// Opaque seekable uncompressed stream (independent readers).
pub trait SeekableBody: Send + Sync {
    fn path(&self) -> &Path;
    fn size(&self) -> u64;
    fn open_reader(&self) -> io::Result<Box<dyn SeekRead>>;
    fn kind(&self) -> &'static str;
    /// Number of restart checkpoints / frames / blocks (diagnostics).
    fn checkpoint_count(&self) -> usize {
        1
    }
}

/// Fully decoded body in RAM or a temp file.
pub struct DecodedBody {
    path: PathBuf,
    size: u64,
    kind: &'static str,
    inner: DecodedInner,
}

enum DecodedInner {
    Memory(Arc<Vec<u8>>),
    Temp(Arc<NamedTempFile>),
}

impl DecodedBody {
    /// Decode `reader` fully into memory (if ≤ `memory_cap`) or a temp file.
    pub fn from_decoder(
        path: &Path,
        kind: &'static str,
        mut decoder: impl Read,
        memory_cap: u64,
    ) -> Result<Arc<Self>> {
        let mut tmp = NamedTempFile::new()?;
        let size = copy(&mut decoder, &mut tmp)?;
        tmp.flush()?;
        if size <= memory_cap {
            let mut data = Vec::with_capacity(size as usize);
            tmp.as_file_mut().seek(SeekFrom::Start(0))?;
            tmp.as_file_mut().read_to_end(&mut data)?;
            Ok(Arc::new(Self {
                path: path.to_path_buf(),
                size,
                kind,
                inner: DecodedInner::Memory(Arc::new(data)),
            }))
        } else {
            tmp.as_file().seek(SeekFrom::Start(0))?;
            Ok(Arc::new(Self {
                path: path.to_path_buf(),
                size,
                kind,
                inner: DecodedInner::Temp(Arc::new(tmp)),
            }))
        }
    }

    pub fn from_bytes(path: &Path, kind: &'static str, data: Vec<u8>) -> Arc<Self> {
        let size = data.len() as u64;
        Arc::new(Self {
            path: path.to_path_buf(),
            size,
            kind,
            inner: DecodedInner::Memory(Arc::new(data)),
        })
    }
}

impl SeekableBody for DecodedBody {
    fn path(&self) -> &Path {
        &self.path
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn open_reader(&self) -> io::Result<Box<dyn SeekRead>> {
        match &self.inner {
            DecodedInner::Memory(data) => Ok(Box::new(ArcBytesReader {
                data: Arc::clone(data),
                pos: 0,
            })),
            DecodedInner::Temp(tmp) => {
                let f = File::open(tmp.path())?;
                Ok(Box::new(f))
            }
        }
    }

    fn kind(&self) -> &'static str {
        self.kind
    }
}

struct ArcBytesReader {
    data: Arc<Vec<u8>>,
    pos: u64,
}

impl Read for ArcBytesReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let start = self.pos as usize;
        if start >= self.data.len() {
            return Ok(0);
        }
        let n = (self.data.len() - start).min(buf.len());
        buf[..n].copy_from_slice(&self.data[start..start + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for ArcBytesReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let len = self.data.len() as i64;
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::End(o) => len + o,
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

/// Peek whether uncompressed body looks like TAR (ustar at offset 257).
pub fn body_looks_like_tar(body: &Arc<dyn SeekableBody>) -> Result<bool> {
    let mut r = body.open_reader().map_err(CompressError::from)?;
    if r.seek(SeekFrom::Start(257)).is_err() {
        return Ok(false);
    }
    let mut magic = [0u8; 5];
    let n = r.read(&mut magic)?;
    Ok(n == 5 && (&magic == b"ustar" || &magic == b"GNU  " || magic.starts_with(b"ustar")))
}

/// Cursor over owned bytes (local helper for tests).
#[allow(dead_code)]
pub fn cursor(data: Vec<u8>) -> Cursor<Vec<u8>> {
    Cursor::new(data)
}
