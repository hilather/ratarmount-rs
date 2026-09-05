//! `Read + Seek` view of the uncompressed inner disk.

use std::io::{self, Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

use bzip2::read::BzDecoder;
use flate2::read::ZlibDecoder;

use crate::adc::adc_decompress;
use crate::udif::{
    load_chunks, looks_like_udif_reader, read_koly, Chunk, ChunkKind, KolyTrailer, SECTOR_SIZE,
};
use crate::{DmgError, Result, SeekRead};

/// Cap a single decompressed run so a crafted mish cannot allocate a whole disk.
const MAX_UNCOMPRESSED_CHUNK: u64 = 32 * 1024 * 1024;

struct Inner {
    file: Box<dyn SeekRead>,
    /// Last decompressed chunk (`index` into `chunks`).
    cache: Option<(usize, Vec<u8>)>,
}

/// Cloneable `Read + Seek` of the virtual disk reconstructed from UDIF runs.
pub struct DmgDisk {
    inner: Arc<Mutex<Inner>>,
    chunks: Arc<Vec<Chunk>>,
    disk_size: u64,
    pos: u64,
}

impl Clone for DmgDisk {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            chunks: Arc::clone(&self.chunks),
            disk_size: self.disk_size,
            pos: 0,
        }
    }
}

impl DmgDisk {
    pub fn open<R>(mut reader: R) -> Result<(Self, KolyTrailer)>
    where
        R: Read + Seek + Send + 'static,
    {
        reader.seek(SeekFrom::Start(0))?;
        if !looks_like_udif_reader(&mut reader) {
            return Err(DmgError::Msg("not a UDIF image (no koly trailer)".into()));
        }
        let koly = read_koly(&mut reader)?;
        let chunks = load_chunks(&mut reader, &koly)?;
        if chunks.is_empty() {
            return Err(DmgError::Msg("UDIF has no reconstructable chunks".into()));
        }
        let from_chunks = chunks
            .iter()
            .map(|c| c.start_byte.saturating_add(c.length))
            .max()
            .unwrap_or(0);
        let disk_size = koly
            .sector_count
            .saturating_mul(SECTOR_SIZE)
            .max(from_chunks);
        reader.seek(SeekFrom::Start(0))?;
        let disk = Self {
            inner: Arc::new(Mutex::new(Inner {
                file: Box::new(reader) as Box<dyn SeekRead>,
                cache: None,
            })),
            chunks: Arc::new(chunks),
            disk_size,
            pos: 0,
        };
        Ok((disk, koly))
    }

    pub fn disk_size(&self) -> u64 {
        self.disk_size
    }

    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, Inner>> {
        self.inner
            .lock()
            .map_err(|_| io::Error::other("shared DMG reader poisoned"))
    }

    fn chunk_index(&self, pos: u64) -> Option<usize> {
        let i = self.chunks.partition_point(|c| c.start_byte <= pos);
        if i == 0 {
            return None;
        }
        let c = &self.chunks[i - 1];
        if pos < c.start_byte.saturating_add(c.length) {
            Some(i - 1)
        } else {
            None
        }
    }

    fn read_into(&self, pos: u64, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || pos >= self.disk_size {
            return Ok(0);
        }
        let want = ((self.disk_size - pos) as usize).min(buf.len());
        match self.chunk_index(pos) {
            None => {
                let next = self
                    .chunks
                    .iter()
                    .find(|c| c.start_byte > pos)
                    .map(|c| c.start_byte)
                    .unwrap_or(self.disk_size);
                let n = ((next - pos) as usize).min(want);
                buf[..n].fill(0);
                Ok(n)
            }
            Some(idx) => {
                let chunk = &self.chunks[idx];
                let off = pos - chunk.start_byte;
                let n = ((chunk.length - off) as usize).min(want);
                self.read_chunk_range(idx, off, &mut buf[..n])?;
                Ok(n)
            }
        }
    }

    fn read_chunk_range(&self, idx: usize, off: u64, dest: &mut [u8]) -> io::Result<()> {
        let chunk = &self.chunks[idx];
        match chunk.kind {
            ChunkKind::Zero => {
                dest.fill(0);
                Ok(())
            }
            ChunkKind::Raw => {
                let mut guard = self.lock()?;
                let file_off = chunk.file_offset.saturating_add(off);
                guard.file.seek(SeekFrom::Start(file_off))?;
                guard.file.read_exact(dest)?;
                Ok(())
            }
            ChunkKind::Adc | ChunkKind::Zlib | ChunkKind::Bzip2 => {
                let decoded = self.decoded_chunk(idx)?;
                let start = off as usize;
                let end = start + dest.len();
                if end > decoded.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "UDIF chunk shorter than mish sector count",
                    ));
                }
                dest.copy_from_slice(&decoded[start..end]);
                Ok(())
            }
            ChunkKind::Lzfse | ChunkKind::Lzma => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "UDIF LZFSE/LZMA chunks are residual",
            )),
        }
    }

    fn decoded_chunk(&self, idx: usize) -> io::Result<Vec<u8>> {
        {
            let guard = self.lock()?;
            if let Some((cidx, bytes)) = &guard.cache {
                if *cidx == idx {
                    return Ok(bytes.clone());
                }
            }
        }
        let chunk = &self.chunks[idx];
        if chunk.length > MAX_UNCOMPRESSED_CHUNK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "UDIF uncompressed chunk exceeds 32 MiB cap",
            ));
        }
        let mut packed = vec![0u8; chunk.compressed_length as usize];
        {
            let mut guard = self.lock()?;
            guard.file.seek(SeekFrom::Start(chunk.file_offset))?;
            guard.file.read_exact(&mut packed)?;
        }
        let mut decoded = match chunk.kind {
            ChunkKind::Zlib => {
                let mut out = Vec::new();
                ZlibDecoder::new(packed.as_slice()).read_to_end(&mut out)?;
                out
            }
            ChunkKind::Bzip2 => {
                let mut out = Vec::new();
                BzDecoder::new(packed.as_slice()).read_to_end(&mut out)?;
                out
            }
            ChunkKind::Adc => {
                let mut out = vec![0u8; chunk.length as usize];
                let n = adc_decompress(&packed, &mut out)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                out.truncate(n);
                out
            }
            _ => return Err(io::Error::other("decoded_chunk on raw/zero")),
        };
        if (decoded.len() as u64) < chunk.length {
            decoded.resize(chunk.length as usize, 0);
        } else {
            decoded.truncate(chunk.length as usize);
        }
        let mut guard = self.lock()?;
        guard.cache = Some((idx, decoded.clone()));
        Ok(decoded)
    }
}

impl Read for DmgDisk {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.read_into(self.pos, buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for DmgDisk {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::Current(o) => self.pos as i64 + o,
            SeekFrom::End(o) => self.disk_size as i64 + o,
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
