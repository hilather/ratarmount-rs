//! Virtual disk `Read + Seek`: translate guest LBA bytes onto the container file.

use std::io::{self, Read, Seek, SeekFrom};

use crate::SeekRead;

/// How a guest offset maps onto the container.
#[derive(Debug, Clone)]
pub(crate) enum DiskMap {
    /// Fixed VHD: guest offset == container offset; footer sits after `virt_size`.
    Fixed,
    /// Dynamic VHD: BAT of 32-bit big-endian sector offsets (`0xFFFFFFFF` = hole).
    DynamicVhd {
        bat: Vec<u32>,
        block_size: u64,
        bitmap_size: u64,
    },
    /// VHDX payload BAT entries only (sector-bitmap slots already stripped).
    /// Low 3 bits = state; bits 20+ = file offset in MiB.
    Vhdx {
        payload_bat: Vec<u64>,
        block_size: u64,
    },
}

const VHD_BAT_UNUSED: u32 = 0xFFFF_FFFF;
const VHDX_STATE_MASK: u64 = 0x7;
const VHDX_STATE_FULLY_PRESENT: u64 = 6;
const VHDX_STATE_PARTIALLY_PRESENT: u64 = 7;
const VHDX_OFFSET_SHIFT: u64 = 20;
const MIB: u64 = 1024 * 1024;

enum MapKind {
    Zero,
    File(u64),
}

/// Guest-visible disk (size = virtual size, not the container length).
pub(crate) struct VirtualDisk {
    inner: Box<dyn SeekRead>,
    map: DiskMap,
    pos: u64,
    virt_size: u64,
}

impl VirtualDisk {
    pub(crate) fn new<R>(inner: R, map: DiskMap, virt_size: u64) -> Self
    where
        R: Read + Seek + Send + 'static,
    {
        Self {
            inner: Box::new(inner),
            map,
            pos: 0,
            virt_size,
        }
    }

    pub(crate) fn virt_size(&self) -> u64 {
        self.virt_size
    }

    fn map_run(&self, virt: u64, max: usize) -> io::Result<(MapKind, usize)> {
        if max == 0 {
            return Ok((MapKind::Zero, 0));
        }
        match &self.map {
            DiskMap::Fixed => Ok((MapKind::File(virt), max)),
            DiskMap::DynamicVhd {
                bat,
                block_size,
                bitmap_size,
            } => {
                if *block_size == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "dynamic VHD block size is 0",
                    ));
                }
                let idx = (virt / *block_size) as usize;
                let in_block = virt % *block_size;
                let run = max.min((*block_size - in_block) as usize);
                let Some(&entry) = bat.get(idx) else {
                    return Ok((MapKind::Zero, run));
                };
                if entry == VHD_BAT_UNUSED {
                    return Ok((MapKind::Zero, run));
                }
                let file_off = u64::from(entry)
                    .saturating_mul(512)
                    .saturating_add(*bitmap_size)
                    .saturating_add(in_block);
                Ok((MapKind::File(file_off), run))
            }
            DiskMap::Vhdx {
                payload_bat,
                block_size,
            } => {
                if *block_size == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "VHDX block size is 0",
                    ));
                }
                let idx = (virt / *block_size) as usize;
                let in_block = virt % *block_size;
                let run = max.min((*block_size - in_block) as usize);
                let Some(&entry) = payload_bat.get(idx) else {
                    return Ok((MapKind::Zero, run));
                };
                let state = entry & VHDX_STATE_MASK;
                if state != VHDX_STATE_FULLY_PRESENT && state != VHDX_STATE_PARTIALLY_PRESENT {
                    return Ok((MapKind::Zero, run));
                }
                let file_off = (entry >> VHDX_OFFSET_SHIFT)
                    .saturating_mul(MIB)
                    .saturating_add(in_block);
                Ok((MapKind::File(file_off), run))
            }
        }
    }
}

impl Read for VirtualDisk {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.virt_size || buf.is_empty() {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.virt_size - self.pos) as usize;
        let mut done = 0usize;
        while done < want {
            let (kind, run) = self.map_run(self.pos, want - done)?;
            if run == 0 {
                break;
            }
            let n = match kind {
                MapKind::Zero => {
                    buf[done..done + run].fill(0);
                    run
                }
                MapKind::File(off) => {
                    self.inner.seek(SeekFrom::Start(off))?;
                    self.inner.read(&mut buf[done..done + run])?
                }
            };
            if n == 0 {
                break;
            }
            self.pos += n as u64;
            done += n;
            // File short-read inside a block: stop rather than spinning.
            if matches!(kind, MapKind::File(_)) && n < run {
                break;
            }
        }
        Ok(done)
    }
}

impl Seek for VirtualDisk {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::Current(o) => self.pos as i64 + o,
            SeekFrom::End(o) => self.virt_size as i64 + o,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start of virtual disk",
            ));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

/// Bitmap bytes for a dynamic VHD block, rounded up to a 512-byte sector.
pub(crate) fn vhd_bitmap_size(block_size: u64) -> u64 {
    let sectors = block_size / 512;
    let bits = sectors; // one bit per sector
    let bytes = bits.div_ceil(8);
    bytes.div_ceil(512).saturating_mul(512)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn fixed_read_seek_matches_bytes() {
        let data: Vec<u8> = (0..256).map(|i| i as u8).collect();
        let mut d = VirtualDisk::new(Cursor::new(data.clone()), DiskMap::Fixed, 256);
        d.seek(SeekFrom::Start(10)).unwrap();
        let mut buf = [0u8; 5];
        d.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, &data[10..15]);
        assert_eq!(d.seek(SeekFrom::End(0)).unwrap(), 256);
        assert_eq!(d.read(&mut buf).unwrap(), 0);
    }

    #[test]
    fn dynamic_unallocated_reads_zeros() {
        let mut container = vec![0u8; 4096];
        // BAT sector 2 → file 1024; skip 512-byte bitmap → payload at 1536.
        container[1536] = 0xAB;
        container[1537] = 0xCD;
        let map = DiskMap::DynamicVhd {
            bat: vec![2, VHD_BAT_UNUSED],
            block_size: 1024,
            bitmap_size: 512,
        };
        let mut d = VirtualDisk::new(Cursor::new(container), map, 2048);
        let mut buf = [0u8; 2];
        d.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0xAB, 0xCD]);
        d.seek(SeekFrom::Start(1024)).unwrap();
        let mut hole = [0xFFu8; 4];
        d.read_exact(&mut hole).unwrap();
        assert_eq!(hole, [0, 0, 0, 0]);
    }

    #[test]
    fn vhdx_zero_state_is_hole() {
        let map = DiskMap::Vhdx {
            payload_bat: vec![0], // NOT_PRESENT
            block_size: 1024,
        };
        let mut d = VirtualDisk::new(Cursor::new(vec![0xFFu8; 64]), map, 1024);
        let mut buf = [0xAAu8; 8];
        d.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [0; 8]);
    }
}
