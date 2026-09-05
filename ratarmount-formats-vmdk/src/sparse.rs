//! KDMV sparse-extent header + grain Read+Seek.

use std::io::{self, Read, Seek, SeekFrom};
use std::sync::{Arc, Mutex};

use crate::descriptor::{parse_vmdk_descriptor, VmdkDescriptor};
use crate::{Result, SeekRead, VmdkError};

pub const SECTOR: u64 = 512;
/// On-disk magic `KDMV` (LE `0x564d444b`).
pub const SPARSE_MAGIC: u32 = 0x564d_444b;
pub const COWD_MAGIC: u32 = 0x4457_4f43; // 'COWD' — ESXi vmfsSparse residual
pub const FLAG_COMPRESS: u32 = 1 << 16;
/// LBA/metadata markers (streamOptimized). Not compression; grain reads do not skip markers.
pub const FLAG_MARKER: u32 = 1 << 17;
/// qemu/libvmdk: GTE `1` is a zeroed grain **only** when this bit is set.
pub const FLAG_ZERO_GRAIN: u32 = 1 << 2;
const GTE_ZEROED: u32 = 1;
const GD_AT_END: u64 = u64::MAX;

#[derive(Debug, Clone)]
pub struct SparseHeader {
    pub flags: u32,
    pub capacity_sectors: u64,
    pub grain_size_sectors: u64,
    pub descriptor_offset: u64,
    pub descriptor_size: u64,
    pub num_gtes_per_gt: u32,
    pub gd_offset: u64,
    pub compress_algorithm: u16,
}

impl SparseHeader {
    pub fn is_compressed(&self) -> bool {
        // FLAG_MARKER is streamOptimized metadata, not deflate. Do not fold it in.
        self.flags & FLAG_COMPRESS != 0 || self.compress_algorithm != 0
    }

    fn gte_is_hole(&self, gte: u32) -> bool {
        gte == 0 || (gte == GTE_ZEROED && self.flags & FLAG_ZERO_GRAIN != 0)
    }

    pub fn grain_bytes(&self) -> u64 {
        self.grain_size_sectors.saturating_mul(SECTOR)
    }

    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_sectors.saturating_mul(SECTOR)
    }

    pub fn gd_entries(&self) -> Result<usize> {
        if self.grain_size_sectors == 0 || self.num_gtes_per_gt == 0 {
            return Err(VmdkError::Msg(
                "VMDK sparse header has grainSize or numGTEsPerGT = 0".into(),
            ));
        }
        if !self.grain_size_sectors.is_power_of_two() {
            return Err(VmdkError::Msg(format!(
                "VMDK grainSize {} is not a power of two",
                self.grain_size_sectors
            )));
        }
        let grains = self
            .capacity_sectors
            .div_ceil(self.grain_size_sectors)
            .max(1);
        let per = self.num_gtes_per_gt as u64;
        let entries = grains.div_ceil(per);
        if entries > 16 * 1024 * 1024 {
            return Err(VmdkError::Msg(format!(
                "VMDK grain directory too large ({entries} entries)"
            )));
        }
        Ok(entries as usize)
    }
}

pub fn parse_sparse_header(buf: &[u8; 512]) -> Result<SparseHeader> {
    let magic = le_u32(buf, 0);
    if magic == COWD_MAGIC {
        return Err(VmdkError::Msg(
            "ESXi COWD/vmfsSparse grain residual (v1 is hosted KDMV sparse only)".into(),
        ));
    }
    if magic != SPARSE_MAGIC {
        return Err(VmdkError::Msg("not a KDMV sparse VMDK extent".into()));
    }
    let version = le_u32(buf, 4);
    if version != 1 && version != 2 && version != 3 {
        return Err(VmdkError::Msg(format!(
            "unsupported VMDK sparse version {version}"
        )));
    }
    let header = SparseHeader {
        flags: le_u32(buf, 8),
        capacity_sectors: le_u64(buf, 0x0C),
        grain_size_sectors: le_u64(buf, 0x14),
        descriptor_offset: le_u64(buf, 0x1C),
        descriptor_size: le_u64(buf, 0x24),
        num_gtes_per_gt: le_u32(buf, 0x2C),
        gd_offset: le_u64(buf, 0x38),
        compress_algorithm: le_u16(buf, 0x4D),
    };
    if header.capacity_sectors == 0 {
        return Err(VmdkError::Msg("VMDK sparse capacity is 0".into()));
    }
    if header.gd_offset == 0 || header.gd_offset == GD_AT_END {
        return Err(VmdkError::Msg(
            "VMDK streamOptimized/footer grain directory residual (gdOffset is 0 or -1)".into(),
        ));
    }
    if header.is_compressed() {
        return Err(VmdkError::Msg(
            "compressed VMDK grains residual (streamOptimized / FLAG_COMPRESS)".into(),
        ));
    }
    let _ = header.gd_entries()?;
    Ok(header)
}

pub fn looks_like_kdmv(buf: &[u8]) -> bool {
    buf.len() >= 4 && le_u32_slice(buf) == SPARSE_MAGIC
}

pub fn looks_like_cowd(buf: &[u8]) -> bool {
    buf.len() >= 4 && le_u32_slice(buf) == COWD_MAGIC
}

/// One hosted sparse extent (grains in a single `Read+Seek` stream).
#[derive(Clone)]
pub struct SparseExtent {
    backend: Arc<Mutex<Box<dyn SeekRead>>>,
    header: SparseHeader,
    gd: Vec<u32>,
}

impl SparseExtent {
    pub fn from_backend(
        backend: Arc<Mutex<Box<dyn SeekRead>>>,
        header: SparseHeader,
        gd: Vec<u32>,
    ) -> Self {
        Self {
            backend,
            header,
            gd,
        }
    }

    pub fn size_bytes(&self) -> u64 {
        self.header.capacity_bytes()
    }

    pub fn read_at(&self, virt_off: u64, buf: &mut [u8]) -> io::Result<usize> {
        let cap = self.size_bytes();
        if virt_off >= cap || buf.is_empty() {
            return Ok(0);
        }
        let want = ((cap - virt_off) as usize).min(buf.len());
        let grain_bytes = self.header.grain_bytes();
        let mut done = 0usize;
        while done < want {
            let pos = virt_off + done as u64;
            let within = (pos % grain_bytes) as usize;
            let chunk = (want - done).min(grain_bytes as usize - within);
            let grain_idx = pos / grain_bytes;
            let gte = self.gte(grain_idx)?;
            if self.header.gte_is_hole(gte) {
                buf[done..done + chunk].fill(0);
            } else {
                let file_off = gte as u64 * SECTOR + within as u64;
                let n = {
                    let mut guard = lock_backend(&self.backend)?;
                    guard.seek(SeekFrom::Start(file_off))?;
                    read_at_most(&mut *guard, &mut buf[done..done + chunk])?
                };
                if n < chunk {
                    buf[done + n..done + chunk].fill(0);
                }
            }
            done += chunk;
        }
        Ok(done)
    }

    fn gte(&self, grain_idx: u64) -> io::Result<u32> {
        let per = self.header.num_gtes_per_gt as u64;
        if per == 0 {
            return Ok(0);
        }
        let gt_idx = (grain_idx / per) as usize;
        let gte_idx = (grain_idx % per) as usize;
        let Some(&gt_sector) = self.gd.get(gt_idx) else {
            return Ok(0);
        };
        if gt_sector == 0 {
            return Ok(0);
        }
        let off = gt_sector as u64 * SECTOR + gte_idx as u64 * 4;
        let mut b = [0u8; 4];
        {
            let mut guard = lock_backend(&self.backend)?;
            guard.seek(SeekFrom::Start(off))?;
            guard.read_exact(&mut b)?;
        }
        Ok(u32::from_le_bytes(b))
    }
}

#[derive(Clone)]
pub struct FlatExtent {
    backend: Arc<Mutex<Box<dyn SeekRead>>>,
    offset_bytes: u64,
    size_bytes: u64,
}

impl FlatExtent {
    pub fn new(backend: Arc<Mutex<Box<dyn SeekRead>>>, offset_bytes: u64, size_bytes: u64) -> Self {
        Self {
            backend,
            offset_bytes,
            size_bytes,
        }
    }

    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub fn read_at(&self, virt_off: u64, buf: &mut [u8]) -> io::Result<usize> {
        if virt_off >= self.size_bytes || buf.is_empty() {
            return Ok(0);
        }
        let want = ((self.size_bytes - virt_off) as usize).min(buf.len());
        let file_off = self.offset_bytes.saturating_add(virt_off);
        let mut guard = lock_backend(&self.backend)?;
        guard.seek(SeekFrom::Start(file_off))?;
        let n = read_at_most(&mut *guard, &mut buf[..want])?;
        if n < want {
            buf[n..want].fill(0);
        }
        Ok(want)
    }
}

#[derive(Clone)]
pub enum DiskExtent {
    Sparse(SparseExtent),
    Flat(FlatExtent),
    Zero { size_bytes: u64 },
}

impl DiskExtent {
    pub fn size_bytes(&self) -> u64 {
        match self {
            Self::Sparse(s) => s.size_bytes(),
            Self::Flat(f) => f.size_bytes(),
            Self::Zero { size_bytes } => *size_bytes,
        }
    }

    pub fn read_at(&self, virt_off: u64, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Sparse(s) => s.read_at(virt_off, buf),
            Self::Flat(f) => f.read_at(virt_off, buf),
            Self::Zero { size_bytes } => {
                if virt_off >= *size_bytes || buf.is_empty() {
                    return Ok(0);
                }
                let n = ((*size_bytes - virt_off) as usize).min(buf.len());
                buf[..n].fill(0);
                Ok(n)
            }
        }
    }
}

/// Concatenated virtual disk (SPARSE + ZERO + FLAT extents).
#[derive(Clone)]
pub struct VmdkDisk {
    extents: Vec<DiskExtent>,
    capacity_bytes: u64,
    pos: u64,
}

impl VmdkDisk {
    pub fn new(extents: Vec<DiskExtent>) -> Result<Self> {
        if extents.is_empty() {
            return Err(VmdkError::Msg("VMDK has no readable extents".into()));
        }
        let capacity_bytes = extents.iter().map(|e| e.size_bytes()).sum();
        if capacity_bytes == 0 {
            return Err(VmdkError::Msg("VMDK virtual capacity is 0".into()));
        }
        Ok(Self {
            extents,
            capacity_bytes,
            pos: 0,
        })
    }

    fn read_at(&self, virt_off: u64, buf: &mut [u8]) -> io::Result<usize> {
        if virt_off >= self.capacity_bytes || buf.is_empty() {
            return Ok(0);
        }
        let want = ((self.capacity_bytes - virt_off) as usize).min(buf.len());
        let mut done = 0usize;
        while done < want {
            let pos = virt_off + done as u64;
            let (ext, local) = self
                .extent_at(pos)
                .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "VMDK extent map"))?;
            let n = ext.read_at(local, &mut buf[done..want])?;
            if n == 0 {
                break;
            }
            done += n;
        }
        Ok(done)
    }

    fn extent_at(&self, pos: u64) -> Option<(&DiskExtent, u64)> {
        let mut off = 0u64;
        for e in &self.extents {
            let sz = e.size_bytes();
            if pos < off + sz {
                return Some((e, pos - off));
            }
            off += sz;
        }
        None
    }
}

impl Read for VmdkDisk {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.read_at(self.pos, buf)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for VmdkDisk {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i128,
            SeekFrom::Current(o) => self.pos as i128 + o as i128,
            SeekFrom::End(o) => self.capacity_bytes as i128 + o as i128,
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

pub fn lock_backend(
    backend: &Arc<Mutex<Box<dyn SeekRead>>>,
) -> io::Result<std::sync::MutexGuard<'_, Box<dyn SeekRead>>> {
    backend
        .lock()
        .map_err(|_| io::Error::other("vmdk reader poisoned"))
}

pub fn load_grain_directory(
    backend: &Arc<Mutex<Box<dyn SeekRead>>>,
    header: &SparseHeader,
) -> Result<Vec<u32>> {
    let entries = header.gd_entries()?;
    let mut buf = vec![0u8; entries.saturating_mul(4)];
    {
        let mut guard = lock_backend(backend)?;
        guard.seek(SeekFrom::Start(header.gd_offset * SECTOR))?;
        guard.read_exact(&mut buf)?;
    }
    Ok(buf
        .chunks_exact(4)
        .map(|c| {
            let mut b = [0u8; 4];
            b.copy_from_slice(c);
            u32::from_le_bytes(b)
        })
        .collect())
}

pub fn read_embedded_descriptor(
    backend: &Arc<Mutex<Box<dyn SeekRead>>>,
    header: &SparseHeader,
) -> Result<Option<VmdkDescriptor>> {
    if header.descriptor_offset == 0 || header.descriptor_size == 0 {
        return Ok(None);
    }
    if header.descriptor_size > 20_480 {
        return Err(VmdkError::Msg(format!(
            "VMDK embedded descriptor too large ({} sectors)",
            header.descriptor_size
        )));
    }
    let n = (header.descriptor_size * SECTOR) as usize;
    let mut buf = vec![0u8; n];
    {
        let mut guard = lock_backend(backend)?;
        guard.seek(SeekFrom::Start(header.descriptor_offset * SECTOR))?;
        guard.read_exact(&mut buf)?;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    let text = String::from_utf8_lossy(&buf[..end]);
    if text.trim().is_empty() {
        return Ok(None);
    }
    parse_vmdk_descriptor(&text).map(Some)
}

pub fn open_sparse_extent(
    backend: Arc<Mutex<Box<dyn SeekRead>>>,
) -> Result<(SparseExtent, Option<VmdkDescriptor>)> {
    let mut hdr_buf = [0u8; 512];
    {
        let mut guard = lock_backend(&backend)?;
        guard.seek(SeekFrom::Start(0))?;
        guard.read_exact(&mut hdr_buf)?;
    }
    let header = parse_sparse_header(&hdr_buf)?;
    let desc = read_embedded_descriptor(&backend, &header)?;
    let gd = load_grain_directory(&backend, &header)?;
    Ok((SparseExtent::from_backend(backend, header, gd), desc))
}

pub fn share_reader<R>(reader: R) -> Arc<Mutex<Box<dyn SeekRead>>>
where
    R: Read + Seek + Send + 'static,
{
    Arc::new(Mutex::new(Box::new(reader) as Box<dyn SeekRead>))
}

fn read_at_most<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut done = 0usize;
    while done < buf.len() {
        match r.read(&mut buf[done..])? {
            0 => break,
            n => done += n,
        }
    }
    Ok(done)
}

fn le_u16(buf: &[u8], off: usize) -> u16 {
    let mut b = [0u8; 2];
    b.copy_from_slice(&buf[off..off + 2]);
    u16::from_le_bytes(b)
}

fn le_u32(buf: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&buf[off..off + 4]);
    u32::from_le_bytes(b)
}

fn le_u64(buf: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    u64::from_le_bytes(b)
}

fn le_u32_slice(buf: &[u8]) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&buf[..4]);
    u32::from_le_bytes(b)
}

/// Build a hosted `monolithicSparse` file wrapping `raw` virtual-disk bytes.
///
/// Used by tests as a always-on fixture (no `qemu-img`). `grain_size_sectors`
/// must be a power of two (typically 8 or 128).
#[cfg(test)]
pub fn build_monolithic_sparse(raw: &[u8], grain_size_sectors: u64) -> Vec<u8> {
    assert!(
        grain_size_sectors.is_power_of_two() && grain_size_sectors > 0,
        "grain size"
    );
    const NUM_GTES: u32 = 512;
    let capacity_sectors = (raw.len() as u64).div_ceil(SECTOR).max(1);
    let capacity_sectors = capacity_sectors.div_ceil(grain_size_sectors) * grain_size_sectors;
    let num_grains = capacity_sectors / grain_size_sectors;
    let gt_count = num_grains.div_ceil(NUM_GTES as u64).max(1);
    let gt_sectors = (NUM_GTES as u64 * 4).div_ceil(SECTOR); // 4
    let gd_sectors = (gt_count * 4).div_ceil(SECTOR).max(1);

    let desc = format!(
        "# Disk DescriptorFile\n\
         version=1\n\
         CID=fffffffe\n\
         parentCID=ffffffff\n\
         createType=\"monolithicSparse\"\n\
         \n\
         # Extent description\n\
         RW {capacity_sectors} SPARSE \"disk.vmdk\"\n\
         \n\
         # The Disk Data Base\n\
         #DDB\n\
         ddb.virtualHWVersion = \"4\"\n\
         ddb.adapterType = \"ide\"\n"
    );
    let desc_sectors = (desc.len() as u64).div_ceil(SECTOR).max(1);

    let rgd_offset = 1 + desc_sectors;
    let rgd_gt_offset = rgd_offset + gd_sectors;
    let gd_offset = rgd_gt_offset + gt_count * gt_sectors;
    let gd_gt_offset = gd_offset + gd_sectors;
    let mut overhead = gd_gt_offset + gt_count * gt_sectors;
    overhead = overhead.div_ceil(grain_size_sectors) * grain_size_sectors;

    let grain_bytes = (grain_size_sectors * SECTOR) as usize;
    let mut gtes = vec![0u32; num_grains as usize];
    let mut grains: Vec<(u64, Vec<u8>)> = Vec::new();
    let mut next = overhead;
    for (i, gte) in gtes.iter_mut().enumerate() {
        let start = i * grain_bytes;
        if start >= raw.len() {
            break;
        }
        let end = (start + grain_bytes).min(raw.len());
        let chunk = &raw[start..end];
        if chunk.iter().all(|&b| b == 0) {
            continue;
        }
        let mut g = vec![0u8; grain_bytes];
        g[..chunk.len()].copy_from_slice(chunk);
        *gte = next as u32;
        grains.push((next, g));
        next += grain_size_sectors;
    }

    let file_sectors = next.max(overhead + grain_size_sectors);
    let mut img = vec![0u8; (file_sectors * SECTOR) as usize];

    // Header
    img[0..4].copy_from_slice(&SPARSE_MAGIC.to_le_bytes());
    img[4..8].copy_from_slice(&1u32.to_le_bytes());
    img[8..12].copy_from_slice(&3u32.to_le_bytes()); // NL_DETECT | RGD
    img[0x0C..0x14].copy_from_slice(&capacity_sectors.to_le_bytes());
    img[0x14..0x1C].copy_from_slice(&grain_size_sectors.to_le_bytes());
    img[0x1C..0x24].copy_from_slice(&1u64.to_le_bytes()); // descriptorOffset
    img[0x24..0x2C].copy_from_slice(&desc_sectors.to_le_bytes());
    img[0x2C..0x30].copy_from_slice(&NUM_GTES.to_le_bytes());
    img[0x30..0x38].copy_from_slice(&rgd_offset.to_le_bytes());
    img[0x38..0x40].copy_from_slice(&gd_offset.to_le_bytes());
    img[0x40..0x48].copy_from_slice(&overhead.to_le_bytes());
    img[0x48] = 0;
    img[0x49] = b'\n';
    img[0x4A] = b' ';
    img[0x4B] = b'\r';
    img[0x4C] = b'\n';
    img[0x4D..0x4F].copy_from_slice(&0u16.to_le_bytes());

    let desc_off = SECTOR as usize;
    img[desc_off..desc_off + desc.len()].copy_from_slice(desc.as_bytes());

    let write_u32s = |img: &mut [u8], sector: u64, vals: &[u32]| {
        let off = (sector * SECTOR) as usize;
        for (i, v) in vals.iter().enumerate() {
            let o = off + i * 4;
            img[o..o + 4].copy_from_slice(&v.to_le_bytes());
        }
    };

    let mut gd = vec![0u32; gt_count as usize];
    let mut rgd = vec![0u32; gt_count as usize];
    for i in 0..gt_count {
        gd[i as usize] = (gd_gt_offset + i * gt_sectors) as u32;
        rgd[i as usize] = (rgd_gt_offset + i * gt_sectors) as u32;
    }
    write_u32s(&mut img, gd_offset, &gd);
    write_u32s(&mut img, rgd_offset, &rgd);

    // Grain tables (primary + redundant) — pad to NUM_GTES with zeros.
    let mut gt_full = vec![0u32; (gt_count as usize) * NUM_GTES as usize];
    gt_full[..gtes.len()].copy_from_slice(&gtes);
    for i in 0..gt_count {
        let start = (i as usize) * NUM_GTES as usize;
        let slice = &gt_full[start..start + NUM_GTES as usize];
        write_u32s(&mut img, gd_gt_offset + i * gt_sectors, slice);
        write_u32s(&mut img, rgd_gt_offset + i * gt_sectors, slice);
    }

    for (sector, grain) in grains {
        let off = (sector * SECTOR) as usize;
        img[off..off + grain.len()].copy_from_slice(&grain);
    }
    img
}

#[cfg(test)]
fn poke_gte0(vmdk: &mut [u8], value: u32) {
    let mut hdr = [0u8; 512];
    hdr.copy_from_slice(&vmdk[..512]);
    let header = parse_sparse_header(&hdr).expect("header");
    let gd_off = (header.gd_offset * SECTOR) as usize;
    let mut gt_sec = [0u8; 4];
    gt_sec.copy_from_slice(&vmdk[gd_off..gd_off + 4]);
    let gt_sector = u32::from_le_bytes(gt_sec);
    let gte_off = (gt_sector as u64 * SECTOR) as usize;
    vmdk[gte_off..gte_off + 4].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Regression: GTE 1 is a sector offset unless ZERO_GRAIN is set.
    #[test]
    fn sparse_gte_one_is_sector_without_zero_grain() {
        let mut raw = vec![0u8; 8 * 512];
        raw[0] = 0xAA;
        let mut vmdk = build_monolithic_sparse(&raw, 8);
        let flags = u32::from_le_bytes(vmdk[8..12].try_into().unwrap());
        assert_eq!(flags & FLAG_ZERO_GRAIN, 0);
        poke_gte0(&mut vmdk, GTE_ZEROED);
        let backend = share_reader(Cursor::new(vmdk.clone()));
        let (extent, _) = open_sparse_extent(backend).unwrap();
        let mut got = [0u8; 4];
        extent.read_at(0, &mut got).unwrap();
        assert_eq!(
            &got, b"# Di",
            "GTE 1 without ZERO_GRAIN reads sector 1 (descriptor)"
        );
    }

    /// Regression: GTE 1 is a hole when ZERO_GRAIN is set.
    #[test]
    fn sparse_gte_one_is_zero_with_zero_grain() {
        let mut raw = vec![0u8; 8 * 512];
        raw[0] = 0xAA;
        let mut vmdk = build_monolithic_sparse(&raw, 8);
        let flags = u32::from_le_bytes(vmdk[8..12].try_into().unwrap()) | FLAG_ZERO_GRAIN;
        vmdk[8..12].copy_from_slice(&flags.to_le_bytes());
        poke_gte0(&mut vmdk, GTE_ZEROED);
        let backend = share_reader(Cursor::new(vmdk));
        let (extent, _) = open_sparse_extent(backend).unwrap();
        let mut got = [0xFFu8; 4];
        extent.read_at(0, &mut got).unwrap();
        assert_eq!(got, [0, 0, 0, 0]);
    }
}
