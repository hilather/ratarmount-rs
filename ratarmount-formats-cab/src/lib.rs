//! Microsoft CAB MountSource (`backendName=CABMountSource`).
//!
//! - typeCompress 0 (none): stencil open across CFDATA blocks
//! - typeCompress 1 (MSZIP): decompress CFDATA folders, slice file
//! - Quantum/LZX: clear error so factory can fall back to libarchive

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use flate2::{Decompress, FlushDecompress, Status};
use ratarmount_compress::StenciledFile;
use ratarmount_core::{
    normpath, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions,
    SQLiteIndexedTarUserData, UserData,
};
use ratarmount_index::{IndexError, SqliteIndex};
use thiserror::Error;

pub const BACKEND_NAME: &str = "CABMountSource";

const TCOMP_MASK_TYPE: u16 = 0x000F;
const TCOMP_TYPE_NONE: u16 = 0x0000;
const TCOMP_TYPE_MSZIP: u16 = 0x0001;
const TCOMP_TYPE_QUANTUM: u16 = 0x0002;
const TCOMP_TYPE_LZX: u16 = 0x0003;
const A_DIRECTORY: u16 = 0x10;
const A_NAME_IS_UTF: u16 = 0x80;
const MSZIP_WINDOW: usize = 32768;

#[derive(Debug, Error)]
pub enum CabError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("unsupported cab compression: {0}")]
    UnsupportedCompression(u16),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, CabError>;

#[derive(Clone, Debug)]
struct CfDataBlock {
    offset: u64,
    compressed_size: u16,
    uncompressed_size: u16,
    uncompressed_offset: u64,
}

#[derive(Clone, Debug)]
struct CfFolder {
    data_offset: u64,
    num_data: u16,
    type_compress: u16,
    blocks: Vec<CfDataBlock>,
}

#[derive(Clone, Debug)]
struct CfFile {
    name: String,
    size: u32,
    folder_index: u16,
    folder_offset: u32,
    attributes: u16,
    #[allow(dead_code)]
    header_offset: u64,
    mtime: f64,
}

pub struct CabMountSource {
    archive_path: PathBuf,
    index: SqliteIndex,
    folders: Vec<CfFolder>,
    folder_cache: Mutex<HashMap<usize, Vec<u8>>>,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl CabMountSource {
    pub fn open(
        archive_path: impl AsRef<Path>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
        recreate: bool,
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        let index_path_buf: Option<PathBuf> = if options.index_in_memory {
            None
        } else {
            Some(
                index_path
                    .map(|p| p.to_path_buf())
                    .unwrap_or_else(|| default_index_path(&archive_path)),
            )
        };

        // Always re-parse folders for open paths; index can be reused.
        let mut file = File::open(&archive_path)?;
        let (folders, files) = parse_cab_archive(&mut file)?;
        for folder in &folders {
            if folder.type_compress != TCOMP_TYPE_NONE && folder.type_compress != TCOMP_TYPE_MSZIP {
                return Err(CabError::UnsupportedCompression(folder.type_compress));
            }
        }

        if let Some(ref ip) = index_path_buf {
            if !recreate && ip.exists() {
                let meta_ok = std::fs::metadata(ip).map(|m| m.len() > 0).unwrap_or(false);
                if meta_ok {
                    match Self::open_existing(&archive_path, ip, options, folders.clone()) {
                        Ok(s) => return Ok(s),
                        Err(e) => eprintln!("info: could not load cab index ({e}); rebuilding"),
                    }
                }
            }
        }
        Self::create_index(
            &archive_path,
            index_path_buf.as_deref(),
            options,
            product_version,
            folders,
            files,
        )
    }

    fn open_existing(
        archive_path: &Path,
        index_path: &Path,
        options: &OpenOptions,
        folders: Vec<CfFolder>,
    ) -> Result<Self> {
        let index = SqliteIndex::open_read_only(index_path)?;
        index.check_backend_name(BACKEND_NAME)?;
        Ok(Self {
            archive_path: archive_path.to_path_buf(),
            index,
            folders,
            folder_cache: Mutex::new(HashMap::new()),
            options: options.clone(),
        })
    }

    fn create_index(
        archive_path: &Path,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
        folders: Vec<CfFolder>,
        files: Vec<CfFile>,
    ) -> Result<Self> {
        let _ = options;
        println!(
            "Creating offset dictionary for {} ...",
            archive_path.display()
        );
        let t0 = Instant::now();

        let index = SqliteIndex::create_writable(index_path)?;
        index.begin_write()?;
        let mut generated = std::collections::BTreeSet::new();

        for f in files {
            let nfull = normpath(&f.name);
            let (path, base) = split_name(&nfull);
            ensure_parents(&index, &path, &mut generated, f.mtime)?;
            let is_dir = f.attributes & A_DIRECTORY != 0;
            let mode = if is_dir {
                (libc::S_IFDIR | 0o755) as i64
            } else {
                (libc::S_IFREG | 0o644) as i64
            };
            // offsetheader = folder_index; offset = uncompressed offset in folder
            index.insert_file(
                &path,
                &base,
                f.folder_index as i64,
                f.folder_offset as i64,
                if is_dir { 0 } else { f.size as i64 },
                f.mtime,
                mode,
                0,
                &format!("cab-folder:{}", f.folder_index),
                0,
                0,
                false,
                false,
                false,
                0,
            )?;
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
            folders,
            folder_cache: Mutex::new(HashMap::new()),
            options: options.clone(),
        })
    }

    fn folder_bytes(&self, folder_index: usize) -> io::Result<Vec<u8>> {
        {
            let cache = self.folder_cache.lock().unwrap();
            if let Some(v) = cache.get(&folder_index) {
                return Ok(v.clone());
            }
        }
        let folder = self
            .folders
            .get(folder_index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad folder index"))?;
        let mut file = File::open(&self.archive_path)?;
        let plain = match folder.type_compress {
            TCOMP_TYPE_NONE => {
                let mut parts = Vec::new();
                for block in &folder.blocks {
                    file.seek(SeekFrom::Start(block.offset))?;
                    let mut buf = vec![0u8; block.compressed_size as usize];
                    file.read_exact(&mut buf)?;
                    parts.extend_from_slice(&buf);
                }
                parts
            }
            TCOMP_TYPE_MSZIP => {
                let mut parts = Vec::new();
                let mut history = Vec::new();
                for block in &folder.blocks {
                    file.seek(SeekFrom::Start(block.offset))?;
                    let mut raw = vec![0u8; block.compressed_size as usize];
                    file.read_exact(&mut raw)?;
                    let chunk =
                        mszip_decompress_block(&raw, block.uncompressed_size as usize, &history)?;
                    history.extend_from_slice(&chunk);
                    if history.len() > MSZIP_WINDOW {
                        history = history[history.len() - MSZIP_WINDOW..].to_vec();
                    }
                    parts.extend_from_slice(&chunk);
                }
                parts
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("Unsupported CAB compression {other}"),
                ));
            }
        };
        self.folder_cache
            .lock()
            .unwrap()
            .insert(folder_index, plain.clone());
        Ok(plain)
    }

    fn open_store_file(
        &self,
        folder_index: usize,
        folder_offset: u64,
        size: u64,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        let folder = self
            .folders
            .get(folder_index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "bad folder"))?;
        let mut regions: Vec<(u64, u64)> = Vec::new();
        let mut remaining = size;
        let mut pos = folder_offset;
        for block in &folder.blocks {
            let block_start = block.uncompressed_offset;
            let block_end = block_start + u64::from(block.uncompressed_size);
            if remaining == 0 {
                break;
            }
            if pos >= block_end {
                continue;
            }
            if pos < block_start {
                continue;
            }
            let local = pos - block_start;
            let take = remaining.min(u64::from(block.uncompressed_size) - local);
            if take == 0 {
                continue;
            }
            regions.push((block.offset + local, take));
            pos += take;
            remaining -= take;
        }
        if remaining != 0 || regions.is_empty() {
            let plain = self.folder_bytes(folder_index)?;
            let end = (folder_offset as usize + size as usize).min(plain.len());
            let start = (folder_offset as usize).min(end);
            return Ok(Box::new(Cursor::new(plain[start..end].to_vec())));
        }
        let file = File::open(&self.archive_path)?;
        Ok(Box::new(StenciledFile::new(file, regions)))
    }
}

impl MountSource for CabMountSource {
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
        if file_info.mode & libc::S_IFMT == libc::S_IFDIR {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "is a directory",
            ));
        }
        if file_info.size == 0 {
            return Ok(Box::new(Cursor::new(Vec::new())));
        }
        let ud = userdata(file_info)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing cab userdata"))?;
        let folder_index = ud.offsetheader.unwrap_or(0) as usize;
        let folder_offset = ud.offset;
        let folder = self
            .folders
            .get(folder_index)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid cab folder"))?;
        if folder.type_compress == TCOMP_TYPE_NONE {
            return self.open_store_file(folder_index, folder_offset, file_info.size);
        }
        let plain = self.folder_bytes(folder_index)?;
        let end = (folder_offset as usize + file_info.size as usize).min(plain.len());
        let start = (folder_offset as usize).min(end);
        Ok(Box::new(Cursor::new(plain[start..end].to_vec())))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

fn parse_cab_archive(file: &mut File) -> Result<(Vec<CfFolder>, Vec<CfFile>)> {
    let start = file.stream_position()?;
    let mut header = [0u8; 36];
    file.read_exact(&mut header)?;
    if &header[..4] != b"MSCF" {
        return Err(CabError::Msg("Not a Microsoft CAB file".into()));
    }
    let coff_files = u32::from_le_bytes(header[16..20].try_into().unwrap());
    let ver_maj = header[25];
    let c_folders = u16::from_le_bytes(header[26..28].try_into().unwrap());
    let c_files = u16::from_le_bytes(header[28..30].try_into().unwrap());
    let flags = u16::from_le_bytes(header[30..32].try_into().unwrap());
    if ver_maj != 1 {
        return Err(CabError::Msg(format!(
            "Unsupported CAB major version: {ver_maj}"
        )));
    }

    let mut cb_cf_folder = 0u8;
    let mut cb_cf_data = 0u8;
    if flags & 0x0004 != 0 {
        let mut res = [0u8; 4];
        file.read_exact(&mut res)?;
        let cb_cf_header = u16::from_le_bytes(res[0..2].try_into().unwrap());
        cb_cf_folder = res[2];
        cb_cf_data = res[3];
        if cb_cf_header > 0 {
            file.seek(SeekFrom::Current(cb_cf_header as i64))?;
        }
    }
    if flags & 0x0001 != 0 {
        read_cstring(file)?;
        read_cstring(file)?;
    }
    if flags & 0x0002 != 0 {
        read_cstring(file)?;
        read_cstring(file)?;
    }

    let mut folders = Vec::with_capacity(c_folders as usize);
    for _ in 0..c_folders {
        let mut raw = [0u8; 8];
        file.read_exact(&mut raw)?;
        let coff_cab_start = u32::from_le_bytes(raw[0..4].try_into().unwrap());
        let c_cf_data = u16::from_le_bytes(raw[4..6].try_into().unwrap());
        let type_compress = u16::from_le_bytes(raw[6..8].try_into().unwrap()) & TCOMP_MASK_TYPE;
        if cb_cf_folder > 0 {
            file.seek(SeekFrom::Current(cb_cf_folder as i64))?;
        }
        folders.push(CfFolder {
            data_offset: start + u64::from(coff_cab_start),
            num_data: c_cf_data,
            type_compress,
            blocks: Vec::new(),
        });
    }

    let mut files = Vec::with_capacity(c_files as usize);
    file.seek(SeekFrom::Start(start + u64::from(coff_files)))?;
    for _ in 0..c_files {
        let header_offset = file.stream_position()? - start;
        let mut raw = [0u8; 16];
        file.read_exact(&mut raw)?;
        let cb_file = u32::from_le_bytes(raw[0..4].try_into().unwrap());
        let uoff_folder_start = u32::from_le_bytes(raw[4..8].try_into().unwrap());
        let i_folder = u16::from_le_bytes(raw[8..10].try_into().unwrap());
        let date = u16::from_le_bytes(raw[10..12].try_into().unwrap());
        let time = u16::from_le_bytes(raw[12..14].try_into().unwrap());
        let attribs = u16::from_le_bytes(raw[14..16].try_into().unwrap());
        let name_raw = read_cstring(file)?;
        let name = if attribs & A_NAME_IS_UTF != 0 {
            String::from_utf8_lossy(&name_raw).into_owned()
        } else {
            name_raw.iter().map(|&b| b as char).collect()
        };
        if i_folder >= 0xFFFD {
            return Err(CabError::Msg(format!(
                "Split CAB file spans not supported: {name:?}"
            )));
        }
        if i_folder as usize >= folders.len() {
            return Err(CabError::Msg(format!(
                "Invalid folder index {i_folder} for {name}"
            )));
        }
        files.push(CfFile {
            name: name.replace('\\', "/"),
            size: cb_file,
            folder_index: i_folder,
            folder_offset: uoff_folder_start,
            attributes: attribs,
            header_offset,
            mtime: cab_dos_datetime_to_mtime(date, time),
        });
    }

    for folder in &mut folders {
        file.seek(SeekFrom::Start(folder.data_offset))?;
        let mut u_off = 0u64;
        for _ in 0..folder.num_data {
            let mut raw = [0u8; 8];
            file.read_exact(&mut raw)?;
            let cb_data = u16::from_le_bytes(raw[4..6].try_into().unwrap());
            let cb_uncomp = u16::from_le_bytes(raw[6..8].try_into().unwrap());
            if cb_cf_data > 0 {
                file.seek(SeekFrom::Current(cb_cf_data as i64))?;
            }
            let payload_offset = file.stream_position()?;
            folder.blocks.push(CfDataBlock {
                offset: payload_offset,
                compressed_size: cb_data,
                uncompressed_size: cb_uncomp,
                uncompressed_offset: u_off,
            });
            file.seek(SeekFrom::Start(payload_offset + u64::from(cb_data)))?;
            u_off += u64::from(cb_uncomp);
        }
    }

    Ok((folders, files))
}

fn read_cstring(file: &mut File) -> Result<Vec<u8>> {
    let mut parts = Vec::new();
    loop {
        let mut b = [0u8; 1];
        file.read_exact(&mut b)?;
        if b[0] == 0 {
            break;
        }
        parts.push(b[0]);
    }
    Ok(parts)
}

fn cab_dos_datetime_to_mtime(date: u16, time: u16) -> f64 {
    if date == 0 && time == 0 {
        return 0.0;
    }
    let day = (date & 0x1F) as u32;
    let month = ((date >> 5) & 0x0F) as u32;
    let year = (((date >> 9) & 0x7F) as u32) + 1980;
    let second = ((time & 0x1F) * 2) as u32;
    let minute = ((time >> 5) & 0x3F) as u32;
    let hour = ((time >> 11) & 0x1F) as u32;
    // Approximate Unix time via days since epoch (UTC).
    if !(1..=12).contains(&month) || day == 0 {
        return 0.0;
    }
    let days = days_from_civil(year as i32, month as i32, day as i32);
    let secs = days * 86400 + hour as i64 * 3600 + minute as i64 * 60 + second as i64;
    secs as f64
}

/// Howard Hinnant days_from_civil
fn days_from_civil(y: i32, m: i32, d: i32) -> i64 {
    let y = y - if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = (y - era * 400) as u32;
    let doy = (153 * (m + if m > 2 { -3 } else { 9 }) as u32 + 2) / 5 + d as u32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    (era as i64) * 146097 + doe as i64 - 719468
}

fn mszip_decompress_block(
    block: &[u8],
    uncompressed_size: usize,
    _history: &[u8],
) -> io::Result<Vec<u8>> {
    if block.len() < 2 || &block[..2] != b"CK" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid MSZIP block (missing CK signature)",
        ));
    }
    let payload = &block[2..];
    // Raw inflate (wbits=-15). flate2's Decompress has no stable set_dictionary API
    // on all backends; first block and many small CABs work without a preset dict.
    let mut d = Decompress::new(false);
    inflate_all(&mut d, payload, uncompressed_size).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("MSZIP decompress failed: {e}"),
        )
    })
}

fn inflate_all(
    d: &mut Decompress,
    payload: &[u8],
    max_out: usize,
) -> std::result::Result<Vec<u8>, String> {
    let mut out = vec![
        0u8;
        if max_out == 0 {
            payload.len() * 4 + 64
        } else {
            max_out
        }
    ];
    loop {
        let in_off = d.total_in() as usize;
        let out_off = d.total_out() as usize;
        if out_off == out.len() {
            out.resize(out.len() * 2 + 64, 0);
        }
        match d.decompress(
            &payload[in_off..],
            &mut out[out_off..],
            FlushDecompress::Finish,
        ) {
            Ok(Status::Ok) => {}
            Ok(Status::StreamEnd) => {
                out.truncate(d.total_out() as usize);
                if max_out > 0 && out.len() > max_out {
                    out.truncate(max_out);
                }
                return Ok(out);
            }
            Ok(Status::BufError) => {
                out.resize(out.len() * 2 + 64, 0);
            }
            Err(e) => return Err(e.to_string()),
        }
        if max_out > 0 && d.total_out() as usize >= max_out {
            out.truncate(max_out);
            return Ok(out);
        }
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
        let mode = (libc::S_IFDIR | 0o755) as i64;
        index.insert_file(
            &parent, part, 0, 0, 0, mtime, mode, 0, "", 0, 0, false, false, true, 0,
        )?;
    }
    Ok(())
}

fn userdata(fi: &FileInfo) -> Option<&SQLiteIndexedTarUserData> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Tar(t) => Some(t),
        _ => None,
    })
}

pub fn looks_like_cab(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        let mut magic = [0u8; 4];
        if f.read(&mut magic).ok() == Some(4) && &magic == b"MSCF" {
            return true;
        }
    }
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("cab"))
}

pub fn default_index_path(archive: &Path) -> PathBuf {
    let mut s = archive.as_os_str().to_os_string();
    s.push(".index.sqlite");
    PathBuf::from(s)
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

// silence unused constants for documentation parity
const _: u16 = TCOMP_TYPE_QUANTUM;
const _: u16 = TCOMP_TYPE_LZX;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_single_file_cab() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let path = PathBuf::from(root).join("tests/single-file.cab");
        if !path.exists() {
            return;
        }
        assert!(looks_like_cab(&path));
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("c.index.sqlite");
        let m = CabMountSource::open(&path, Some(&idx), &OpenOptions::default(), "0.1.0", true)
            .unwrap();
        let fi = m.lookup("/bar", 0).expect("bar");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"foo\n");
    }
}
