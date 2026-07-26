//! CPIO archive support: newc/crc (070701/070702), portable ASCII odc (070707),
//! and old binary (0x71c7 LE/BE). Random access via [`StenciledFile`].

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Instant;

use ratarmount_compress::StenciledFile;
use ratarmount_core::{
    normpath, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions, UserData,
    SQLiteIndexedTarUserData,
};
use ratarmount_index::{IndexError, SqliteIndex};
use thiserror::Error;

pub const BACKEND_NAME: &str = "CpioMountSource";
const NEWC_MAGIC: &[u8; 6] = b"070701";
const CRC_MAGIC: &[u8; 6] = b"070702";
const ODC_MAGIC: &[u8; 6] = b"070707";
const BIN_MAGIC_LE: &[u8; 2] = b"\xc7\x71";
const BIN_MAGIC_BE: &[u8; 2] = b"\x71\xc7";

#[derive(Debug, Error)]
pub enum CpioError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, CpioError>;

enum CpioKind {
    Newc,
    Odc,
    BinLe,
    BinBe,
}

pub struct CpioMountSource {
    archive_path: PathBuf,
    index: SqliteIndex,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl CpioMountSource {
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

        if let Some(ref ip) = index_path_buf {
            if !recreate && ip.exists() {
                let meta_ok = std::fs::metadata(ip)
                    .map(|m| m.len() > 0)
                    .unwrap_or(false);
                if meta_ok {
                    match Self::open_existing(&archive_path, ip, options) {
                        Ok(s) => return Ok(s),
                        Err(e) => eprintln!("info: could not load cpio index ({e}); rebuilding"),
                    }
                }
            }
        }
        Self::create_index(
            &archive_path,
            index_path_buf.as_deref(),
            options,
            product_version,
        )
    }

    fn open_existing(archive_path: &Path, index_path: &Path, options: &OpenOptions) -> Result<Self> {
        let index = SqliteIndex::open_read_only(index_path)?;
        index.check_backend_name(BACKEND_NAME)?;
        Ok(Self {
            archive_path: archive_path.to_path_buf(),
            index,
            options: options.clone(),
        })
    }

    fn create_index(
        archive_path: &Path,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
    ) -> Result<Self> {
        let _ = options;
        println!(
            "Creating offset dictionary for {} ...",
            archive_path.display()
        );
        let t0 = Instant::now();

        let mut file = File::open(archive_path)?;
        let kind = detect_kind(&mut file)?;
        file.seek(SeekFrom::Start(0))?;

        let index = SqliteIndex::create_writable(index_path)?;
        index.begin_write()?;
        let mut generated = std::collections::BTreeSet::new();

        match kind {
            CpioKind::Newc => parse_newc(&mut file, &index, &mut generated)?,
            CpioKind::Odc => parse_odc(&mut file, &index, &mut generated)?,
            CpioKind::BinLe => parse_bin(&mut file, &index, &mut generated, true)?,
            CpioKind::BinBe => parse_bin(&mut file, &index, &mut generated, false)?,
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
            options: options.clone(),
        })
    }
}

impl MountSource for CpioMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        self.index
            .list(path)
            .ok()
            .flatten()
            .map(ListResult::Infos)
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
        let ud = userdata(file_info).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing cpio userdata")
        })?;
        let file = File::open(&self.archive_path)?;
        Ok(Box::new(StenciledFile::new(
            file,
            vec![(ud.offset, file_info.size)],
        )))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

fn detect_kind(file: &mut File) -> Result<CpioKind> {
    let mut magic = [0u8; 6];
    let n = file.read(&mut magic)?;
    if n >= 6 {
        if &magic == NEWC_MAGIC || &magic == CRC_MAGIC {
            return Ok(CpioKind::Newc);
        }
        if &magic == ODC_MAGIC {
            return Ok(CpioKind::Odc);
        }
    }
    if n >= 2 {
        if &magic[..2] == BIN_MAGIC_LE {
            return Ok(CpioKind::BinLe);
        }
        if &magic[..2] == BIN_MAGIC_BE {
            return Ok(CpioKind::BinBe);
        }
    }
    Err(CpioError::Msg(format!("unrecognized cpio magic {magic:?}")))
}

fn parse_newc(
    file: &mut File,
    index: &SqliteIndex,
    generated: &mut std::collections::BTreeSet<String>,
) -> Result<()> {
    loop {
        let header_offset = file.stream_position()?;
        let mut magic = [0u8; 6];
        match file.read(&mut magic)? {
            0 => break,
            n if n < 6 => return Err(CpioError::Msg("truncated cpio magic".into())),
            _ => {}
        }
        if magic.iter().all(|&b| b == 0) {
            break;
        }
        if &magic != NEWC_MAGIC && &magic != CRC_MAGIC {
            return Err(CpioError::Msg(format!("unsupported cpio magic {magic:?}")));
        }

        let mut fields = [0u8; 104];
        file.read_exact(&mut fields)?;
        let mode = hex_u32(&fields[8..16])?;
        let uid = hex_u32(&fields[16..24])?;
        let gid = hex_u32(&fields[24..32])?;
        let mtime = hex_u32(&fields[40..48])? as f64;
        let filesize = hex_u32(&fields[48..56])? as u64;
        let namesize = hex_u32(&fields[88..96])? as usize;

        let mut name_buf = vec![0u8; namesize];
        file.read_exact(&mut name_buf)?;
        while name_buf.last() == Some(&0) {
            name_buf.pop();
        }
        let name = String::from_utf8_lossy(&name_buf).into_owned();

        let header_and_name = 110 + namesize;
        let name_pad = (4 - (header_and_name % 4)) % 4;
        if name_pad > 0 {
            file.seek(SeekFrom::Current(name_pad as i64))?;
        }
        let data_offset = file.stream_position()?;

        if name == "TRAILER!!!" {
            break;
        }

        insert_entry(
            index,
            generated,
            &name,
            mode,
            mtime,
            filesize,
            header_offset,
            data_offset,
            uid,
            gid,
            file,
            4,
        )?;
    }
    Ok(())
}

fn parse_odc(
    file: &mut File,
    index: &SqliteIndex,
    generated: &mut std::collections::BTreeSet<String>,
) -> Result<()> {
    // Portable ASCII odc: 76-byte header (magic 6 + 70 octal fields).
    loop {
        let header_offset = file.stream_position()?;
        let mut magic = [0u8; 6];
        match file.read(&mut magic)? {
            0 => break,
            n if n < 6 => return Err(CpioError::Msg("truncated odc magic".into())),
            _ => {}
        }
        if magic.iter().all(|&b| b == 0) {
            break;
        }
        if &magic != ODC_MAGIC {
            return Err(CpioError::Msg(format!("invalid odc magic {magic:?}")));
        }
        let mut rest = [0u8; 70];
        file.read_exact(&mut rest)?;
        let s = std::str::from_utf8(&rest).map_err(|e| CpioError::Msg(e.to_string()))?;
        // after magic: dev6 ino6 mode6 uid6 gid6 nlink6 rdev6 mtime11 namesize6 filesize11
        let mode = oct_u32(&s[12..18])?;
        let uid = oct_u32(&s[18..24])?;
        let gid = oct_u32(&s[24..30])?;
        let mtime = oct_u64(&s[42..53])? as f64;
        let namesize = oct_u32(&s[53..59])? as usize;
        let filesize = oct_u64(&s[59..70])?;

        let mut name_buf = vec![0u8; namesize];
        file.read_exact(&mut name_buf)?;
        while name_buf.last() == Some(&0) {
            name_buf.pop();
        }
        let name = String::from_utf8_lossy(&name_buf).into_owned();
        let data_offset = file.stream_position()?;

        if name == "TRAILER!!!" {
            break;
        }

        // odc: no padding on name or data
        insert_entry(
            index,
            generated,
            &name,
            mode,
            mtime,
            filesize,
            header_offset,
            data_offset,
            uid,
            gid,
            file,
            1,
        )?;
    }
    Ok(())
}

fn parse_bin(
    file: &mut File,
    index: &SqliteIndex,
    generated: &mut std::collections::BTreeSet<String>,
    little_endian: bool,
) -> Result<()> {
    loop {
        let header_offset = file.stream_position()?;
        let mut magic = [0u8; 2];
        match file.read(&mut magic)? {
            0 => break,
            n if n < 2 => return Err(CpioError::Msg("truncated binary magic".into())),
            _ => {}
        }
        if magic == [0, 0] {
            break;
        }
        let ok = if little_endian {
            &magic == BIN_MAGIC_LE
        } else {
            &magic == BIN_MAGIC_BE
        };
        if !ok {
            return Err(CpioError::Msg(format!(
                "invalid binary cpio magic {magic:?}"
            )));
        }
        let mut rest = [0u8; 24];
        file.read_exact(&mut rest)?;
        // 12 u16 fields after magic
        let fields: [u16; 12] = if little_endian {
            let mut out = [0u16; 12];
            for i in 0..12 {
                out[i] = u16::from_le_bytes([rest[i * 2], rest[i * 2 + 1]]);
            }
            out
        } else {
            let mut out = [0u16; 12];
            for i in 0..12 {
                out[i] = u16::from_be_bytes([rest[i * 2], rest[i * 2 + 1]]);
            }
            out
        };
        let mode = fields[2] as u32;
        let uid = fields[3] as u32;
        let gid = fields[4] as u32;
        let mtime = (((fields[7] as u32) << 16) | fields[8] as u32) as f64;
        let namesize = fields[9] as usize;
        let filesize = (((fields[10] as u32) << 16) | fields[11] as u32) as u64;

        let mut name_buf = vec![0u8; namesize];
        file.read_exact(&mut name_buf)?;
        while name_buf.last() == Some(&0) {
            name_buf.pop();
        }
        let name = String::from_utf8_lossy(&name_buf).into_owned();
        // Align to even after name
        if file.stream_position()? % 2 == 1 {
            file.seek(SeekFrom::Current(1))?;
        }
        let data_offset = file.stream_position()?;

        if name == "TRAILER!!!" {
            break;
        }

        insert_entry(
            index,
            generated,
            &name,
            mode,
            mtime,
            filesize,
            header_offset,
            data_offset,
            uid,
            gid,
            file,
            2,
        )?;
    }
    Ok(())
}

fn insert_entry(
    index: &SqliteIndex,
    generated: &mut std::collections::BTreeSet<String>,
    name: &str,
    mode: u32,
    mtime: f64,
    filesize: u64,
    header_offset: u64,
    data_offset: u64,
    uid: u32,
    gid: u32,
    file: &mut File,
    data_align: u64,
) -> Result<()> {
    let is_dir = mode & libc::S_IFMT == libc::S_IFDIR;
    let is_lnk = mode & libc::S_IFMT == libc::S_IFLNK;
    let mut linkname = String::new();
    let mut size = filesize;

    if is_lnk && filesize > 0 && filesize < 4096 {
        let mut buf = vec![0u8; filesize as usize];
        file.read_exact(&mut buf)?;
        linkname = String::from_utf8_lossy(&buf).into_owned();
        size = 0;
        let pad = if data_align > 1 {
            (data_align - (filesize % data_align)) % data_align
        } else {
            0
        };
        if pad > 0 {
            file.seek(SeekFrom::Current(pad as i64))?;
        }
    } else {
        let pad = if data_align > 1 {
            (data_align - (filesize % data_align)) % data_align
        } else {
            0
        };
        file.seek(SeekFrom::Current((filesize + pad) as i64))?;
        if is_dir {
            size = 0;
        }
    }

    if name.is_empty() || name == "." {
        return Ok(());
    }

    let full = normpath(name);
    let (path, base) = match full.rsplit_once('/') {
        Some(("", n)) => (String::new(), n.to_string()),
        Some((p, n)) => (p.to_string(), n.to_string()),
        None => (String::new(), full.clone()),
    };
    ensure_parents(index, &path, generated, mtime)?;

    let ifmt = if is_dir {
        libc::S_IFDIR
    } else if is_lnk {
        libc::S_IFLNK
    } else {
        libc::S_IFREG
    };
    let fmode = (mode & 0o7777) | ifmt as u32;

    index.insert_file(
        &path,
        &base,
        header_offset as i64,
        data_offset as i64,
        size as i64,
        mtime,
        fmode as i64,
        0,
        &linkname,
        uid as i64,
        gid as i64,
        false,
        false,
        false,
        0,
    )?;
    Ok(())
}

fn userdata(fi: &FileInfo) -> Option<&SQLiteIndexedTarUserData> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Tar(t) => Some(t),
        _ => None,
    })
}

/// Detect any supported CPIO variant (newc/crc/odc/binary) by magic or extension.
pub fn looks_like_cpio(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        let mut magic = [0u8; 6];
        if let Ok(n) = f.read(&mut magic) {
            if n >= 6
                && (&magic == NEWC_MAGIC
                    || &magic == CRC_MAGIC
                    || &magic == ODC_MAGIC)
            {
                return true;
            }
            if n >= 2 && (&magic[..2] == BIN_MAGIC_LE || &magic[..2] == BIN_MAGIC_BE) {
                return true;
            }
        }
    }
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("cpio"))
}

/// Backward-compatible alias.
pub fn looks_like_cpio_newc(path: &Path) -> bool {
    looks_like_cpio(path)
}

pub fn default_index_path(archive: &Path) -> PathBuf {
    let mut s = archive.as_os_str().to_os_string();
    s.push(".index.sqlite");
    PathBuf::from(s)
}

fn hex_u32(bytes: &[u8]) -> Result<u32> {
    let s = std::str::from_utf8(bytes).map_err(|e| CpioError::Msg(e.to_string()))?;
    u32::from_str_radix(s, 16).map_err(|e| CpioError::Msg(e.to_string()))
}

fn oct_u32(s: &str) -> Result<u32> {
    u32::from_str_radix(s.trim(), 8).map_err(|e| CpioError::Msg(e.to_string()))
}

fn oct_u64(s: &str) -> Result<u64> {
    u64::from_str_radix(s.trim(), 8).map_err(|e| CpioError::Msg(e.to_string()))
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
        let parent = if i == 0 {
            String::new()
        } else {
            cur.clone()
        };
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

    fn py_root() -> PathBuf {
        PathBuf::from(
            std::env::var("RATARMOUNT_PY_ROOT")
                .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into()),
        )
    }

    fn open_and_read_bar(path: &Path) {
        if !path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("c.index.sqlite");
        let m = CpioMountSource::open(path, Some(&idx), &OpenOptions::default(), "0.1.0", true)
            .unwrap();
        let fi = m.lookup("/bar", 0).expect("bar");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"foo\n");
    }

    #[test]
    fn open_newc_cpio() {
        open_and_read_bar(&py_root().join("tests/single-file.newc.cpio"));
    }

    #[test]
    fn open_odc_cpio() {
        open_and_read_bar(&py_root().join("tests/single-file.odc.cpio"));
    }

    #[test]
    fn open_bin_cpio() {
        open_and_read_bar(&py_root().join("tests/single-file.bin.cpio"));
    }

    #[test]
    fn looks_like_detects_variants() {
        let root = py_root();
        for name in [
            "tests/single-file.newc.cpio",
            "tests/single-file.odc.cpio",
            "tests/single-file.bin.cpio",
            "tests/single-file.crc.cpio",
        ] {
            let p = root.join(name);
            if p.exists() {
                assert!(looks_like_cpio(&p), "{name}");
            }
        }
    }
}
