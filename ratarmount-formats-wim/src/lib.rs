//! Read-only WIM mount source (first image; uncompressed + XPRESS).
//!
//! Detection is magic `MSWIM\0\0\0` at byte 0 plus header size 208. Nested
//! members open without `/tmp` via [`WimMountSource::open_from_reader`].
//!
//! # Residuals
//!
//! LZX / LZMS (typical `install.wim` / ESD), WIMBoot, solid / delta / split
//! WIMs, images after the first, and ADS. Encrypted members list but `open`
//! returns [`io::ErrorKind::PermissionDenied`]. This crate does not edit
//! session `factory.rs`.

mod parse;
mod xpress;

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use ratarmount_core::{CheapDirent, FileInfo, ListModeResult, ListResult, MountSource, UserData};
use thiserror::Error;

use parse::{header_looks_like_wim, parse_wim, read_blob, CatalogEntry, ParsedWim};

pub const BACKEND_NAME: &str = "WimMountSource";

#[derive(Debug, Error)]
pub enum WimError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, WimError>;

trait SeekRead: Read + Seek + Send {}
impl<T: Read + Seek + Send> SeekRead for T {}

pub struct WimMountSource {
    #[allow(dead_code)]
    archive_path: PathBuf,
    shared: Arc<Mutex<Box<dyn SeekRead>>>,
    parsed: ParsedWim,
}

impl WimMountSource {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if !looks_like_wim(path) {
            return Err(WimError::Msg(format!(
                "{} is not a WIM image (MSWIM magic)",
                path.display()
            )));
        }
        let file = File::open(path)?;
        Self::from_reader(file, path.to_path_buf())
    }

    /// Open a WIM from any `Read + Seek` source without `/tmp`.
    ///
    /// The reader is retained under a mutex; each blob `open` re-seeks that
    /// shared body. The full image is **not** copied into a second buffer.
    pub fn open_from_reader<R>(reader: R, archive_label: impl AsRef<Path>) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        let archive_path = archive_label.as_ref().to_path_buf();
        let mut reader = reader;
        reader.seek(SeekFrom::Start(0))?;
        if !looks_like_wim_reader(&mut reader) {
            return Err(WimError::Msg(format!(
                "{} is not a WIM image (MSWIM magic)",
                archive_path.display()
            )));
        }
        reader.seek(SeekFrom::Start(0))?;
        Self::from_reader(reader, archive_path)
    }

    fn from_reader<R>(mut reader: R, archive_path: PathBuf) -> Result<Self>
    where
        R: Read + Seek + Send + 'static,
    {
        let parsed = parse_wim(&mut reader)?;
        let shared: Arc<Mutex<Box<dyn SeekRead>>> =
            Arc::new(Mutex::new(Box::new(reader) as Box<dyn SeekRead>));
        Ok(Self {
            archive_path,
            shared,
            parsed,
        })
    }

    fn with_reader<T>(&self, f: impl FnOnce(&mut dyn SeekRead) -> Result<T>) -> Result<T> {
        let mut guard = self
            .shared
            .lock()
            .map_err(|_| WimError::Msg("shared WIM reader poisoned".into()))?;
        f(&mut **guard)
    }

    fn entry(&self, path: &str) -> Option<&CatalogEntry> {
        self.parsed.entries.get(&abs_path(path))
    }

    fn list_dir(&self, path: &str) -> Option<BTreeMap<String, FileInfo>> {
        let key = abs_path(path);
        let ent = self.parsed.entries.get(&key)?;
        if !ent.is_dir {
            return None;
        }
        let names = self.parsed.children.get(&key)?;
        let mut map = BTreeMap::new();
        for name in names {
            let child = child_path(&key, name);
            if let Some(c) = self.parsed.entries.get(&child) {
                map.insert(name.clone(), entry_to_file_info(&child, c));
            }
        }
        Some(map)
    }

    fn list_dirents_dir(&self, path: &str) -> Option<Vec<CheapDirent>> {
        let key = abs_path(path);
        let ent = self.parsed.entries.get(&key)?;
        if !ent.is_dir {
            return None;
        }
        let names = self.parsed.children.get(&key)?;
        let mut out = Vec::new();
        for name in names {
            let child = child_path(&key, name);
            if let Some(c) = self.parsed.entries.get(&child) {
                let (mode, size) = entry_mode_size(c.is_dir, c.size);
                out.push(CheapDirent {
                    name: name.clone(),
                    mode,
                    size,
                });
            }
        }
        Some(out)
    }

    fn read_file(&self, path: &str) -> io::Result<Vec<u8>> {
        let key = abs_path(path);
        let ent = self
            .parsed
            .entries
            .get(&key)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "not found"))?;
        if ent.is_dir {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "is a directory",
            ));
        }
        if ent.encrypted {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "WIM encrypted member (EFS residual)",
            ));
        }
        self.with_reader(|r| read_blob(r, &self.parsed, &ent.hash))
            .map_err(map_read_error)
    }
}

impl MountSource for WimMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        let map = self.list_dir(path)?;
        Some(ListResult::Infos(map))
    }

    fn list_mode(&self, path: &str) -> Option<ListModeResult> {
        let map = self.list_dir(path)?;
        Some(ListModeResult::Modes(
            map.into_iter().map(|(k, v)| (k, v.mode)).collect(),
        ))
    }

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        self.list_dirents_dir(path)
    }

    fn lookup(&self, path: &str, _file_version: i32) -> Option<FileInfo> {
        let key = abs_path(path);
        let ent = self.entry(&key)?;
        Some(entry_to_file_info(&key, ent))
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
        let path = path_from_userdata(file_info).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "missing WIM path userdata")
        })?;
        let data = self.read_file(&path)?;
        Ok(Box::new(Cursor::new(data)))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

fn wim_path_userdata(path: &str) -> UserData {
    UserData::Other(format!("wim:{path}"))
}

fn path_from_userdata(fi: &FileInfo) -> Option<String> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Other(s) if s.starts_with("wim:") => Some(s[4..].to_string()),
        _ => None,
    })
}

fn abs_path(path: &str) -> String {
    let t = path.trim();
    if t.is_empty() || t == "/" {
        "/".into()
    } else if t.starts_with('/') {
        t.trim_end_matches('/').to_string()
    } else {
        format!("/{t}")
    }
}

fn child_path(parent: &str, name: &str) -> String {
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{}/{name}", parent.trim_end_matches('/'))
    }
}

fn entry_mode_size(is_dir: bool, size: u64) -> (u32, u64) {
    if is_dir {
        (ratarmount_core::S_IFDIR | 0o777, 0)
    } else {
        (ratarmount_core::S_IFREG | 0o777, size)
    }
}

fn entry_to_file_info(name_path: &str, e: &CatalogEntry) -> FileInfo {
    let (mode, size) = entry_mode_size(e.is_dir, e.size);
    FileInfo {
        size,
        mtime: e.mtime,
        mode,
        linkname: String::new(),
        uid: ratarmount_core::effective_uid(),
        gid: ratarmount_core::effective_gid(),
        userdata: vec![wim_path_userdata(name_path)],
    }
}

fn map_read_error(e: WimError) -> io::Error {
    match e {
        WimError::Io(io) => io,
        WimError::Msg(m) => {
            let kind = if m.contains("LZX") || m.contains("LZMS") || m.contains("residual") {
                io::ErrorKind::Unsupported
            } else if m.contains("encrypted") {
                io::ErrorKind::PermissionDenied
            } else if m.contains("not found") {
                io::ErrorKind::NotFound
            } else {
                io::ErrorKind::Other
            };
            io::Error::new(kind, m)
        }
    }
}

fn wim_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("wim"))
}

/// Detect WIM via `MSWIM` magic, or `*.wim` extension fallback.
pub fn looks_like_wim(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        if looks_like_wim_reader(&mut f) {
            return true;
        }
    }
    wim_extension(path)
}

/// Magic probe for nested streams (does not use filename).
///
/// Leaves the reader at an unspecified position; callers should seek to 0 after.
pub fn looks_like_wim_reader<R: Read + Seek>(reader: &mut R) -> bool {
    let mut buf = [0u8; 12];
    if reader.seek(SeekFrom::Start(0)).is_err() {
        return false;
    }
    match reader.read(&mut buf) {
        Ok(n) if n >= 12 => header_looks_like_wim(&buf),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::ResHdr;
    use crate::parse::{
        filetime_to_unix, sha1_bytes, write_reshdr, ATTR_FLAG_ARCHIVE, ATTR_FLAG_DIRECTORY,
        FILETIME_UNIX_DELTA, HDR_COMPRESSION, HDR_COMPRESS_LZX, HDR_COMPRESS_XPRESS,
        HEADER_DISK_SIZE, MAGIC, RES_FLAG_COMPRESSED, RES_FLAG_METADATA, WIM_VERSION_DEFAULT,
    };
    use std::io::Write;
    use std::process::Command;

    const DENTRY_BASE: usize = 102;
    const BLOB_ENTRY: usize = 50;

    fn align8(n: usize) -> usize {
        (n + 7) & !7
    }

    fn dentry_len(name: &str) -> usize {
        let n = name.encode_utf16().count() * 2;
        let mut len = DENTRY_BASE;
        if n > 0 {
            len += n + 2;
        }
        align8(len)
    }

    fn write_dentry(name: &str, attr: u32, subdir: u64, hash: [u8; 20], ft: u64) -> Vec<u8> {
        let utf16: Vec<u16> = name.encode_utf16().collect();
        let name_bytes: Vec<u8> = utf16.iter().flat_map(|c| c.to_le_bytes()).collect();
        let len = dentry_len(name);
        let mut d = vec![0u8; len];
        d[0..8].copy_from_slice(&(len as u64).to_le_bytes());
        d[8..12].copy_from_slice(&attr.to_le_bytes());
        d[12..16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        d[16..24].copy_from_slice(&subdir.to_le_bytes());
        d[40..48].copy_from_slice(&ft.to_le_bytes());
        d[48..56].copy_from_slice(&ft.to_le_bytes());
        d[56..64].copy_from_slice(&ft.to_le_bytes());
        d[64..84].copy_from_slice(&hash);
        d[100..102].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        if !name_bytes.is_empty() {
            d[102..102 + name_bytes.len()].copy_from_slice(&name_bytes);
        }
        d
    }

    fn unix_to_filetime(unix: u64) -> u64 {
        unix.saturating_mul(10_000_000) + FILETIME_UNIX_DELTA
    }

    struct BlobOut {
        hash: [u8; 20],
        data: Vec<u8>,
        compressed: bool,
        packed: Vec<u8>,
    }

    fn blob_store(data: &[u8], compress: bool) -> BlobOut {
        let hash = sha1_bytes(data);
        if compress {
            let packed = crate::xpress::compress(data);
            assert!(
                packed.len() < data.len(),
                "XPRESS fixture payload did not shrink ({} >= {})",
                packed.len(),
                data.len()
            );
            return BlobOut {
                hash,
                data: data.to_vec(),
                compressed: true,
                packed,
            };
        }
        BlobOut {
            hash,
            data: data.to_vec(),
            compressed: false,
            packed: data.to_vec(),
        }
    }

    fn write_blob_entry(part: u16, res: &ResHdr, hash: [u8; 20]) -> [u8; BLOB_ENTRY] {
        let mut e = [0u8; BLOB_ENTRY];
        write_reshdr(&mut e[0..24], res);
        e[24..26].copy_from_slice(&part.to_le_bytes());
        e[26..30].copy_from_slice(&1u32.to_le_bytes());
        e[30..50].copy_from_slice(&hash);
        e
    }

    /// Uncompressed first-image WIM: `/hello.txt`, `/foo/ufo`, `/empty`.
    fn synthetic_uncompressed_wim() -> Vec<u8> {
        build_wim(
            &[
                ("hello.txt", b"hello-wim\n".as_slice(), false),
                ("foo/ufo", b"iriya\n".as_slice(), false),
                ("empty", b"".as_slice(), false),
            ],
            false,
        )
    }

    /// First-image WIM whose `hello.txt` blob is XPRESS-compressed.
    fn synthetic_xpress_hello_wim() -> Vec<u8> {
        let mut hello = b"hello-wim-".to_vec();
        hello.extend(vec![b'x'; 2000]);
        hello.push(b'\n');
        build_wim(
            &[
                ("hello.txt", hello.as_slice(), true),
                ("foo/ufo", b"iriya\n".as_slice(), false),
            ],
            true,
        )
    }

    fn build_wim(files: &[(&str, &[u8], bool)], header_xpress: bool) -> Vec<u8> {
        let ft = unix_to_filetime(1_592_222_400);
        let hello_name = files
            .iter()
            .find(|(p, _, _)| *p == "hello.txt")
            .map(|(_, b, c)| blob_store(b, *c));
        let ufo = files
            .iter()
            .find(|(p, _, _)| p.ends_with("ufo"))
            .map(|(_, b, c)| blob_store(b, *c));
        let empty = files.iter().any(|(p, b, _)| *p == "empty" && b.is_empty());

        let mut blobs_out: Vec<BlobOut> = Vec::new();
        if let Some(b) = hello_name {
            blobs_out.push(b);
        }
        if let Some(b) = ufo {
            blobs_out.push(b);
        }

        let hello_hash = blobs_out
            .iter()
            .find(|b| b.data.starts_with(b"hello-wim"))
            .map(|b| b.hash)
            .unwrap_or([0u8; 20]);
        let ufo_hash = blobs_out
            .iter()
            .find(|b| b.data == b"iriya\n")
            .map(|b| b.hash)
            .unwrap_or([0u8; 20]);

        let has_foo = files.iter().any(|(p, _, _)| p.starts_with("foo/"));
        let has_hello = files.iter().any(|(p, _, _)| *p == "hello.txt");

        // Metadata layout: security(8) + root + term + root children + foo children.
        let sec = 8usize;
        let root_len = dentry_len("");
        let after_root = sec + root_len + 8;
        let hello_len = if has_hello {
            dentry_len("hello.txt")
        } else {
            0
        };
        let foo_len = if has_foo { dentry_len("foo") } else { 0 };
        let empty_len = if empty { dentry_len("empty") } else { 0 };
        let root_kids = hello_len + foo_len + empty_len + 8;
        let foo_off = after_root + root_kids;
        let ufo_len = if has_foo { dentry_len("ufo") } else { 0 };
        let foo_kids = if has_foo { ufo_len + 8 } else { 0 };
        let meta_len = foo_off + foo_kids;

        let mut meta = vec![0u8; meta_len];
        meta[0..4].copy_from_slice(&(8u32).to_le_bytes());
        let root = write_dentry("", ATTR_FLAG_DIRECTORY, after_root as u64, [0u8; 20], ft);
        meta[sec..sec + root_len].copy_from_slice(&root);
        let mut p = after_root;
        if has_hello {
            let d = write_dentry("hello.txt", ATTR_FLAG_ARCHIVE, 0, hello_hash, ft);
            meta[p..p + hello_len].copy_from_slice(&d);
            p += hello_len;
        }
        if has_foo {
            let d = write_dentry("foo", ATTR_FLAG_DIRECTORY, foo_off as u64, [0u8; 20], ft);
            meta[p..p + foo_len].copy_from_slice(&d);
            p += foo_len;
        }
        if empty {
            let d = write_dentry("empty", ATTR_FLAG_ARCHIVE, 0, [0u8; 20], ft);
            meta[p..p + empty_len].copy_from_slice(&d);
            p += empty_len;
        }
        p += 8; // root terminator already zero
        debug_assert_eq!(p, foo_off);
        if has_foo {
            let d = write_dentry("ufo", ATTR_FLAG_ARCHIVE, 0, ufo_hash, ft);
            meta[foo_off..foo_off + ufo_len].copy_from_slice(&d);
        }

        let meta_hash = sha1_bytes(&meta);

        // Layout: header | file blobs | metadata | blob table | xml
        let mut cursor = HEADER_DISK_SIZE as u64;
        let mut file_res = Vec::new();
        for b in &blobs_out {
            let flags = if b.compressed { RES_FLAG_COMPRESSED } else { 0 };
            let packed = if b.compressed { &b.packed } else { &b.data };
            file_res.push((
                ResHdr {
                    size_in_wim: packed.len() as u64,
                    flags,
                    offset: cursor,
                    uncompressed_size: b.data.len() as u64,
                },
                b.hash,
                packed.clone(),
            ));
            cursor += packed.len() as u64;
        }
        let meta_res = ResHdr {
            size_in_wim: meta.len() as u64,
            flags: RES_FLAG_METADATA,
            offset: cursor,
            uncompressed_size: meta.len() as u64,
        };
        cursor += meta.len() as u64;

        let n_entries = file_res.len() + 1;
        let table_size = n_entries * BLOB_ENTRY;
        let table_res = ResHdr {
            size_in_wim: table_size as u64,
            flags: 0,
            offset: cursor,
            uncompressed_size: table_size as u64,
        };
        cursor += table_size as u64;
        let xml = b"<WIM><IMAGE INDEX=\"1\"><NAME>1</NAME></IMAGE></WIM>".to_vec();
        let xml_res = ResHdr {
            size_in_wim: xml.len() as u64,
            flags: 0,
            offset: cursor,
            uncompressed_size: xml.len() as u64,
        };

        let mut table = Vec::with_capacity(table_size);
        for (res, hash, _) in &file_res {
            table.extend_from_slice(&write_blob_entry(1, res, *hash));
        }
        table.extend_from_slice(&write_blob_entry(1, &meta_res, meta_hash));

        let mut hdr = vec![0u8; HEADER_DISK_SIZE];
        hdr[0..8].copy_from_slice(MAGIC);
        hdr[8..12].copy_from_slice(&(HEADER_DISK_SIZE as u32).to_le_bytes());
        hdr[12..16].copy_from_slice(&WIM_VERSION_DEFAULT.to_le_bytes());
        let mut flags = 0u32;
        if header_xpress {
            flags |= HDR_COMPRESSION | HDR_COMPRESS_XPRESS;
            hdr[20..24].copy_from_slice(&32768u32.to_le_bytes());
        }
        hdr[16..20].copy_from_slice(&flags.to_le_bytes());
        hdr[40..42].copy_from_slice(&1u16.to_le_bytes());
        hdr[42..44].copy_from_slice(&1u16.to_le_bytes());
        hdr[44..48].copy_from_slice(&1u32.to_le_bytes());
        write_reshdr(&mut hdr[48..72], &table_res);
        write_reshdr(&mut hdr[72..96], &xml_res);

        let mut out = hdr;
        for (_, _, packed) in &file_res {
            out.extend_from_slice(packed);
        }
        out.extend_from_slice(&meta);
        out.extend_from_slice(&table);
        out.extend_from_slice(&xml);
        out
    }

    fn synthetic_lzx_header() -> Vec<u8> {
        let mut h = vec![0u8; HEADER_DISK_SIZE];
        h[0..8].copy_from_slice(MAGIC);
        h[8..12].copy_from_slice(&(HEADER_DISK_SIZE as u32).to_le_bytes());
        h[12..16].copy_from_slice(&WIM_VERSION_DEFAULT.to_le_bytes());
        let flags = HDR_COMPRESSION | HDR_COMPRESS_LZX;
        h[16..20].copy_from_slice(&flags.to_le_bytes());
        h[20..24].copy_from_slice(&32768u32.to_le_bytes());
        h[40..42].copy_from_slice(&1u16.to_le_bytes());
        h[42..44].copy_from_slice(&1u16.to_le_bytes());
        h[44..48].copy_from_slice(&1u32.to_le_bytes());
        h
    }

    fn which_wimlib_imagex() -> Option<PathBuf> {
        if let Some(path) = std::env::var_os("PATH") {
            for dir in std::env::split_paths(&path) {
                let p = dir.join("wimlib-imagex");
                if p.is_file() {
                    return Some(p);
                }
            }
        }
        None
    }

    #[test]
    fn looks_like_wim_magic() {
        let bytes = synthetic_uncompressed_wim();
        assert!(looks_like_wim_reader(&mut Cursor::new(&bytes)));
        assert!(header_looks_like_wim(&bytes[..12]));
        let mut short = bytes[..8].to_vec();
        assert!(!looks_like_wim_reader(&mut Cursor::new(short.split_off(0))));
        assert!(!looks_like_wim_reader(&mut Cursor::new(b"not-a-wim!!!!")));
    }

    #[test]
    fn looks_like_wim_false_on_fat_boot() {
        let mut boot = [0u8; 512];
        boot[3..11].copy_from_slice(b"MSDOS5.0");
        boot[510] = 0x55;
        boot[511] = 0xAA;
        assert!(!looks_like_wim_reader(&mut Cursor::new(boot)));
    }

    #[test]
    fn open_from_reader_rejects_bad_magic() {
        let err = WimMountSource::open_from_reader(Cursor::new(b"not-a-wim-image!!!!"), "bad")
            .err()
            .expect("expected open_from_reader failure");
        assert!(
            err.to_string().contains("not a WIM"),
            "unexpected error: {err}"
        );
    }

    /// Always-on uncompressed fixture (no wimlib-imagex).
    #[test]
    fn open_from_reader_list_and_read() {
        let bytes = synthetic_uncompressed_wim();
        assert!(looks_like_wim_reader(&mut Cursor::new(&bytes)));
        let m = WimMountSource::open_from_reader(Cursor::new(bytes), "nested.wim")
            .expect("open_from_reader");

        let fi = m.lookup("/hello.txt", 0).expect("hello.txt");
        assert_eq!(fi.size, 10);
        let mut s = String::new();
        m.open(&fi, 0).unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello-wim\n");

        let ufo = m.lookup("/foo/ufo", 0).expect("ufo");
        assert_eq!(ufo.size, 6);
        let mut s = String::new();
        m.open(&ufo, 0).unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "iriya\n");

        let empty = m.lookup("/empty", 0).expect("empty");
        assert_eq!(empty.size, 0);
        let mut data = Vec::new();
        m.open(&empty, 0).unwrap().read_to_end(&mut data).unwrap();
        assert!(data.is_empty());

        match m.list("/").expect("list /") {
            ListResult::Infos(map) => {
                assert!(map.contains_key("hello.txt"));
                assert!(map.contains_key("foo"));
                assert!(map.contains_key("empty"));
            }
            other => panic!("expected infos, got {other:?}"),
        }
        match m.list("/foo").expect("list /foo") {
            ListResult::Infos(map) => assert!(map.contains_key("ufo")),
            other => panic!("expected infos, got {other:?}"),
        }
        assert!(m.lookup("/", 0).is_some());
    }

    /// Regression: cheap readdirplus sizes.
    #[test]
    fn list_dirents_sizes_match_lookup_without_requiring_list() {
        let bytes = synthetic_uncompressed_wim();
        let src = WimMountSource::open_from_reader(Cursor::new(bytes), "dirents.wim")
            .expect("open_from_reader");
        let dents = src.list_dirents("/").expect("dirents");
        let d = dents
            .iter()
            .find(|e| e.name == "hello.txt")
            .expect("hello.txt dirent");
        let fi = src.lookup("/hello.txt", 0).expect("lookup hello.txt");
        assert_eq!(d.size, fi.size);
        assert_eq!(d.mode, fi.mode);
        assert_eq!(d.size, 10);
        assert_ne!(d.size, 0);
        let foo = dents.iter().find(|e| e.name == "foo").expect("foo dirent");
        assert_eq!(foo.size, 0);
        assert_eq!(foo.mode & ratarmount_core::S_IFMT, ratarmount_core::S_IFDIR);
    }

    #[test]
    fn open_from_reader_matches_path_open() {
        let bytes = synthetic_uncompressed_wim();
        let dir = tempfile::tempdir().unwrap();
        let img = dir.path().join("match.wim");
        std::fs::write(&img, &bytes).unwrap();

        let path_src = WimMountSource::open(&img).expect("path open");
        let reader_src = WimMountSource::open_from_reader(Cursor::new(bytes), "match.wim")
            .expect("open_from_reader");

        let path_fi = path_src.lookup("/foo/ufo", 0).expect("path ufo");
        let reader_fi = reader_src.lookup("/foo/ufo", 0).expect("reader ufo");
        assert_eq!(path_fi.size, reader_fi.size);
        assert_eq!(path_fi.mode, reader_fi.mode);

        let mut path_data = Vec::new();
        path_src
            .open(&path_fi, 0)
            .unwrap()
            .read_to_end(&mut path_data)
            .unwrap();
        let mut reader_data = Vec::new();
        reader_src
            .open(&reader_fi, 0)
            .unwrap()
            .read_to_end(&mut reader_data)
            .unwrap();
        assert_eq!(path_data, reader_data);
        assert_eq!(path_data, b"iriya\n");
    }

    #[test]
    fn open_from_reader_xpress_blob() {
        let bytes = synthetic_xpress_hello_wim();
        let m = WimMountSource::open_from_reader(Cursor::new(bytes), "xpress.wim")
            .expect("open xpress wim");
        let fi = m.lookup("/hello.txt", 0).expect("hello");
        let mut s = String::new();
        m.open(&fi, 0).unwrap().read_to_string(&mut s).unwrap();
        assert!(s.starts_with("hello-wim-"));
        assert!(s.ends_with('\n'));
        assert_eq!(s.len(), 10 + 2000 + 1);
        let ufo = m.lookup("/foo/ufo", 0).expect("ufo");
        let mut s = String::new();
        m.open(&ufo, 0).unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "iriya\n");
    }

    /// LZX is residual: magic still matches, open names the codec.
    #[test]
    fn open_from_reader_lzx_is_residual() {
        let bytes = synthetic_lzx_header();
        assert!(looks_like_wim_reader(&mut Cursor::new(&bytes)));
        let err = WimMountSource::open_from_reader(Cursor::new(bytes), "lzx.wim")
            .err()
            .expect("LZX must not open");
        let msg = err.to_string();
        assert!(
            msg.contains("LZX") && msg.contains("residual"),
            "unexpected error: {msg}"
        );
    }

    /// Regression: FILETIME 1601→1970 delta must be 100ns ticks.
    #[test]
    fn filetime_unix_epoch_is_zero() {
        assert_eq!(filetime_to_unix(0), 0.0);
        let ft = FILETIME_UNIX_DELTA;
        assert!((filetime_to_unix(ft) - 0.0).abs() < 1e-6);
        let unix = 1_592_222_400u64;
        let ft = unix * 10_000_000 + FILETIME_UNIX_DELTA;
        let got = filetime_to_unix(ft);
        assert!((got - unix as f64).abs() < 1.0, "got {got} expected {unix}");
        let bytes = synthetic_uncompressed_wim();
        let m = WimMountSource::open_from_reader(Cursor::new(bytes), "mtime.wim").unwrap();
        let fi = m.lookup("/hello.txt", 0).unwrap();
        assert!((fi.mtime - unix as f64).abs() < 1.0, "mtime {}", fi.mtime);
    }

    #[test]
    fn looks_like_wim_extension_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("disk.wim");
        File::create(&p).unwrap().write_all(&[0u8; 64]).unwrap();
        assert!(looks_like_wim(&p), "extension fallback");
        assert!(!looks_like_wim_reader(&mut File::open(&p).unwrap()));
    }

    #[test]
    fn wimlib_imagex_uncompressed_round_trip() {
        let Some(bin) = which_wimlib_imagex() else {
            eprintln!("skip: wimlib-imagex not available");
            return;
        };
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("src");
        std::fs::create_dir(&src).unwrap();
        std::fs::write(src.join("hello.txt"), b"hello-wim\n").unwrap();
        std::fs::create_dir(src.join("foo")).unwrap();
        std::fs::write(src.join("foo").join("ufo"), b"iriya\n").unwrap();
        let wim = dir.path().join("out.wim");
        let status = Command::new(&bin)
            .args(["capture", "--compress=none"])
            .arg(&src)
            .arg(&wim)
            .arg("image")
            .status();
        let status = match status {
            Ok(s) => s,
            Err(e) => {
                eprintln!("skip: wimlib-imagex failed to spawn ({e})");
                return;
            }
        };
        if !status.success() {
            eprintln!("skip: wimlib-imagex capture failed ({})", bin.display());
            return;
        }
        let m = WimMountSource::open(&wim).expect("open wimlib-imagex capture");
        let fi = m.lookup("/hello.txt", 0).expect("hello.txt from imagex");
        let mut s = String::new();
        m.open(&fi, 0).unwrap().read_to_string(&mut s).unwrap();
        assert_eq!(s, "hello-wim\n");
    }
}
