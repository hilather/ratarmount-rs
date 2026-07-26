//! XAR archive MountSource with TOC heap offsets (`backendName=XARMountSource`).

use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Instant;

use flate2::read::{GzDecoder, ZlibDecoder};
use quick_xml::events::Event;
use quick_xml::Reader;
use ratarmount_compress::StenciledFile;
use ratarmount_core::{
    normpath, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions,
    SQLiteIndexedTarUserData, UserData,
};
use ratarmount_index::{IndexError, SqliteIndex};
use thiserror::Error;

pub const BACKEND_NAME: &str = "XARMountSource";

#[derive(Debug, Error)]
pub enum XarError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, XarError>;

pub struct XarMountSource {
    archive_path: PathBuf,
    index: SqliteIndex,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl XarMountSource {
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
                let meta_ok = std::fs::metadata(ip).map(|m| m.len() > 0).unwrap_or(false);
                if meta_ok {
                    match Self::open_existing(&archive_path, ip, options) {
                        Ok(s) => return Ok(s),
                        Err(e) => eprintln!("info: could not load xar index ({e}); rebuilding"),
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

    fn open_existing(
        archive_path: &Path,
        index_path: &Path,
        options: &OpenOptions,
    ) -> Result<Self> {
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
        let mut header = [0u8; 28];
        file.read_exact(&mut header)?;
        if &header[..4] != b"xar!" {
            return Err(XarError::Msg("Not a XAR archive".into()));
        }
        let header_size = u16::from_be_bytes([header[4], header[5]]) as u64;
        let toc_comp_len = u64::from_be_bytes(header[8..16].try_into().unwrap());
        let header_size = if header_size < 28 { 28 } else { header_size };

        file.seek(SeekFrom::Start(header_size))?;
        let mut toc_compressed = vec![0u8; toc_comp_len as usize];
        file.read_exact(&mut toc_compressed)?;
        let mut decoder = ZlibDecoder::new(&toc_compressed[..]);
        let mut toc_xml = Vec::new();
        decoder
            .read_to_end(&mut toc_xml)
            .map_err(|e| XarError::Msg(format!("Failed to decompress XAR TOC: {e}")))?;

        let heap_offset = header_size + toc_comp_len;
        let rows = parse_toc_xml(&toc_xml, heap_offset)?;
        if rows.is_empty() {
            return Err(XarError::Msg("XAR archive contains no files".into()));
        }

        let index = SqliteIndex::create_writable(index_path)?;
        index.begin_write()?;
        let mut generated = std::collections::BTreeSet::new();
        for row in rows {
            ensure_parents(&index, &row.path, &mut generated, row.mtime)?;
            index.insert_file(
                &row.path,
                &row.name,
                row.header_offset,
                row.data_offset,
                row.size,
                row.mtime,
                row.mode,
                0,
                &row.linkname,
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
            options: options.clone(),
        })
    }
}

struct XarRow {
    path: String,
    name: String,
    header_offset: i64,
    data_offset: i64,
    size: i64,
    mtime: f64,
    mode: i64,
    linkname: String,
}

fn parse_toc_xml(toc_xml: &[u8], heap_offset: u64) -> Result<Vec<XarRow>> {
    let mut reader = Reader::from_reader(toc_xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();
    let mut rows = Vec::new();

    #[derive(Default)]
    struct St {
        name: String,
        file_type: String,
        length: u64,
        offset: u64,
        size: u64,
        encoding: String,
        in_data: bool,
        cur_field: Option<String>,
        pushed_dir: bool,
    }

    let mut stack: Vec<St> = Vec::new();
    let mut dir_stack: Vec<String> = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(e)) => {
                let local = local_name(e.name().as_ref());
                if local == "file" {
                    stack.push(St {
                        file_type: "file".into(),
                        encoding: "application/octet-stream".into(),
                        ..St::default()
                    });
                } else if let Some(st) = stack.last_mut() {
                    if local == "data" {
                        st.in_data = true;
                    } else if st.in_data {
                        if matches!(local.as_str(), "length" | "offset" | "size") {
                            st.cur_field = Some(local);
                        } else if local == "encoding" {
                            for a in e.attributes().flatten() {
                                let key = local_name(a.key.as_ref());
                                if key == "style" || key == "name" {
                                    st.encoding = String::from_utf8_lossy(&a.value).into_owned();
                                }
                            }
                        }
                    } else if matches!(local.as_str(), "name" | "type") {
                        st.cur_field = Some(local);
                    }
                }
            }
            Ok(Event::Empty(e)) => {
                if local_name(e.name().as_ref()) == "encoding" {
                    if let Some(st) = stack.last_mut() {
                        for a in e.attributes().flatten() {
                            let key = local_name(a.key.as_ref());
                            if key == "style" || key == "name" {
                                st.encoding = String::from_utf8_lossy(&a.value).into_owned();
                            }
                        }
                    }
                }
            }
            Ok(Event::Text(t)) => {
                if let Some(st) = stack.last_mut() {
                    if let Some(field) = st.cur_field.take() {
                        let text = t.unescape().unwrap_or_default().into_owned();
                        match field.as_str() {
                            "name" if !st.in_data => {
                                st.name = text;
                                if st.file_type == "directory"
                                    && !st.name.is_empty()
                                    && !st.pushed_dir
                                {
                                    dir_stack.push(st.name.clone());
                                    st.pushed_dir = true;
                                }
                            }
                            "type" if !st.in_data => {
                                st.file_type = text;
                                if st.file_type == "directory"
                                    && !st.name.is_empty()
                                    && !st.pushed_dir
                                {
                                    dir_stack.push(st.name.clone());
                                    st.pushed_dir = true;
                                }
                            }
                            "length" => st.length = text.trim().parse().unwrap_or(0),
                            "offset" => st.offset = text.trim().parse().unwrap_or(0),
                            "size" => st.size = text.trim().parse().unwrap_or(0),
                            _ => {}
                        }
                    }
                }
            }
            Ok(Event::End(e)) => {
                let local = local_name(e.name().as_ref());
                if local == "data" {
                    if let Some(st) = stack.last_mut() {
                        st.in_data = false;
                    }
                } else if local == "file" {
                    if let Some(st) = stack.pop() {
                        let name = if st.name.is_empty() {
                            "unnamed".into()
                        } else {
                            st.name
                        };
                        let parent_parts: Vec<String> =
                            if st.file_type == "directory" && st.pushed_dir {
                                dir_stack[..dir_stack.len().saturating_sub(1)].to_vec()
                            } else {
                                dir_stack.clone()
                            };
                        let full = if parent_parts.is_empty() {
                            name.clone()
                        } else {
                            format!("{}/{}", parent_parts.join("/"), name)
                        };
                        if st.file_type == "directory" {
                            let nfull = normpath(&full);
                            let (path, base) = split_name(&nfull);
                            rows.push(XarRow {
                                path,
                                name: base,
                                header_offset: 0,
                                data_offset: 0,
                                size: 0,
                                mtime: 0.0,
                                mode: (libc::S_IFDIR | 0o755) as i64,
                                linkname: String::new(),
                            });
                            if st.pushed_dir {
                                dir_stack.pop();
                            }
                        } else {
                            let data_offset = heap_offset + st.offset;
                            let size = if st.size != 0 { st.size } else { st.length };
                            let nfull = normpath(&full);
                            let (path, base) = split_name(&nfull);
                            let linkname = format!("xar-enc:{}|packed:{}", st.encoding, st.length);
                            rows.push(XarRow {
                                path,
                                name: base,
                                header_offset: data_offset as i64,
                                data_offset: data_offset as i64,
                                size: size as i64,
                                mtime: 0.0,
                                mode: (libc::S_IFREG | 0o644) as i64,
                                linkname,
                            });
                        }
                    }
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => return Err(XarError::Msg(format!("Invalid XAR TOC XML: {e}"))),
            _ => {}
        }
        buf.clear();
    }
    Ok(rows)
}

fn local_name(qname: &[u8]) -> String {
    let s = String::from_utf8_lossy(qname);
    s.rsplit('}').next().unwrap_or(&s).to_string()
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

impl MountSource for XarMountSource {
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
        let ud = userdata(file_info)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing xar userdata"))?;
        let link = file_info.linkname.as_str();
        if !link.starts_with("xar-enc:") {
            let file = File::open(&self.archive_path)?;
            return Ok(Box::new(StenciledFile::new(
                file,
                vec![(ud.offset, file_info.size)],
            )));
        }

        let rest = &link["xar-enc:".len()..];
        let (style, packed_meta) = rest.split_once("|packed:").unwrap_or((rest, ""));
        let packed_size = packed_meta.parse::<u64>().unwrap_or(file_info.size);

        if style == "application/octet-stream" || style.is_empty() {
            let file = File::open(&self.archive_path)?;
            return Ok(Box::new(StenciledFile::new(
                file,
                vec![(ud.offset, packed_size)],
            )));
        }

        let mut file = File::open(&self.archive_path)?;
        file.seek(SeekFrom::Start(ud.offset))?;
        let mut packed = vec![0u8; packed_size as usize];
        file.read_exact(&mut packed)?;

        let data = if style == "application/x-bzip2" {
            let mut d = bzip2::read::BzDecoder::new(&packed[..]);
            let mut out = Vec::new();
            d.read_to_end(&mut out)?;
            out
        } else if style == "application/x-xz" || style == "application/xz" {
            let mut d = xz2::read::XzDecoder::new(&packed[..]);
            let mut out = Vec::new();
            d.read_to_end(&mut out)?;
            out
        } else if style == "application/x-gzip"
            || style == "application/gzip"
            || style.contains("gzip")
        {
            decompress_zlib_or_gzip(&packed)?
        } else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("XAR member encoding not supported for random access: {style}"),
            ));
        };

        Ok(Box::new(Cursor::new(data)))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

fn decompress_zlib_or_gzip(packed: &[u8]) -> io::Result<Vec<u8>> {
    {
        let mut d = ZlibDecoder::new(packed);
        let mut out = Vec::new();
        if d.read_to_end(&mut out).is_ok() && !out.is_empty() {
            return Ok(out);
        }
    }
    {
        let mut d = GzDecoder::new(packed);
        let mut out = Vec::new();
        if d.read_to_end(&mut out).is_ok() {
            return Ok(out);
        }
    }
    let mut d = flate2::Decompress::new(false);
    let mut out = vec![0u8; packed.len() * 4 + 64];
    loop {
        let before_in = d.total_in() as usize;
        let before_out = d.total_out() as usize;
        match d.decompress(
            &packed[before_in..],
            &mut out[before_out..],
            flate2::FlushDecompress::Finish,
        ) {
            Ok(flate2::Status::Ok) => {
                if d.total_out() as usize == out.len() {
                    out.resize(out.len() * 2, 0);
                }
            }
            Ok(flate2::Status::StreamEnd) => {
                out.truncate(d.total_out() as usize);
                return Ok(out);
            }
            Ok(flate2::Status::BufError) => out.resize(out.len() * 2, 0),
            Err(e) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("gzip/zlib decompress failed: {e}"),
                ));
            }
        }
    }
}

fn userdata(fi: &FileInfo) -> Option<&SQLiteIndexedTarUserData> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Tar(t) => Some(t),
        _ => None,
    })
}

pub fn looks_like_xar(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        let mut magic = [0u8; 4];
        if f.read(&mut magic).ok() == Some(4) && &magic == b"xar!" {
            return true;
        }
    }
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("xar"))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_single_file_xar() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let path = PathBuf::from(root).join("tests/single-file.xar");
        if !path.exists() {
            return;
        }
        assert!(looks_like_xar(&path));
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("x.index.sqlite");
        let m = XarMountSource::open(&path, Some(&idx), &OpenOptions::default(), "0.1.0", true)
            .unwrap();
        let fi = m.lookup("/bar", 0).expect("bar");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"foo\n");
    }
}
