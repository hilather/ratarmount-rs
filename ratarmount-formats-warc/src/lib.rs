//! WARC MountSource with random access via record payload offsets (`backendName=WARCMountSource`).

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Instant;

use ratarmount_compress::StenciledFile;
use ratarmount_core::{
    normpath, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions,
    SQLiteIndexedTarUserData, UserData,
};
use ratarmount_index::{IndexError, SqliteIndex};
use thiserror::Error;
use url::Url;

pub const BACKEND_NAME: &str = "WARCMountSource";

#[derive(Debug, Error)]
pub enum WarcError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, WarcError>;

pub struct WarcMountSource {
    archive_path: PathBuf,
    index: SqliteIndex,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl WarcMountSource {
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
                        Err(e) => eprintln!("info: could not load warc index ({e}); rebuilding"),
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
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        if !data.starts_with(b"WARC/") {
            return Err(WarcError::Msg(
                "Not a WARC file (missing WARC/ version line)".into(),
            ));
        }

        let index = SqliteIndex::create_writable(index_path)?;
        index.begin_write()?;
        let mut generated = std::collections::BTreeSet::new();
        let mut used_names: HashMap<String, u32> = HashMap::new();
        let mut pos = 0usize;
        let mut record_index = 0usize;

        while pos < data.len() {
            // Skip blank lines between records.
            while pos < data.len() && (data[pos] == b'\r' || data[pos] == b'\n') {
                if data[pos..].starts_with(b"\r\n") {
                    pos += 2;
                } else {
                    pos += 1;
                }
            }
            if pos >= data.len() {
                break;
            }
            if !data[pos..].starts_with(b"WARC/") {
                break;
            }

            let header_start = pos;
            let (header_blob, payload_offset) =
                if let Some(rel) = find_subslice(&data[pos..], b"\r\n\r\n") {
                    let sep = pos + rel;
                    (&data[pos..sep], sep + 4)
                } else if let Some(rel) = find_subslice(&data[pos..], b"\n\n") {
                    let sep = pos + rel;
                    (&data[pos..sep], sep + 2)
                } else {
                    return Err(WarcError::Msg(format!(
                        "WARC record at {pos} missing header terminator"
                    )));
                };

            let content_length = header_field(header_blob, b"Content-Length")
                .and_then(|v| std::str::from_utf8(v).ok())
                .and_then(|s| s.trim().parse::<usize>().ok())
                .ok_or_else(|| {
                    WarcError::Msg(format!(
                        "WARC record at {header_start} missing Content-Length"
                    ))
                })?;

            let warc_type = header_field(header_blob, b"WARC-Type")
                .map(|v| String::from_utf8_lossy(v).trim().to_ascii_lowercase())
                .unwrap_or_else(|| "unknown".into());

            let mut display = if let Some(uri) = header_field(header_blob, b"WARC-Target-URI") {
                uri_to_path(&String::from_utf8_lossy(uri))
            } else if let Some(rid) = header_field(header_blob, b"WARC-Record-ID") {
                let s = String::from_utf8_lossy(rid)
                    .trim()
                    .trim_start_matches('<')
                    .trim_end_matches('>')
                    .replace(':', "_");
                s
            } else {
                format!("record-{record_index}")
            };

            if matches!(
                warc_type.as_str(),
                "warcinfo" | "request" | "metadata" | "revisit" | "conversion"
            ) {
                display = format!("_warc/{warc_type}/{display}");
            }
            display = sanitize_name(&display, &mut used_names);

            if payload_offset + content_length > data.len() {
                return Err(WarcError::Msg(format!(
                    "WARC record at {header_start} truncated payload"
                )));
            }

            let nfull = normpath(&display);
            let (path, base) = split_name(&nfull);
            ensure_parents(&index, &path, &mut generated, 0.0)?;
            let mode = (libc::S_IFREG | 0o644) as i64;
            index.insert_file(
                &path,
                &base,
                header_start as i64,
                payload_offset as i64,
                content_length as i64,
                0.0,
                mode,
                0,
                "",
                0,
                0,
                false,
                false,
                false,
                0,
            )?;

            pos = payload_offset + content_length;
            record_index += 1;
        }

        if record_index == 0 {
            return Err(WarcError::Msg("WARC file contains no records".into()));
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

impl MountSource for WarcMountSource {
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
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing warc userdata"))?;
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

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn header_field<'a>(header: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    // Case-insensitive field match; value is rest of line after ':'
    let mut pos = 0usize;
    while pos < header.len() {
        let line_end = header[pos..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|i| pos + i)
            .unwrap_or(header.len());
        let mut line = &header[pos..line_end];
        if line.ends_with(b"\r") {
            line = &line[..line.len() - 1];
        }
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let key = &line[..colon];
            if key.eq_ignore_ascii_case(name) {
                let mut val = &line[colon + 1..];
                while val.first() == Some(&b' ') || val.first() == Some(&b'\t') {
                    val = &val[1..];
                }
                return Some(val);
            }
        }
        pos = line_end + 1;
    }
    None
}

fn uri_to_path(uri: &str) -> String {
    let uri = uri.trim().replace('\\', "/");
    if uri.contains("://") {
        if let Ok(parsed) = Url::parse(&uri) {
            let host = parsed.host_str().unwrap_or("unknown-host");
            let mut path = parsed.path().to_string();
            if path.is_empty() {
                path = "/".into();
            }
            if let Some(q) = parsed.query() {
                path = format!("{path}?{q}");
            }
            return format!("{host}{path}").trim_start_matches('/').to_string();
        }
    }
    let s = uri.trim_start_matches('/');
    if s.is_empty() {
        "index".into()
    } else {
        s.to_string()
    }
}

fn sanitize_name(name: &str, used: &mut HashMap<String, u32>) -> String {
    let mut name = uri_to_path(name);
    if name.is_empty() || name.ends_with('/') {
        name = format!(
            "{}index.html",
            if name.is_empty() { "record" } else { &name }
        );
    }
    let key = name.clone();
    if let Some(n) = used.get_mut(&key) {
        *n += 1;
        let count = *n;
        if let Some((stem, ext)) = name.rsplit_once('.') {
            if !stem.is_empty() {
                return format!("{stem}-{count}.{ext}");
            }
        }
        format!("{name}-{count}")
    } else {
        used.insert(key, 0);
        name
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

pub fn looks_like_warc(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        let mut head = [0u8; 5];
        if f.read(&mut head).ok() == Some(5) && &head == b"WARC/" {
            return true;
        }
    }
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("warc"))
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
    fn open_hello_world_warc() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let path = PathBuf::from(root).join("tests/hello-world.warc");
        if !path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("w.index.sqlite");
        let m = WarcMountSource::open(&path, Some(&idx), &OpenOptions::default(), "0.1.0", true)
            .unwrap();
        let fi = m
            .lookup(
                "/iipc.github.io/warc-specifications/primers/web-archive-formats/hello-world.txt",
                0,
            )
            .expect("response payload");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert!(buf.windows(11).any(|w| w == b"Hello World"), "{buf:?}");
    }

    #[test]
    fn open_simple_response_warc() {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        let path = PathBuf::from(root).join("tests/simple-response.warc");
        if !path.exists() {
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let idx = dir.path().join("w.index.sqlite");
        let m = WarcMountSource::open(&path, Some(&idx), &OpenOptions::default(), "0.1.0", true)
            .unwrap();
        let fi = m.lookup("/example.com/hello.txt", 0).expect("hello");
        let mut r = m.open(&fi, 0).unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert!(buf.ends_with(b"hello warc\n"), "{buf:?}");
    }
}
