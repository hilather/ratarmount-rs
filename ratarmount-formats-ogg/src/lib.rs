//! Ogg container demux MountSource (`backendName=OGGMountSource`).
//!
//! Parses `OggS` pages, demultiplexes by stream serial, and exposes each logical
//! stream as a virtual file via multi-region [`StenciledFile`] (raw Ogg pages).

use std::collections::HashMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::Instant;

use ratarmount_compress::StenciledFile;
use ratarmount_core::{
    normpath, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions, UserData,
};
use ratarmount_index::{IndexError, SqliteIndex};
use thiserror::Error;

pub const BACKEND_NAME: &str = "OGGMountSource";

#[derive(Debug, Error)]
pub enum OggError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, OggError>;

#[derive(Debug, Clone)]
struct OggPage {
    header_offset: u64,
    data_offset: u64,
    data_size: u64,
}

#[derive(Debug, Clone)]
pub struct OggStream {
    pub media_type: String,
    pub subtype: String,
    pages: Vec<OggPage>,
    last_sequence: i64,
}

fn detect_media_type(data: &[u8]) -> (&'static str, &'static str) {
    // https://wiki.xiph.org/index.php/MIMETypesCodecs
    let codecs: &[(&str, &str, &[u8])] = &[
        ("audio", "celt", b"CELT    "),
        ("audio", "flac", b"\x7FFLAC"),
        ("audio", "opus", b"OpusHead"),
        ("audio", "pcm", b"PCM     "),
        ("audio", "speex", b"Speex   "),
        ("audio", "vorbis", b"\x01vorbis"),
        ("audio", "ogm", b"\x01audio"),
        ("text", "cmml", b"CMML\x00\x00\x00\x00"),
        ("text", "kate", b"\x80kate\x00\x00\x00"),
        ("text", "midi", b"OggMIDI\x00"),
        ("text", "ogm", b"\x01text"),
        ("video", "dirac", b"BBCD\x00"),
        ("video", "jng", b"\x8bJNG\r\n\x1a\n"),
        ("video", "mng", b"\x8aMNG\r\n\x1a\n"),
        ("video", "png", b"\x89PNG\r\n\x1a\n"),
        ("video", "theora", b"\x80theora"),
        ("video", "yuv4mpeg", b"YUV4MPEG"),
        ("video", "ogm", b"\x01video"),
    ];
    for &(media, codec, magic) in codecs {
        if data.starts_with(magic) {
            return (media, codec);
        }
    }
    ("unknown", "unknown")
}

/// Parse Ogg pages and group by stream serial.
pub fn parse_ogg<R: Read + Seek>(file: &mut R) -> Result<HashMap<u32, OggStream>> {
    let mut streams: HashMap<u32, OggStream> = HashMap::new();
    let mut complete: HashMap<u32, OggStream> = HashMap::new();

    loop {
        let page_offset = file.stream_position()?;
        let mut header_bytes = [0u8; 27];
        match file.read_exact(&mut header_bytes) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                // Short trailing data: stop cleanly.
                break;
            }
            Err(e) => return Err(e.into()),
        }
        if &header_bytes[0..4] != b"OggS" {
            // End of contiguous Ogg stream.
            break;
        }
        let version = header_bytes[4];
        if version != 0 {
            return Err(OggError::Msg(format!("invalid Ogg version {version}")));
        }
        let flags = header_bytes[5];
        // granule_pos at [6..14] unused for demux
        let stream_id = u32::from_le_bytes(header_bytes[14..18].try_into().unwrap());
        let sequence_number = u32::from_le_bytes(header_bytes[18..22].try_into().unwrap());
        // crc at [22..26]
        let page_segments = header_bytes[26] as usize;

        let mut segment_table = vec![0u8; page_segments];
        file.read_exact(&mut segment_table)?;
        let data_size: u64 = segment_table.iter().map(|&b| u64::from(b)).sum();
        let data_offset = file.stream_position()?;

        let is_beginning = flags & 0x02 != 0;
        if is_beginning != !streams.contains_key(&stream_id) {
            return Err(OggError::Msg(
                "beginning-of-stream flag must be set exactly for the first page of each stream"
                    .into(),
            ));
        }

        if let std::collections::hash_map::Entry::Vacant(e) = streams.entry(stream_id) {
            let mut stream_data = vec![0u8; data_size as usize];
            if data_size > 0 {
                file.read_exact(&mut stream_data)?;
            }
            let (media_type, subtype) = detect_media_type(&stream_data);
            e.insert(OggStream {
                media_type: media_type.into(),
                subtype: subtype.into(),
                pages: Vec::new(),
                last_sequence: -1,
            });
            // data already consumed
        } else {
            file.seek(SeekFrom::Start(data_offset + data_size))?;
        }

        let stream = streams.get_mut(&stream_id).unwrap();
        if (sequence_number as i64) <= stream.last_sequence {
            return Err(OggError::Msg(format!(
                "page sequence number must increase (stream {stream_id:#x})"
            )));
        }
        stream.last_sequence = sequence_number as i64;
        stream.pages.push(OggPage {
            header_offset: page_offset,
            data_offset,
            data_size,
        });

        if flags & 0x04 != 0 {
            if let Some(s) = streams.remove(&stream_id) {
                complete.insert(stream_id, s);
            }
        }
    }

    for (id, s) in streams {
        complete.insert(id, s);
    }
    Ok(complete)
}

pub fn looks_like_ogg(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        let mut magic = [0u8; 5];
        if f.read(&mut magic).ok() == Some(5) && &magic == b"OggS\0" {
            return true;
        }
        // Also accept OggS without requiring version byte if extension matches.
        if magic.starts_with(b"OggS") {
            return true;
        }
    }
    path.extension().and_then(|e| e.to_str()).is_some_and(|e| {
        let e = e.to_ascii_lowercase();
        matches!(e.as_str(), "ogg" | "ogm" | "ogv" | "oga" | "opus" | "spx")
    })
}

pub struct OggMountSource {
    archive_path: PathBuf,
    index: SqliteIndex,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl OggMountSource {
    pub fn open(
        archive_path: impl AsRef<Path>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
        recreate: bool,
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        if !looks_like_ogg(&archive_path) {
            // Soft check: still require magic for open.
            let mut f = File::open(&archive_path)?;
            let mut magic = [0u8; 4];
            f.read_exact(&mut magic)?;
            if &magic != b"OggS" {
                return Err(OggError::Msg("Not a valid OGG file!".into()));
            }
        }

        let index_path_buf: Option<PathBuf> = if options.index_in_memory {
            None
        } else {
            Some(index_path.map(|p| p.to_path_buf()).unwrap_or_else(|| {
                let mut s = archive_path.as_os_str().to_os_string();
                s.push(".index.sqlite");
                PathBuf::from(s)
            }))
        };

        if let Some(ref ip) = index_path_buf {
            if !recreate && ip.exists() {
                let meta_ok = std::fs::metadata(ip).map(|m| m.len() > 0).unwrap_or(false);
                if meta_ok {
                    match Self::open_existing(&archive_path, ip, options) {
                        Ok(s) => return Ok(s),
                        Err(e) => eprintln!("info: could not load ogg index ({e}); rebuilding"),
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
        let streams = parse_ogg(&mut file)?;
        if streams.is_empty() {
            return Err(OggError::Msg("OGG file contains no streams".into()));
        }

        let mtime = std::fs::metadata(archive_path)
            .map(|m| {
                use std::os::unix::fs::MetadataExt;
                m.mtime() as f64
            })
            .unwrap_or(0.0);

        let index = SqliteIndex::create_writable(index_path)?;
        index.begin_write()?;

        for (serial, stream) in streams {
            let extension = if stream.subtype == "ogm" {
                ".ogm"
            } else if stream.media_type == "video" {
                ".ogv"
            } else if stream.media_type == "audio" {
                ".oga"
            } else {
                ".ogg"
            };
            let name = format!("{}_{serial:08x}{extension}", stream.media_type);
            let nfull = normpath(&name);
            let (path, base) = split_name(&nfull);

            let stencils: Vec<(u64, u64)> = stream
                .pages
                .iter()
                .map(|p| {
                    (
                        p.header_offset,
                        p.data_offset - p.header_offset + p.data_size,
                    )
                })
                .collect();
            let size: u64 = stencils.iter().map(|(_, s)| s).sum();
            let ranges =
                serde_json::to_string(&stencils).map_err(|e| OggError::Msg(e.to_string()))?;
            let page0 = &stream.pages[0];
            let mode = (libc::S_IFREG | 0o644) as i64;
            index.insert_file(
                &path,
                &base,
                page0.header_offset as i64,
                page0.data_offset as i64,
                size as i64,
                mtime,
                mode,
                0,
                &ranges,
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

impl MountSource for OggMountSource {
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
        let regions: Vec<(u64, u64)> = if file_info.linkname.is_empty() {
            // Fallback single region from userdata.
            let ud = userdata(file_info).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidInput, "missing ogg userdata")
            })?;
            vec![(ud.offset, file_info.size)]
        } else {
            serde_json::from_str(&file_info.linkname)
                .map_err(|e| io::Error::other(format!("ogg stencil json: {e}")))?
        };
        let file = File::open(&self.archive_path)?;
        Ok(Box::new(StenciledFile::new(file, regions)))
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

fn split_name(full: &str) -> (String, String) {
    match full.rsplit_once('/') {
        Some(("", n)) => (String::new(), n.to_string()),
        Some((p, n)) => (p.to_string(), n.to_string()),
        None => (String::new(), full.to_string()),
    }
}

fn userdata(fi: &FileInfo) -> Option<&ratarmount_core::SQLiteIndexedTarUserData> {
    fi.userdata.iter().rev().find_map(|u| match u {
        UserData::Tar(t) => Some(t),
        _ => None,
    })
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
    use std::io::Cursor;

    /// Minimal single-page OggS with a fake vorbis-like identification packet.
    fn synthetic_ogg() -> Vec<u8> {
        // Payload: \x01vorbis + padding so detect_media_type sees vorbis.
        let payload = b"\x01vorbis\0\0\0\0\0\0\0\0";
        let mut page = Vec::new();
        page.extend_from_slice(b"OggS");
        page.push(0); // version
        page.push(0x02); // BOS
        page.extend_from_slice(&0u64.to_le_bytes()); // granule
        page.extend_from_slice(&0x1234_5678u32.to_le_bytes()); // serial
        page.extend_from_slice(&0u32.to_le_bytes()); // sequence
        page.extend_from_slice(&0u32.to_le_bytes()); // crc
        page.push(1); // 1 segment
        page.push(payload.len() as u8);
        page.extend_from_slice(payload);

        // EOS page empty-ish
        let mut page2 = Vec::new();
        page2.extend_from_slice(b"OggS");
        page2.push(0);
        page2.push(0x04); // EOS
        page2.extend_from_slice(&0u64.to_le_bytes());
        page2.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        page2.extend_from_slice(&1u32.to_le_bytes());
        page2.extend_from_slice(&0u32.to_le_bytes());
        page2.push(1);
        page2.push(0); // empty segment
                       // data size 0

        let mut out = page;
        out.extend_from_slice(&page2);
        out
    }

    #[test]
    fn parse_synthetic() {
        let data = synthetic_ogg();
        let mut c = Cursor::new(data);
        let streams = parse_ogg(&mut c).unwrap();
        assert_eq!(streams.len(), 1);
        let s = streams.get(&0x1234_5678).unwrap();
        assert_eq!(s.media_type, "audio");
        assert_eq!(s.subtype, "vorbis");
        assert_eq!(s.pages.len(), 2);
    }

    #[test]
    fn mount_synthetic() {
        let data = synthetic_ogg();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.ogg");
        std::fs::write(&path, &data).unwrap();
        assert!(looks_like_ogg(&path));
        let idx = dir.path().join("i.sqlite");
        let m = OggMountSource::open(&path, Some(&idx), &OpenOptions::default(), "0.1.0", true)
            .unwrap();
        let list = m.list("/").expect("list");
        match list {
            ListResult::Infos(map) => {
                assert!(!map.is_empty());
                let (name, fi) = map.iter().next().unwrap();
                assert!(name.contains("audio_"));
                assert!(fi.size > 0);
                let mut r = m.open(fi, 0).unwrap();
                let mut out = Vec::new();
                r.read_to_end(&mut out).unwrap();
                assert!(out.starts_with(b"OggS"));
                assert_eq!(out.len() as u64, fi.size);
            }
            _ => panic!("expected infos"),
        }
    }
}
