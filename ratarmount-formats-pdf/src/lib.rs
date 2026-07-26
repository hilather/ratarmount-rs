//! PDF attachment MountSource (`backendName=PDFMountSource`).
//!
//! MVP: extract embedded file attachments via [`lopdf`] (Names tree + FileAttachment
//! annotations + Filespec objects). Page images/text extraction is out of scope.

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use lopdf::{Document, Object, ObjectId};
use ratarmount_core::{
    normpath, FileInfo, ListModeResult, ListResult, MountSource, OpenOptions, UserData,
};
use ratarmount_index::{IndexError, SqliteIndex};
use thiserror::Error;

pub const BACKEND_NAME: &str = "PDFMountSource";

#[derive(Debug, Error)]
pub enum PdfError {
    #[error(transparent)]
    Index(#[from] IndexError),
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("{0}")]
    Msg(String),
}

pub type Result<T> = std::result::Result<T, PdfError>;

pub fn looks_like_pdf(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        let mut magic = [0u8; 5];
        if f.read(&mut magic).ok() == Some(5) && &magic == b"%PDF-" {
            return true;
        }
    }
    path.extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("pdf"))
}

fn pdf_string(obj: &Object) -> Option<String> {
    match obj {
        Object::String(bytes, _) => Some(String::from_utf8_lossy(bytes).into_owned()),
        Object::Name(n) => Some(String::from_utf8_lossy(n).into_owned()),
        _ => None,
    }
}

fn resolve<'a>(doc: &'a Document, obj: &'a Object) -> Option<&'a Object> {
    match obj {
        Object::Reference(id) => doc.get_object(*id).ok(),
        other => Some(other),
    }
}

fn stream_bytes(doc: &Document, id: ObjectId) -> Option<Vec<u8>> {
    let obj = doc.get_object(id).ok()?;
    match obj {
        Object::Stream(stream) => {
            if let Ok(data) = stream.decompressed_content() {
                Some(data)
            } else {
                Some(stream.content.clone())
            }
        }
        _ => None,
    }
}

/// Collect (display_name, embedded_stream_id, payload).
fn gather_attachments(doc: &Document) -> Vec<(String, ObjectId, Vec<u8>)> {
    let mut found: Vec<(String, ObjectId)> = Vec::new();
    let mut seen_streams: HashSet<ObjectId> = HashSet::new();

    // 1) Catalog -> Names -> EmbeddedFiles
    if let Ok(catalog) = doc.catalog() {
        if let Ok(names_obj) = catalog.get(b"Names") {
            if let Some(Object::Dictionary(names)) = resolve(doc, names_obj) {
                if let Ok(ef_obj) = names.get(b"EmbeddedFiles") {
                    collect_name_tree(doc, ef_obj, &mut found);
                }
            }
        }
    }

    // 2) Walk all objects for Filespec with EF, and FileAttachment annotations.
    for obj in doc.objects.values() {
        let Object::Dictionary(dict) = obj else {
            continue;
        };
        // Filespec
        if let Ok(Object::Name(t)) = dict.get(b"Type") {
            if t == b"Filespec" {
                if let Some(pair) = filespec_pair(doc, dict) {
                    found.push(pair);
                }
            }
        }
        // Annotation FileAttachment
        if let Ok(Object::Name(st)) = dict.get(b"Subtype") {
            if st == b"FileAttachment" {
                if let Ok(fs) = dict.get(b"FS") {
                    if let Some(Object::Dictionary(fsd)) = resolve(doc, fs) {
                        if let Some(pair) = filespec_pair(doc, fsd) {
                            found.push(pair);
                        }
                    }
                }
            }
        }
    }

    let mut out = Vec::new();
    let mut used_names: HashMap<String, u32> = HashMap::new();
    for (name, stream_id) in found {
        if !seen_streams.insert(stream_id) {
            continue;
        }
        let Some(data) = stream_bytes(doc, stream_id) else {
            continue;
        };
        let mut name = if name.is_empty() {
            format!("attachment-{}-{}", stream_id.0, stream_id.1)
        } else {
            name
        };
        // sanitize path separators
        name = name.replace('\\', "/");
        if let Some(n) = used_names.get_mut(&name) {
            *n += 1;
            let count = *n;
            if let Some((stem, ext)) = name.rsplit_once('.') {
                name = format!("{stem}-{count}.{ext}");
            } else {
                name = format!("{name}-{count}");
            }
        } else {
            used_names.insert(name.clone(), 0);
        }
        out.push((name, stream_id, data));
    }
    out
}

fn filespec_pair(doc: &Document, dict: &lopdf::Dictionary) -> Option<(String, ObjectId)> {
    let name = dict
        .get(b"UF")
        .ok()
        .and_then(pdf_string)
        .or_else(|| dict.get(b"F").ok().and_then(pdf_string))
        .unwrap_or_default();
    let ef = dict.get(b"EF").ok()?;
    let ef_dict = match resolve(doc, ef)? {
        Object::Dictionary(d) => d,
        _ => return None,
    };
    // Prefer /UF then /F then /DOS /Unix /Mac
    for key in [b"UF".as_slice(), b"F", b"DOS", b"Unix", b"Mac"] {
        if let Ok(obj) = ef_dict.get(key) {
            if let Object::Reference(id) = obj {
                return Some((name, *id));
            }
            if let Some(Object::Stream(_)) = resolve(doc, obj) {
                // rare inline
            }
            if let Object::Reference(id) = obj {
                return Some((name, *id));
            }
        }
    }
    None
}

fn collect_name_tree(doc: &Document, node: &Object, out: &mut Vec<(String, ObjectId)>) {
    let Some(Object::Dictionary(dict)) = resolve(doc, node) else {
        return;
    };
    if let Ok(names) = dict.get(b"Names") {
        if let Some(Object::Array(arr)) = resolve(doc, names) {
            let mut i = 0;
            while i + 1 < arr.len() {
                let name = pdf_string(&arr[i]).unwrap_or_default();
                if let Object::Reference(id) = &arr[i + 1] {
                    if let Ok(Object::Dictionary(fs)) = doc.get_object(*id) {
                        if let Some(pair) = filespec_pair(doc, fs) {
                            out.push(pair);
                        } else {
                            // filespec may use name from Names array
                            if let Some((_, sid)) =
                                filespec_pair(doc, fs).or_else(|| filespec_stream_only(doc, fs))
                            {
                                out.push((name, sid));
                            }
                        }
                    }
                } else if let Some(Object::Dictionary(fs)) = resolve(doc, &arr[i + 1]) {
                    if let Some((n, sid)) = filespec_pair(doc, fs) {
                        out.push((if name.is_empty() { n } else { name }, sid));
                    }
                }
                i += 2;
            }
        }
    }
    if let Ok(kids) = dict.get(b"Kids") {
        if let Some(Object::Array(arr)) = resolve(doc, kids) {
            for kid in arr {
                collect_name_tree(doc, kid, out);
            }
        }
    }
}

fn filespec_stream_only(doc: &Document, dict: &lopdf::Dictionary) -> Option<(String, ObjectId)> {
    filespec_pair(doc, dict)
}

pub struct PdfMountSource {
    #[allow(dead_code)]
    archive_path: PathBuf,
    index: SqliteIndex,
    payloads: Mutex<HashMap<i64, Vec<u8>>>,
    #[allow(dead_code)]
    options: OpenOptions,
}

impl PdfMountSource {
    pub fn open(
        archive_path: impl AsRef<Path>,
        index_path: Option<&Path>,
        options: &OpenOptions,
        product_version: &str,
        recreate: bool,
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        if !looks_like_pdf(&archive_path) {
            return Err(PdfError::Msg("Not a valid PDF file!".into()));
        }
        // Force memory index (decoded attachment payloads not stable on disk).
        let _ = (index_path, recreate);
        let mut opts = options.clone();
        opts.index_in_memory = true;
        Self::create_index(&archive_path, &opts, product_version)
    }

    fn create_index(
        archive_path: &Path,
        options: &OpenOptions,
        product_version: &str,
    ) -> Result<Self> {
        let _ = options;
        println!(
            "Creating offset dictionary for {} ...",
            archive_path.display()
        );
        let t0 = Instant::now();

        let doc = Document::load(archive_path)
            .map_err(|e| PdfError::Msg(format!("failed to load PDF: {e}")))?;
        let attachments = gather_attachments(&doc);

        let mtime = std::fs::metadata(archive_path)
            .map(|m| {
                use std::os::unix::fs::MetadataExt;
                m.mtime() as f64
            })
            .unwrap_or(0.0);

        let index = SqliteIndex::create_writable(None)?;
        index.begin_write()?;
        let mut payloads = HashMap::new();
        let mut generated = std::collections::BTreeSet::new();

        for (name, stream_id, data) in attachments {
            let nfull = normpath(&name);
            let (path, base) = split_name(&nfull);
            ensure_parents(&index, &path, &mut generated, mtime)?;
            let key = stream_id.0 as i64;
            let mode = (libc::S_IFREG | 0o644) as i64;
            index.insert_file(
                &path,
                &base,
                key,
                0,
                data.len() as i64,
                mtime,
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
            payloads.insert(key, data);
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
            payloads: Mutex::new(payloads),
            options: options.clone(),
        })
    }
}

impl MountSource for PdfMountSource {
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
        let key = file_info
            .userdata
            .iter()
            .rev()
            .find_map(|u| match u {
                UserData::Tar(t) => t.offsetheader.map(|v| v as i64),
                _ => None,
            })
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing pdf userdata"))?;
        let map = self
            .payloads
            .lock()
            .map_err(|_| io::Error::other("pdf payload lock poisoned"))?;
        let data = map
            .get(&key)
            .cloned()
            .ok_or_else(|| io::Error::other(format!("missing pdf payload for object {key}")))?;
        Ok(Box::new(Cursor::new(data)))
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

    fn py_fixture(name: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        PathBuf::from(root).join("tests").join(name)
    }

    #[test]
    fn pypdf_minimal_attachment() {
        let path = py_fixture("pypdf-minimal-single-attachment.pdf");
        if !path.exists() {
            return;
        }
        assert!(looks_like_pdf(&path));
        let m = PdfMountSource::open(&path, None, &OpenOptions::default(), "0.1.0", true).unwrap();
        let fi = m.lookup("/test.bin", 0).expect("test.bin");
        assert_eq!(fi.size, 28);
        let mut r = m.open(&fi, 0).unwrap();
        let mut s = String::new();
        r.read_to_string(&mut s).unwrap();
        assert_eq!(s, "This is a test embedded file");
    }

    #[test]
    fn example_pdf_attachments() {
        let path = py_fixture("example.pdf");
        if !path.exists() {
            return;
        }
        let m = PdfMountSource::open(&path, None, &OpenOptions::default(), "0.1.0", true).unwrap();
        let list = m.list("/").expect("list");
        match list {
            ListResult::Infos(map) => {
                assert!(
                    map.contains_key("example.tex") || map.keys().any(|k| k.contains("example")),
                    "keys: {:?}",
                    map.keys().collect::<Vec<_>>()
                );
                assert!(
                    map.contains_key("single-file.tar")
                        || map.keys().any(|k| k.contains("single-file")),
                    "keys: {:?}",
                    map.keys().collect::<Vec<_>>()
                );
                if let Some(fi) = map.get("example.tex") {
                    let mut r = m.open(fi, 0).unwrap();
                    let mut buf = Vec::new();
                    r.read_to_end(&mut buf).unwrap();
                    assert!(!buf.is_empty());
                }
            }
            _ => panic!("expected infos"),
        }
    }
}
