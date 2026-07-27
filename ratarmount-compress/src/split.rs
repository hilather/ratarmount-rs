//! Split multi-volume files (Python `check_for_split_file_in` / `JoinedFileFromFactory`).
//!
//! Detects consecutive parts like `name.001`/`name.002` (decimal), hex, or alphabetic
//! (`name.aa`/`name.ab`) and joins them into a single seekable stream.

use std::fs::{self, File};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

/// First-part extension only: `.aa`, `.AAA`, `.0`, `.1`, `.001`, `.01`, …
/// Matches Python `FIRST_SPLIT_EXTENSION_REGEX`.
pub fn is_first_split_extension(ext: &str) -> bool {
    let ext = ext.strip_prefix('.').unwrap_or(ext);
    if ext.is_empty() {
        return false;
    }
    let all_a = ext.chars().all(|c| c == 'a');
    let all_a_upper = ext.chars().all(|c| c == 'A');
    let digits = ext.chars().all(|c| c.is_ascii_digit());
    if all_a || all_a_upper {
        return true;
    }
    if digits {
        // 0*[01] in the sense: all zeros then optional 0/1, or pure zeros/ones width
        // Python: r"[.]([a]+|[A]+|0*[01])" — for digits only 0* then 0 or 1, or just 0/1
        // Actually `0*[01]` means zeros then a single 0 or 1 → "0","1","00","01","000","001",...
        // But "002" is NOT first part.
        let trimmed = ext.trim_start_matches('0');
        return trimmed.is_empty() || trimmed == "0" || trimmed == "1";
    }
    false
}

fn is_latin_alpha(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase())
}
fn is_latin_digit(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_digit())
}
fn is_latin_hex_alpha(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
}

fn has_matching_alphabets(a: &str, b: &str) -> bool {
    (is_latin_alpha(a) && is_latin_alpha(b))
        || (is_latin_digit(a) && is_latin_digit(b))
        || (is_latin_hex_alpha(a) && is_latin_hex_alpha(b))
}

/// Python `format_number(i, base, length)`.
fn format_number(mut i: usize, base: &str, length: usize) -> String {
    assert!(base.len() > 1);
    let radix = base.len();
    let chars: Vec<char> = base.chars().collect();
    let mut result = String::new();
    let mut len = length as isize;
    while i > 0 || len > 0 || result.is_empty() {
        result.push(chars[i % radix]);
        i /= radix;
        len -= 1;
    }
    result.chars().rev().collect()
}

fn check_for_sequence(
    extensions: &[String],
    number_formatter: impl Fn(usize) -> String,
) -> Vec<String> {
    let mut suffix_sequence = Vec::new();
    let mut i = 0usize;
    let suffix_length = number_formatter(0).len();
    loop {
        let suffix = number_formatter(i);
        if extensions.iter().any(|e| e == &suffix) {
            suffix_sequence.push(suffix);
        } else if i > 0 || suffix.len() != suffix_length {
            break;
        }
        i += 1;
    }
    suffix_sequence
}

const HEX: &str = "0123456789abcdef";

/// Result of split detection: ordered absolute paths + format (`a`/`0`/`x`).
#[derive(Debug, Clone)]
pub struct SplitFileSet {
    pub paths: Vec<PathBuf>,
    /// `a` alphabetical, `0` decimal, `x` hexadecimal (Python).
    pub format: char,
}

/// Basename without the split extension (Python joined file name).
pub fn joined_base_name(first_path: &Path) -> String {
    first_path
        .file_name()
        .and_then(|s| s.to_str())
        .map(|n| match n.rsplit_once('.') {
            Some((base, _)) => base.to_string(),
            None => n.to_string(),
        })
        .unwrap_or_else(|| "joined".into())
}

/// Python `check_for_split_file_in(path, candidateNames)`.
///
/// `path` may be a full path or just a file name; `candidate_names` are basenames
/// of siblings in the same folder.
pub fn check_for_split_file_in(
    path: &str,
    candidate_names: impl IntoIterator<Item = impl AsRef<str>>,
) -> Option<SplitFileSet> {
    let filename = Path::new(path)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(path);
    let (basename, extension) = filename.rsplit_once('.')?;
    if basename.is_empty() || extension.is_empty() {
        return None;
    }

    let candidates: Vec<String> = candidate_names
        .into_iter()
        .map(|s| s.as_ref().to_string())
        .collect();
    let prefix = format!("{basename}.");
    let extensions: Vec<String> = candidates
        .iter()
        .filter_map(|name| {
            name.strip_prefix(&prefix)
                .filter(|e| has_matching_alphabets(e, extension))
                .map(|e| e.to_string())
        })
        .collect();
    if extensions.is_empty() {
        return None;
    }
    if !extensions.iter().any(|e| e == extension) {
        return None;
    }

    let width = extension.len();
    let mut max_format = ' ';
    let mut max_extensions: Vec<String> = Vec::new();
    for (format_spec, base_digits) in [
        ('a', "abcdefghijklmnopqrstuvwxyz"),
        ('0', "0123456789"),
        ('x', HEX),
    ] {
        let seq = check_for_sequence(&extensions, |i| format_number(i, base_digits, width));
        if seq.len() > max_extensions.len() {
            max_format = format_spec;
            max_extensions = seq;
        }
    }

    if max_format != ' ' && max_extensions.len() > 1 {
        // Reconstruct absolute/relative paths using the directory of `path`.
        let base_str = match Path::new(path).parent() {
            Some(p) if !p.as_os_str().is_empty() => p.join(basename),
            _ => PathBuf::from(basename),
        };
        let paths: Vec<PathBuf> = max_extensions
            .iter()
            .map(|ext| {
                let mut p = base_str.as_os_str().to_os_string();
                p.push(".");
                p.push(ext);
                PathBuf::from(p)
            })
            .collect();
        return Some(SplitFileSet {
            paths,
            format: max_format,
        });
    }
    None
}

/// Python `check_for_split_file_in_folder`.
pub fn check_for_split_file_in_folder(path: &Path) -> Option<SplitFileSet> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let names = fs::read_dir(parent).ok()?;
    let candidates: Vec<String> = names
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    let path_str = path.to_string_lossy();
    check_for_split_file_in(&path_str, &candidates)
}

/// Concatenate split parts into a seekable temp file (small/medium volumes; matches tests).
pub fn materialize_joined_parts(parts: &[PathBuf]) -> io::Result<(NamedTempFile, u64)> {
    let mut tmp = NamedTempFile::new()?;
    let mut total = 0u64;
    for p in parts {
        let mut f = File::open(p)?;
        let n = io::copy(&mut f, &mut tmp)?;
        total += n;
    }
    tmp.flush()?;
    Ok((tmp, total))
}

/// Lazy multi-file join (Python `JoinedFileFromFactory`) — one FD at a time.
pub struct JoinedFile {
    parts: Vec<(PathBuf, u64)>, // path, size
    total: u64,
    pos: u64,
    open: Option<(usize, File)>,
}

impl JoinedFile {
    pub fn open_parts(paths: &[PathBuf]) -> io::Result<Self> {
        let mut parts = Vec::with_capacity(paths.len());
        let mut total = 0u64;
        for p in paths {
            let meta = fs::metadata(p)?;
            let sz = meta.len();
            parts.push((p.clone(), sz));
            total = total.saturating_add(sz);
        }
        Ok(Self {
            parts,
            total,
            pos: 0,
            open: None,
        })
    }

    pub fn len(&self) -> u64 {
        self.total
    }

    pub fn is_empty(&self) -> bool {
        self.total == 0
    }

    fn locate(&self, pos: u64) -> Option<(usize, u64)> {
        let mut off = 0u64;
        for (i, (_, sz)) in self.parts.iter().enumerate() {
            if pos < off + sz || (pos == off + sz && i + 1 == self.parts.len()) {
                return Some((i, pos.saturating_sub(off)));
            }
            off += sz;
        }
        None
    }
}

impl Read for JoinedFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.total || buf.is_empty() {
            return Ok(0);
        }
        let (idx, local) = self
            .locate(self.pos)
            .ok_or_else(|| io::Error::new(io::ErrorKind::UnexpectedEof, "joined eof"))?;
        // Reopen if needed
        if !matches!(&self.open, Some((i, _)) if *i == idx) {
            let f = File::open(&self.parts[idx].0)?;
            self.open = Some((idx, f));
        }
        let file = &mut self.open.as_mut().unwrap().1;
        file.seek(SeekFrom::Start(local))?;
        let max_here = (self.parts[idx].1 - local) as usize;
        let take = buf.len().min(max_here);
        let n = file.read(&mut buf[..take])?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for JoinedFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::End(o) => self.total as i64 + o,
            SeekFrom::Current(o) => self.pos as i64 + o,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn first_split_ext() {
        assert!(is_first_split_extension(".001"));
        assert!(is_first_split_extension(".01"));
        assert!(is_first_split_extension(".1"));
        assert!(is_first_split_extension(".0"));
        assert!(is_first_split_extension(".aa"));
        assert!(!is_first_split_extension(".002"));
        assert!(!is_first_split_extension(".ab"));
        assert!(!is_first_split_extension(".tar"));
    }

    #[test]
    fn format_number_decimal() {
        assert_eq!(format_number(1, "0123456789", 3), "001");
        assert_eq!(format_number(2, "0123456789", 3), "002");
        assert_eq!(format_number(0, "0123456789", 3), "000");
    }

    #[test]
    fn detect_decimal_split() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("foo.001"), b"foo").unwrap();
        fs::write(dir.path().join("foo.002"), b"bar").unwrap();
        let set = check_for_split_file_in_folder(&dir.path().join("foo.001")).unwrap();
        assert_eq!(set.paths.len(), 2);
        assert_eq!(set.format, '0');
        assert_eq!(joined_base_name(&set.paths[0]), "foo");
    }

    #[test]
    fn join_file_contents() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("foo.001"), b"foo").unwrap();
        fs::write(dir.path().join("foo.002"), b"bar").unwrap();
        let set = check_for_split_file_in_folder(&dir.path().join("foo.002")).unwrap();
        let mut jf = JoinedFile::open_parts(&set.paths).unwrap();
        let mut buf = Vec::new();
        jf.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"foobar");
        jf.seek(SeekFrom::Start(3)).unwrap();
        let mut rest = Vec::new();
        jf.read_to_end(&mut rest).unwrap();
        assert_eq!(rest, b"bar");
    }

    #[test]
    fn join_many_parts_handle_limit() {
        // Python uses 1100 parts to stress FD limits; keep 200 for unit speed.
        let dir = tempfile::tempdir().unwrap();
        let mut expected = Vec::new();
        let mut paths = Vec::new();
        for i in 0..200 {
            let p = dir.path().join(format!("foo.{i:03}"));
            let data = i.to_string().into_bytes();
            expected.extend_from_slice(&data);
            fs::write(&p, &data).unwrap();
            paths.push(p);
        }
        let set = check_for_split_file_in_folder(&paths[5]).unwrap();
        assert_eq!(set.paths.len(), 200);
        let mut jf = JoinedFile::open_parts(&set.paths).unwrap();
        let mut got = Vec::new();
        jf.read_to_end(&mut got).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn materialize_and_bz2_join() {
        use bzip2::write::BzEncoder;
        use bzip2::Compression;
        let dir = tempfile::tempdir().unwrap();
        let mut enc = BzEncoder::new(Vec::new(), Compression::default());
        enc.write_all(b"foobar").unwrap();
        let compressed = enc.finish().unwrap();
        let mid = compressed.len() / 2;
        fs::write(dir.path().join("foo.001"), &compressed[..mid]).unwrap();
        fs::write(dir.path().join("foo.002"), &compressed[mid..]).unwrap();
        let set = check_for_split_file_in_folder(&dir.path().join("foo.001")).unwrap();
        let (tmp, n) = materialize_joined_parts(&set.paths).unwrap();
        assert_eq!(n as usize, compressed.len());
        let data = fs::read(tmp.path()).unwrap();
        assert_eq!(data, compressed);
    }
}
