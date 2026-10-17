//! Bounded bencode parsing, exact info hashes, and BEP 3 / BEP 52 piece geometry.

use std::collections::BTreeMap;
use std::io;

use sha1::Sha1;
use sha2::{Digest, Sha256};

pub(crate) const MAX_META: u64 = 64 * 1024 * 1024;
const MAX_PIECE: u64 = 64 * 1024 * 1024;
pub(crate) const BLOCK: usize = 16 * 1024;

pub(crate) fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[derive(Debug)]
pub(crate) struct Node<'a> {
    pub raw: &'a [u8],
    value: Value<'a>,
}

#[derive(Debug)]
enum Value<'a> {
    Int(i64),
    Bytes(&'a [u8]),
    List(Vec<Node<'a>>),
    Dict(BTreeMap<&'a [u8], Node<'a>>),
}

impl<'a> Node<'a> {
    pub fn get(&self, key: &[u8]) -> Option<&Self> {
        match &self.value {
            Value::Dict(d) => d.get(key),
            _ => None,
        }
    }

    pub fn required(&self, key: &[u8]) -> io::Result<&Self> {
        self.get(key)
            .ok_or_else(|| invalid("missing torrent field"))
    }

    pub fn bytes(&self) -> io::Result<&'a [u8]> {
        match &self.value {
            Value::Bytes(b) => Ok(b),
            _ => Err(invalid("expected bencode bytes")),
        }
    }

    fn text(&self) -> io::Result<String> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| invalid("non-UTF-8 torrent path"))
    }

    fn number(&self) -> io::Result<u64> {
        match self.value {
            Value::Int(n) if n >= 0 => Ok(n as u64),
            _ => Err(invalid("expected nonnegative torrent integer")),
        }
    }

    fn list(&self) -> io::Result<&[Node<'a>]> {
        match &self.value {
            Value::List(v) => Ok(v),
            _ => Err(invalid("expected bencode list")),
        }
    }

    fn dict(&self) -> io::Result<&BTreeMap<&'a [u8], Node<'a>>> {
        match &self.value {
            Value::Dict(v) => Ok(v),
            _ => Err(invalid("expected bencode dictionary")),
        }
    }
}

pub(crate) fn parse(bytes: &[u8]) -> io::Result<Node<'_>> {
    fn node<'a>(bytes: &mut &'a [u8], depth: usize, count: &mut usize) -> io::Result<Node<'a>> {
        *count += 1;
        if depth > 64 || *count > 2_000_000 {
            return Err(invalid("torrent bencode complexity limit"));
        }
        let original = *bytes;
        let first = *bytes.first().ok_or_else(|| invalid("truncated bencode"))?;
        let value = match first {
            b'i' => {
                let end = bytes
                    .iter()
                    .position(|b| *b == b'e')
                    .ok_or_else(|| invalid("truncated integer"))?;
                let s =
                    std::str::from_utf8(&bytes[1..end]).map_err(|_| invalid("invalid integer"))?;
                if s.is_empty()
                    || s == "-0"
                    || s.starts_with('+')
                    || s.starts_with("00")
                    || s.len() > 1 && s.starts_with('0')
                    || s.starts_with("-0")
                {
                    return Err(invalid("noncanonical integer"));
                }
                let n = s.parse().map_err(|_| invalid("integer overflow"))?;
                *bytes = &bytes[end + 1..];
                Value::Int(n)
            }
            b'l' | b'd' => {
                *bytes = &bytes[1..];
                let mut list = Vec::new();
                let mut dict = BTreeMap::new();
                let mut last: Option<&[u8]> = None;
                while bytes.first() != Some(&b'e') {
                    let item = node(bytes, depth + 1, count)?;
                    if first == b'l' {
                        list.push(item);
                    } else {
                        let key = item.bytes()?;
                        if last.is_some_and(|p| p >= key) {
                            return Err(invalid("unsorted or duplicate bencode dictionary key"));
                        }
                        last = Some(key);
                        dict.insert(key, node(bytes, depth + 1, count)?);
                    }
                }
                *bytes = &bytes[1..];
                if first == b'l' {
                    Value::List(list)
                } else {
                    Value::Dict(dict)
                }
            }
            b'0'..=b'9' => {
                let end = bytes
                    .iter()
                    .position(|b| *b == b':')
                    .ok_or_else(|| invalid("truncated string"))?;
                if end > 1 && first == b'0' {
                    return Err(invalid("noncanonical string length"));
                }
                let len: usize = std::str::from_utf8(&bytes[..end])
                    .ok()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| invalid("invalid string length"))?;
                let finish = (end + 1)
                    .checked_add(len)
                    .ok_or_else(|| invalid("string length overflow"))?;
                let data = bytes
                    .get(end + 1..finish)
                    .ok_or_else(|| invalid("truncated string"))?;
                *bytes = &bytes[finish..];
                Value::Bytes(data)
            }
            _ => return Err(invalid("invalid bencode tag")),
        };
        Ok(Node {
            raw: &original[..original.len() - bytes.len()],
            value,
        })
    }
    if bytes.len() as u64 > MAX_META {
        return Err(invalid("torrent metadata exceeds 64 MiB"));
    }
    let mut remaining = bytes;
    let result = node(&mut remaining, 0, &mut 0)?;
    if !remaining.is_empty() {
        return Err(invalid("trailing bencode data"));
    }
    Ok(result)
}

#[derive(Clone, Debug)]
pub(crate) struct File {
    pub path: String,
    pub len: u64,
    pub offset: u64,
    pub padding: bool,
    pub sha256: Option<[u8; 32]>,
    pub v2: Option<V2File>,
}

#[derive(Clone, Debug)]
pub(crate) struct V2File {
    pub root: [u8; 32],
    pub pieces: Vec<[u8; 32]>,
}

#[derive(Clone, Debug)]
pub(crate) struct Metainfo {
    pub bytes: Vec<u8>,
    pub info: Vec<u8>,
    pub v1_hash: Option<String>,
    pub v2_hash: Option<String>,
    pub name: String,
    pub multi: bool,
    pub piece_len: u64,
    pub pieces: Vec<[u8; 20]>,
    pub files: Vec<File>,
    pub total: u64,
    pub web_seeds: Vec<String>,
    pub trackers: Vec<String>,
}

pub(crate) fn component(s: &str) -> io::Result<()> {
    if s.is_empty() || matches!(s, "." | "..") || s.contains(['/', '\\', '\0', ':']) {
        return Err(invalid("unsafe torrent path component"));
    }
    #[cfg(not(unix))]
    if windows_reserved(s) {
        return Err(invalid("reserved Windows torrent path"));
    }
    Ok(())
}

#[cfg(any(not(unix), test))]
fn windows_reserved(s: &str) -> bool {
    let stem = s.split('.').next().unwrap_or("").to_ascii_uppercase();
    s.ends_with(['.', ' '])
        || s.contains(['<', '>', '"', '|', '?', '*'])
        || s.chars().any(char::is_control)
        || matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        )
        || ["COM", "LPT"].iter().any(|p| {
            stem.strip_prefix(p).is_some_and(|n| {
                matches!(
                    n,
                    "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                )
            })
        })
}

fn validate_paths<'a>(paths: impl Iterator<Item = &'a str>, fold_case: bool) -> io::Result<()> {
    let paths: Vec<_> = paths.collect();
    let key = |s: &str| {
        if fold_case {
            s.to_lowercase()
        } else {
            s.to_string()
        }
    };
    let mut names = BTreeMap::new();
    for path in &paths {
        if names.insert(key(path), ()).is_some() {
            return Err(invalid("duplicate torrent path"));
        }
    }
    let mut spellings = BTreeMap::new();
    for mut path in paths {
        loop {
            if let Some(previous) = spellings.insert(key(path), path) {
                if previous != path {
                    return Err(invalid("case-insensitive torrent path collision"));
                }
            }
            let Some((parent, _)) = path.rsplit_once('/') else {
                break;
            };
            if names.contains_key(&key(parent)) {
                return Err(invalid("torrent file/directory collision"));
            }
            path = parent;
        }
    }
    Ok(())
}

fn sha256_field(n: &Node<'_>) -> io::Result<Option<[u8; 32]>> {
    n.get(b"sha256")
        .map(|n| {
            let bytes = n.bytes()?;
            if bytes.len() == 32 {
                return Ok(bytes.try_into().unwrap());
            }
            let decoded = hex::decode(bytes).map_err(|_| invalid("invalid file SHA-256"))?;
            decoded
                .try_into()
                .map_err(|_| invalid("invalid file SHA-256 length"))
        })
        .transpose()
}

fn hash_pair(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(a);
    hash.update(b);
    hash.finalize().into()
}

pub(crate) fn merkle(mut hashes: Vec<[u8; 32]>, padding: [u8; 32]) -> [u8; 32] {
    hashes.resize(hashes.len().max(1).next_power_of_two(), padding);
    while hashes.len() > 1 {
        hashes = hashes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| hash_pair(pair[0], pair[1]))
            .collect();
    }
    hashes[0]
}

pub(crate) fn piece_root(data: &[u8], blocks: usize) -> [u8; 32] {
    let mut hashes: Vec<_> = data
        .chunks(BLOCK)
        .map(|b| Sha256::digest(b).into())
        .collect();
    hashes.resize(blocks, [0; 32]);
    merkle(hashes, [0; 32])
}

impl Metainfo {
    pub fn parse(bytes: Vec<u8>) -> io::Result<Self> {
        let top = parse(&bytes)?;
        let info = top.required(b"info")?;
        info.dict()?;
        let v2 = match info.get(b"meta version") {
            None => false,
            Some(n) if n.number()? == 2 => true,
            Some(_) => return Err(invalid("unsupported torrent meta version")),
        };
        let v1 = info.get(b"pieces").is_some();
        if !v1 && !v2 {
            return Err(invalid("torrent has no piece hashes"));
        }
        let name = info.required(b"name")?.text()?;
        component(&name)?;
        let piece_len = info.required(b"piece length")?.number()?;
        if piece_len == 0
            || piece_len > MAX_PIECE
            || (v2 && (!piece_len.is_power_of_two() || piece_len < BLOCK as u64))
        {
            return Err(invalid("unsupported torrent piece length (maximum 64 MiB)"));
        }
        let mut files = Vec::new();
        let v1_multi = info.get(b"files").is_some();
        let mut total = 0u64;
        if v1 {
            let entries: Vec<_> = if let Some(n) = info.get(b"files") {
                n.list()?.iter().collect()
            } else {
                vec![info]
            };
            for entry in entries {
                let path = if v1_multi {
                    let parts: Vec<_> = entry
                        .required(b"path")?
                        .list()?
                        .iter()
                        .map(Node::text)
                        .collect::<io::Result<_>>()?;
                    if parts.is_empty() {
                        return Err(invalid("empty torrent file path"));
                    }
                    for part in &parts {
                        component(part)?;
                    }
                    parts.join("/")
                } else {
                    name.clone()
                };
                let len = entry.required(b"length")?.number()?;
                let padding = entry
                    .get(b"attr")
                    .map(Node::bytes)
                    .transpose()?
                    .is_some_and(|s| s.contains(&b'p'));
                if entry
                    .get(b"attr")
                    .map(Node::bytes)
                    .transpose()?
                    .is_some_and(|s| s.contains(&b'l'))
                {
                    return Err(invalid("torrent symlinks are unsupported"));
                }
                files.push(File {
                    path,
                    len,
                    offset: total,
                    padding,
                    sha256: sha256_field(entry)?,
                    v2: None,
                });
                total = total
                    .checked_add(len)
                    .ok_or_else(|| invalid("torrent size overflow"))?;
            }
        }
        let pieces = if v1 {
            let p = info.required(b"pieces")?.bytes()?;
            if p.len() % 20 != 0 || p.len() as u64 / 20 != total.div_ceil(piece_len) {
                return Err(invalid("torrent piece count does not match file lengths"));
            }
            p.as_chunks::<20>().0.to_vec()
        } else {
            Vec::new()
        };
        if v2 {
            let mut v2_files = Vec::new();
            Self::walk_v2(
                info.required(b"file tree")?,
                "",
                &mut v2_files,
                &top,
                piece_len,
                v1,
            )?;
            if v1 {
                let visible: Vec<_> = files.iter_mut().filter(|f| !f.padding).collect();
                if visible.len() != v2_files.len() {
                    return Err(invalid("hybrid file trees disagree"));
                }
                for (a, b) in visible.into_iter().zip(v2_files) {
                    if a.path != b.path || a.len != b.len || a.offset % piece_len != 0 {
                        return Err(invalid("hybrid file layout disagrees with v2"));
                    }
                    if a.sha256.is_some() && b.sha256.is_some() && a.sha256 != b.sha256 {
                        return Err(invalid("hybrid file checksums disagree"));
                    }
                    a.sha256 = a.sha256.or(b.sha256);
                    a.v2 = b.v2;
                }
            } else {
                for f in &mut v2_files {
                    f.offset = total;
                    total = total
                        .checked_add(f.len)
                        .ok_or_else(|| invalid("torrent size overflow"))?;
                }
                files = v2_files;
            }
        }
        if total > i64::MAX as u64 {
            return Err(invalid("torrent total length exceeds seek address space"));
        }
        let multi = if v1 {
            v1_multi
        } else {
            files.len() != 1 || files.first().is_some_and(|f| f.path.contains('/'))
        };
        validate_paths(
            files.iter().filter(|f| !f.padding).map(|f| f.path.as_str()),
            !cfg!(unix),
        )?;
        let mut web_seeds = Vec::new();
        if let Some(urls) = top.get(b"url-list") {
            match &urls.value {
                Value::Bytes(_) => web_seeds.push(urls.text()?),
                Value::List(list) => {
                    for n in list {
                        web_seeds.push(n.text()?);
                    }
                }
                _ => return Err(invalid("invalid url-list")),
            }
        }
        let mut trackers = Vec::new();
        if let Some(n) = top.get(b"announce") {
            trackers.push(n.text()?);
        }
        if let Some(n) = top.get(b"announce-list") {
            for tier in n.list()? {
                for n in tier.list()? {
                    trackers.push(n.text()?);
                }
            }
        }
        let raw_info = info.raw.to_vec();
        let v1_hash = v1.then(|| hex::encode(Sha1::digest(&raw_info)));
        let v2_hash = v2.then(|| hex::encode(Sha256::digest(&raw_info)));
        Ok(Self {
            bytes,
            info: raw_info,
            v1_hash,
            v2_hash,
            name,
            multi,
            piece_len,
            pieces,
            files,
            total,
            web_seeds,
            trackers,
        })
    }

    fn walk_v2(
        tree: &Node<'_>,
        prefix: &str,
        files: &mut Vec<File>,
        top: &Node<'_>,
        piece_len: u64,
        hybrid: bool,
    ) -> io::Result<()> {
        if let Some(props) = tree.get(b"") {
            if prefix.is_empty() || tree.dict()?.len() != 1 {
                return Err(invalid("invalid v2 file tree leaf"));
            }
            let len = props.required(b"length")?.number()?;
            if props
                .get(b"attr")
                .map(Node::bytes)
                .transpose()?
                .is_some_and(|a| a.contains(&b'l') || a.contains(&b'p'))
            {
                return Err(invalid("unsupported v2 symlink/padding file"));
            }
            let v2 = if len == 0 {
                None
            } else {
                let root: [u8; 32] = props
                    .required(b"pieces root")?
                    .bytes()?
                    .try_into()
                    .map_err(|_| invalid("invalid v2 root"))?;
                let layer = top
                    .get(b"piece layers")
                    .map(Node::dict)
                    .transpose()?
                    .and_then(|layers| layers.get(root.as_slice()));
                if len > piece_len && layer.is_none() && hybrid {
                    // BEP 9 transfers only the info dictionary. A hybrid still
                    // has authenticated v1 hashes when v2 layers are absent.
                    None
                } else {
                    let pieces = if len > piece_len {
                        let layer = layer
                            .ok_or_else(|| invalid("missing v2 piece layer"))?
                            .bytes()?;
                        if layer.len() as u64 != len.div_ceil(piece_len) * 32 {
                            return Err(invalid("incorrect v2 piece layer length"));
                        }
                        let hashes = layer.as_chunks::<32>().0.to_vec();
                        let mut padding = [0; 32];
                        for _ in 0..(piece_len / BLOCK as u64).ilog2() {
                            padding = hash_pair(padding, padding);
                        }
                        if merkle(hashes.clone(), padding) != root {
                            return Err(invalid("v2 piece layer does not match info root"));
                        }
                        hashes
                    } else {
                        vec![root]
                    };
                    Some(V2File { root, pieces })
                }
            };
            files.push(File {
                path: prefix.into(),
                len,
                offset: 0,
                padding: false,
                sha256: sha256_field(props)?,
                v2,
            });
            return Ok(());
        }
        for (name, child) in tree.dict()? {
            let name = std::str::from_utf8(name).map_err(|_| invalid("non-UTF-8 v2 path"))?;
            component(name)?;
            let path = if prefix.is_empty() {
                name.into()
            } else {
                format!("{prefix}/{name}")
            };
            Self::walk_v2(child, &path, files, top, piece_len, hybrid)?;
        }
        Ok(())
    }

    pub fn complete_v2(&self) -> bool {
        self.v2_hash.is_some()
            && self
                .files
                .iter()
                .filter(|f| !f.padding && f.len != 0)
                .all(|f| f.v2.is_some())
    }

    /// Prefer the authenticated v2 identity for hybrid metadata and cache keys;
    /// the v1 hash is retained for rqbit's v1 wire protocol only.
    pub fn identity(&self) -> &str {
        self.v2_hash.as_ref().or(self.v1_hash.as_ref()).unwrap()
    }

    /// File spans intersecting a v1 piece: (file index, file offset, byte count).
    pub fn spans(&self, piece: u64) -> Vec<(usize, u64, usize)> {
        let start = piece * self.piece_len;
        let end = (start + self.piece_len).min(self.total);
        self.files
            .iter()
            .enumerate()
            .filter_map(|(i, f)| {
                let a = start.max(f.offset);
                let b = end.min(f.offset + f.len);
                (a < b).then(|| (i, a - f.offset, (b - a) as usize))
            })
            .collect()
    }
}

#[cfg(test)]
mod path_tests {
    use super::*;
    /// Regression: Windows device names and case-folded duplicate paths could escape file semantics.
    #[test]
    fn regression_windows_reserved_torrent_names() {
        for name in [
            "CON", "con.txt", "NUL", "com1", "Lpt9.bin", "COM¹", "a.", "a ", "x*y",
        ] {
            assert!(windows_reserved(name), "{name}");
        }
        assert!(!windows_reserved("weights.bin"));
        for paths in [["A/B", "a/b"], ["A", "a/b"], ["Dir/a", "dir/b"]] {
            assert!(validate_paths(paths.into_iter(), true).is_err());
            assert!(validate_paths(paths.into_iter(), false).is_ok());
        }
    }
}
