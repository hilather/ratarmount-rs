//! Lazy torrent trees. HTTP payloads are never cached until the entire piece verifies.

mod checksums;
mod metadata;
mod metainfo;
mod swarm;

use std::collections::BTreeMap;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use ratarmount_core::{
    create_root_file_info, normpath, ArchiveRead, CheapDirent, FileInfo, ListResult, MountSource,
    UserData, S_IFDIR, S_IFREG,
};
use ratarmount_index::{ContentToken, RangeCache};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use url::Url;

use crate::{HfRepo, HttpAuthOptions, HttpLocation, HttpRangeSource};
use metainfo::{invalid, piece_root, Metainfo, BLOCK};
use swarm::Swarm;
pub use swarm::SwarmOptions;

#[derive(Clone)]
pub struct TorrentOptions {
    pub metadata_dir: PathBuf,
    pub range_cache: Option<RangeCache>,
    pub swarm: SwarmOptions,
    /// Additional following bytes to prefetch through the verified HTTP path.
    /// rqbit itself has a fixed 32 MiB streaming lookahead.
    pub readahead_bytes: u64,
}

impl Default for TorrentOptions {
    fn default() -> Self {
        Self {
            metadata_dir: ratarmount_index::platform_cache_root().join("torrent-v1"),
            range_cache: RangeCache::from_env(),
            swarm: SwarmOptions::default(),
            readahead_bytes: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Piece {
    file: Option<usize>,
    index: u64,
}

#[derive(Default)]
struct Verification {
    expected: Option<[u8; 32]>,
    loaded: bool,
    bad: bool,
    complete: bool,
    // Covered byte intervals merge immediately, including reads from other handles.
    ranges: BTreeMap<u64, u64>,
}

impl Verification {
    fn cover(&mut self, mut start: u64, mut end: u64) {
        if let Some((&s, &e)) = self.ranges.range(..=start).next_back() {
            if e >= start {
                start = s;
                end = end.max(e);
                self.ranges.remove(&s);
            }
        }
        while let Some((&s, &e)) = self.ranges.range(start..).next() {
            if s > end {
                break;
            }
            end = end.max(e);
            self.ranges.remove(&s);
        }
        self.ranges.insert(start, end);
    }
}

type HttpSources = BTreeMap<(usize, usize), Arc<HttpRangeSource>>;
struct Data {
    meta: Metainfo,
    options: TorrentOptions,
    swarm: Mutex<Option<Arc<Swarm>>>,
    sources: Mutex<HttpSources>,
    last: Mutex<Option<(Piece, Arc<Vec<u8>>)>>,
    verification: Vec<Mutex<Verification>>,
    expected_hashes: OnceLock<BTreeMap<String, [u8; 32]>>,
    prefetching: AtomicBool,
    generation: AtomicU64,
}

/// A read-only metadata tree; constructing/listing it fetches no payload pieces.
pub struct TorrentMountSource {
    data: Arc<Data>,
    entries: BTreeMap<String, FileInfo>,
    children: BTreeMap<String, Vec<CheapDirent>>,
}

impl TorrentMountSource {
    pub fn open(input: &str, options: TorrentOptions) -> io::Result<Self> {
        Self::from_metainfo(metadata::resolve(input, &options)?, options)
    }

    pub fn from_bytes(bytes: Vec<u8>, options: TorrentOptions) -> io::Result<Self> {
        let meta = Metainfo::parse(bytes)?;
        Self::from_metainfo(meta, options)
    }

    fn from_metainfo(meta: Metainfo, options: TorrentOptions) -> io::Result<Self> {
        let mut entries = BTreeMap::new();
        entries.insert("/".to_string(), create_root_file_info());
        let verification = meta
            .files
            .iter()
            .map(|f| {
                Mutex::new(Verification {
                    expected: f.sha256,
                    loaded: f.sha256.is_some(),
                    ..Default::default()
                })
            })
            .collect();
        for (id, file) in meta.files.iter().enumerate().filter(|(_, f)| !f.padding) {
            let path = format!("/{}", file.path);
            let mut fi = create_root_file_info();
            fi.size = file.len;
            fi.mode = S_IFREG | 0o444;
            fi.userdata = vec![UserData::Other(format!("torrent:{id}"))];
            entries.insert(path.clone(), fi);
            let mut parent = path.as_str();
            while let Some((p, _)) = parent.rsplit_once('/') {
                if p.is_empty() {
                    break;
                }
                entries
                    .entry(p.into())
                    .or_insert_with(create_root_file_info);
                parent = p;
            }
        }
        let mut children: BTreeMap<String, Vec<CheapDirent>> = entries
            .iter()
            .filter(|(_, fi)| fi.mode & S_IFDIR != 0)
            .map(|(p, _)| (p.clone(), Vec::new()))
            .collect();
        for (path, fi) in &entries {
            if path == "/" {
                continue;
            }
            let (parent, name) = path.rsplit_once('/').unwrap();
            children
                .entry(if parent.is_empty() { "/" } else { parent }.into())
                .or_default()
                .push(CheapDirent {
                    name: name.into(),
                    mode: fi.mode,
                    size: fi.size,
                });
        }
        Ok(Self {
            data: Arc::new(Data {
                meta,
                options,
                swarm: Mutex::new(None),
                sources: Mutex::new(BTreeMap::new()),
                last: Mutex::new(None),
                verification,
                expected_hashes: OnceLock::new(),
                prefetching: AtomicBool::new(false),
                generation: AtomicU64::new(0),
            }),
            entries,
            children,
        })
    }

    pub fn infohash(&self) -> &str {
        self.data.meta.identity()
    }

    /// AI-BT2 hook: only files that passed the independent whole-file digest are
    /// eligible for Hub blob publication. The caller can read through this source.
    pub fn verified_file_sha256(&self, path: &str) -> Option<String> {
        let fi = self.lookup(path, 0)?;
        let id = file_id(&fi).ok()?;
        let state = self.data.verification[id]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        state
            .complete
            .then(|| state.expected.map(hex::encode))
            .flatten()
    }
}

fn file_id(fi: &FileInfo) -> io::Result<usize> {
    fi.userdata
        .iter()
        .rev()
        .find_map(|u| match u {
            UserData::Other(s) => s.strip_prefix("torrent:")?.parse().ok(),
            _ => None,
        })
        .ok_or_else(|| invalid("missing torrent file identity"))
}

impl MountSource for TorrentMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        let path = normpath(path);
        let children = self.children.get(&path)?;
        Some(ListResult::Infos(
            children
                .iter()
                .map(|e| {
                    let child = format!("{}/{}", path.trim_end_matches('/'), e.name);
                    (e.name.clone(), self.entries[&child].clone())
                })
                .collect(),
        ))
    }
    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        self.children.get(&normpath(path)).cloned()
    }
    fn lookup(&self, path: &str, _version: i32) -> Option<FileInfo> {
        self.entries.get(&normpath(path)).cloned()
    }
    fn open(&self, fi: &FileInfo, _buffering: i32) -> io::Result<Box<dyn ArchiveRead>> {
        if fi.mode & S_IFDIR != 0 {
            return Err(io::Error::new(
                io::ErrorKind::IsADirectory,
                "torrent directory",
            ));
        }
        let file = file_id(fi)?;
        if file >= self.data.meta.files.len() {
            return Err(invalid("invalid torrent file identity"));
        }
        Ok(Box::new(TorrentReader {
            data: self.data.clone(),
            file,
            pos: 0,
        }))
    }
    fn is_immutable(&self) -> bool {
        true
    }
}

impl Data {
    fn key(&self, file: usize, offset: u64) -> (Piece, usize) {
        let f = &self.meta.files[file];
        let v2 = f.v2.is_some();
        let offset = if v2 { offset } else { f.offset + offset };
        (
            Piece {
                file: v2.then_some(file),
                index: offset / self.meta.piece_len,
            },
            (offset % self.meta.piece_len) as usize,
        )
    }

    fn size(&self, key: Piece) -> u64 {
        let total = key.file.map_or(self.meta.total, |f| self.meta.files[f].len);
        self.meta
            .piece_len
            .min(total - key.index * self.meta.piece_len)
    }

    fn token(&self, key: Piece) -> ContentToken {
        ContentToken::TorrentPiece {
            infohash: self.meta.identity().into(),
            file: key.file.map(|f| self.meta.files[f].path.clone()),
            piece: key.index,
            size: self.size(key),
        }
    }

    fn verify_piece(&self, key: Piece, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() as u64 != self.size(key) {
            return Err(invalid("short torrent piece"));
        }
        let valid = if let Some(file) = key.file {
            let f = &self.meta.files[file];
            let v2 = f.v2.as_ref().unwrap();
            let blocks = if f.len <= self.meta.piece_len {
                f.len.div_ceil(BLOCK as u64).next_power_of_two() as usize
            } else {
                self.meta.piece_len as usize / BLOCK
            };
            let root = piece_root(bytes, blocks);
            let expected = if f.len <= self.meta.piece_len {
                v2.root
            } else {
                v2.pieces[key.index as usize]
            };
            root == expected
        } else {
            Sha1::digest(bytes).as_slice() == self.meta.pieces[key.index as usize]
        };
        if !valid {
            return Err(invalid("torrent piece hash mismatch"));
        }
        Ok(())
    }

    fn cached(&self, key: Piece) -> Option<Vec<u8>> {
        let cache = self.options.range_cache.as_ref()?;
        let token = self.token(key);
        let mut out = Vec::new();
        for chunk in 0..self.size(key).div_ceil(cache.chunk_size()) {
            out.extend(cache.get(&token, chunk)?);
        }
        self.verify_piece(key, &out).ok()?;
        Some(out)
    }

    fn store(&self, key: Piece, bytes: &[u8]) {
        if let Some(cache) = &self.options.range_cache {
            for (chunk, data) in bytes.chunks(cache.chunk_size() as usize).enumerate() {
                if let Err(e) = cache.put(&self.token(key), chunk as u64, data) {
                    log::debug!("torrent range cache: {e}");
                }
            }
        }
    }

    fn piece(&self, key: Piece) -> io::Result<Arc<Vec<u8>>> {
        self.fetch_piece(key, true)
    }

    fn fetch_piece(&self, key: Piece, allow_swarm: bool) -> io::Result<Arc<Vec<u8>>> {
        if let Some((old, bytes)) = &*self.last.lock().unwrap_or_else(|e| e.into_inner()) {
            if *old == key {
                return Ok(bytes.clone());
            }
        }
        let bytes = if let Some(bytes) = self.cached(key) {
            bytes
        } else {
            let mut good = None;
            for seed in 0..self.meta.web_seeds.len() {
                match self.http_piece(key, seed).and_then(|b| {
                    self.verify_piece(key, &b)?;
                    Ok(b)
                }) {
                    Ok(bytes) => {
                        good = Some(bytes);
                        break;
                    }
                    Err(e) => log::warn!(
                        "torrent {} piece {} web seed {seed} refused: {e}",
                        self.meta.identity(),
                        key.index
                    ),
                }
            }
            let bytes = match good {
                Some(b) => b,
                None if allow_swarm => self.swarm_piece(key)?,
                None => return Err(io::Error::other("no verified HTTP piece for prefetch")),
            };
            self.verify_piece(key, &bytes)?;
            self.store(key, &bytes);
            bytes
        };
        let bytes = Arc::new(bytes);
        *self.last.lock().unwrap_or_else(|e| e.into_inner()) = Some((key, bytes.clone()));
        Ok(bytes)
    }

    fn http_source(&self, seed: usize, file: usize) -> io::Result<Arc<HttpRangeSource>> {
        let mut sources = self.sources.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = sources.get(&(seed, file)) {
            return Ok(s.clone());
        }
        let url = web_seed_url(&self.meta, seed, file)?;
        let mut auth = HttpAuthOptions::default();
        if let Some((repo_url, _)) = hub_file(&url) {
            // Credentials belong only to the actual Hub origin, not the Pirate
            // Face redirect proxy. HttpRangeSource strips them on every redirect.
            if Url::parse(&url).is_ok_and(|u| u.host_str() == Some("huggingface.co")) {
                if let Ok(repo) = HfRepo::resolve(&repo_url) {
                    auth = repo.torrent_http_auth(&url);
                }
            }
        }
        let source = Arc::new(
            HttpRangeSource::new(
                HttpLocation {
                    url,
                    auth: None,
                    cookie: None,
                },
                auth,
            )
            .without_range_cache(),
        );
        sources.insert((seed, file), source.clone());
        Ok(source)
    }

    fn http_piece(&self, key: Piece, seed: usize) -> io::Result<Vec<u8>> {
        let spans = if let Some(file) = key.file {
            vec![(
                file,
                key.index * self.meta.piece_len,
                self.size(key) as usize,
            )]
        } else {
            self.meta.spans(key.index)
        };
        let mut bytes = Vec::new();
        for (file, offset, len) in spans {
            if self.meta.files[file].padding {
                bytes.resize(bytes.len() + len, 0);
                continue;
            }
            let source = self.http_source(seed, file)?;
            bytes.extend(source.fetch(
                offset,
                offset + len as u64 - 1,
                self.meta.files[file].len,
                None,
            )?);
        }
        Ok(bytes)
    }

    fn swarm_piece(&self, key: Piece) -> io::Result<Vec<u8>> {
        if self.meta.v1_hash.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "v2 web seeds failed; librqbit 9.0.1 has no v2 swarm support",
            ));
        }
        let swarm = {
            let mut slot = self.swarm.lock().unwrap_or_else(|e| e.into_inner());
            if slot.is_none() {
                *slot = Some(Arc::new(Swarm::new(
                    self.options.swarm.clone(),
                    self.options.metadata_dir.join("scratch"),
                )?));
            }
            slot.as_ref().unwrap().clone()
        };
        let index = key.file.map_or(key.index, |f| {
            self.meta.files[f].offset / self.meta.piece_len + key.index
        });
        let spans = self
            .meta
            .spans(index)
            .into_iter()
            .map(|(f, offset, len)| ((!self.meta.files[f].padding).then_some(f), offset, len))
            .collect();
        let bytes = swarm.read(&self.meta.bytes, spans)?;
        self.verify_piece(Piece { file: None, index }, &bytes)?;
        Ok(bytes[..self.size(key) as usize].to_vec())
    }

    fn expected(&self, file: usize, state: &mut Verification) {
        if state.loaded {
            return;
        }
        state.loaded = true;
        let hashes = self
            .expected_hashes
            .get_or_init(|| checksums::load(&self.meta, &self.options.metadata_dir));
        state.expected = hashes.get(&self.meta.files[file].path).copied();
    }

    fn after_read(&self, file: usize, start: u64, end: u64) -> io::Result<()> {
        let mut state = self.verification[file]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if state.bad {
            return Err(io::Error::from_raw_os_error(5));
        }
        self.expected(file, &mut state);
        let Some(expected) = state.expected else {
            return Ok(());
        };
        if state.complete {
            return Ok(());
        }
        state.cover(start, end);
        let len = self.meta.files[file].len;
        if state.ranges.get(&0) != Some(&len) {
            return Ok(());
        }
        let mut hash = Sha256::new();
        let mut pos = 0;
        while pos < len {
            let (key, offset) = self.key(file, pos);
            let bytes = self.piece(key)?;
            let n = (len - pos).min((bytes.len() - offset) as u64) as usize;
            hash.update(&bytes[offset..offset + n]);
            pos += n as u64;
        }
        if hash.finalize().as_slice() != expected {
            state.bad = true;
            log::error!(
                "TORRENT SHA-256 MISMATCH: {} in {}; all further reads refused",
                self.meta.files[file].path,
                self.meta.identity()
            );
            return Err(io::Error::from_raw_os_error(5));
        }
        state.complete = true;
        state.ranges.clear();
        Ok(())
    }

    fn prefetch(self: &Arc<Self>, file: usize, pos: u64) {
        let limit = self.options.readahead_bytes.min(64 * 1024 * 1024);
        if limit == 0
            || !self
                .options
                .range_cache
                .as_ref()
                .is_some_and(RangeCache::is_enabled)
            || self.prefetching.swap(true, Ordering::AcqRel)
        {
            return;
        }
        let generation = self.generation.load(Ordering::Relaxed);
        let data = self.clone();
        let result = std::thread::Builder::new()
            .name("torrent-readahead".into())
            .spawn(move || {
                let end = pos.saturating_add(limit).min(data.meta.files[file].len);
                let mut pos = pos;
                while pos < end && data.generation.load(Ordering::Relaxed) == generation {
                    let (key, offset) = data.key(file, pos);
                    // Speculative HTTP failures must not queue ahead of a demand
                    // request on the swarm bridge. rqbit has its own stream lookahead.
                    match data.fetch_piece(key, false) {
                        Ok(bytes) => pos += (bytes.len() - offset) as u64,
                        Err(_) => break,
                    }
                }
                data.prefetching.store(false, Ordering::Release);
            });
        if result.is_err() {
            self.prefetching.store(false, Ordering::Release);
        }
    }
}

fn web_seed_url(meta: &Metainfo, seed: usize, file: usize) -> io::Result<String> {
    let base = &meta.web_seeds[seed];
    let mut url = Url::parse(base).map_err(|_| invalid("invalid web seed URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(invalid("web seed must use HTTP(S)"));
    }
    if meta.multi || url.path().ends_with('/') {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| invalid("invalid web seed base"))?;
        segments.pop_if_empty();
        if meta.multi {
            segments.push(&meta.name);
        }
        for part in meta.files[file].path.split('/') {
            segments.push(part);
        }
    }
    Ok(url.to_string())
}

/// Pinned Hub URLs, including Pirate Face's BEP 19 redirect proxy. A mutable
/// branch is never treated as independent evidence for a torrent checksum.
fn hub_file(url: &str) -> Option<(String, String)> {
    let url = Url::parse(url).ok()?;
    if url.scheme() != "https"
        || url.port_or_known_default() != Some(443)
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return None;
    }
    let parts: Vec<_> = url.path_segments()?.collect();
    let (kind, owner, repo, revision, path) = match url.host_str()? {
        "huggingface.co" => {
            let (kind, p) = if matches!(parts.first().copied(), Some("datasets" | "spaces")) {
                (format!("{}/", parts[0]), &parts[1..])
            } else {
                (String::new(), parts.as_slice())
            };
            if p.len() < 5 || p[2] != "resolve" {
                return None;
            }
            (kind, p[0], p[1], p[3], p[4..].join("/"))
        }
        "pirateface.co" if parts.len() >= 6 && parts[..2] == ["api", "ws"] => {
            // web_seed_url adds the torrent root before the repo-relative path.
            (
                String::new(),
                parts[2],
                parts[3],
                parts[4],
                parts[6..].join("/"),
            )
        }
        _ => return None,
    };
    if revision.len() != 40 || !revision.bytes().all(|b| b.is_ascii_hexdigit()) || path.is_empty() {
        return None;
    }
    // Reuse the Hub parser for percent decoding without treating '+' as space.
    let decoded =
        crate::parse_hf_url(&format!("hf://{kind}{owner}/{repo}@{revision}/{path}")).ok()?;
    Some((
        format!("hf://{kind}{owner}/{repo}@{revision}"),
        decoded.path,
    ))
}

struct TorrentReader {
    data: Arc<Data>,
    file: usize,
    pos: u64,
}
impl Read for TorrentReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = self.data.meta.files[self.file].len;
        if self.data.verification[self.file]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .bad
        {
            return Err(io::Error::from_raw_os_error(5));
        }
        if buf.is_empty() {
            return Ok(0);
        }
        if self.pos >= len {
            if len == 0 {
                self.data.after_read(self.file, 0, 0)?;
            }
            return Ok(0);
        }
        let (key, offset) = self.data.key(self.file, self.pos);
        let bytes = self.data.piece(key)?;
        let n = buf
            .len()
            .min(bytes.len() - offset)
            .min((len - self.pos).min(usize::MAX as u64) as usize);
        // Do not copy the completing read to the caller until whole-file verification succeeds.
        self.data
            .after_read(self.file, self.pos, self.pos + n as u64)?;
        buf[..n].copy_from_slice(&bytes[offset..offset + n]);
        self.pos += n as u64;
        self.data.prefetch(self.file, self.pos);
        Ok(n)
    }
}
impl Seek for TorrentReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let next = match from {
            SeekFrom::Start(n) => n as i128,
            SeekFrom::Current(n) => self.pos as i128 + n as i128,
            SeekFrom::End(n) => self.data.meta.files[self.file].len as i128 + n as i128,
        };
        self.pos = u64::try_from(next)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid torrent seek"))?;
        self.data.generation.fetch_add(1, Ordering::Relaxed);
        Ok(self.pos)
    }
}

#[cfg(test)]
mod tests;
