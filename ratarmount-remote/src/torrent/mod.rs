//! Lazy torrent trees. HTTP payloads are never cached until the entire piece verifies.

mod cache;
mod checksums;
mod metadata;
mod metainfo;
mod pieces;
mod scratch;
mod seeding;
mod swarm;
mod verification;

use std::collections::BTreeMap;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};

use ratarmount_core::{
    create_root_file_info, normpath, ArchiveRead, CheapDirent, FileInfo, ListResult, MountSource,
    UserData, S_IFDIR, S_IFREG,
};
use ratarmount_index::{ContentToken, RangeCache};
use sha1::Sha1;
use sha2::Digest;
#[cfg(test)]
use sha2::Sha256;
use url::Url;

use crate::{HfRepo, HttpAuthOptions, HttpLocation, HttpRangeSource};
use metainfo::{invalid, piece_root, Metainfo, BLOCK};
pub use ratarmount_core::TorrentSwarmPolicy;
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Piece {
    file: Option<usize>,
    index: u64,
}

#[derive(Default)]
struct Verification {
    expected: Option<[u8; 32]>,
    notified: bool,
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
    self_ref: std::sync::Weak<Data>,
    seed_pending: Mutex<std::collections::BTreeSet<u64>>,
    stopped: AtomicBool,
    lan_probe_done: AtomicBool,
    lan_retry_at: Mutex<Option<std::time::Instant>>,
    swarm_gate: Mutex<()>,
    hub: cache::HubFiles,
    swarm: Mutex<Option<Arc<Swarm>>>,
    seeder: Mutex<Option<Arc<Swarm>>>,
    sources: Mutex<HttpSources>,
    pieces: Mutex<pieces::Pieces>,
    verification: Vec<Mutex<Verification>>,
    verify_tx: mpsc::Sender<verification::Event>,
}

/// A read-only metadata tree; constructing/listing it fetches no payload pieces.
pub struct TorrentMountSource {
    data: Arc<Data>,
    entries: BTreeMap<String, FileInfo>,
    children: BTreeMap<String, Vec<CheapDirent>>,
}

impl TorrentMountSource {
    pub fn open(input: &str, mut options: TorrentOptions) -> io::Result<Self> {
        options.swarm.validate()?;
        Self::from_metainfo(metadata::resolve(input, &mut options)?, options)
    }

    pub fn from_bytes(bytes: Vec<u8>, options: TorrentOptions) -> io::Result<Self> {
        options.swarm.validate()?;
        let meta = Metainfo::parse(bytes)?;
        Self::from_metainfo(meta, options)
    }

    fn from_metainfo(meta: Metainfo, options: TorrentOptions) -> io::Result<Self> {
        let hub = cache::HubFiles::new(&meta);
        Self::with_hub(meta, options, hub)
    }

    fn with_hub(meta: Metainfo, options: TorrentOptions, hub: cache::HubFiles) -> io::Result<Self> {
        options.swarm.validate()?;
        if options.swarm.seed && meta.v1_hash.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "librqbit 9.0.1 cannot seed v2-only torrents",
            ));
        }
        let mut entries = BTreeMap::new();
        entries.insert("/".to_string(), create_root_file_info());
        let known = checksums::cached_only(&meta, &options.metadata_dir);
        let verification = meta
            .files
            .iter()
            .map(|f| {
                Mutex::new(Verification {
                    expected: f.sha256.or_else(|| known.get(&f.path).copied()),
                    bad: f
                        .sha256
                        .zip(known.get(&f.path).copied())
                        .is_some_and(|(a, b)| a != b),
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
        let (verify_tx, verify_rx) = mpsc::channel();
        let data = Arc::new_cyclic(|weak| Data {
            meta,
            options,
            self_ref: weak.clone(),
            seed_pending: Mutex::default(),
            stopped: AtomicBool::new(false),
            lan_probe_done: AtomicBool::new(false),
            lan_retry_at: Mutex::default(),
            swarm_gate: Mutex::new(()),
            hub,
            swarm: Mutex::new(None),
            seeder: Mutex::new(None),
            sources: Mutex::new(BTreeMap::new()),
            pieces: Mutex::default(),
            verification,
            verify_tx,
        });
        verification::start(&data, verify_rx)?;
        if data.options.swarm.seed {
            data.start_seed()?;
        } else if matches!(
            data.options.swarm.policy,
            TorrentSwarmPolicy::Always | TorrentSwarmPolicy::Lan
        ) {
            data.start_swarm()?;
        }
        Ok(Self {
            data,
            entries,
            children,
        })
    }

    pub fn infohash(&self) -> &str {
        self.data.meta.identity()
    }

    /// Independent whole-file digest, available after its background check succeeds.
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

impl Drop for TorrentMountSource {
    fn drop(&mut self) {
        self.data.stopped.store(true, Ordering::Release);
        for slot in [&self.data.swarm, &self.data.seeder] {
            if let Some(swarm) = slot.lock().unwrap_or_else(|e| e.into_inner()).as_ref() {
                swarm.stop();
            }
        }
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
            prefetch: Arc::default(),
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

    fn available_piece(&self, key: Piece) -> Option<Arc<Vec<u8>>> {
        if let Some(bytes) = self
            .pieces
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
        {
            return Some(bytes);
        }
        let bytes = self.cached(key).or_else(|| self.hub.piece(self, key))?;
        self.verify_piece(key, &bytes).ok()?;
        let bytes = Arc::new(bytes);
        self.pieces
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, bytes.clone());
        Some(bytes)
    }

    fn notify_seed(&self, key: Piece) {
        if self.options.swarm.seed {
            let index = key.file.map_or(key.index, |f| {
                self.meta.files[f].offset / self.meta.piece_len + key.index
            });
            self.seed_pending
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(index);
        }
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
        let (flight, owner) = {
            let mut pieces = self.pieces.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(bytes) = pieces.get(key) {
                return Ok(bytes);
            }
            if let Some(flight) = pieces.flights.get(&key) {
                (flight.clone(), false)
            } else {
                let flight = Arc::new(pieces::Flight::new(allow_swarm));
                pieces.flights.insert(key, flight.clone());
                (flight, true)
            }
        };
        if !owner {
            let result = flight.wait();
            if result.is_err() && allow_swarm && !flight.allow_swarm {
                return self.fetch_piece(key, true);
            }
            return result;
        }
        let result = self.produce_piece(key, allow_swarm).map(Arc::new);
        {
            let mut pieces = self.pieces.lock().unwrap_or_else(|e| e.into_inner());
            if let Ok(bytes) = &result {
                pieces.insert(key, bytes.clone());
                let _ = self
                    .verify_tx
                    .send(verification::Event::Piece(key, Arc::downgrade(bytes)));
            }
            flight.finish(&result);
            pieces.flights.remove(&key);
        }
        result
    }

    fn produce_piece(&self, key: Piece, allow_swarm: bool) -> io::Result<Vec<u8>> {
        let bytes = if let Some(bytes) = self.cached(key).or_else(|| self.hub.piece(self, key)) {
            bytes
        } else {
            let mut good = if allow_swarm && self.options.swarm.policy == TorrentSwarmPolicy::Lan {
                match self.swarm_piece(key).and_then(|b| {
                    self.verify_piece(key, &b)?;
                    Ok(b)
                }) {
                    Ok(bytes) => Some(bytes),
                    Err(e) => {
                        log::debug!("torrent LAN peer unavailable: {e}");
                        None
                    }
                }
            } else {
                None
            };
            for seed in 0..self.meta.web_seeds.len() {
                if good.is_some() {
                    break;
                }
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
                None if allow_swarm && self.options.swarm.policy != TorrentSwarmPolicy::Lan => {
                    self.swarm_piece(key)?
                }
                None if allow_swarm => {
                    return Err(io::Error::other(
                        "no verified piece available from LAN peers or web seeds",
                    ))
                }
                None => return Err(io::Error::other("no verified HTTP piece for prefetch")),
            };
            self.verify_piece(key, &bytes)?;
            self.store(key, &bytes);
            if self.options.swarm.seed {
                self.notify_seed(key);
            }
            bytes
        };
        Ok(bytes)
    }

    fn http_source(&self, seed: usize, file: usize) -> io::Result<Arc<HttpRangeSource>> {
        let mut sources = self.sources.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(s) = sources.get(&(seed, file)) {
            return Ok(s.clone());
        }
        let url = web_seed_url(&self.meta, seed, file)?;
        let auth = if Url::parse(&url).is_ok_and(|u| u.host_str() == Some("huggingface.co")) {
            HfRepo::torrent_auth_from_env(&url)
        } else {
            HttpAuthOptions::default()
        };
        let source = Arc::new(
            HttpRangeSource::new(
                HttpLocation {
                    url,
                    auth: None,
                    cookie: None,
                },
                auth,
            )
            .without_range_cache()
            .with_max_skip_prefix(1024 * 1024),
        );
        sources.insert((seed, file), source.clone());
        Ok(source)
    }

    fn spans(&self, key: Piece) -> Vec<(usize, u64, usize)> {
        key.file.map_or_else(
            || self.meta.spans(key.index),
            |file| {
                vec![(
                    file,
                    key.index * self.meta.piece_len,
                    self.size(key) as usize,
                )]
            },
        )
    }

    fn start_swarm(&self) -> io::Result<Arc<Swarm>> {
        self.start_session(false)
    }

    fn start_seed(&self) -> io::Result<Arc<Swarm>> {
        self.start_session(true)
    }

    fn start_session(&self, seed: bool) -> io::Result<Arc<Swarm>> {
        if self.stopped.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "torrent source unmounted",
            ));
        }
        // A downloader can read incomplete scratch blocks internally. Keep that
        // protocol storage separate from the upload session's verified-cache view.
        let slot = if seed { &self.seeder } else { &self.swarm };
        let mut slot = slot.lock().unwrap_or_else(|e| e.into_inner());
        if slot.is_none() {
            let mut options = self.options.swarm.clone();
            options.seed = seed;
            *slot = Some(Arc::new(Swarm::with_cache(
                options,
                self.options.metadata_dir.join("scratch"),
                self.meta.identity(),
                self.self_ref.clone(),
            )?));
        }
        Ok(slot.as_ref().unwrap().clone())
    }

    fn http_piece(&self, key: Piece, seed: usize) -> io::Result<Vec<u8>> {
        let spans = self.spans(key);
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
        let lan = self.options.swarm.policy == TorrentSwarmPolicy::Lan;
        let _gate = if lan && !self.meta.web_seeds.is_empty() {
            // Another LAN attempt must never hold unrelated web-seed reads up.
            self.swarm_gate.try_lock().map_err(|_| {
                io::Error::new(io::ErrorKind::WouldBlock, "LAN probe already running")
            })?
        } else {
            self.swarm_gate.lock().unwrap_or_else(|e| e.into_inner())
        };
        if lan
            && self
                .lan_retry_at
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .is_some_and(|at| std::time::Instant::now() < at)
        {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "LAN peers unavailable; discovery backoff",
            ));
        }
        if self.meta.v1_hash.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "v2 web seeds failed; librqbit 9.0.1 has no v2 swarm support",
            ));
        }
        let index = key.file.map_or(key.index, |f| {
            self.meta.files[f].offset / self.meta.piece_len + key.index
        });
        let spans: Vec<_> = self
            .meta
            .spans(index)
            .into_iter()
            .map(|(f, offset, len)| ((!self.meta.files[f].padding).then_some(f), offset, len))
            .collect();
        let auto_lan = self.options.swarm.policy == TorrentSwarmPolicy::Auto
            && self.options.swarm.lsd
            && !self.options.swarm.seed;
        let probe = auto_lan && !self.lan_probe_done.swap(true, Ordering::AcqRel);
        if probe {
            let mut options = self.options.swarm.clone();
            options.policy = TorrentSwarmPolicy::Lan;
            options.announced = Arc::default();
            // Explicit peer overrides must also stay inside the LAN probe's policy.
            options
                .initial_peers
                .retain(|peer| swarm::is_lan(peer.ip()));
            if let Ok(local) = Swarm::with_cache(
                options,
                self.options.metadata_dir.join("scratch"),
                self.meta.identity(),
                self.self_ref.clone(),
            ) {
                let local = Arc::new(local);
                {
                    let mut slot = self.swarm.lock().unwrap_or_else(|e| e.into_inner());
                    if self.stopped.load(Ordering::Acquire) {
                        local.stop();
                        return Err(io::Error::new(
                            io::ErrorKind::Interrupted,
                            "torrent source unmounted",
                        ));
                    }
                    // Register the probe before waiting, so unmount cancels it too.
                    *slot = Some(local.clone());
                }
                let result = local.read_with_timeout(
                    &self.meta.bytes,
                    spans.clone(),
                    Some(
                        self.options
                            .swarm
                            .timeout
                            .min(std::time::Duration::from_secs(3)),
                    ),
                );
                if let Ok(bytes) = result {
                    self.verify_piece(Piece { file: None, index }, &bytes)?;
                    return Ok(bytes[..self.size(key) as usize].to_vec());
                }
                local.stop();
                self.swarm.lock().unwrap_or_else(|e| e.into_inner()).take();
            }
        }
        let swarm = self.start_swarm()?;
        let result = if lan {
            swarm.read_with_timeout(
                &self.meta.bytes,
                spans.clone(),
                Some(
                    self.options
                        .swarm
                        .timeout
                        .min(std::time::Duration::from_secs(2)),
                ),
            )
        } else {
            swarm.read(&self.meta.bytes, spans.clone())
        };
        if lan {
            *self.lan_retry_at.lock().unwrap_or_else(|e| e.into_inner()) = result
                .is_err()
                .then(|| std::time::Instant::now() + std::time::Duration::from_secs(60));
        }
        let bytes = match result {
            Ok(bytes) => bytes,
            Err(_) if auto_lan && swarm.lan_only => {
                swarm.stop();
                self.swarm.lock().unwrap_or_else(|e| e.into_inner()).take();
                self.start_swarm()?.read(&self.meta.bytes, spans)?
            }
            Err(e) => return Err(e),
        };
        self.verify_piece(Piece { file: None, index }, &bytes)?;
        Ok(bytes[..self.size(key) as usize].to_vec())
    }

    fn after_read(&self, file: usize, start: u64, end: u64) -> io::Result<()> {
        let mut state = self.verification[file]
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if state.bad {
            return Err(io::Error::from_raw_os_error(5));
        }
        if !state.complete && !state.notified {
            state.cover(start, end);
            if state.ranges.get(&0) == Some(&self.meta.files[file].len) {
                state.notified = true;
                let _ = self.verify_tx.send(verification::Event::Complete(file));
            }
        }
        Ok(())
    }

    fn prefetch(self: &Arc<Self>, file: usize, pos: u64, reader: &Arc<Prefetch>) {
        let limit = self.options.readahead_bytes.min(64 * 1024 * 1024);
        if limit == 0
            || !self
                .options
                .range_cache
                .as_ref()
                .is_some_and(RangeCache::is_enabled)
            || reader.running.swap(true, Ordering::AcqRel)
        {
            return;
        }
        let generation = reader.generation.load(Ordering::Relaxed);
        let worker = reader.clone();
        let data = self.clone();
        let result = std::thread::Builder::new()
            .name("torrent-readahead".into())
            .spawn(move || {
                let end = pos.saturating_add(limit).min(data.meta.files[file].len);
                let mut pos = pos;
                while pos < end && worker.generation.load(Ordering::Relaxed) == generation {
                    let (key, offset) = data.key(file, pos);
                    // Speculative HTTP failures must not queue ahead of a demand
                    // request on the swarm bridge. rqbit has its own stream lookahead.
                    match data.fetch_piece(key, false) {
                        Ok(bytes) => pos += (bytes.len() - offset) as u64,
                        Err(_) => break,
                    }
                }
                worker.running.store(false, Ordering::Release);
            });
        if result.is_err() {
            reader.running.store(false, Ordering::Release);
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

#[derive(Default)]
struct Prefetch {
    running: AtomicBool,
    generation: AtomicU64,
}

struct TorrentReader {
    data: Arc<Data>,
    file: usize,
    pos: u64,
    prefetch: Arc<Prefetch>,
}
impl Drop for TorrentReader {
    fn drop(&mut self) {
        self.prefetch.generation.fetch_add(1, Ordering::Relaxed);
    }
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
        // Piece integrity is synchronous; the independent whole-file digest is asynchronous.
        self.data
            .after_read(self.file, self.pos, self.pos + n as u64)?;
        buf[..n].copy_from_slice(&bytes[offset..offset + n]);
        self.pos += n as u64;
        self.data.prefetch(self.file, self.pos, &self.prefetch);
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
        self.prefetch.generation.fetch_add(1, Ordering::Relaxed);
        Ok(self.pos)
    }
}

#[cfg(test)]
mod tests;
