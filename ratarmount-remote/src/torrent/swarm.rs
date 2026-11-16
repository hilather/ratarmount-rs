//! Blocking bridge to a private rqbit runtime. No runtime is entered on a FUSE thread.

use super::{scratch, seeding, Data, TorrentSwarmPolicy};
use futures_lite::StreamExt;
use librqbit::storage::StorageFactoryExt;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, Weak};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use librqbit::{
    AddTorrent, AddTorrentOptions, AddTorrentResponse, DhtSessionConfig, Session, SessionOptions,
};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

#[derive(Clone, Debug)]
pub struct SwarmOptions {
    pub dht: bool,
    pub trackers: bool,
    pub initial_peers: Vec<SocketAddr>,
    pub timeout: Duration,
    pub policy: TorrentSwarmPolicy,
    pub scratch_bytes: u64,
    pub lsd: bool,
    pub seed: bool,
    /// rqbit limits have a one-second burst capacity and accept u32 byte rates.
    pub upload_limit: u32,
    pub listen_port: u16,
    /// Library/test override; the CLI listens on all interfaces when seeding.
    pub listen_ip: std::net::IpAddr,
    /// Shared across metadata resolution and payload sessions for one mount.
    pub announced: Arc<AtomicBool>,
}

impl Default for SwarmOptions {
    fn default() -> Self {
        Self {
            dht: true,
            trackers: true,
            initial_peers: Vec::new(),
            timeout: Duration::from_secs(30),
            policy: TorrentSwarmPolicy::default(),
            scratch_bytes: 2 * 1024 * 1024 * 1024,
            lsd: true,
            seed: false,
            upload_limit: 1024 * 1024,
            listen_port: 0,
            listen_ip: std::net::Ipv6Addr::UNSPECIFIED.into(),
            announced: Arc::default(),
        }
    }
}

impl SwarmOptions {
    pub(crate) fn validate(&self) -> io::Result<()> {
        if self.seed && self.policy == TorrentSwarmPolicy::Never {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--seed conflicts with --torrent-swarm never (the default); pass --torrent-swarm lan, auto or always",
            ));
        }
        if self.policy == TorrentSwarmPolicy::Lan
            && self.initial_peers.iter().any(|peer| !is_lan(peer.ip()))
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--torrent-swarm lan requires private, link-local or loopback peer addresses",
            ));
        }
        if self.seed && self.upload_limit > 1_000_000_000 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--seed-upload-limit must be at most 1000000000 bytes/s (limiter clock resolution)",
            ));
        }
        if self.seed && self.upload_limit < 16 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "--seed-upload-limit must be at least 16384 bytes/s (one protocol block)",
            ));
        }
        Ok(())
    }

    fn effective_upload_limit(&self) -> u32 {
        // governor's per_second() floors the per-byte interval to nanoseconds.
        // Round down the rate first, retaining capacity for one protocol block.
        const NANOS_PER_SECOND: u64 = 1_000_000_000;
        let requested = u64::from(self.upload_limit.clamp(16 * 1024, 1_000_000_000));
        let interval = NANOS_PER_SECOND.div_ceil(requested);
        (NANOS_PER_SECOND / interval).max(16 * 1024) as u32
    }

    fn public_discovery(&self) -> bool {
        self.policy != TorrentSwarmPolicy::Lan && self.policy != TorrentSwarmPolicy::Never
    }
}

pub(super) fn is_lan(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ip) => ip.is_private() || ip.is_loopback() || ip.is_link_local(),
        std::net::IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or_else(
            || ip.is_loopback() || ip.is_unique_local() || ip.is_unicast_link_local(),
            |ip| is_lan(ip.into()),
        ),
    }
}

// Applied to incoming connections and PEX peers too, so a LAN peer cannot
// introduce an internet peer after DHT and trackers have been disabled.
const LAN_ALLOWLIST: &str = concat!(
    "loopback:127.0.0.0-127.255.255.255\n",
    "private:10.0.0.0-10.255.255.255\n",
    "private:172.16.0.0-172.31.255.255\n",
    "private:192.168.0.0-192.168.255.255\n",
    "link:169.254.0.0-169.254.255.255\n",
    "loopback:::1-::1\n",
    "private:fc00::-fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff\n",
    "link:fe80::-febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff\n",
    "mapped:::ffff:127.0.0.0-::ffff:127.255.255.255\n",
    "mapped:::ffff:10.0.0.0-::ffff:10.255.255.255\n",
    "mapped:::ffff:172.16.0.0-::ffff:172.31.255.255\n",
    "mapped:::ffff:192.168.0.0-::ffff:192.168.255.255\n",
    "mapped:::ffff:169.254.0.0-::ffff:169.254.255.255\n",
);

fn lan_listen_ip() -> std::net::IpAddr {
    // UDP connect selects a route without transmitting a packet. A public default
    // address must never turn the LAN discovery listener into a public listener.
    let local = || -> io::Result<std::net::IpAddr> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
        socket.connect("192.0.2.1:9")?;
        Ok(socket.local_addr()?.ip())
    };
    local()
        .ok()
        .filter(|ip| is_lan(*ip))
        .unwrap_or(std::net::Ipv4Addr::LOCALHOST.into())
}

pub(crate) fn session_options(options: &SwarmOptions) -> SessionOptions {
    SessionOptions {
        dht: (options.dht && options.public_discovery()).then(|| DhtSessionConfig {
            persistence: None,
            ..Default::default()
        }),
        disable_trackers: !options.trackers || !options.public_discovery(),
        disable_upload: !options.seed,
        disable_local_service_discovery: !options.lsd
            || options.policy == TorrentSwarmPolicy::Never,
        // Public downloaders never accept inbound TCP connections. LAN discovery
        // may solicit replies using a listener bound to one private local address.
        listen: (options.seed || (options.lsd && options.policy == TorrentSwarmPolicy::Lan)).then(
            || librqbit::ListenerOptions {
                listen_addr: SocketAddr::new(
                    if options.seed || is_lan(options.listen_ip) {
                        options.listen_ip
                    } else {
                        lan_listen_ip()
                    },
                    if options.seed { options.listen_port } else { 0 },
                ),
                ..Default::default()
            },
        ),
        ratelimits: librqbit::limits::LimitsConfig {
            upload_bps: std::num::NonZeroU32::new(options.effective_upload_limit()),
            ..Default::default()
        },
        persistence: None,
        peer_limit: Some(32),
        runtime_worker_threads: Some(2),
        ..Default::default()
    }
}

type Reply = mpsc::SyncSender<io::Result<Vec<u8>>>;
enum Command {
    Resolve(String, Reply),
    Read(
        Vec<u8>,
        Vec<(Option<usize>, u64, usize)>,
        Option<Duration>,
        Reply,
    ),
}

pub(crate) struct Swarm {
    tx: Option<mpsc::SyncSender<Command>>,
    thread: Mutex<Option<JoinHandle<()>>>,
    cancel: Box<dyn Fn() + Send + Sync>,
    pub(super) lan_only: bool,
    metadata_peers: Arc<Mutex<Vec<SocketAddr>>>,
    #[cfg(test)]
    pub(super) listen_addr: Option<SocketAddr>,
    #[cfg(test)]
    pub(super) seed_checks: Arc<Mutex<Vec<u32>>>,
}

fn error(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("torrent swarm: {e}"))
}

async fn until_stopped<T>(
    session: &Session,
    work: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    tokio::select! {
        _ = session.cancellation_token().cancelled() => Err(io::Error::new(io::ErrorKind::Interrupted, "torrent source unmounted")),
        result = work => result,
    }
}

async fn command_deadline<T>(
    session: &Session,
    timeout: Duration,
    connected_timeout: Option<Duration>,
    work: impl std::future::Future<Output = io::Result<T>>,
) -> io::Result<T> {
    let timed_out = || io::Error::new(io::ErrorKind::TimedOut, "torrent swarm timed out");
    tokio::pin!(work);
    until_stopped(session, async {
        tokio::select! {
            result = &mut work => result,
            _ = tokio::time::sleep(timeout) => {
                let connected = session.with_torrents(|torrents| {
                    for (_, torrent) in torrents {
                        if torrent.live().is_some_and(|live| live.stats_snapshot().peer_stats.live != 0) { return true; }
                    }
                    false
                });
                if let Some(limit) = connected_timeout.filter(|_| connected) {
                    // With no web-seed fallback, a connected, capped transfer is
                    // allowed its normal deadline. Discovery still fails quickly.
                    tokio::time::timeout(limit.saturating_sub(timeout), &mut work).await.map_err(|_| timed_out())?
                } else { Err(timed_out()) }
            }
        }
    }).await
}

async fn add_payload(
    session: &Arc<Session>,
    options: &SwarmOptions,
    bytes: Vec<u8>,
    initializing: &AtomicBool,
) -> io::Result<Arc<librqbit::ManagedTorrent>> {
    initializing.store(true, Ordering::Release);
    let torrent = session
        .add_torrent(
            AddTorrent::TorrentFileBytes(bytes.into()),
            Some(AddTorrentOptions {
                paused: true,
                only_files: Some(Vec::new()),
                initial_peers: Some(options.initial_peers.clone()),
                disable_trackers: !options.trackers || !options.public_discovery(),
                overwrite: true,
                ..Default::default()
            }),
        )
        .await
        .map_err(error)?
        .into_handle()
        .ok_or_else(|| error("no torrent handle"))?;
    torrent.wait_until_initialized().await.map_err(error)?;
    initializing.store(false, Ordering::Release);
    Ok(torrent)
}

impl Swarm {
    pub fn new(options: SwarmOptions, cache_dir: PathBuf, infohash: &str) -> io::Result<Self> {
        Self::with_cache(options, cache_dir, infohash, Weak::new())
    }

    pub(super) fn with_cache(
        options: SwarmOptions,
        cache_dir: PathBuf,
        infohash: &str,
        data: Weak<Data>,
    ) -> io::Result<Self> {
        options.validate()?;
        if options.policy == TorrentSwarmPolicy::Never {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "--torrent-swarm never: metadata or a verified piece is unavailable from cache/web seeds; pass --torrent-swarm lan or auto to allow peers"));
        }
        if !options.announced.swap(true, Ordering::Relaxed) {
            if options.policy == TorrentSwarmPolicy::Lan {
                log::info!("BitTorrent LAN swarm enabled for {infohash}: local discovery only; DHT and trackers disabled");
            } else {
                log::info!("BitTorrent swarm enabled for {infohash}: your IP is visible to trackers/DHT peers");
            }
        }
        let lan_only = options.policy == TorrentSwarmPolicy::Lan;
        let metadata_peers = Arc::new(Mutex::new(Vec::new()));
        let found_peers = metadata_peers.clone();
        #[cfg(test)]
        let seed_checks: Arc<Mutex<Vec<u32>>> = Arc::default();
        #[cfg(test)]
        let checked_pieces = seed_checks.clone();
        let (tx, rx) = mpsc::sync_channel(8);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("torrent-runtime".into())
            .spawn(move || {
                let initializing = Arc::new(AtomicBool::new(true));
                let setup = || -> io::Result<_> {
                    #[expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-E0091-M01","item":"<ratarmount_remote::torrent::swarm::Swarm>::with_cache","disposition":"output-owner","category":"torrent-scratch-directory","reason":"Create the selected swarm cache root before stale scratch sweeping and private scratch allocation.","creation":{"policy":"recursive-directory","basis":"The cache root keeps current defaults; tempfile creates the per-swarm child and its ownership marker is reviewed separately."}}"###)]
std::fs::create_dir_all(&cache_dir)?;
                    scratch::sweep(&cache_dir, Duration::from_secs(24 * 60 * 60));
                    #[expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0535-M01","item":"<ratarmount_remote::torrent::swarm::Swarm>::with_cache","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###)]
let scratch = tempfile::Builder::new()
                        .prefix("swarm-")
                        .tempdir_in(cache_dir)?;
                    let owner = scratch::mark_owned(scratch.path())?;
                    let rt = tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .enable_all()
                        .build()?;
                    let mut config = session_options(&options);
                    if options.policy == TorrentSwarmPolicy::Lan && data.strong_count() == 0 {
                        // Metadata uses the actively queried, address-filtered LSD stream
                        // below; rqbit's metadata resolver does not apply its peer allowlist.
                        config.disable_local_service_discovery = true;
                    }
                    if options.policy == TorrentSwarmPolicy::Lan {
                        let path = scratch.path().join("lan-allowlist.txt");
                        #[expect(clippy::disallowed_methods, reason = r###"internal-read:v1 {"id":"IR-B0536-M01","item":"<ratarmount_remote::torrent::swarm::Swarm>::with_cache","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###)]
std::fs::write(&path, LAN_ALLOWLIST)?;
                        config.allowlist_url = Some(url::Url::from_file_path(path).map_err(|_| error("invalid LAN allowlist path"))?.into());
                    }
                    if config.dht.is_some() {
                        config.bind_device_name = default_device()?;
                        config.ipv4_only = true;
                    }
                    let factory = scratch::Factory {
                        dir: scratch.path().to_owned(),
                        limit: options.scratch_bytes,
                    };
                    config.default_storage_factory = Some(if options.seed && data.strong_count() != 0 {
                        seeding::Factory { scratch: factory, data: data.clone(), initializing: initializing.clone() }.boxed()
                    } else {
                        factory.boxed()
                    });
                    let session = rt
                        .block_on(Session::new_with_opts(scratch.path().to_owned(), config))
                        .map_err(error)?;
                    Ok((scratch, owner, rt, session))
                };
                let (scratch, owner, rt, session) = match setup() {
                    Ok(value) => {
                        let token = value.3.cancellation_token().clone();
                        let addr = value.3.listen_addr();
                        let cancel: Box<dyn Fn() + Send + Sync> = Box::new(move || token.cancel());
                        let _ = ready_tx.send(Ok((cancel, addr)));
                        value
                    }
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                let mut handle: Option<std::sync::Arc<librqbit::ManagedTorrent>> = None;
                let mut current_file = None;
                let mut current_stream = None;
                if options.seed {
                    log::warn!("BITTORRENT SEEDING ENABLED: incoming {:?}; upload limit {} bytes/s; verified pieces only; stops on unmount", session.listen_addr(), options.effective_upload_limit());
                }
                let mut seed_ready = false;
                let mut seed_cursor = 0u64;
                loop {
                    if session.cancellation_token().is_cancelled() { break; }
                    let queued = match rx.try_recv() {
                        Ok(command) => Some(command),
                        Err(mpsc::TryRecvError::Empty) => None,
                        Err(mpsc::TryRecvError::Disconnected) => break,
                    };
                    if options.seed {
                        if let Some(data) = data.upgrade() {
                            if handle.is_none() {
                                let result = rt.block_on(until_stopped(&session, async {
                                    let torrent = add_payload(&session, &options, data.meta.bytes.clone(), &initializing).await?;
                                    session.unpause(&torrent).await.map_err(error)?;
                                    Ok(torrent)
                                }));
                                match result {
                                    Ok(torrent) => handle = Some(torrent),
                                    Err(e) => { log::warn!("torrent seed initialization: {e}"); break; }
                                }
                            }
                            if let Some(live) = handle.as_ref().and_then(|h| h.live()) {
                                // Inspect each cache slot once on startup; thereafter only
                                // newly verified pieces. HAVE updates keep peers connected.
                                let count = data.meta.total.div_ceil(data.meta.piece_len);
                                let mut pending = data.seed_pending.lock().unwrap_or_else(|e| e.into_inner());
                                let mut batch = Vec::with_capacity(32);
                                while batch.len() < 32 {
                                    if let Some(index) = pending.pop_first() { batch.push(index); }
                                    else if seed_cursor < count { batch.push(seed_cursor); seed_cursor += 1; }
                                    else { break; }
                                }
                                drop(pending);
                                for index in batch {
                                    #[cfg(test)]
                                    checked_pieces.lock().unwrap().push(index as u32);
                                    if session.cancellation_token().is_cancelled() { break; }
                                    if let Err(e) = rt.block_on(async { tokio::task::spawn_blocking({
                                        let live = live.clone();
                                        move || live.recheck_external_piece(index as u32)
                                    }).await }).map_err(error).and_then(|r| r.map_err(error)) {
                                        log::debug!("torrent seed piece {index} unavailable: {e}");
                                    }
                                }
                                if seed_cursor == count && !seed_ready {
                                    log::warn!("BITTORRENT SEEDING READY: initial cache inspection finished; verified pieces available on {:?}", session.listen_addr());
                                    seed_ready = true;
                                }
                                if seed_cursor < count && queued.is_none() { continue; }
                            }
                        }
                    }
                    let command = match queued.map(Ok).unwrap_or_else(|| rx.recv_timeout(Duration::from_millis(100))) {
                        Ok(command) => command,
                        Err(mpsc::RecvTimeoutError::Timeout) => continue,
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                    };
                    let reply = match &command {
                        Command::Resolve(_, r) | Command::Read(_, _, _, r) => r.clone(),
                    };
                    let timeout = match &command { Command::Read(_, _, limit, _) => limit.unwrap_or(options.timeout), _ => options.timeout };
                    let connected_timeout = (options.policy == TorrentSwarmPolicy::Lan
                        && matches!(&command, Command::Read(..))
                        && data.upgrade().is_some_and(|d| d.options.swarm.policy == TorrentSwarmPolicy::Lan && d.meta.web_seeds.is_empty()))
                        .then_some(options.timeout);
                    let result = rt.block_on(command_deadline(&session, timeout, connected_timeout, async {
                                match command {
                                    Command::Resolve(magnet, _) => {
                                        let mut peers = options.initial_peers.clone();
                                        // rqbit's list-only resolution subscribes to LSD without
                                        // announcing. Actively solicit the donor's reply so an
                                        // existing LAN seed need not wait five minutes to announce.
                                        if options.policy == TorrentSwarmPolicy::Lan && options.lsd && peers.is_empty() {
                                            let token = session.cancellation_token().child_token();
                                            let lsd = librqbit_lsd::LocalServiceDiscovery::new(librqbit_lsd::LocalServiceDiscoveryOptions {
                                                cancel_token: token.clone(), ..Default::default()
                                            }).await.map_err(error)?;
                                            let hash = librqbit::Magnet::parse(&magnet).map_err(error)?.as_id20().ok_or_else(|| error("no v1 metadata identity"))?;
                                            let mut discovery = Box::pin(lsd.announce(hash, session.listen_addr().map(|a| a.port())));
                                            loop {
                                                let peer = tokio::select! {
                                                    _ = token.cancelled() => return Err(error("LAN discovery stopped")),
                                                    peer = discovery.next() => peer.ok_or_else(|| error("LAN discovery ended"))?,
                                                };
                                                if is_lan(peer.ip()) { peers.push(peer); break; }
                                            }
                                            token.cancel();
                                        }
                                        let result = session
                                            .add_torrent(
                                                AddTorrent::from_url(magnet),
                                                Some(AddTorrentOptions {
                                                    list_only: true,
                                                    initial_peers: Some(
                                                        peers,
                                                    ),
                                                    disable_trackers: !options.trackers || !options.public_discovery(),
                                                    ..Default::default()
                                                }),
                                            )
                                            .await
                                            .map_err(error)?;
                                        match result {
                                            AddTorrentResponse::ListOnly(response) => {
                                                *found_peers.lock().unwrap_or_else(|e| e.into_inner()) = response.seen_peers;
                                                Ok(response.torrent_bytes.to_vec())
                                            }
                                            _ => Err(error("metadata response was not list-only")),
                                        }
                                    }
                                    Command::Read(bytes, spans, _, _) => {
                                        if handle.is_none() {
                                            handle = Some(add_payload(&session, &options, bytes, &initializing).await?);
                                        }
                                        let torrent = handle
                                            .as_ref()
                                            .ok_or_else(|| error("no torrent handle"))?;
                                        torrent.wait_until_initialized().await.map_err(error)?;
                                        initializing.store(false, Ordering::Release);
                                        if options.seed && !seed_ready {
                                            log::warn!("BITTORRENT SEEDING READY: initial cache scan finished; verified pieces available on {:?}", session.listen_addr());
                                            seed_ready = true;
                                        }
                                        let mut output = Vec::new();
                                        for (file, offset, len) in spans {
                                            let start = output.len();
                                            output.resize(start + len, 0);
                                            let Some(file) = file else {
                                                // BEP 47 padding has no backing file in rqbit.
                                                continue;
                                            };
                                            if current_file != Some(file) {
                                                // rqbit reconnects before registering a stream.
                                                // With no selected files and uploads disabled,
                                                // the peer-adder can dismiss that peer as idle.
                                                // Register while paused so start sees the stream.
                                                if !torrent.is_paused() {
                                                    session.pause(torrent).await.map_err(error)?;
                                                }
                                                current_stream.take();
                                                current_file = None;
                                                current_stream = Some(
                                                    torrent
                                                        .clone()
                                                        .stream(file)
                                                        .await
                                                        .map_err(error)?,
                                                );
                                                current_file = Some(file);
                                            }
                                            let stream = current_stream.as_mut().unwrap();
                                            stream.seek(io::SeekFrom::Start(offset)).await?;
                                            if torrent.is_paused() {
                                                session.unpause(torrent).await.map_err(error)?;
                                            }
                                            stream.read_exact(&mut output[start..]).await?;
                                        }
                                        Ok(output)
                                    }
                                }
                        }));
                    let _ = reply.send(result);
                }
                drop(current_stream);
                rt.block_on(session.stop());
                drop(session);
                rt.shutdown_timeout(Duration::from_secs(2));
                drop(owner);
                drop(scratch);
            })?;
        let (cancel, _listen_addr) = ready_rx.recv().map_err(error)??;
        Ok(Self {
            tx: Some(tx),
            thread: Mutex::new(Some(thread)),
            cancel,
            lan_only,
            metadata_peers,
            #[cfg(test)]
            listen_addr: _listen_addr,
            #[cfg(test)]
            seed_checks,
        })
    }

    pub(super) fn stop(&self) {
        (self.cancel)();
    }

    pub fn resolve(&self, magnet: String) -> io::Result<Vec<u8>> {
        self.resolve_with_timeout(magnet, None)
    }

    pub(super) fn metadata_peers(&self) -> Vec<SocketAddr> {
        self.metadata_peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    pub(super) fn resolve_with_timeout(
        &self,
        magnet: String,
        timeout: Option<Duration>,
    ) -> io::Result<Vec<u8>> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.tx
            .as_ref()
            .unwrap()
            .send(Command::Resolve(magnet, tx))
            .map_err(error)?;
        match timeout {
            Some(timeout) => rx
                .recv_timeout(timeout)
                .map_err(|e| io::Error::new(io::ErrorKind::TimedOut, e))?,
            None => rx.recv().map_err(error)?,
        }
    }

    pub fn read(
        &self,
        bytes: &[u8],
        spans: Vec<(Option<usize>, u64, usize)>,
    ) -> io::Result<Vec<u8>> {
        self.read_with_timeout(bytes, spans, None)
    }

    pub(super) fn read_with_timeout(
        &self,
        bytes: &[u8],
        spans: Vec<(Option<usize>, u64, usize)>,
        timeout: Option<Duration>,
    ) -> io::Result<Vec<u8>> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.tx
            .as_ref()
            .unwrap()
            .send(Command::Read(bytes.to_vec(), spans, timeout, tx))
            .map_err(error)?;
        // The runtime owns the deadline and cancels the actual request. Let an
        // established LAN-only transfer use its longer no-web-seed deadline.
        rx.recv().map_err(error)?
    }
}

impl Drop for Swarm {
    fn drop(&mut self) {
        self.stop();
        self.tx.take();
        if let Some(thread) = self
            .thread
            .get_mut()
            .unwrap_or_else(|e| e.into_inner())
            .take()
        {
            // Dropping a JoinHandle detaches an in-flight request. The runtime
            // retains its locked scratch owner and cleans up after its timeout.
            if thread.is_finished() {
                let _ = thread.join();
            }
        }
    }
}

/// Select the kernel's IPv4 default-route interface without sending a packet.
#[cfg(unix)]
fn default_device() -> io::Result<Option<String>> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("192.0.2.1:9")?;
    let std::net::IpAddr::V4(ip) = socket.local_addr()?.ip() else {
        return Err(error("no IPv4 default route for DHT"));
    };
    let mut list = std::ptr::null_mut();
    // getifaddrs owns the linked list until freeifaddrs; inspect only AF_INET addresses.
    unsafe {
        if libc::getifaddrs(&mut list) != 0 {
            return Err(io::Error::last_os_error());
        }
        let mut cursor = list;
        let mut found = None;
        while !cursor.is_null() {
            let entry = &*cursor;
            if !entry.ifa_addr.is_null() && (*entry.ifa_addr).sa_family as i32 == libc::AF_INET {
                let addr = &*(entry.ifa_addr as *const libc::sockaddr_in);
                if addr.sin_addr.s_addr.to_ne_bytes() == ip.octets() {
                    found = Some(
                        std::ffi::CStr::from_ptr(entry.ifa_name)
                            .to_string_lossy()
                            .into_owned(),
                    );
                    break;
                }
            }
            cursor = entry.ifa_next;
        }
        libc::freeifaddrs(list);
        found
            .map(Some)
            .ok_or_else(|| error("cannot identify default-route interface for DHT"))
    }
}

#[cfg(not(unix))]
fn default_device() -> io::Result<Option<String>> {
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Regression: unmount joined a stalled swarm command for its full network timeout.
    #[test]
    fn regression_swarm_drop_does_not_wait_for_command_timeout() {
        let (release, wait) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            let _ = wait.recv();
        });
        let (tx, _rx) = mpsc::sync_channel(1);
        let swarm = Swarm {
            tx: Some(tx),
            thread: Mutex::new(Some(thread)),
            cancel: Box::new(|| {}),
            lan_only: false,
            metadata_peers: Arc::default(),
            listen_addr: None,
            seed_checks: Arc::default(),
        };
        let start = std::time::Instant::now();
        drop(swarm);
        assert!(start.elapsed() < Duration::from_secs(1));
        release.send(()).unwrap();
    }
}

#[cfg(test)]
mod lan_tests {
    use super::*;

    /// Regression: a large upload cap produced a zero clock interval, while rounding could exceed smaller caps.
    #[test]
    fn regression_seed_upload_limit_keeps_nonzero_clock_and_bounded_rate() {
        for requested in [
            16384,
            16385,
            65536,
            1048576,
            104857600,
            501000000,
            1_000_000_000,
        ] {
            let options = SwarmOptions {
                seed: true,
                policy: TorrentSwarmPolicy::Lan,
                upload_limit: requested,
                ..Default::default()
            };
            options.validate().unwrap();
            let rate = session_options(&options)
                .ratelimits
                .upload_bps
                .unwrap()
                .get();
            assert!(rate >= 16384 && rate <= requested);
            let interval_ns = 1_000_000_000 / u64::from(rate);
            assert_ne!(interval_ns, 0);
            // One-block minimum has sub-byte rounding; all other rates round down.
            let effective_rate = 1_000_000_000.0 / interval_ns as f64;
            assert!(effective_rate <= requested as f64 * 1.00001);
        }
        let options = SwarmOptions {
            seed: true,
            policy: TorrentSwarmPolicy::Lan,
            upload_limit: 1_000_000_001,
            ..Default::default()
        };
        let err = options.validate().unwrap_err();
        assert!(err.to_string().contains("--seed-upload-limit"), "{err}");
    }

    /// Regression: unmount left a seed runtime waiting forever for a canceled initial cache scan.
    #[test]
    fn regression_seed_shutdown_interrupts_pending_cache_scan() {
        let dir = tempfile::tempdir().unwrap();
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let options = SwarmOptions {
            dht: false,
            trackers: false,
            lsd: false,
            ..Default::default()
        };
        let session = rt
            .block_on(Session::new_with_opts(
                dir.path().into(),
                session_options(&options),
            ))
            .unwrap();
        session.cancellation_token().cancel();
        let start = std::time::Instant::now();
        let result = rt.block_on(until_stopped(
            &session,
            std::future::pending::<io::Result<()>>(),
        ));
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Interrupted);
        assert!(start.elapsed() < Duration::from_secs(1));
        rt.block_on(session.stop());
    }

    /// Regression: PEX or an incoming socket bypassed the LAN-only discovery policy.
    #[test]
    fn regression_lan_allowlist_blocks_public_pex_and_incoming_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("lan.txt");
        std::fs::write(&file, LAN_ALLOWLIST).unwrap();
        let options = SwarmOptions {
            policy: TorrentSwarmPolicy::Lan,
            lsd: false,
            ..Default::default()
        };
        let mut config = session_options(&options);
        config.allowlist_url = Some(url::Url::from_file_path(&file).unwrap().into());
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let session = rt
            .block_on(Session::new_with_opts(dir.path().into(), config))
            .unwrap();
        let allow = session.allowlist.as_ref().unwrap();
        for address in [
            "127.0.0.1",
            "10.2.3.4",
            "172.16.1.1",
            "192.168.1.2",
            "169.254.1.2",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:192.168.0.1",
        ] {
            let ip = address.parse().unwrap();
            assert!(is_lan(ip));
            assert!(allow.has(ip), "LAN address refused: {ip}");
        }
        for address in [
            "203.0.113.1",
            "8.8.8.8",
            "172.32.0.1",
            "2001:db8::1",
            "ff02::1",
            "::ffff:8.8.8.8",
        ] {
            let ip = address.parse().unwrap();
            assert!(!is_lan(ip));
            assert!(!allow.has(ip), "public address allowed: {ip}");
        }
        rt.block_on(session.stop());
    }
}

#[cfg(test)]
mod listener_tests {
    use super::*;

    /// Regression: the default policy was `auto`, so a failed web seed joined
    /// the public DHT/tracker swarm without the user asking.
    #[test]
    fn regression_swarm_options_default_never() {
        let options = SwarmOptions::default();
        assert_eq!(options.policy, TorrentSwarmPolicy::Never);
        assert!(!options.public_discovery());
        let config = session_options(&options);
        assert!(config.listen.is_none());
        assert!(config.dht.is_none());
        assert!(config.disable_trackers);
        assert!(config.disable_local_service_discovery);
    }

    /// Regression: default LSD enabled an inbound listener on public downloader sessions.
    #[test]
    fn regression_public_downloaders_never_listen_and_lan_binds_private() {
        for policy in [
            TorrentSwarmPolicy::Auto,
            TorrentSwarmPolicy::Always,
            TorrentSwarmPolicy::Never,
        ] {
            let opts = SwarmOptions {
                policy,
                ..Default::default()
            };
            let config = session_options(&opts);
            assert!(config.listen.is_none());
            assert_eq!(config.peer_limit, Some(32));
        }
        let config = session_options(&SwarmOptions {
            policy: TorrentSwarmPolicy::Lan,
            ..Default::default()
        });
        let addr = config.listen.unwrap().listen_addr;
        assert!(!addr.ip().is_unspecified());
        assert!(is_lan(addr.ip()));
        assert!(!is_lan("100.64.0.1".parse().unwrap()));
    }

    /// Regression: two seed mounts collided on the fixed default port, and IPv6 peers could not connect.
    #[test]
    fn regression_seed_default_random_port_accepts_ipv6() {
        let dir = tempfile::tempdir().unwrap();
        let options = SwarmOptions {
            seed: true,
            dht: false,
            trackers: false,
            lsd: false,
            policy: TorrentSwarmPolicy::Lan,
            ..Default::default()
        };
        assert_eq!(options.listen_port, 0);
        assert!(options.listen_ip.is_ipv6());
        let probe = match std::net::TcpListener::bind("[::1]:0") {
            Ok(probe) => probe,
            Err(e) => {
                eprintln!("skip: IPv6 loopback unavailable: {e}");
                return;
            }
        };
        drop(probe);
        let first = Swarm::new(options.clone(), dir.path().join("first"), "test").unwrap();
        let second = Swarm::new(options, dir.path().join("second"), "test").unwrap();
        let a = first.listen_addr.unwrap();
        let b = second.listen_addr.unwrap();
        assert_ne!(a.port(), b.port());
        for addr in [a, b] {
            std::net::TcpStream::connect((std::net::Ipv6Addr::LOCALHOST, addr.port())).unwrap();
            std::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, addr.port())).unwrap();
        }
    }
}
