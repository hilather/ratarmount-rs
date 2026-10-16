//! Blocking bridge to a private rqbit runtime. No runtime is entered on a FUSE thread.

use super::{scratch, TorrentSwarmPolicy};
use librqbit::storage::StorageFactoryExt;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
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
            policy: TorrentSwarmPolicy::Auto,
            scratch_bytes: 2 * 1024 * 1024 * 1024,
            announced: Arc::default(),
        }
    }
}

pub(crate) fn session_options(options: &SwarmOptions) -> SessionOptions {
    SessionOptions {
        dht: options.dht.then(|| DhtSessionConfig {
            persistence: None,
            ..Default::default()
        }),
        disable_trackers: !options.trackers,
        disable_upload: true,
        disable_local_service_discovery: true,
        listen: None,
        persistence: None,
        runtime_worker_threads: Some(2),
        ..Default::default()
    }
}

type Reply = mpsc::SyncSender<io::Result<Vec<u8>>>;
enum Command {
    Resolve(String, Reply),
    Read(Vec<u8>, Vec<(Option<usize>, u64, usize)>, Reply),
}

pub(crate) struct Swarm {
    tx: Option<mpsc::SyncSender<Command>>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

fn error(e: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("torrent swarm: {e}"))
}

impl Swarm {
    pub fn new(options: SwarmOptions, cache_dir: PathBuf, infohash: &str) -> io::Result<Self> {
        if options.policy == TorrentSwarmPolicy::Never {
            return Err(io::Error::new(io::ErrorKind::PermissionDenied,
                "--torrent-swarm never: metadata or a verified piece is unavailable from cache/web seeds"));
        }
        if !options.announced.swap(true, Ordering::Relaxed) {
            log::info!(
                "BitTorrent swarm enabled for {infohash}: your IP is visible to trackers/DHT peers"
            );
        }
        let (tx, rx) = mpsc::sync_channel(8);
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let thread = thread::Builder::new()
            .name("torrent-runtime".into())
            .spawn(move || {
                let setup = || -> io::Result<_> {
                    std::fs::create_dir_all(&cache_dir)?;
                    scratch::sweep(&cache_dir, Duration::from_secs(24 * 60 * 60));
                    let scratch = tempfile::Builder::new()
                        .prefix("swarm-")
                        .tempdir_in(cache_dir)?;
                    let owner = scratch::mark_owned(scratch.path())?;
                    let rt = tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .enable_all()
                        .build()?;
                    let mut config = session_options(&options);
                    if options.dht {
                        config.bind_device_name = default_device()?;
                        config.ipv4_only = true;
                    }
                    config.default_storage_factory = Some(
                        scratch::Factory {
                            dir: scratch.path().to_owned(),
                            limit: options.scratch_bytes,
                        }
                        .boxed(),
                    );
                    let session = rt
                        .block_on(Session::new_with_opts(scratch.path().to_owned(), config))
                        .map_err(error)?;
                    Ok((scratch, owner, rt, session))
                };
                let (scratch, owner, rt, session) = match setup() {
                    Ok(value) => {
                        let _ = ready_tx.send(Ok(()));
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
                while let Ok(command) = rx.recv() {
                    let reply = match &command {
                        Command::Resolve(_, r) | Command::Read(_, _, r) => r.clone(),
                    };
                    let result = rt
                        .block_on(async {
                            tokio::time::timeout(options.timeout, async {
                                match command {
                                    Command::Resolve(magnet, _) => {
                                        let result = session
                                            .add_torrent(
                                                AddTorrent::from_url(magnet),
                                                Some(AddTorrentOptions {
                                                    list_only: true,
                                                    initial_peers: Some(
                                                        options.initial_peers.clone(),
                                                    ),
                                                    disable_trackers: !options.trackers,
                                                    ..Default::default()
                                                }),
                                            )
                                            .await
                                            .map_err(error)?;
                                        match result {
                                            AddTorrentResponse::ListOnly(response) => {
                                                Ok(response.torrent_bytes.to_vec())
                                            }
                                            _ => Err(error("metadata response was not list-only")),
                                        }
                                    }
                                    Command::Read(bytes, spans, _) => {
                                        if handle.is_none() {
                                            handle = session
                                                .add_torrent(
                                                    AddTorrent::TorrentFileBytes(bytes.into()),
                                                    Some(AddTorrentOptions {
                                                        paused: true,
                                                        only_files: Some(Vec::new()),
                                                        initial_peers: Some(
                                                            options.initial_peers.clone(),
                                                        ),
                                                        disable_trackers: !options.trackers,
                                                        overwrite: true,
                                                        ..Default::default()
                                                    }),
                                                )
                                                .await
                                                .map_err(error)?
                                                .into_handle();
                                        }
                                        let torrent = handle
                                            .as_ref()
                                            .ok_or_else(|| error("no torrent handle"))?;
                                        torrent.wait_until_initialized().await.map_err(error)?;
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
                            })
                            .await
                        })
                        .unwrap_or_else(|_| {
                            Err(io::Error::new(
                                io::ErrorKind::TimedOut,
                                "torrent swarm timed out",
                            ))
                        });
                    let _ = reply.send(result);
                }
                drop(current_stream);
                rt.block_on(session.stop());
                drop(session);
                rt.shutdown_timeout(Duration::from_secs(2));
                drop(owner);
                drop(scratch);
            })?;
        ready_rx.recv().map_err(error)??;
        Ok(Self {
            tx: Some(tx),
            thread: Mutex::new(Some(thread)),
        })
    }

    pub fn resolve(&self, magnet: String) -> io::Result<Vec<u8>> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.tx
            .as_ref()
            .unwrap()
            .send(Command::Resolve(magnet, tx))
            .map_err(error)?;
        rx.recv().map_err(error)?
    }

    pub fn read(
        &self,
        bytes: &[u8],
        spans: Vec<(Option<usize>, u64, usize)>,
    ) -> io::Result<Vec<u8>> {
        let (tx, rx) = mpsc::sync_channel(1);
        self.tx
            .as_ref()
            .unwrap()
            .send(Command::Read(bytes.to_vec(), spans, tx))
            .map_err(error)?;
        rx.recv().map_err(error)?
    }
}

impl Drop for Swarm {
    fn drop(&mut self) {
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
        };
        let start = std::time::Instant::now();
        drop(swarm);
        assert!(start.elapsed() < Duration::from_secs(1));
        release.send(()).unwrap();
    }
}
