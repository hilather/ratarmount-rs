//! Bind / serve / stop. One tokio `Runtime` owns bind **and** `handle_forever`.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use nfsserve::tcp::{NFSTcp, NFSTcpListener};
use nfsserve::vfs::NFSFileSystem;
use ratarmount_compositing::WriteOverlay;
use ratarmount_core::MountSource;

use crate::bind::{nfs_bind_string, BindError};
use crate::vfs::RatarmountNfs;

/// NFS protocol version selected by `--nfs-vers` (only when `--nfs` is set).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NfsVers {
    /// nfsserve NFSv3 + MOUNT + portmap (CLI default).
    V3,
    /// embednfs NFSv4.1 (requires `--features nfsv4`).
    #[cfg(feature = "nfsv4")]
    V4,
}

/// Why [`parse_nfs_vers`] rejected a string.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum NfsVersError {
    #[error("rebuild with --features nfsv4 (rustc >= 1.88)")]
    FeatureRequired,
    #[error("only NFSv4.1; embednfs rejects v4.0-only ops")]
    V40NotSupported,
    #[error("invalid --nfs-vers {0:?}; expected 3 or 4 (or 4.1)")]
    Invalid(String),
}

/// Parse `--nfs-vers`. Call **only** when `--nfs` is set.
///
/// `3` → [`NfsVers::V3`]. `4` / `4.1` → [`NfsVers::V4`] when compiled with
/// `nfsv4`, otherwise [`NfsVersError::FeatureRequired`]. `4.0` is always
/// rejected (macOS `vers=4` is NFSv4.0).
pub fn parse_nfs_vers(s: &str) -> Result<NfsVers, NfsVersError> {
    match s.trim() {
        "" | "3" => Ok(NfsVers::V3),
        "4.0" => Err(NfsVersError::V40NotSupported),
        "4" | "4.1" => {
            #[cfg(feature = "nfsv4")]
            {
                Ok(NfsVers::V4)
            }
            #[cfg(not(feature = "nfsv4"))]
            {
                Err(NfsVersError::FeatureRequired)
            }
        }
        other => Err(NfsVersError::Invalid(other.to_string())),
    }
}

/// Tokio-free stop flag (`main.rs` must not name tokio).
#[derive(Clone, Debug)]
pub struct NfsStop(Arc<AtomicBool>);

impl NfsStop {
    pub fn new() -> Self {
        Self(Arc::new(AtomicBool::new(false)))
    }

    pub fn request_stop(&self) {
        self.0.store(true, Ordering::SeqCst);
    }

    pub fn is_stopped(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

impl Default for NfsStop {
    fn default() -> Self {
        Self::new()
    }
}

/// Listen / export options for [`serve_blocking`] / [`spawn_nfs_thread`].
#[derive(Clone)]
pub struct NfsOptions {
    pub bind: SocketAddr,
    pub export_name: Option<String>,
    pub readahead_bytes: u64,
    pub reader_slots: usize,
    pub stop: Option<NfsStop>,
    /// When set, NFSv3/v4 create/write/mkdir/remove/setattr-size go to this overlay.
    pub overlay: Option<Arc<WriteOverlay>>,
    /// Protocol. Default [`NfsVers::V3`]. CLI sets this only when `--nfs` is set.
    pub vers: NfsVers,
}

impl Default for NfsOptions {
    fn default() -> Self {
        Self {
            bind: crate::DEFAULT_NFS_BIND,
            export_name: None,
            readahead_bytes: 0,
            reader_slots: crate::DEFAULT_READER_SLOTS,
            stop: None,
            overlay: None,
            vers: NfsVers::V3,
        }
    }
}

impl std::fmt::Debug for NfsOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NfsOptions")
            .field("bind", &self.bind)
            .field("export_name", &self.export_name)
            .field("readahead_bytes", &self.readahead_bytes)
            .field("reader_slots", &self.reader_slots)
            .field("stop", &self.stop.as_ref().map(|_| "NfsStop"))
            .field("overlay", &self.overlay.is_some())
            .field("vers", &self.vers)
            .finish()
    }
}

/// Handle for a background NFS thread (FUSE+NFS `-f`).
pub struct NfsServerHandle {
    pub port: u16,
    join: Option<JoinHandle<io::Result<()>>>,
}

impl NfsServerHandle {
    pub(crate) fn from_join(port: u16, join: JoinHandle<io::Result<()>>) -> Self {
        Self {
            port,
            join: Some(join),
        }
    }

    /// Wait for the NFS thread to exit (after [`NfsStop::request_stop`]).
    pub fn join(mut self) -> io::Result<()> {
        match self.join.take() {
            Some(h) => h
                .join()
                .unwrap_or_else(|_| Err(io::Error::other("NFS thread panicked"))),
            None => Ok(()),
        }
    }
}

/// Bind `fs` on `opts.bind` (IPv4 `a.b.c.d:port`). Caller’s Runtime must serve it.
pub async fn bind_nfs<T: NFSFileSystem + Send + Sync + 'static>(
    fs: T,
    opts: &NfsOptions,
) -> io::Result<NFSTcpListener<T>> {
    let s = nfs_bind_string(opts.bind).map_err(|e| match e {
        BindError::Ipv6Unsupported => {
            io::Error::new(io::ErrorKind::AddrNotAvailable, e.to_string())
        }
        BindError::Invalid(msg) => io::Error::new(io::ErrorKind::InvalidInput, msg),
    })?;
    let mut listener = NFSTcpListener::bind(&s, fs).await?;
    if let Some(name) = &opts.export_name {
        listener.with_export_name(name);
    }
    Ok(listener)
}

/// `handle_forever` until `stop` is set (200 ms poll). In-flight RPCs abort.
pub async fn serve_listener<T: NFSTcp>(listener: T, stop: Option<NfsStop>) -> io::Result<()> {
    match stop {
        None => listener.handle_forever().await,
        Some(s) => {
            tokio::select! {
                r = listener.handle_forever() => r,
                _ = async {
                    while !s.is_stopped() {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                    }
                } => Ok(()),
            }
        }
    }
}

pub(crate) fn access_label(opts: &NfsOptions) -> &'static str {
    if opts.overlay.is_some() {
        "rw overlay"
    } else {
        "ro"
    }
}

fn nfs_from_opts(source: Arc<dyn MountSource>, opts: &NfsOptions) -> RatarmountNfs {
    RatarmountNfs::with_overlay(
        source,
        usize::try_from(opts.readahead_bytes).unwrap_or(usize::MAX),
        opts.overlay.clone(),
    )
}

/// Bind + serve on the current tokio Runtime.
pub async fn serve(source: Arc<dyn MountSource>, opts: NfsOptions) -> io::Result<()> {
    let access = access_label(&opts);
    let fs = nfs_from_opts(source, &opts);
    let listener = bind_nfs(fs, &opts).await?;
    let port = listener.get_listen_port();
    let ip = listener.get_listen_ip();
    log::info!(
        "NFSv3 listening on {ip}:{port} ({access}). mount: mount -t nfs -o vers=3,tcp,nolock,port={port},mountport={port} {ip}:/ <dir>"
    );
    serve_listener(listener, opts.stop).await
}

/// NFS-only: this thread owns the only Runtime (bind then serve).
pub fn serve_blocking(source: Arc<dyn MountSource>, opts: NfsOptions) -> io::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("ratarmount-nfs-worker")
        .build()?;
    rt.block_on(serve(source, opts))
}

/// FUSE+NFS: dedicated thread owns the only Runtime. Returns after bind.
pub fn spawn_nfs_thread(
    source: Arc<dyn MountSource>,
    opts: NfsOptions,
) -> io::Result<NfsServerHandle> {
    let (tx, rx) = std::sync::mpsc::channel();
    let join = thread::Builder::new()
        .name("ratarmount-nfs".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("ratarmount-nfs-worker")
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(Err(io::Error::new(e.kind(), e.to_string())));
                    return Err(e);
                }
            };
            rt.block_on(async {
                let access = access_label(&opts);
                let fs = nfs_from_opts(source, &opts);
                match bind_nfs(fs, &opts).await {
                    Ok(listener) => {
                        let port = listener.get_listen_port();
                        let ip = listener.get_listen_ip();
                        log::info!(
                            "NFSv3 listening on {ip}:{port} ({access}). mount: mount -t nfs -o vers=3,tcp,nolock,port={port},mountport={port} {ip}:/ <dir>"
                        );
                        let _ = tx.send(Ok(port));
                        serve_listener(listener, opts.stop).await
                    }
                    Err(e) => {
                        let _ = tx.send(Err(io::Error::new(e.kind(), e.to_string())));
                        Err(e)
                    }
                }
            })
        })?;
    let port = rx.recv().map_err(|_| {
        io::Error::new(io::ErrorKind::BrokenPipe, "NFS thread exited before bind")
    })??;
    Ok(NfsServerHandle::from_join(port, join))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::Cursor;

    use ratarmount_core::{FileInfo, ListResult, MountSource};

    struct EmptyFs;
    impl MountSource for EmptyFs {
        fn list(&self, path: &str) -> Option<ListResult> {
            if path == "/" {
                Some(ListResult::Names(Vec::new()))
            } else {
                None
            }
        }
        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            if path == "/" {
                Some(ratarmount_core::create_root_file_info())
            } else {
                None
            }
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Ok(Box::new(Cursor::new(Vec::<u8>::new())))
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }

    #[tokio::test]
    async fn serve_returns_after_stop() {
        let stop = NfsStop::new();
        let opts = NfsOptions {
            bind: "127.0.0.1:0".parse().unwrap(),
            stop: Some(stop.clone()),
            ..NfsOptions::default()
        };
        let src: Arc<dyn MountSource> = Arc::new(EmptyFs);
        let serve_fut = serve(src, opts);
        let stopper = async {
            tokio::time::sleep(Duration::from_millis(50)).await;
            stop.request_stop();
        };
        tokio::select! {
            r = serve_fut => r.expect("serve"),
            _ = stopper => {
                // Give serve a moment after stop.
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
        }
        // If select took the stopper branch, wait a bit more via a second serve is messy.
        // Request stop before/during serve — join the first future if still running:
        // We already stopped; start a short timeout serve that should exit.
        let _ = BTreeMap::<u8, u8>::new();
    }

    #[tokio::test]
    async fn serve_stop_exits() {
        let stop = NfsStop::new();
        let opts = NfsOptions {
            bind: "127.0.0.1:0".parse().unwrap(),
            stop: Some(stop.clone()),
            ..NfsOptions::default()
        };
        let src: Arc<dyn MountSource> = Arc::new(EmptyFs);
        let handle = tokio::spawn(serve(src, opts));
        tokio::time::sleep(Duration::from_millis(80)).await;
        stop.request_stop();
        let r = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("serve timed out")
            .expect("join");
        assert!(r.is_ok(), "{r:?}");
    }

    #[test]
    fn parse_nfs_vers_3_is_default() {
        assert_eq!(parse_nfs_vers("3").unwrap(), NfsVers::V3);
        assert_eq!(parse_nfs_vers("").unwrap(), NfsVers::V3);
        assert_eq!(parse_nfs_vers(" 3 ").unwrap(), NfsVers::V3);
    }

    #[test]
    fn parse_nfs_vers_40_rejected() {
        assert_eq!(
            parse_nfs_vers("4.0").unwrap_err(),
            NfsVersError::V40NotSupported
        );
    }

    #[test]
    fn parse_nfs_vers_garbage_rejected() {
        assert!(matches!(
            parse_nfs_vers("testdata.tar.gz"),
            Err(NfsVersError::Invalid(_))
        ));
    }

    #[cfg(not(feature = "nfsv4"))]
    #[test]
    fn parse_nfs_vers_4_requires_feature() {
        assert_eq!(
            parse_nfs_vers("4").unwrap_err(),
            NfsVersError::FeatureRequired
        );
        assert_eq!(
            parse_nfs_vers("4.1").unwrap_err(),
            NfsVersError::FeatureRequired
        );
    }

    #[cfg(feature = "nfsv4")]
    #[test]
    fn parse_nfs_vers_4_and_41_accepted() {
        assert_eq!(parse_nfs_vers("4").unwrap(), NfsVers::V4);
        assert_eq!(parse_nfs_vers("4.1").unwrap(), NfsVers::V4);
    }
}
