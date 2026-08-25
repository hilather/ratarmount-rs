//! Bind / serve / stop. Blocking `TcpListener` + 200 ms [`ExportStop`] poll.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::thread;

use ratarmount_compositing::WriteOverlay;
use ratarmount_core::MountSource;
use ratarmount_export_core::{
    parse_export_bind, BindError, ExportServerHandle, ExportStop, DEFAULT_HTTP_PORT,
    STOP_POLL_INTERVAL,
};

use crate::handler::{handle_connection, HttpState};
use crate::webdav::{webdav_credentials_from_env, LockTable, WebDavOptions};

/// Default `--http-bind` (`127.0.0.1:20491`).
pub const DEFAULT_HTTP_BIND: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, DEFAULT_HTTP_PORT));

/// Listen / export options for [`serve_blocking`] / [`spawn_http_thread`].
#[derive(Clone)]
pub struct HttpOptions {
    pub bind: SocketAddr,
    pub stop: Option<ExportStop>,
    /// WebDAV PUT/DELETE/MKCOL/MOVE. GET/PROPFIND use `source` (pass overlay as both).
    pub overlay: Option<Arc<WriteOverlay>>,
    /// Body fill chunk (0 → 64 KiB). Not a reader LRU — each GET opens, fill-loops, drops.
    pub readahead_bytes: u64,
    /// Enable PROPFIND and overlay writes. GET/HEAD still work (P-5 reuse).
    pub webdav: bool,
    /// On-disk SQLite sidecar served at `/.ratarmount-control/index.sqlite`.
    /// HTTP-only (not a FUSE control file). `None` / missing / `:memory:` → 404.
    pub index_sidecar: Option<PathBuf>,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            bind: DEFAULT_HTTP_BIND,
            stop: None,
            overlay: None,
            readahead_bytes: 0,
            webdav: false,
            index_sidecar: None,
        }
    }
}

impl std::fmt::Debug for HttpOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpOptions")
            .field("bind", &self.bind)
            .field("stop", &self.stop.as_ref().map(|_| "ExportStop"))
            .field("overlay", &self.overlay.is_some())
            .field("readahead_bytes", &self.readahead_bytes)
            .field("webdav", &self.webdav)
            .field("index_sidecar", &self.index_sidecar)
            .finish()
    }
}

/// Parse `[host:]port` into an IPv4 listen address (default port 20491).
pub fn parse_http_bind(s: &str) -> Result<SocketAddr, BindError> {
    parse_export_bind(s, DEFAULT_HTTP_PORT)
}

fn fill_chunk(opts: &HttpOptions) -> usize {
    if opts.readahead_bytes == 0 {
        64 * 1024
    } else {
        usize::try_from(opts.readahead_bytes)
            .unwrap_or(64 * 1024)
            .max(1)
    }
}

fn access_label(opts: &HttpOptions) -> &'static str {
    if opts.overlay.is_some() {
        "rw overlay"
    } else {
        "ro"
    }
}

fn warn_non_loopback(addr: SocketAddr, webdav: bool) {
    if !addr.ip().is_loopback() {
        if webdav {
            if webdav_credentials_from_env().0.is_some() {
                log::warn!(
                    "WebDAV bind {addr} is not loopback; Basic auth is required (RATARMOUNT_WEBDAV_USER)"
                );
            } else {
                log::warn!(
                    "WebDAV bind {addr} is not loopback; PROPFIND/GET/PUT has no auth (localhost is the security boundary)"
                );
            }
        } else {
            log::warn!(
                "HTTP bind {addr} is not loopback; GET/HEAD has no auth (localhost is the security boundary)"
            );
        }
    }
}

fn bind_http(opts: &HttpOptions) -> io::Result<TcpListener> {
    if opts.bind.is_ipv6() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            BindError::Ipv6Unsupported.to_string(),
        ));
    }
    warn_non_loopback(opts.bind, opts.webdav);
    TcpListener::bind(opts.bind)
}

fn log_listen(addr: SocketAddr, opts: &HttpOptions) {
    let access = access_label(opts);
    let ip = addr.ip();
    let port = addr.port();
    if opts.webdav {
        let auth = if webdav_credentials_from_env().0.is_some() {
            "Basic auth"
        } else {
            "auth none"
        };
        log::info!(
            "WebDAV listening on {ip}:{port} ({access}, {auth}). PROPFIND Depth 0/1; GET/HEAD Range; LOCK/COPY; writes need overlay (-w)"
        );
    } else {
        log::info!(
            "HTTP listening on {ip}:{port} ({access}). curl: curl -r 0-1023 http://{ip}:{port}/member"
        );
    }
}

fn serve_listener(
    listener: TcpListener,
    source: Arc<dyn MountSource>,
    opts: HttpOptions,
) -> io::Result<()> {
    let basic = if opts.webdav {
        let (user, pass) = webdav_credentials_from_env();
        user.map(|u| (u, pass.unwrap_or_default()))
    } else {
        None
    };
    let state = Arc::new(HttpState {
        source,
        chunk: fill_chunk(&opts),
        overlay: opts.overlay.clone(),
        webdav: opts.webdav,
        locks: std::sync::Mutex::new(LockTable::default()),
        basic,
        index_sidecar: opts.index_sidecar.clone(),
    });
    match &opts.stop {
        None => {
            listener.set_nonblocking(false)?;
            loop {
                let (stream, _) = listener.accept()?;
                spawn_conn(stream, Arc::clone(&state));
            }
        }
        Some(stop) => {
            listener.set_nonblocking(true)?;
            loop {
                if stop.is_stopped() {
                    return Ok(());
                }
                match listener.accept() {
                    Ok((stream, _)) => spawn_conn(stream, Arc::clone(&state)),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(STOP_POLL_INTERVAL);
                    }
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                }
            }
        }
    }
}

fn spawn_conn(stream: TcpStream, state: Arc<HttpState>) {
    let _ = stream.set_nonblocking(false);
    let _ = thread::Builder::new()
        .name("ratarmount-http-conn".into())
        .spawn(move || {
            if let Err(e) = handle_connection(stream, &state) {
                log::debug!("HTTP connection: {e}");
            }
        });
}

impl From<WebDavOptions> for HttpOptions {
    fn from(opts: WebDavOptions) -> Self {
        Self {
            bind: opts.bind,
            stop: opts.stop,
            overlay: opts.overlay,
            readahead_bytes: opts.readahead_bytes,
            webdav: true,
            index_sidecar: None,
        }
    }
}

/// HTTP-only: this thread owns the listener (bind then serve).
pub fn serve_blocking(source: Arc<dyn MountSource>, opts: HttpOptions) -> io::Result<()> {
    let listener = bind_http(&opts)?;
    let addr = listener.local_addr()?;
    log_listen(addr, &opts);
    serve_listener(listener, source, opts)
}

/// WebDAV: same listener loop as HTTP with PROPFIND/PUT enabled.
pub fn serve_webdav_blocking(source: Arc<dyn MountSource>, opts: WebDavOptions) -> io::Result<()> {
    serve_blocking(source, HttpOptions::from(opts))
}

/// FUSE+HTTP: dedicated thread. Returns after bind with the real port.
pub fn spawn_http_thread(
    source: Arc<dyn MountSource>,
    opts: HttpOptions,
) -> io::Result<ExportServerHandle> {
    let (tx, rx) = std::sync::mpsc::channel();
    let join = thread::Builder::new()
        .name("ratarmount-http".into())
        .spawn(move || match bind_http(&opts) {
            Ok(listener) => {
                let addr = match listener.local_addr() {
                    Ok(a) => a,
                    Err(e) => {
                        let _ = tx.send(Err(io::Error::new(e.kind(), e.to_string())));
                        return Err(e);
                    }
                };
                log_listen(addr, &opts);
                let _ = tx.send(Ok(addr.port()));
                serve_listener(listener, source, opts)
            }
            Err(e) => {
                let _ = tx.send(Err(io::Error::new(e.kind(), e.to_string())));
                Err(e)
            }
        })?;
    let port = rx.recv().map_err(|_| {
        io::Error::new(io::ErrorKind::BrokenPipe, "HTTP thread exited before bind")
    })??;
    Ok(ExportServerHandle::from_join(port, join))
}

/// FUSE+WebDAV: dedicated thread. Returns after bind with the real port.
pub fn spawn_webdav_thread(
    source: Arc<dyn MountSource>,
    opts: WebDavOptions,
) -> io::Result<ExportServerHandle> {
    spawn_http_thread(source, HttpOptions::from(opts))
}
