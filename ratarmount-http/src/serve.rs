//! Bind / serve / stop. Blocking `TcpListener` + 200 ms [`ExportStop`] poll.

use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;

use ratarmount_compositing::WriteOverlay;
use ratarmount_core::MountSource;
use ratarmount_export_core::{
    parse_export_bind, BindError, ExportServerHandle, ExportStop, DEFAULT_HTTP_PORT,
    STOP_POLL_INTERVAL,
};

use crate::handler::{handle_connection, HttpState};

/// Default `--http-bind` (`127.0.0.1:20491`).
pub const DEFAULT_HTTP_BIND: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, DEFAULT_HTTP_PORT));

/// Listen / export options for [`serve_blocking`] / [`spawn_http_thread`].
#[derive(Clone)]
pub struct HttpOptions {
    pub bind: SocketAddr,
    pub stop: Option<ExportStop>,
    /// Ignored in v1 (GET/HEAD only). Kept so later CLI glue can pass `-w`.
    pub overlay: Option<Arc<WriteOverlay>>,
    /// Body fill chunk (0 → 64 KiB). Not a reader LRU — each GET opens, fill-loops, drops.
    pub readahead_bytes: u64,
}

impl Default for HttpOptions {
    fn default() -> Self {
        Self {
            bind: DEFAULT_HTTP_BIND,
            stop: None,
            overlay: None,
            readahead_bytes: 0,
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

fn access_label(_opts: &HttpOptions) -> &'static str {
    "ro"
}

fn warn_non_loopback(addr: SocketAddr) {
    if !addr.ip().is_loopback() {
        log::warn!(
            "HTTP bind {addr} is not loopback; GET/HEAD has no auth (localhost is the security boundary)"
        );
    }
}

fn bind_http(opts: &HttpOptions) -> io::Result<TcpListener> {
    if opts.bind.is_ipv6() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            BindError::Ipv6Unsupported.to_string(),
        ));
    }
    warn_non_loopback(opts.bind);
    TcpListener::bind(opts.bind)
}

fn log_listen(addr: SocketAddr, opts: &HttpOptions) {
    let access = access_label(opts);
    let ip = addr.ip();
    let port = addr.port();
    log::info!(
        "HTTP listening on {ip}:{port} ({access}). curl: curl -r 0-1023 http://{ip}:{port}/member"
    );
}

fn serve_listener(
    listener: TcpListener,
    source: Arc<dyn MountSource>,
    opts: HttpOptions,
) -> io::Result<()> {
    let state = Arc::new(HttpState {
        source,
        chunk: fill_chunk(&opts),
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

/// HTTP-only: this thread owns the listener (bind then serve).
pub fn serve_blocking(source: Arc<dyn MountSource>, opts: HttpOptions) -> io::Result<()> {
    let listener = bind_http(&opts)?;
    let addr = listener.local_addr()?;
    log_listen(addr, &opts);
    serve_listener(listener, source, opts)
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
