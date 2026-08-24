//! Tokio-free stop flag and join handle (copied from `NfsStop` / `NfsServerHandle`).
//!
//! `main.rs` must not name tokio. Export crates poll [`STOP_POLL_INTERVAL`]
//! (200 ms, same as NFS `serve_listener`) until [`ExportStop::is_stopped`].

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

/// How often a serve loop should poll [`ExportStop`] (NFS `serve_listener`).
pub const STOP_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Tokio-free stop flag (`main.rs` must not name tokio).
#[derive(Clone, Debug)]
pub struct ExportStop(Arc<AtomicBool>);

impl ExportStop {
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

impl Default for ExportStop {
    fn default() -> Self {
        Self::new()
    }
}

/// Handle for a background export thread (FUSE+export `-f`).
pub struct ExportServerHandle {
    pub port: u16,
    join: Option<JoinHandle<io::Result<()>>>,
}

impl ExportServerHandle {
    pub fn from_join(port: u16, join: JoinHandle<io::Result<()>>) -> Self {
        Self {
            port,
            join: Some(join),
        }
    }

    /// Wait for the export thread to exit (after [`ExportStop::request_stop`]).
    pub fn join(mut self) -> io::Result<()> {
        match self.join.take() {
            Some(h) => h
                .join()
                .unwrap_or_else(|_| Err(io::Error::other("export thread panicked"))),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Instant;

    #[test]
    fn request_stop_is_shared() {
        let stop = ExportStop::new();
        assert!(!stop.is_stopped());
        let clone = stop.clone();
        clone.request_stop();
        assert!(stop.is_stopped());
        assert!(clone.is_stopped());
    }

    #[test]
    fn handle_join_after_stop() {
        let stop = ExportStop::new();
        let stop2 = stop.clone();
        let join = thread::spawn(move || {
            let start = Instant::now();
            while !stop2.is_stopped() {
                if start.elapsed() > Duration::from_secs(2) {
                    return Err(io::Error::other("stop was never requested"));
                }
                thread::sleep(Duration::from_millis(10));
            }
            Ok(())
        });
        let h = ExportServerHandle::from_join(20491, join);
        assert_eq!(h.port, 20491);
        stop.request_stop();
        h.join().expect("join");
    }
}
