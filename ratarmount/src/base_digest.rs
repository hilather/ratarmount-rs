//! Lazy base digest: an archive base whose digest was not cached is recorded
//! as `pending` at creation and hashed here, after the mount is serving.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use ratarmount_compositing::WriteOverlay;

use crate::overlay_commit;

static WORKER: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);

/// Test seam: when set, the background hash waits until this path exists.
/// Offline verbs never read it.
const GATE_ENV: &str = "RATARMOUNT_TEST_HASH_GATE";

fn check_not_stopping() -> std::io::Result<()> {
    if overlay_commit::term_requested() {
        Err(std::io::Error::new(
            std::io::ErrorKind::Interrupted,
            "unmounting",
        ))
    } else {
        Ok(())
    }
}

/// Start the hasher in the process that serves the mount, when the overlay's
/// base digest is `pending`. The thread holds only a `Weak`, so it never keeps
/// the overlay alive; [`join`] runs before the overlay is dropped.
pub fn spawn_if_pending(overlay: &Option<Arc<WriteOverlay>>) {
    let Some(overlay) = overlay else { return };
    let mut worker = WORKER.lock().expect("base digest worker");
    if worker.is_some() {
        return;
    }
    let pending = match overlay.pending_base() {
        Ok(Some(pending)) => pending,
        Ok(None) => return,
        Err(e) => {
            log::warn!("base digest stays pending: {e}");
            return;
        }
    };
    let weak = Arc::downgrade(overlay);
    *worker = thread::Builder::new()
        .name("ratarmount-base-digest".into())
        .spawn(move || {
            if let Some(gate) = std::env::var_os(GATE_ENV).map(PathBuf::from) {
                while !gate.exists() {
                    if check_not_stopping().is_err() {
                        return;
                    }
                    thread::sleep(Duration::from_millis(20));
                }
            }
            // Computed once per archive and cached in its index: without a
            // writable cache every mount would hash it again, so stay pending
            // (seal and the verbs that need the digest resolve it).
            if !pending.cache_available() {
                log::info!(
                    "base digest stays pending: no writable index cache for {}",
                    pending.path.display()
                );
                return;
            }
            match pending.hash(&check_not_stopping) {
                Ok(digest) => {
                    let Some(overlay) = weak.upgrade() else {
                        return;
                    };
                    match overlay.record_base_digest(&pending, &digest) {
                        Ok(true) => log::debug!("recorded base digest {digest}"),
                        Ok(false) => log::debug!("base digest no longer pending; not recorded"),
                        Err(e) => log::warn!("base digest stays pending: {e}"),
                    }
                }
                Err(_) if overlay_commit::term_requested() => {}
                Err(e) => log::warn!("base digest stays pending: {e}"),
            }
        })
        .map_err(|e| log::warn!("cannot start base digest thread: {e}"))
        .ok();
}

/// Wait for the hasher after [`overlay_commit::request_shutdown`] (it polls
/// that flag between chunks, so this is quick).
pub fn join() {
    let handle = WORKER.lock().expect("base digest worker").take();
    if let Some(handle) = handle {
        let _ = handle.join();
    }
}
