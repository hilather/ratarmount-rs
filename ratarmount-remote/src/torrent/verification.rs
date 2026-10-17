//! Whole-file hashing and checksum discovery never run on a reader thread.
use super::{checksums, Data, Piece};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{mpsc, Arc, Weak};

pub(super) enum Event {
    RetryPublication,
    #[cfg(test)]
    Barrier(mpsc::SyncSender<()>),
    Piece(Piece, Weak<Vec<u8>>),
    Complete(usize),
    Hashes(BTreeMap<String, [u8; 32]>),
}
#[derive(Default)]
struct Stream {
    hash: Sha256,
    next: u64,
    digest: Option<[u8; 32]>,
    covered: bool,
}

fn publish(data: &Arc<Data>, file: usize, expected: [u8; 32], pending: &mut BTreeSet<usize>) {
    if let Err(e) = data.hub.publish(data, file, expected) {
        pending.insert(file);
        log::debug!("torrent Hub cache publication deferred: {e}");
    } else {
        pending.remove(&file);
    }
}

pub(super) fn start(data: &Arc<Data>, rx: mpsc::Receiver<Event>) -> std::io::Result<()> {
    let weak = Arc::downgrade(data);
    std::thread::Builder::new()
        .name("torrent-sha256".into())
        .spawn(move || {
            let mut streams: BTreeMap<usize, Stream> = BTreeMap::new();
            let mut pending = BTreeSet::new();
            loop {
                let event = match rx.recv_timeout(std::time::Duration::from_secs(5)) {
                    Ok(event) => event,
                    Err(mpsc::RecvTimeoutError::Timeout) => Event::RetryPublication,
                    Err(mpsc::RecvTimeoutError::Disconnected) => break,
                };
                let Some(data) = weak.upgrade() else {
                    break;
                };
                if data.stopped.load(std::sync::atomic::Ordering::Acquire) { break; }
                let mut affected = Vec::new();
                match event {
                    Event::RetryPublication => affected.extend(pending.iter().copied()),
                    #[cfg(test)]
                    Event::Barrier(tx) => {
                        let _ = tx.send(());
                    }
                    Event::Piece(key, bytes) => {
                        if let Some(bytes) = bytes.upgrade() {
                            let mut offset = 0;
                            for (file, start, len) in data.spans(key) {
                                let stream = streams.entry(file).or_default();
                                if !data.meta.files[file].padding
                                    && start == stream.next
                                    && stream.digest.is_none()
                                {
                                    // Hashing can be expensive. No read-path mutex is held here.
                                    stream.hash.update(&bytes[offset..offset + len]);
                                    stream.next += len as u64;
                                    if stream.next == data.meta.files[file].len {
                                        stream.digest = Some(stream.hash.clone().finalize().into());
                                    }
                                    affected.push(file);
                                }
                                offset += len;
                            }
                        }
                    }
                    Event::Complete(file) => {
                        streams.entry(file).or_default().covered = true;
                        affected.push(file);
                    }
                    Event::Hashes(hashes) => {
                        data.hub.authorize(&data.meta, &hashes);
                        for (file, meta) in data.meta.files.iter().enumerate() {
                            let mut state = data.verification[file]
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            if let Some(hash) = hashes.get(&meta.path) {
                                if state.expected.is_some_and(|expected| expected != *hash) {
                                    state.bad = true;
                                    state.complete = false;
                                    log::error!("torrent metainfo SHA-256 disagrees with pinned Hub/manifest hash: {}", meta.path);
                                }
                                state.expected = Some(*hash);
                            }
                            affected.push(file);
                        }
                    }
                }
                for file in affected {
                    let stream = streams.entry(file).or_default();
                    let expected = {
                        let state = data.verification[file]
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        if state.bad { continue; }
                        if state.complete {
                            let expected = state.expected;
                            drop(state);
                            if let Some(expected) = expected {
                                publish(&data, file, expected, &mut pending);
                            }
                            continue;
                        }
                        state.expected
                    };
                    let Some(expected) = expected else {
                        continue;
                    };
                    if stream.digest.is_none() && stream.covered {
                        // Random reads (or an evicted weak piece) need an independent
                        // pass. It may use HTTP, but never holds a reader's mutex.
                        let result = (|| -> std::io::Result<[u8; 32]> {
                            let mut hash = Sha256::new();
                            let mut pos = 0;
                            while pos < data.meta.files[file].len {
                                let (key, offset) = data.key(file, pos);
                                let bytes = data.fetch_piece(key, true)?;
                                let n = (data.meta.files[file].len - pos)
                                    .min((bytes.len() - offset) as u64)
                                    as usize;
                                hash.update(&bytes[offset..offset + n]);
                                pos += n as u64;
                            }
                            Ok(hash.finalize().into())
                        })();
                        match result {
                            Ok(digest) => stream.digest = Some(digest),
                            Err(e) => {
                                log::warn!("torrent background SHA-256 verification: {e}");
                                continue;
                            }
                        }
                    }
                    if let Some(digest) = stream.digest {
                        let mut state = data.verification[file]
                            .lock()
                            .unwrap_or_else(|e| e.into_inner());
                        state.bad = digest != expected;
                        state.complete = !state.bad;
                        state.ranges.clear();
                        let complete = state.complete;
                        if state.bad {
                            log::error!(
                                "TORRENT SHA-256 MISMATCH: {} in {}; all further reads refused",
                                data.meta.files[file].path,
                                data.meta.identity()
                            );
                        }
                        drop(state);
                        if complete {
                            publish(&data, file, expected, &mut pending);
                        }
                    }
                }
            }
        })?;
    let weak = Arc::downgrade(data);
    std::thread::Builder::new()
        .name("torrent-checksums".into())
        .spawn(move || {
            let Some(data) = weak.upgrade() else {
                return;
            };
            let hashes = if data.hub.all_local(&data) {
                BTreeMap::new()
            } else {
                if data.stopped.load(std::sync::atomic::Ordering::Acquire) {
                    return;
                }
                checksums::load(&data.meta, &data.options.metadata_dir)
            };
            let _ = data.verify_tx.send(Event::Hashes(hashes));
        })?;
    Ok(())
}
