//! Whole-file hashing and checksum discovery never run on a reader thread.
use super::{checksums, Data, Piece};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::{mpsc, Arc, Weak};

pub(super) enum Event {
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

pub(super) fn start(data: &Arc<Data>, rx: mpsc::Receiver<Event>) -> std::io::Result<()> {
    let weak = Arc::downgrade(data);
    std::thread::Builder::new()
        .name("torrent-sha256".into())
        .spawn(move || {
            let mut streams: BTreeMap<usize, Stream> = BTreeMap::new();
            while let Ok(event) = rx.recv() {
                let Some(data) = weak.upgrade() else {
                    break;
                };
                let mut affected = Vec::new();
                match event {
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
                        for (file, meta) in data.meta.files.iter().enumerate() {
                            let mut state = data.verification[file]
                                .lock()
                                .unwrap_or_else(|e| e.into_inner());
                            state.expected =
                                state.expected.or_else(|| hashes.get(&meta.path).copied());
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
                        if state.bad || state.complete {
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
                        if state.bad {
                            log::error!(
                                "TORRENT SHA-256 MISMATCH: {} in {}; all further reads refused",
                                data.meta.files[file].path,
                                data.meta.identity()
                            );
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
            let hashes = checksums::load(&data.meta, &data.options.metadata_dir);
            let _ = data.verify_tx.send(Event::Hashes(hashes));
        })?;
    Ok(())
}
