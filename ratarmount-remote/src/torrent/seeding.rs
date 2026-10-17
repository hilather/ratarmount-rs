//! rqbit storage overlay: verified cache bytes first, quota-limited protocol scratch second.
//! Cache misses never fetch from the network on an upload/storage thread.
use super::{scratch, Data};
use anyhow::Context;
use librqbit::storage::{BoxStorageFactory, StorageFactory, StorageFactoryExt, TorrentStorage};
use librqbit::{ManagedTorrentShared, TorrentMetadata};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};

#[derive(Clone)]
pub(super) struct Factory {
    pub scratch: scratch::Factory,
    pub data: Weak<Data>,
    pub initializing: Arc<AtomicBool>,
}
impl StorageFactory for Factory {
    type Storage = Storage;
    fn create(
        &self,
        shared: &ManagedTorrentShared,
        metadata: &TorrentMetadata,
    ) -> anyhow::Result<Storage> {
        Ok(Storage {
            scratch: self.scratch.create(shared, metadata)?,
            data: self.data.clone(),
            initializing: self.initializing.clone(),
        })
    }
    fn clone_box(&self) -> BoxStorageFactory {
        self.clone().boxed()
    }
}

pub(super) struct Storage {
    scratch: scratch::Storage,
    data: Weak<Data>,
    initializing: Arc<AtomicBool>,
}
impl Storage {
    fn verified_scratch_piece(
        &self,
        data: &Data,
        key: super::Piece,
    ) -> anyhow::Result<Arc<Vec<u8>>> {
        let mut bytes = vec![0; data.size(key) as usize];
        let mut pos = 0;
        for (file, offset, len) in data.spans(key) {
            if !data.meta.files[file].padding {
                self.scratch
                    .pread_present(file, offset, &mut bytes[pos..pos + len])?;
            }
            pos += len;
        }
        // rqbit may have hashed the cache overlay, while a speculative download
        // wrote different scratch blocks underneath it. Its HAVE bit alone cannot
        // authenticate that shadow after the cached piece is evicted.
        data.verify_piece(key, &bytes)?;
        let bytes = Arc::new(bytes);
        data.pieces
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(key, bytes.clone());
        Ok(bytes)
    }
}

impl TorrentStorage for Storage {
    fn externally_populated(&self) -> bool {
        true
    }
    fn init(
        &mut self,
        shared: &ManagedTorrentShared,
        metadata: &TorrentMetadata,
    ) -> anyhow::Result<()> {
        self.scratch.init(shared, metadata)
    }
    fn pread_exact(&self, file: usize, mut offset: u64, mut buf: &mut [u8]) -> anyhow::Result<()> {
        let data = self.data.upgrade().context("torrent source unmounted")?;
        if data.verification[file]
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .bad
        {
            anyhow::bail!("torrent file failed whole-file SHA-256 verification");
        }
        while !buf.is_empty() {
            let (key, within) = data.key(file, offset);
            let n = buf.len().min(data.size(key) as usize - within);
            if let Some(bytes) = data.available_piece(key) {
                buf[..n].copy_from_slice(&bytes[within..within + n]);
            } else {
                // rqbit hashes scratch before setting HAVE or answering requests.
                // Zero-filled missing slots fail that check (unless authentically zero).
                if self.initializing.load(Ordering::Acquire) {
                    self.scratch.pread_exact(file, offset, &mut buf[..n])?;
                } else {
                    // A previously advertised cache piece may have been evicted or
                    // corrupted. Never replace it with an unverified zero-filled hole.
                    let bytes = self.verified_scratch_piece(&data, key)?;
                    buf[..n].copy_from_slice(&bytes[within..within + n]);
                }
            }
            offset += n as u64;
            buf = &mut std::mem::take(&mut buf)[n..];
        }
        Ok(())
    }
    fn pwrite_all(&self, file: usize, offset: u64, buf: &[u8]) -> anyhow::Result<()> {
        self.scratch.pwrite_all(file, offset, buf)
    }
    fn remove_file(&self, file: usize, path: &Path) -> anyhow::Result<()> {
        self.scratch.remove_file(file, path)
    }
    fn remove_directory_if_empty(&self, path: &Path) -> anyhow::Result<()> {
        self.scratch.remove_directory_if_empty(path)
    }
    fn ensure_file_length(&self, file: usize, len: u64) -> anyhow::Result<()> {
        self.scratch.ensure_file_length(file, len)
    }
    fn take(&self) -> anyhow::Result<Box<dyn TorrentStorage>> {
        Ok(Box::new(Self {
            scratch: self.scratch.take_storage(),
            data: self.data.clone(),
            initializing: self.initializing.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::torrent::{
        Piece, SwarmOptions, TorrentMountSource, TorrentOptions, TorrentSwarmPolicy,
    };
    use ratarmount_index::RangeCache;

    /// Regression: rqbit authenticated a cached overlay, then eviction exposed different unverified scratch blocks.
    #[test]
    fn regression_cache_eviction_never_exposes_unverified_scratch_shadow() {
        let dir = tempfile::tempdir().unwrap();
        let cache = RangeCache::with_dirs(
            dir.path().join("range-v1"),
            dir.path().into(),
            1024 * 1024,
            4096,
        );
        let source = TorrentMountSource::from_bytes(
            crate::torrent::tests::single_file_fixture(),
            TorrentOptions {
                metadata_dir: dir.path().join("metadata"),
                range_cache: Some(cache.clone()),
                swarm: SwarmOptions {
                    policy: TorrentSwarmPolicy::Never,
                    ..Default::default()
                },
                readahead_bytes: 0,
            },
        )
        .unwrap();
        let storage = Storage {
            scratch: scratch::Storage::new(dir.path(), 16384).unwrap(),
            data: Arc::downgrade(&source.data),
            initializing: Arc::new(AtomicBool::new(false)),
        };
        let key = Piece {
            file: None,
            index: 0,
        };
        source.data.store(key, b"test");
        storage.pwrite_all(0, 0, b"evil").unwrap();
        let mut output = [0; 4];
        storage.pread_exact(0, 0, &mut output).unwrap();
        assert_eq!(&output, b"test");
        cache.remove_file(&source.data.token(key));
        *source.data.pieces.lock().unwrap() = Default::default();
        assert!(storage.pread_exact(0, 0, &mut output).is_err());
        storage.pwrite_all(0, 0, b"test").unwrap();
        storage.pread_exact(0, 0, &mut output).unwrap();
        assert_eq!(&output, b"test");
    }
}
