//! Compact, quota-limited scratch storage. Logical torrent offsets never allocate holes.
use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, SystemTime};

use anyhow::{anyhow, Context};
use librqbit::storage::{BoxStorageFactory, StorageFactory, StorageFactoryExt, TorrentStorage};
use librqbit::{ManagedTorrentShared, TorrentMetadata};

const BLOCK: u64 = 16 * 1024;
const OWNER: &str = ".ratarmount-scratch-v1";

#[derive(Clone)]
pub(super) struct Factory {
    pub dir: PathBuf,
    pub limit: u64,
}
impl StorageFactory for Factory {
    type Storage = Storage;
    fn create(&self, _: &ManagedTorrentShared, _: &TorrentMetadata) -> anyhow::Result<Storage> {
        Storage::new(&self.dir, self.limit)
    }
    fn clone_box(&self) -> BoxStorageFactory {
        self.clone().boxed()
    }
}
struct Store {
    file: std::fs::File,
    slots: BTreeMap<(usize, u64), u64>,
    limit: u64,
}
pub(super) struct Storage(Mutex<Option<Store>>);
impl Storage {
    pub(super) fn new(dir: &Path, limit: u64) -> anyhow::Result<Self> {
        Ok(Self(Mutex::new(Some(Store {
            file: tempfile::tempfile_in(dir)?,
            slots: BTreeMap::new(),
            limit,
        }))))
    }
    fn with(&self, f: impl FnOnce(&mut Store) -> anyhow::Result<()>) -> anyhow::Result<()> {
        let mut store = self.0.lock().unwrap_or_else(|e| e.into_inner());
        f(store.as_mut().context("scratch storage paused")?)
    }
    pub(super) fn take_storage(&self) -> Self {
        Self(Mutex::new(
            self.0.lock().unwrap_or_else(|e| e.into_inner()).take(),
        ))
    }

    pub(super) fn pread_present(
        &self,
        file: usize,
        offset: u64,
        buf: &mut [u8],
    ) -> anyhow::Result<()> {
        self.pread(file, offset, buf, true)
    }

    fn pread(
        &self,
        file: usize,
        mut offset: u64,
        mut buf: &mut [u8],
        require_present: bool,
    ) -> anyhow::Result<()> {
        self.with(|store| {
            while !buf.is_empty() {
                let within = offset % BLOCK;
                let n = buf.len().min((BLOCK - within) as usize);
                if let Some(slot) = store.slots.get(&(file, offset / BLOCK)) {
                    store.file.seek(SeekFrom::Start(slot + within))?;
                    store.file.read_exact(&mut buf[..n])?;
                } else if require_present {
                    return Err(anyhow!(
                        "verified piece no longer available in cache/scratch"
                    ));
                } else {
                    buf[..n].fill(0);
                }
                offset += n as u64;
                buf = &mut std::mem::take(&mut buf)[n..];
            }
            Ok(())
        })
    }
}
impl TorrentStorage for Storage {
    fn init(&mut self, _: &ManagedTorrentShared, _: &TorrentMetadata) -> anyhow::Result<()> {
        Ok(())
    }
    fn pread_exact(&self, file: usize, offset: u64, buf: &mut [u8]) -> anyhow::Result<()> {
        self.pread(file, offset, buf, false)
    }
    fn pwrite_all(&self, file: usize, mut offset: u64, mut buf: &[u8]) -> anyhow::Result<()> {
        self.with(|store| {
            while !buf.is_empty() {
                let within = offset % BLOCK;
                let n = buf.len().min((BLOCK - within) as usize);
                let key = (file, offset / BLOCK);
                let slot = match store.slots.get(&key) {
                    Some(slot) => *slot,
                    None => {
                        let slot = store.slots.len() as u64 * BLOCK;
                        if slot + BLOCK > store.limit {
                            return Err(anyhow!("torrent scratch limit reached ({} bytes); increase --torrent-scratch-limit or use web seeds", store.limit));
                        }
                        store.file.set_len(slot + BLOCK)?;
                        store.slots.insert(key, slot);
                        slot
                    }
                };
                store.file.seek(SeekFrom::Start(slot + within))?;
                store.file.write_all(&buf[..n])?;
                offset += n as u64;
                buf = &buf[n..];
            }
            Ok(())
        })
    }
    fn remove_file(&self, _: usize, _: &Path) -> anyhow::Result<()> {
        Ok(())
    }
    fn remove_directory_if_empty(&self, _: &Path) -> anyhow::Result<()> {
        Ok(())
    }
    fn ensure_file_length(&self, _: usize, _: u64) -> anyhow::Result<()> {
        Ok(())
    }
    fn take(&self) -> anyhow::Result<Box<dyn TorrentStorage>> {
        Ok(Box::new(self.take_storage()))
    }
}

pub(super) fn mark_owned(dir: &Path) -> std::io::Result<std::fs::File> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(dir.join(OWNER))?;
    file.lock()?;
    Ok(file)
}

pub(super) fn sweep(dir: &Path, age: Duration) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        if !entry.file_name().to_string_lossy().starts_with("swarm-") {
            continue;
        }
        let Ok(meta) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if !meta.is_dir() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            // Only our own scratch directories are eligible for deletion.
            if meta.uid() != unsafe { libc::geteuid() } {
                continue;
            }
        }
        let marker = entry.path().join(OWNER);
        let Ok(meta) = std::fs::symlink_metadata(&marker) else {
            continue;
        };
        if !meta.is_file()
            || !meta
                .modified()
                .ok()
                .and_then(|t| SystemTime::now().duration_since(t).ok())
                .is_some_and(|elapsed| elapsed >= age)
        {
            continue;
        }
        let Ok(file) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(marker)
        else {
            continue;
        };
        if file.try_lock().is_err() {
            continue;
        }
        // An active runtime holds the marker lock, including during detached shutdown.
        if let Err(e) = std::fs::remove_dir_all(entry.path()) {
            log::debug!("torrent stale scratch cleanup: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Regression: an evicted verified piece was replaced by an unverified zero-filled scratch hole.
    #[test]
    fn regression_scratch_missing_slot_refuses_upload_read() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path(), BLOCK).unwrap();
        let mut bytes = [7; 5];
        storage.pread_exact(0, 0, &mut bytes).unwrap();
        assert_eq!(bytes, [0; 5]);
        assert!(storage.pread_present(0, 0, &mut bytes).is_err());
        storage.pwrite_all(0, 0, b"valid").unwrap();
        storage.pread_present(0, 0, &mut bytes).unwrap();
        assert_eq!(&bytes, b"valid");
    }

    /// Regression: sparse high-offset swarm reads grew scratch without a disk quota.
    #[test]
    fn regression_scratch_quota_bounds_high_offsets() {
        let dir = tempfile::tempdir().unwrap();
        let storage = Storage::new(dir.path(), 2 * BLOCK).unwrap();
        storage.pwrite_all(0, 1 << 40, b"hello").unwrap();
        storage.pwrite_all(1, 0, b"world").unwrap();
        storage.pwrite_all(0, 1 << 40, b"HELLO").unwrap();
        assert!(storage.pwrite_all(2, 0, b"refused").is_err());
        storage
            .with(|store| {
                assert_eq!(store.file.metadata()?.len(), 2 * BLOCK);
                assert_eq!(store.slots.len(), 2);
                Ok(())
            })
            .unwrap();
        let mut bytes = [0; 5];
        let storage = storage.take().unwrap();
        storage.pread_exact(0, 1 << 40, &mut bytes).unwrap();
        assert_eq!(&bytes, b"HELLO");
    }
    /// Regression: crashed swarm scratch leaked, while an age-only sweep could delete live data.
    #[test]
    fn regression_scratch_sweep_preserves_active_and_foreign() {
        let dir = tempfile::tempdir().unwrap();
        let stale = dir.path().join("swarm-stale");
        let active = dir.path().join("swarm-active");
        let foreign = dir.path().join("swarm-foreign");
        for p in [&stale, &active, &foreign] {
            std::fs::create_dir(p).unwrap();
        }
        drop(mark_owned(&stale).unwrap());
        let _lock = mark_owned(&active).unwrap();
        sweep(dir.path(), Duration::ZERO);
        assert!(!stale.exists());
        assert!(active.exists());
        assert!(foreign.exists());
    }
}
