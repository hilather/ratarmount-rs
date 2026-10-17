//! Share only complete SHA-256 files with the pinned Hub repository's blob cache.
use super::{hub_file, web_seed_url, Data, Metainfo, Piece};
use crate::hf_cache::{HubCache, LocalBlob};
use crate::HfLocation;
use std::io::{self, Read};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

struct Target {
    location: HfLocation,
    path: String,
    local: Mutex<(Option<String>, Option<LocalBlob>)>,
    trusted: Mutex<Option<(u64, String)>>,
    source: String,
}
pub(super) struct HubFiles {
    cache: Option<HubCache>,
    targets: Vec<Option<Target>>,
    pub(super) discover: bool,
}
impl HubFiles {
    pub fn new(meta: &Metainfo) -> Self {
        let mut files = Self::with_cache(meta, HubCache::sharing(&|key| std::env::var(key).ok()));
        // Tests inject mock Hub observations explicitly; never contact public APIs.
        files.discover = !cfg!(test);
        files
    }
    pub(super) fn with_cache(meta: &Metainfo, cache: Option<HubCache>) -> Self {
        let targets = (0..meta.files.len())
            .map(|file| {
                if meta.files[file].padding {
                    return None;
                }
                let mut identities = std::collections::BTreeSet::new();
                for seed in 0..meta.web_seeds.len() {
                    if let Some(identity) = web_seed_url(meta, seed, file)
                        .ok()
                        .and_then(|url| hub_file(&url))
                    {
                        identities.insert(identity);
                    }
                }
                // Conflicting repository identities cannot establish a snapshot mapping.
                if identities.len() != 1 {
                    return None;
                }
                let (repo, path) = identities.into_iter().next()?;
                Some(Target {
                    location: crate::parse_hf_url(&repo).ok()?,
                    path,
                    source: repo,
                    local: Mutex::new((None, None)),
                    trusted: Mutex::new(None),
                })
            })
            .collect();
        Self {
            cache,
            targets,
            discover: false,
        }
    }

    pub fn authorize(&self, hashes: &super::checksums::HubHashes) {
        for target in self.targets.iter().flatten() {
            if let Some(oid) = hashes.get(&(target.source.clone(), target.path.clone())) {
                *target.trusted.lock().unwrap_or_else(|e| e.into_inner()) = Some(oid.clone());
            }
        }
    }

    pub fn git_oid(&self, file: usize) -> Option<String> {
        self.targets[file]
            .as_ref()?
            .trusted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .filter(|(_, oid)| oid.len() == 40)
            .map(|(_, oid)| oid.clone())
    }

    fn local(&self, data: &Data, file: usize) -> Option<LocalBlob> {
        let target = self.targets[file].as_ref()?;
        let cache = self.cache.as_ref()?;
        let expected = {
            let state = data.verification[file]
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if state.bad {
                return None;
            }
            state.expected
        };
        let mut local = target.local.lock().unwrap_or_else(|e| e.into_inner());
        let expected = match expected {
            Some(hash) => hex::encode(hash),
            None => {
                let (blob, hash) = cache.find_snapshot_sha256(
                    &target.location,
                    &target.path,
                    data.meta.files[file].len,
                )?;
                let mut state = data.verification[file]
                    .lock()
                    .unwrap_or_else(|e| e.into_inner());
                if state.bad {
                    return None;
                }
                if state.expected.is_some_and(|expected| expected != hash) {
                    state.bad = true;
                    state.complete = false;
                    return None;
                }
                state.expected = Some(hash);
                *local = (Some(hex::encode(hash)), Some(blob.clone()));
                return Some(blob);
            }
        };
        if local.0.as_ref() != Some(&expected) {
            local.1 = cache.find_sha256(
                &target.location,
                &target.path,
                &expected,
                data.meta.files[file].len,
            );
            local.0 = Some(expected);
        }
        local.1.clone()
    }

    pub fn all_local(&self, data: &Data) -> bool {
        self.cache.is_some()
            && data
                .meta
                .files
                .iter()
                .enumerate()
                .all(|(file, meta)| meta.padding || self.local(data, file).is_some())
    }

    pub fn piece(&self, data: &Data, key: Piece) -> Option<Vec<u8>> {
        self.cache.as_ref()?;
        let spans = data.spans(key);
        let sources: Option<Vec<_>> = spans
            .iter()
            .map(|(file, _, _)| {
                if data.meta.files[*file].padding {
                    Some(None)
                } else {
                    self.local(data, *file).map(Some)
                }
            })
            .collect();
        let sources = sources?;
        let mut bytes = vec![0; data.size(key) as usize];
        let mut pos = 0;
        for ((_, mut offset, len), blob) in spans.into_iter().zip(sources) {
            if let Some(blob) = blob {
                let mut rest = &mut bytes[pos..pos + len];
                while !rest.is_empty() {
                    let n = blob.read_at(offset, rest).ok()?;
                    if n == 0 {
                        return None;
                    }
                    offset += n as u64;
                    rest = &mut rest[n..];
                }
            }
            pos += len;
        }
        data.verify_piece(key, &bytes).ok()?;
        Some(bytes)
    }

    pub fn publish(&self, data: &Arc<Data>, file: usize, sha256: [u8; 32]) -> io::Result<()> {
        let (Some(cache), Some(target)) = (&self.cache, &self.targets[file]) else {
            return Ok(());
        };
        let Some((size, etag)) = target
            .trusted
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
        else {
            // Metainfo, third-party manifests, checksum caches and local snapshots
            // never authorize new Hub snapshot entries. Only the pinned Hub API does.
            return Ok(());
        };
        if size != data.meta.files[file].len || (etag.len() == 64 && etag != hex::encode(sha256)) {
            return Ok(());
        }
        if target
            .local
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .1
            .is_some()
        {
            return Ok(());
        }
        let sha256 = hex::encode(sha256);
        let mut reader = FileReader {
            data: data.clone(),
            file,
            pos: 0,
        };
        let blob = match cache.install_reader(
            &target.location,
            &target.location.revision,
            &target.path,
            &etag,
            data.meta.files[file].len,
            &mut reader,
        ) {
            Ok(blob) => blob,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
            Err(e) => return Err(e),
        };
        *target.local.lock().unwrap_or_else(|e| e.into_inner()) = (Some(sha256), Some(blob));
        if let Some(ranges) = &data.options.range_cache {
            let mut pos = 0;
            while pos < data.meta.files[file].len {
                let (key, within) = data.key(file, pos);
                // Keep cross-file v1 pieces until every non-padding span is in a Hub blob.
                if data
                    .spans(key)
                    .iter()
                    .all(|(f, _, _)| data.meta.files[*f].padding || self.local(data, *f).is_some())
                {
                    ranges.remove_file(&data.token(key));
                }
                data.notify_seed(key);
                pos += data.size(key) - within as u64;
            }
        }
        Ok(())
    }
}

struct FileReader {
    data: Arc<Data>,
    file: usize,
    pos: u64,
}
impl Read for FileReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.data.stopped.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "torrent source unmounted",
            ));
        }
        let len = self.data.meta.files[self.file].len;
        if buf.is_empty() || self.pos == len {
            return Ok(0);
        }
        let (key, offset) = self.data.key(self.file, self.pos);
        let bytes = self.data.fetch_piece(key, true)?;
        let n = buf
            .len()
            .min(bytes.len() - offset)
            .min((len - self.pos) as usize);
        buf[..n].copy_from_slice(&bytes[offset..offset + n]);
        self.pos += n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: metainfo's hash alone or two different pinned repositories authorized a Hub snapshot.
    #[test]
    fn regression_hub_snapshot_requires_source_hash_and_unambiguous_identity() {
        let mut meta = Metainfo::parse(super::super::tests::single_file_fixture()).unwrap();
        meta.web_seeds = vec![format!(
            "https://huggingface.co/org/model/resolve/{}/file",
            "a".repeat(40)
        )];
        let files = HubFiles::with_cache(&meta, None);
        assert_eq!(
            *files.targets[0].as_ref().unwrap().trusted.lock().unwrap(),
            None
        );
        files.authorize(&std::collections::BTreeMap::from([(
            (format!("hf://org/model@{}", "a".repeat(40)), "file".into()),
            (4, "07".repeat(32)),
        )]));
        assert_eq!(
            *files.targets[0].as_ref().unwrap().trusted.lock().unwrap(),
            Some((4, "07".repeat(32)))
        );
        meta.web_seeds.push(format!(
            "https://huggingface.co/other/model/resolve/{}/file",
            "a".repeat(40)
        ));
        assert!(HubFiles::with_cache(&meta, None).targets[0].is_none());
    }
}
