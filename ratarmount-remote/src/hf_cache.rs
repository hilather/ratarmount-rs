//! Shared huggingface_hub blobs and network-free snapshot mounts.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{mpsc, Arc, Condvar, Mutex, Once, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use ratarmount_core::{
    create_root_file_info, ArchiveRead, BackingExtent, CheapDirent, FileInfo, ListResult,
    MountSource, UserData, S_IFDIR, S_IFREG,
};
use ratarmount_index::{ContentToken, RangeCache};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::{parse_hf_url, HfLocation, RemoteError, Result};

fn error(message: impl Into<String>) -> RemoteError {
    RemoteError::Hf(message.into())
}

pub(crate) fn is_commit(value: &str) -> bool {
    value.len() == 40 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_etag(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|b| b.is_ascii_hexdigit())
}

fn relative(path: &Path) -> bool {
    !path.as_os_str().is_empty() && path.components().all(|p| matches!(p, Component::Normal(_)))
}

/// Below the explicitly configured root, directory symlinks are never traversed.
fn directories(root: &Path, path: &Path, create: bool) -> io::Result<()> {
    let suffix = path.strip_prefix(root).map_err(io::Error::other)?;
    if create {
        fs::create_dir_all(root)?;
    }
    let mut current = root.to_path_buf();
    for part in suffix.components() {
        if !matches!(part, Component::Normal(_)) {
            return Err(io::Error::other("invalid Hub cache directory"));
        }
        current.push(part);
        if create {
            match fs::create_dir(&current) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
        }
        if !fs::symlink_metadata(&current)?.is_dir() {
            return Err(io::Error::other(
                "Hub cache directory is a symlink or non-directory",
            ));
        }
    }
    Ok(())
}

pub(crate) fn open_regular(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() || fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(io::Error::other("Hub cache blob is not a regular file"));
    }
    Ok(file)
}

#[derive(Clone, PartialEq, Eq)]
struct Stamp {
    len: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    identity: (u64, u64, i64, i64),
}

fn stamp(file: &File) -> io::Result<Stamp> {
    let meta = file.metadata()?;
    Ok(Stamp {
        len: meta.len(),
        modified: meta.modified().ok(),
        #[cfg(unix)]
        identity: {
            use std::os::unix::fs::MetadataExt;
            (meta.dev(), meta.ino(), meta.ctime(), meta.ctime_nsec())
        },
    })
}

fn digest(file: &mut File, etag: &str) -> io::Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut sha256 = Sha256::new();
    let mut sha1 = Sha1::new();
    sha1.update(format!("blob {}\0", file.metadata()?.len()).as_bytes());
    let mut buf = [0; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        if etag.len() == 64 {
            sha256.update(&buf[..n]);
        } else {
            sha1.update(&buf[..n]);
        }
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(if etag.len() == 64 {
        format!("{:x}", sha256.finalize())
    } else {
        format!("{:x}", sha1.finalize())
    })
}

fn copy_verified(source: &mut File, dest: &mut File, etag: &str, size: u64) -> io::Result<()> {
    let mut sha256 = Sha256::new();
    let mut sha1 = Sha1::new();
    sha1.update(format!("blob {size}\0").as_bytes());
    let mut reader = source.take(size.saturating_add(1));
    let mut copied = 0u64;
    let mut buf = [0; 64 * 1024];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        copied += n as u64;
        dest.write_all(&buf[..n])?;
        if etag.len() == 64 {
            sha256.update(&buf[..n]);
        } else {
            sha1.update(&buf[..n]);
        }
    }
    let actual = if etag.len() == 64 {
        format!("{:x}", sha256.finalize())
    } else {
        format!("{:x}", sha1.finalize())
    };
    if copied != size || !actual.eq_ignore_ascii_case(etag) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Hub cache content hash mismatch",
        ));
    }
    Ok(())
}

const VERIFY_MEMO_LIMIT: usize = 1024;
const RETRY_DELAY: Duration = Duration::from_secs(30);
const TEMP_MAX_AGE: Duration = Duration::from_secs(3600);
const TEMP_PREFIX: &str = ".tmp-ratarmount-hf3-";

#[derive(Default)]
struct VerifiedBlobs {
    entries: BTreeMap<PathBuf, (String, Stamp, bool, u64)>,
    clock: u64,
    order: BTreeSet<(u64, PathBuf)>,
}

impl VerifiedBlobs {
    fn get(&mut self, path: &Path, etag: &str, stamp: &Stamp) -> Option<bool> {
        let entry = self.entries.get_mut(path)?;
        if entry.0 != etag || &entry.1 != stamp {
            return None;
        }
        self.order.remove(&(entry.3, path.to_path_buf()));
        self.clock += 1;
        entry.3 = self.clock;
        self.order.insert((self.clock, path.to_path_buf()));
        Some(entry.2)
    }

    fn insert(&mut self, path: PathBuf, etag: String, stamp: Stamp, valid: bool) {
        if let Some(old) = self.entries.remove(&path) {
            self.order.remove(&(old.3, path.clone()));
        }
        if self.entries.len() >= VERIFY_MEMO_LIMIT {
            if let Some((_, oldest)) = self.order.pop_first() {
                self.entries.remove(&oldest);
            }
        }
        self.clock += 1;
        self.order.insert((self.clock, path.clone()));
        self.entries.insert(path, (etag, stamp, valid, self.clock));
    }
}

fn temporary(dir: &Path) -> io::Result<tempfile::NamedTempFile> {
    tempfile::Builder::new()
        .prefix(&format!("{TEMP_PREFIX}{}-", std::process::id()))
        .tempfile_in(dir)
}

// Probe the kernel-applied umask without changing the process-global mask.
// The descriptor receives fchmod before its name is published, like the Hub.
fn published_permissions(file: &File, dir: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let probe = tempfile::Builder::new()
            .prefix(&format!("{TEMP_PREFIX}{}-", std::process::id()))
            .permissions(fs::Permissions::from_mode(0o666))
            .tempfile_in(dir)?;
        file.set_permissions(fs::Permissions::from_mode(
            probe.as_file().metadata()?.permissions().mode() & 0o666,
        ))?;
    }
    #[cfg(not(unix))]
    let _ = (file, dir);
    Ok(())
}

fn sync_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn try_lock(file: &File) -> io::Result<()> {
    file.try_lock().map_err(|error| match error {
        std::fs::TryLockError::WouldBlock => io::Error::from(io::ErrorKind::WouldBlock),
        std::fs::TryLockError::Error(error) => error,
    })
}

fn reclaim_temps(dir: &Path, now: SystemTime) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(rest) = name.to_str().and_then(|s| s.strip_prefix(TEMP_PREFIX)) else {
            continue;
        };
        let Some(pid) = rest.split('-').next().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(meta) = fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if !meta.is_file()
            || !meta
                .modified()
                .ok()
                .and_then(|t| now.duration_since(t).ok())
                .is_some_and(|age| age > TEMP_MAX_AGE)
        {
            continue;
        }
        #[cfg(unix)]
        {
            // Do not unlink a live publisher's slow copy, regardless of its age.
            if pid > i32::MAX as u32
                || unsafe { libc::kill(pid as i32, 0) } == 0
                || io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
            {
                continue;
            }
            let _ = fs::remove_file(entry.path());
        }
        #[cfg(not(unix))]
        let _ = pid;
    }
}

#[cfg(test)]
type AfterFind = Box<dyn FnOnce(&Path) + Send>;

#[cfg(test)]
#[derive(Default)]
struct CacheStats {
    finds: std::sync::atomic::AtomicUsize,
    hashes: std::sync::atomic::AtomicUsize,
    installs: std::sync::atomic::AtomicUsize,
    after_find: Mutex<Option<AfterFind>>,
    spools: Mutex<Vec<PathBuf>>,
    before_install: Mutex<Option<(Arc<std::sync::Barrier>, Arc<std::sync::Barrier>)>>,
}

#[derive(Clone)]
pub(crate) struct HubCache {
    root: PathBuf,
    // None: verify LFS, trust regular blob size/name. Explicit true verifies both.
    verify: Option<bool>,
    verified: Arc<Mutex<VerifiedBlobs>>,
    disable_symlinks: bool,
    cleaned: Arc<Mutex<BTreeSet<PathBuf>>>,
    #[cfg(test)]
    stats: Arc<CacheStats>,
}

impl HubCache {
    pub(crate) fn from_values(env: &impl Fn(&str) -> Option<String>) -> Self {
        let home = env("HF_HOME").or_else(|| {
            env("XDG_CACHE_HOME")
                .or_else(|| env("HOME").map(|h| format!("{h}/.cache")))
                .map(|cache| format!("{cache}/huggingface"))
        });
        let root = env("HF_HUB_CACHE")
            .or_else(|| env("HUGGINGFACE_HUB_CACHE"))
            .or_else(|| home.map(|h| format!("{h}/hub")));
        let root = root
            .map(|path| crate::hf::expand_env_path(&path, env))
            .filter(|path| path != "~" && !path.starts_with("~/"))
            .map(PathBuf::from)
            .unwrap_or_default();
        Self {
            root,
            verify: env("RATARMOUNT_HF_CACHE_VERIFY").map(|v| v != "0"),
            verified: Arc::default(),
            disable_symlinks: env("HF_HUB_DISABLE_SYMLINKS").is_some_and(|v| {
                matches!(v.to_ascii_uppercase().as_str(), "1" | "TRUE" | "YES" | "ON")
            }),
            cleaned: Arc::default(),
            #[cfg(test)]
            stats: Arc::default(),
        }
    }

    pub(crate) fn sharing(env: &impl Fn(&str) -> Option<String>) -> Option<Self> {
        let cache = Self::from_values(env);
        if cache.root.as_os_str().is_empty() {
            return None;
        }
        match env("RATARMOUNT_HF_SHARE_CACHE").as_deref() {
            Some("0") => None,
            Some("1") => Some(cache),
            _ => cache.root.is_dir().then_some(cache),
        }
    }

    fn repo_dir(&self, location: &HfLocation) -> PathBuf {
        self.root.join(format!(
            "{}--{}",
            location.kind,
            location.repo.replace('/', "--")
        ))
    }

    fn checked(&self, path: &Path, etag: &str, size: Option<u64>, full: bool) -> Option<File> {
        let mut file = open_regular(path).ok()?;
        let before = stamp(&file).ok()?;
        if size.is_some_and(|size| size != before.len) {
            return None;
        }
        if full || is_etag(etag) && self.verify.unwrap_or(etag.len() == 64) {
            if !is_etag(etag) {
                return None;
            }
            #[cfg(unix)]
            let known = self
                .verified
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(path, etag, &before);
            #[cfg(not(unix))]
            let known = None;
            if known == Some(false) {
                return None;
            }
            if known != Some(true) {
                #[cfg(test)]
                self.stats
                    .hashes
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let valid = digest(&mut file, etag).ok()?.eq_ignore_ascii_case(etag);
                if stamp(&file).ok()? != before {
                    return None;
                }
                self.verified
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .insert(path.into(), etag.into(), before, valid);
                if !valid {
                    return None;
                }
            }
        }
        Some(file)
    }

    fn find(
        &self,
        location: &HfLocation,
        commit: &str,
        path: &str,
        etag: Option<&str>,
        size: Option<u64>,
    ) -> Option<LocalBlob> {
        #[cfg(test)]
        self.stats
            .finds
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if !is_commit(commit) || !relative(Path::new(path)) {
            return None;
        }
        let repo = self.repo_dir(location);
        let blobs = repo.join("blobs");
        directories(&self.root, &blobs, false).ok()?;
        let snapshot = repo.join("snapshots").join(commit).join(path);
        let mut candidates = Vec::new();
        if let Some(etag) = etag.filter(|etag| is_etag(etag)) {
            candidates.push((blobs.join(etag), etag.to_string()));
        }
        if directories(&self.root, snapshot.parent()?, false).is_ok() {
            if let Ok(meta) = fs::symlink_metadata(&snapshot) {
                if meta.file_type().is_symlink() {
                    if let (Ok(target), Ok(blobs)) = (snapshot.canonicalize(), blobs.canonicalize())
                    {
                        if target.parent() == Some(blobs.as_path()) {
                            if let Some(name) = target
                                .file_name()
                                .and_then(|n| n.to_str())
                                .filter(|n| is_etag(n))
                            {
                                if etag.is_none_or(|expected| expected.eq_ignore_ascii_case(name)) {
                                    candidates.push((target.clone(), name.into()));
                                }
                            }
                        }
                    }
                } else if meta.is_file() {
                    // huggingface_hub copies snapshots on systems without symlink support.
                    candidates.push((snapshot, etag.unwrap_or("").into()));
                }
            }
        }
        for (path, etag) in candidates {
            if let Some(file) = self.checked(&path, &etag, size, false) {
                #[cfg(test)]
                {
                    let hook = self.stats.after_find.lock().unwrap().take();
                    if let Some(hook) = hook {
                        hook(&path);
                    }
                }
                return Some(LocalBlob {
                    size: file.metadata().ok()?.len(),
                    path,
                    file: Arc::new(file),
                });
            }
        }
        None
    }

    fn tree_hashes(&self, location: &HfLocation, commit: &str) -> BTreeMap<String, String> {
        let trees = self.repo_dir(location).join("trees");
        let read = || -> Option<BTreeMap<String, String>> {
            directories(&self.root, &trees, false).ok()?;
            let value: serde_json::Value = serde_json::from_reader(
                open_regular(&trees.join(format!("{commit}.json")))
                    .ok()?
                    .take(256 * 1024 * 1024),
            )
            .ok()?;
            let hash = |entry: &serde_json::Value| {
                entry["lfs"]["oid"]
                    .as_str()
                    .or_else(|| entry["lfs_sha256"].as_str())
                    .or_else(|| entry["oid"].as_str())
                    .or_else(|| entry["blob_id"].as_str())
                    .map(|h| h.strip_prefix("sha256:").unwrap_or(h))
                    .filter(|h| is_etag(h))
                    .map(str::to_ascii_lowercase)
            };
            let mut hashes = BTreeMap::new();
            if let Some(files) = value["files"].as_object() {
                for (path, entry) in files {
                    if let Some(hash) = hash(entry) {
                        hashes.insert(path.clone(), hash);
                    }
                }
            } else if let Some(files) = value.as_array() {
                for entry in files {
                    if let (Some(path), Some(hash)) = (entry["path"].as_str(), hash(entry)) {
                        hashes.insert(path.into(), hash);
                    }
                }
            }
            Some(hashes)
        };
        read().unwrap_or_default()
    }

    fn copied_hash(&self, location: &HfLocation, commit: &str, path: &str) -> Option<String> {
        let meta = self
            .repo_dir(location)
            .join(".ratarmount-hashes-v1")
            .join(commit)
            .join(path);
        directories(&self.root, meta.parent()?, false).ok()?;
        let mut hash = String::new();
        open_regular(&meta)
            .ok()?
            .take(128)
            .read_to_string(&mut hash)
            .ok()?;
        is_etag(&hash).then_some(hash)
    }

    fn record_copy_hash(
        &self,
        location: &HfLocation,
        commit: &str,
        path: &str,
        etag: &str,
    ) -> io::Result<()> {
        let meta = self
            .repo_dir(location)
            .join(".ratarmount-hashes-v1")
            .join(commit)
            .join(path);
        let parent = meta.parent().unwrap();
        directories(&self.root, parent, true)?;
        let mut tmp = temporary(parent)?;
        tmp.write_all(etag.as_bytes())?;
        published_permissions(tmp.as_file(), parent)?;
        tmp.as_file().sync_all()?;
        tmp.persist(&meta).map_err(|e| e.error)?;
        sync_dir(parent)
    }

    pub(crate) fn observe_ref(&self, location: &HfLocation) -> Option<String> {
        let reference = self
            .repo_dir(location)
            .join("refs")
            .join(&location.revision);
        directories(&self.root, reference.parent()?, false).ok()?;
        let mut value = String::new();
        open_regular(&reference)
            .ok()?
            .take(128)
            .read_to_string(&mut value)
            .ok()?;
        Some(value)
    }

    pub(crate) fn record_open(
        &self,
        location: &HfLocation,
        commit: &str,
        observed: Option<&str>,
    ) -> io::Result<()> {
        if is_commit(&location.revision) || !relative(Path::new(&location.revision)) {
            return Ok(());
        }
        let reference = self
            .repo_dir(location)
            .join("refs")
            .join(&location.revision);
        let parent = reference.parent().unwrap();
        directories(&self.root, parent, true)?;
        let mut tmp = temporary(parent)?;
        tmp.write_all(commit.as_bytes())?;
        published_permissions(tmp.as_file(), parent)?;
        tmp.as_file().sync_all()?;
        let current = self.observe_ref(location);
        if current.as_deref() != observed {
            return Ok(());
        }
        if observed.is_none() {
            match tmp.persist_noclobber(&reference) {
                Ok(_) => {}
                Err(e) if e.error.kind() == io::ErrorKind::AlreadyExists => return Ok(()),
                Err(e) => return Err(e.error),
            }
        } else {
            tmp.persist(&reference).map_err(|e| e.error)?;
        }
        sync_dir(parent)
    }

    fn install(
        &self,
        location: &HfLocation,
        commit: &str,
        path: &str,
        etag: &str,
        complete: &Path,
        size: u64,
    ) -> io::Result<LocalBlob> {
        if !is_etag(etag) || !is_commit(commit) || !relative(Path::new(path)) {
            return Err(io::Error::other("invalid Hub cache identity"));
        }
        #[cfg(test)]
        self.stats
            .installs
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let repo = self.repo_dir(location);
        let blobs = repo.join("blobs");
        directories(&self.root, &blobs, true)?;
        let locks = self.root.join(".locks").join(repo.file_name().unwrap());
        directories(&self.root, &locks, true)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let lock = options.open(locks.join(format!("{etag}.lock")))?;
        try_lock(&lock)?;
        #[cfg(test)]
        {
            let gate = self.stats.before_install.lock().unwrap().take();
            if let Some((started, resume)) = gate {
                started.wait();
                resume.wait();
            }
        }
        let clean = self
            .cleaned
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(blobs.clone());
        if clean {
            reclaim_temps(&blobs, SystemTime::now());
        }
        let blob = blobs.join(etag);
        let file = if let Some(file) = self.checked(&blob, etag, Some(size), true) {
            file
        } else {
            let mut source = open_regular(complete)?;
            let mut tmp = temporary(&blobs)?;
            copy_verified(&mut source, tmp.as_file_mut(), etag, size)?;
            published_permissions(tmp.as_file(), &blobs)?;
            tmp.as_file().sync_all()?;
            let file = open_regular(tmp.path())?;
            if stamp(&file)? != stamp(tmp.as_file())? {
                return Err(io::Error::other(
                    "Hub temporary blob replaced during publication",
                ));
            }
            tmp.persist(&blob).map_err(|e| e.error)?;
            sync_dir(&blobs)?;
            self.verified
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .insert(blob.clone(), etag.into(), stamp(&file)?, true);
            file
        };
        let snapshot = repo.join("snapshots").join(commit).join(path);
        self.snapshot(&snapshot, path, etag, &file)?;
        if self.disable_symlinks || !cfg!(unix) {
            self.record_copy_hash(location, commit, path, etag)?;
        }
        // Publishing a pinned file must never move a mutable branch ref.
        Ok(LocalBlob {
            path: blob,
            size,
            file: Arc::new(file),
        })
    }

    fn snapshot(&self, snapshot: &Path, path: &str, etag: &str, blob: &File) -> io::Result<()> {
        let parent = snapshot.parent().unwrap();
        directories(&self.root, parent, true)?;
        #[cfg(unix)]
        if !self.disable_symlinks {
            let mut target = PathBuf::from("../..");
            for _ in Path::new(path).parent().unwrap().components() {
                target.push("..");
            }
            target.push("blobs");
            target.push(etag);
            let tmp = temporary(parent)?.into_temp_path();
            fs::remove_file(&tmp)?;
            std::os::unix::fs::symlink(target, &tmp)?;
            // TempPath owns cleanup even when rename fails or the link is dangling.
            fs::rename(&tmp, snapshot)?;
            return sync_dir(parent);
        }
        let mut tmp = temporary(parent)?;
        let mut reader = LocalReader {
            file: Arc::new(blob.try_clone()?),
            size: blob.metadata()?.len(),
            pos: 0,
        };
        io::copy(&mut reader, &mut tmp)?;
        published_permissions(tmp.as_file(), parent)?;
        tmp.as_file().sync_all()?;
        tmp.persist(snapshot).map_err(|e| e.error)?;
        sync_dir(parent)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct LocalBlob {
    pub(crate) path: PathBuf,
    pub(crate) size: u64,
    file: Arc<File>,
}

impl LocalBlob {
    pub(crate) fn read_at(&self, start: u64, buf: &mut [u8]) -> io::Result<usize> {
        read_at(&self.file, start, buf)
    }

    pub(crate) fn backing_file(&self) -> Option<File> {
        self.file.try_clone().ok()
    }

    fn reader(&self) -> LocalReader {
        LocalReader {
            file: self.file.clone(),
            size: self.size,
            pos: 0,
        }
    }
}

fn read_at(file: &File, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_at(buf, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        file.seek_read(buf, offset)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (file, offset, buf);
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
}

struct LocalReader {
    file: Arc<File>,
    size: u64,
    pos: u64,
}
impl Read for LocalReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = (buf.len() as u64).min(self.size.saturating_sub(self.pos)) as usize;
        if len == 0 {
            return Ok(0);
        }
        let n = read_at(&self.file, self.pos, &mut buf[..len])?;
        self.pos += n as u64;
        Ok(n)
    }
}
impl Seek for LocalReader {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let pos = match from {
            SeekFrom::Start(p) => i128::from(p),
            SeekFrom::Current(p) => i128::from(self.pos) + i128::from(p),
            SeekFrom::End(p) => i128::from(self.size) + i128::from(p),
        };
        self.pos = u64::try_from(pos).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        Ok(self.pos)
    }
}

type PublishJob = Box<dyn FnOnce() + Send>;
fn publisher() -> Option<&'static mpsc::SyncSender<PublishJob>> {
    static POOL: OnceLock<Option<mpsc::SyncSender<PublishJob>>> = OnceLock::new();
    POOL.get_or_init(|| {
        let (sender, receiver) = mpsc::sync_channel::<PublishJob>(64);
        let receiver = Arc::new(Mutex::new(receiver));
        for index in 0..2 {
            let receiver = receiver.clone();
            std::thread::Builder::new()
                .name(format!("hf-cache-{index}"))
                .spawn(move || loop {
                    let job = receiver.lock().unwrap_or_else(|e| e.into_inner()).recv();
                    let Ok(job) = job else {
                        break;
                    };
                    job();
                })
                .ok()?;
        }
        Some(sender)
    })
    .as_ref()
}

#[derive(Default)]
struct PublishState {
    chunks: BTreeSet<u64>,
    busy: bool,
    retry_at: Option<Instant>,
}

/// Read-side lookups are resolved once at open. Successful publication installs
/// an already-verified descriptor without revisiting a pathname in byte reads.
#[derive(Clone)]
pub(crate) struct HubCacheFile {
    cache: HubCache,
    location: HfLocation,
    commit: String,
    path: String,
    etag: Option<String>,
    size: Option<u64>,
    local: Arc<OnceLock<LocalBlob>>,
    lookup: Arc<Once>,
    state: Arc<(Mutex<PublishState>, Condvar)>,
}

/// Publication owns the same bytes/reservation or disk spool as live readers.
enum BufferedBody {
    Memory {
        bytes: Arc<Vec<u8>>,
        _memory: Option<Arc<ratarmount_core::budget::Reservation>>,
    },
    Disk {
        file: Arc<Mutex<File>>,
        size: u64,
    },
}

// Windows seek_read changes the shared cursor. Lock only each read, restoring
// that cursor before releasing it; publication writes never hold the reader lock.
#[cfg(any(not(unix), test))]
struct SpoolReader<'a> {
    file: &'a Mutex<File>,
    pos: u64,
    size: u64,
}

#[cfg(any(not(unix), test))]
impl Read for SpoolReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = (buf.len() as u64).min(self.size.saturating_sub(self.pos)) as usize;
        if len == 0 {
            return Ok(0);
        }
        let mut file = self.file.lock().unwrap_or_else(|e| e.into_inner());
        let saved = file.stream_position()?;
        file.seek(SeekFrom::Start(self.pos))?;
        let result = file.read(&mut buf[..len]);
        let restored = file.seek(SeekFrom::Start(saved));
        let count = result?;
        restored?;
        self.pos += count as u64;
        Ok(count)
    }
}

impl BufferedBody {
    fn size(&self) -> u64 {
        match self {
            Self::Memory { bytes, .. } => bytes.len() as u64,
            Self::Disk { size, .. } => *size,
        }
    }

    fn write_to(&self, writer: &mut impl Write) -> io::Result<()> {
        match self {
            Self::Memory { bytes, .. } => writer.write_all(bytes),
            Self::Disk { file, size } => {
                #[cfg(unix)]
                let mut reader = {
                    let file = file.lock().unwrap_or_else(|e| e.into_inner()).try_clone()?;
                    LocalReader {
                        file: Arc::new(file),
                        size: *size,
                        pos: 0,
                    }
                };
                #[cfg(not(unix))]
                let mut reader = SpoolReader {
                    file,
                    size: *size,
                    pos: 0,
                };
                if io::copy(&mut reader, writer)? != *size {
                    return Err(io::ErrorKind::UnexpectedEof.into());
                }
                Ok(())
            }
        }
    }
}

impl HubCacheFile {
    pub(crate) fn new(
        cache: HubCache,
        location: HfLocation,
        commit: String,
        path: String,
        etag: Option<String>,
        size: Option<u64>,
    ) -> Self {
        Self {
            cache,
            location,
            commit,
            path,
            etag,
            size,
            local: Arc::default(),
            lookup: Arc::new(Once::new()),
            state: Arc::default(),
        }
    }

    pub(crate) fn initialize(&self) {
        self.lookup.call_once(|| {
            if let Some(blob) = self.cache.find(
                &self.location,
                &self.commit,
                &self.path,
                self.etag.as_deref(),
                self.size,
            ) {
                let _ = self.local.set(blob);
            }
        });
    }

    pub(crate) fn local(&self) -> Option<&LocalBlob> {
        self.local.get()
    }

    pub(crate) fn complete(&self, ranges: &RangeCache, token: &ContentToken) -> Option<PathBuf> {
        if self.etag.is_none() {
            return ranges.complete_file(token);
        }
        self.schedule(Some(ranges.clone()), token.clone(), None);
        self.local()
            .filter(|b| b.size == token.size())
            .map(|b| b.path.clone())
    }

    fn schedule(
        &self,
        ranges: Option<RangeCache>,
        token: ContentToken,
        buffered: Option<BufferedBody>,
    ) {
        let mut state = self.state.0.lock().unwrap_or_else(|e| e.into_inner());
        if state.busy || state.retry_at.is_some_and(|t| t > Instant::now()) || self.etag.is_none() {
            return;
        }
        state.busy = true;
        drop(state);
        let bridge = self.clone();
        let job = Box::new(move || {
            let result = (|| -> io::Result<()> {
                if bridge.local().is_some() {
                    if let Some(ranges) = &ranges {
                        ranges.remove_file(&token);
                    }
                    return Ok(());
                }
                let mut spool = None;
                let complete = if let Some(bytes) = buffered {
                    let blobs = bridge.cache.repo_dir(&bridge.location).join("blobs");
                    directories(&bridge.cache.root, &blobs, true)?;
                    let mut tmp = temporary(&blobs)?;
                    bytes.write_to(&mut tmp)?;
                    let path = tmp.path().to_path_buf();
                    #[cfg(test)]
                    bridge.cache.stats.spools.lock().unwrap().push(path.clone());
                    spool = Some(tmp);
                    path
                } else {
                    ranges
                        .as_ref()
                        .and_then(|r| r.complete_file(&token))
                        .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))?
                };
                let blob = bridge.cache.install(
                    &bridge.location,
                    &bridge.commit,
                    &bridge.path,
                    bridge.etag.as_deref().unwrap(),
                    &complete,
                    token.size(),
                )?;
                let _ = bridge.local.set(blob);
                if let Some(ranges) = &ranges {
                    ranges.remove_file(&token);
                }
                drop(spool);
                Ok(())
            })();
            let mut state = bridge.state.0.lock().unwrap_or_else(|e| e.into_inner());
            state.busy = false;
            state.retry_at = result.as_ref().err().map(|_| Instant::now() + RETRY_DELAY);
            drop(state);
            bridge.state.1.notify_all();
            if let Err(error) = result {
                log::debug!("Hub cache background publication skipped: {error}");
            }
        });
        if publisher().is_none_or(|sender| sender.try_send(job).is_err()) {
            let mut state = self.state.0.lock().unwrap_or_else(|e| e.into_inner());
            state.busy = false;
            state.retry_at = Some(Instant::now() + RETRY_DELAY);
            self.state.1.notify_all();
        }
    }

    pub(crate) fn buffered(
        &self,
        bytes: Arc<Vec<u8>>,
        memory: Option<Arc<ratarmount_core::budget::Reservation>>,
    ) {
        self.publish_body(BufferedBody::Memory {
            bytes,
            _memory: memory,
        });
    }

    pub(crate) fn spooled(&self, file: Arc<Mutex<File>>, size: u64) {
        self.publish_body(BufferedBody::Disk { file, size });
    }

    fn publish_body(&self, body: BufferedBody) {
        let token = ContentToken::HfCommitPath {
            endpoint: "buffered".into(),
            repo_kind: self.location.kind.clone(),
            repo: self.location.repo.clone(),
            commit: self.commit.clone(),
            path: self.path.clone(),
            size: body.size(),
        };
        self.schedule(None, token, Some(body));
    }

    pub(crate) fn observed(&self, ranges: &RangeCache, token: &ContentToken, chunk: u64) {
        let mut state = self.state.0.lock().unwrap_or_else(|e| e.into_inner());
        state.chunks.insert(chunk);
        let ready = self.local.get().is_some()
            || state.chunks.len() as u64 == token.size().div_ceil(ranges.chunk_size());
        drop(state);
        if ready {
            self.schedule(Some(ranges.clone()), token.clone(), None);
        }
    }

    #[cfg(test)]
    pub(crate) fn wait(&self) {
        let state = self.state.0.lock().unwrap();
        let (_state, timed) = self
            .state
            .1
            .wait_timeout_while(state, Duration::from_secs(10), |s| s.busy)
            .unwrap();
        assert!(!timed.timed_out(), "Hub background publication timed out");
    }
}

/// A cached repository snapshot, or a directory of cached repository IDs.
/// This source never constructs an HTTP client and ignores HF_HUB_OFFLINE.
pub struct HfCacheMountSource {
    cache: HubCache,
    entries: BTreeMap<String, FileInfo>,
    files: BTreeMap<String, (HfLocation, String, String)>,
    commit: Option<String>,
    hashes: BTreeMap<String, String>,
}

impl HfCacheMountSource {
    pub fn open(input: &str) -> Result<Self> {
        Self::with_cache(input, HubCache::from_values(&|key| std::env::var(key).ok()))
    }

    fn with_cache(input: &str, cache: HubCache) -> Result<Self> {
        let (scheme, rest) = input
            .split_once("://")
            .ok_or_else(|| error("expected hf-cache:// URL"))?;
        if !scheme.eq_ignore_ascii_case("hf-cache") {
            return Err(error("expected hf-cache:// URL"));
        }
        if cache.root.as_os_str().is_empty() {
            return Err(error(
                "Hub cache location unavailable; set HF_HUB_CACHE, HF_HOME, XDG_CACHE_HOME or HOME",
            ));
        }
        let mut source = Self {
            cache,
            entries: BTreeMap::new(),
            files: BTreeMap::new(),
            commit: None,
            hashes: BTreeMap::new(),
        };
        source.add("", true, 0);
        if rest.is_empty() {
            for entry in fs::read_dir(&source.cache.root)? {
                let entry = entry?;
                let Ok(name) = entry.file_name().into_string() else {
                    continue;
                };
                if entry.file_type()?.is_dir()
                    && ["models--", "datasets--", "spaces--"]
                        .iter()
                        .any(|p| name.starts_with(p))
                {
                    source.add(&name, true, 0);
                }
            }
            return Ok(source);
        }
        let location = parse_hf_url(&format!("hf://{rest}"))?;
        let repo = source.cache.repo_dir(&location);
        let commit = if is_commit(&location.revision) {
            location.revision.to_ascii_lowercase()
        } else {
            let reference = repo.join("refs").join(&location.revision);
            let safe = directories(&source.cache.root, reference.parent().unwrap(), false).is_ok();
            safe.then(|| open_regular(&reference).ok())
                .flatten()
                .and_then(|file| {
                    let mut text = String::new();
                    file.take(128).read_to_string(&mut text).ok()?;
                    is_commit(text.trim()).then(|| text.trim().to_ascii_lowercase())
                })
                .unwrap_or_default()
        };
        let commit = if commit.is_empty()
            && (4..40).contains(&location.revision.len())
            && location.revision.bytes().all(|b| b.is_ascii_hexdigit())
        {
            let prefix = location.revision.to_ascii_lowercase();
            let mut matches = Vec::new();
            if directories(&source.cache.root, &repo.join("snapshots"), false).is_ok() {
                if let Ok(entries) = fs::read_dir(repo.join("snapshots")) {
                    for entry in entries.flatten() {
                        let Ok(name) = entry.file_name().into_string() else {
                            continue;
                        };
                        if is_commit(&name)
                            && name.starts_with(&prefix)
                            && entry.file_type().is_ok_and(|t| t.is_dir())
                        {
                            matches.push(name);
                        }
                    }
                }
            }
            if matches.len() > 1 {
                return Err(error(format!(
                    "ambiguous cached commit prefix: {}",
                    location.revision
                )));
            }
            matches.pop().unwrap_or_default()
        } else {
            commit
        };
        let snapshot = repo.join("snapshots").join(&commit);
        if commit.is_empty() || directories(&source.cache.root, &snapshot, false).is_err() {
            let mut available = Vec::new();
            source.available(&repo.join("refs"), "", &mut available);
            if let Ok(entries) = fs::read_dir(repo.join("snapshots")) {
                available.extend(entries.flatten().filter_map(|e| {
                    e.file_name()
                        .to_str()
                        .filter(|s| is_commit(s))
                        .map(str::to_owned)
                }));
            }
            available.sort();
            return Err(error(format!(
                "cached Hub snapshot not found for {}@{}; available revisions: {}",
                location.repo,
                location.revision,
                if available.is_empty() {
                    "(none)".into()
                } else {
                    available.join(", ")
                }
            )));
        }
        source.hashes = source.cache.tree_hashes(&location, &commit);
        source.commit = Some(commit.clone());
        source.walk(&snapshot, "", &location, &commit)?;
        if !location.path.is_empty() {
            let prefix = format!("{}/", location.path);
            if !source
                .entries
                .get(&location.path)
                .is_some_and(|fi| fi.mode & S_IFDIR != 0)
            {
                return Err(error("hf-cache:// path must name a cached directory"));
            }
            source.entries = source
                .entries
                .into_iter()
                .filter_map(|(path, fi)| {
                    if path == location.path {
                        Some((String::new(), fi))
                    } else {
                        path.strip_prefix(&prefix).map(|p| (p.into(), fi))
                    }
                })
                .collect();
            source.files = source
                .files
                .into_iter()
                .filter_map(|(path, file)| path.strip_prefix(&prefix).map(|p| (p.into(), file)))
                .collect();
            for (path, fi) in &mut source.entries {
                fi.userdata = vec![UserData::Other(path.clone())];
            }
        }
        Ok(source)
    }

    fn available(&self, dir: &Path, prefix: &str, out: &mut Vec<String>) {
        if directories(&self.cache.root, dir, false).is_err() {
            return;
        }
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let Ok(name) = entry.file_name().into_string() else {
                    continue;
                };
                let name = format!("{prefix}{name}");
                if entry.file_type().is_ok_and(|ty| ty.is_dir()) {
                    self.available(&entry.path(), &format!("{name}/"), out);
                } else if entry.file_type().is_ok_and(|ty| ty.is_file()) {
                    out.push(name);
                }
            }
        }
    }

    fn add(&mut self, path: &str, dir: bool, size: u64) {
        let mut fi = create_root_file_info();
        fi.mode = if dir {
            S_IFDIR | 0o555
        } else {
            S_IFREG | 0o444
        };
        fi.size = size;
        fi.userdata = vec![UserData::Other(path.into())];
        self.entries.insert(path.into(), fi);
    }

    fn walk(
        &mut self,
        dir: &Path,
        prefix: &str,
        location: &HfLocation,
        commit: &str,
    ) -> Result<()> {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let Ok(name) = entry.file_name().into_string() else {
                continue;
            };
            let path = format!("{prefix}{name}");
            let ty = entry.file_type()?;
            if ty.is_dir() {
                self.add(&path, true, 0);
                self.walk(&entry.path(), &format!("{path}/"), location, commit)?;
            } else if let Some(blob) = {
                // Listing needs blob metadata, not a full scan of every cached weight.
                // Read/open and backing_extent apply the configured verification.
                let mut metadata_cache = self.cache.clone();
                metadata_cache.verify = Some(false);
                metadata_cache.find(location, commit, &path, None, None)
            } {
                self.add(&path, false, blob.size);
                self.files
                    .insert(path.clone(), (location.clone(), commit.into(), path));
            }
        }
        Ok(())
    }

    fn children(&self, path: &str) -> Option<impl Iterator<Item = (&str, &FileInfo)>> {
        let path = path.trim_matches('/');
        if self.entries.get(path)?.mode & S_IFDIR == 0 {
            return None;
        }
        let prefix = if path.is_empty() {
            String::new()
        } else {
            format!("{path}/")
        };
        let len = prefix.len();
        Some(
            self.entries
                .range(prefix.clone()..)
                .take_while(move |(path, _)| path.starts_with(&prefix))
                .filter_map(move |(path, fi)| {
                    let name = &path[len..];
                    (!name.is_empty() && !name.contains('/')).then_some((name, fi))
                }),
        )
    }

    fn blob(&self, fi: &FileInfo) -> Option<LocalBlob> {
        let path = fi.userdata.iter().find_map(|u| {
            if let UserData::Other(p) = u {
                Some(p)
            } else {
                None
            }
        })?;
        let (location, commit, original) = self.files.get(path)?;
        let expected = self
            .hashes
            .get(original)
            .cloned()
            .or_else(|| self.cache.copied_hash(location, commit, original));
        self.cache.find(
            location,
            commit,
            original,
            expected.as_deref(),
            Some(fi.size),
        )
    }
}

impl MountSource for HfCacheMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        Some(ListResult::Infos(
            self.children(path)?
                .map(|(name, fi)| (name.into(), fi.clone()))
                .collect(),
        ))
    }
    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        Some(
            self.children(path)?
                .map(|(name, fi)| CheapDirent {
                    name: name.into(),
                    mode: fi.mode,
                    size: fi.size,
                })
                .collect(),
        )
    }
    fn lookup(&self, path: &str, _version: i32) -> Option<FileInfo> {
        self.entries.get(path.trim_matches('/')).cloned()
    }
    fn open(&self, fi: &FileInfo, _buffering: i32) -> io::Result<Box<dyn ArchiveRead>> {
        let blob = self.blob(fi).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                "cached Hub blob missing or corrupt",
            )
        })?;
        Ok(Box::new(blob.reader()))
    }
    fn supports_backing_extents(&self) -> bool {
        true
    }
    fn backing_extent(&self, fi: &FileInfo) -> Option<BackingExtent> {
        let blob = self.blob(fi)?;
        Some(BackingExtent {
            file: blob.backing_file()?,
            offset: 0,
            len: blob.size,
        })
    }
    fn member_seek_is_cheap(&self, _fi: &FileInfo) -> bool {
        true
    }
    fn is_immutable(&self) -> bool {
        true
    }
    fn list_xattr(&self, _fi: &FileInfo) -> Vec<String> {
        self.commit
            .as_ref()
            .map(|_| vec!["user.hf.commit".into()])
            .unwrap_or_default()
    }
    fn get_xattr(&self, _fi: &FileInfo, key: &str) -> Option<Vec<u8>> {
        (key == "user.hf.commit")
            .then(|| self.commit.as_ref().map(|s| s.as_bytes().to_vec()))
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

    fn cache(root: &Path) -> HubCache {
        HubCache::from_values(&|key| (key == "HF_HUB_CACHE").then(|| root.to_string_lossy().into()))
    }

    fn fixture(
        root: &Path,
        path: &str,
        bytes: &[u8],
        lfs: bool,
    ) -> (HubCache, HfLocation, String, PathBuf) {
        let cache = cache(root);
        let location = parse_hf_url("hf://datasets/org/data@feature%2Fone").unwrap();
        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(bytes).unwrap();
        let hash_template = "0".repeat(if lfs { 64 } else { 40 });
        let etag = digest(source.as_file_mut(), &hash_template).unwrap();
        cache.record_open(&location, COMMIT, None).unwrap();
        let blob = cache
            .install(
                &location,
                COMMIT,
                path,
                &etag,
                source.path(),
                bytes.len() as u64,
            )
            .unwrap();
        (cache, location, etag, blob.path)
    }

    /// Regression: completed remote bytes used a second layout unrecognized by the Hub.
    #[test]
    fn regression_hf_cache_atomic_layout_git_and_lfs() {
        for lfs in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let (cache, location, etag, blob) =
                fixture(dir.path(), "sub/data.bin", b"shared bytes", lfs);
            let repo = cache.repo_dir(&location);
            assert_eq!(fs::read(&blob).unwrap(), b"shared bytes");
            assert_eq!(
                fs::read_to_string(repo.join("refs/feature/one")).unwrap(),
                COMMIT
            );
            let pointer = repo.join("snapshots").join(COMMIT).join("sub/data.bin");
            #[cfg(unix)]
            assert_eq!(
                fs::read_link(&pointer).unwrap(),
                Path::new("../../../blobs").join(&etag)
            );
            assert_eq!(fs::read(pointer).unwrap(), b"shared bytes");
            assert!(dir
                .path()
                .join(".locks/datasets--org--data")
                .join(format!("{etag}.lock"))
                .is_file());
            assert_eq!(fs::read_dir(repo.join("blobs")).unwrap().count(), 1);
            assert_eq!(
                cache
                    .find(&location, COMMIT, "another-name", Some(&etag), Some(12))
                    .unwrap()
                    .path,
                blob
            );
        }
    }

    /// Regression: same-size corrupt LFS blobs were served, and verification memo hid replacement.
    #[test]
    fn regression_hf_cache_lfs_corruption_invalidates_verification_memo() {
        let dir = tempfile::tempdir().unwrap();
        let (cache, location, etag, blob) = fixture(dir.path(), "weights", b"correct", true);
        assert!(cache
            .find(&location, COMMIT, "weights", Some(&etag), Some(7))
            .is_some());
        fs::write(&blob, b"corrupt").unwrap();
        assert!(cache
            .find(&location, COMMIT, "weights", Some(&etag), Some(7))
            .is_none());
        assert!(
            !cache.verified.lock().unwrap().entries.get(&blob).unwrap().2,
            "remember a rejected fingerprint too, rather than rehashing a corrupt weight per read"
        );
        let mut unchecked = cache.clone();
        unchecked.verify = Some(false);
        assert!(unchecked
            .find(&location, COMMIT, "weights", Some(&etag), Some(7))
            .is_some());
        assert!(unchecked
            .find(&location, COMMIT, "weights", Some(&etag), Some(8))
            .is_none());
    }

    /// Regression: full verification must use Git's blob header for ordinary file hashes.
    #[test]
    fn regression_hf_cache_regular_full_verification_and_wrong_publication() {
        let dir = tempfile::tempdir().unwrap();
        let (mut cache, location, etag, blob) = fixture(dir.path(), "config", b"correct", false);
        fs::write(&blob, b"corrupt").unwrap();
        assert!(cache
            .find(&location, COMMIT, "config", Some(&etag), Some(7))
            .is_some());
        cache.verify = Some(true);
        assert!(cache
            .find(&location, COMMIT, "config", Some(&etag), Some(7))
            .is_none());
        let error = cache
            .install(&location, COMMIT, "bad", &etag, &blob, 7)
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(!cache
            .repo_dir(&location)
            .join("snapshots")
            .join(COMMIT)
            .join("bad")
            .exists());
    }

    /// Regression: snapshot symlinks and cache subdirectories escaped the configured blobs directory.
    #[cfg(unix)]
    #[test]
    fn regression_hf_cache_symlink_escape_and_incomplete_rejected() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let (cache, location, etag, _) = fixture(dir.path(), "good", b"good", true);
        let repo = cache.repo_dir(&location);
        let snapshot = repo.join("snapshots").join(COMMIT);
        let outside = tempfile::tempdir().unwrap();
        fs::write(outside.path().join(&etag), b"good").unwrap();
        symlink(outside.path().join(&etag), snapshot.join("escape")).unwrap();
        symlink(outside.path(), snapshot.join("directory")).unwrap();
        fs::write(
            repo.join("blobs").join(format!("{etag}.incomplete")),
            b"good",
        )
        .unwrap();
        symlink(
            format!("../../blobs/{etag}.incomplete"),
            snapshot.join("partial"),
        )
        .unwrap();
        assert!(cache
            .find(&location, COMMIT, "escape", None, None)
            .is_none());
        assert!(cache
            .find(&location, COMMIT, "directory/anything", None, None)
            .is_none());
        assert!(cache
            .find(&location, COMMIT, "partial", None, None)
            .is_none());
        let source =
            HfCacheMountSource::with_cache("hf-cache://datasets/org/data@feature%2Fone", cache)
                .unwrap();
        assert!(source.lookup("/good", 0).is_some());
        assert!(source.lookup("/escape", 0).is_none());
        assert!(source.lookup("/directory", 0).is_none());
        assert!(source.lookup("/partial", 0).is_none());
    }

    /// Regression: hf-cache:// needs no endpoint/token, exposes symlinks as regular files and local extents.
    #[test]
    fn regression_hf_cache_offline_revisions_listing_reads_and_extent() {
        let dir = tempfile::tempdir().unwrap();
        let (cache, _, _, _) = fixture(dir.path(), "sub/file", b"offline", true);
        for revision in ["feature%2Fone", COMMIT] {
            let source = HfCacheMountSource::with_cache(
                &format!("hf-cache://datasets/org/data@{revision}"),
                cache.clone(),
            )
            .unwrap();
            let fi = source.lookup("/sub/file", 0).unwrap();
            assert_eq!(fi.mode & S_IFREG, S_IFREG);
            assert_eq!(fi.size, 7);
            assert_eq!(source.list_dirents("/sub").unwrap()[0].name, "file");
            let mut data = Vec::new();
            source.open(&fi, 0).unwrap().read_to_end(&mut data).unwrap();
            assert_eq!(data, b"offline");
            let mut extent = source.backing_extent(&fi).unwrap();
            assert_eq!(extent.offset, 0);
            assert_eq!(extent.len, 7);
            let mut data = Vec::new();
            extent.file.read_to_end(&mut data).unwrap();
            assert_eq!(data, b"offline");
        }
        let source = HfCacheMountSource::with_cache(
            "hf-cache://datasets/org/data@feature%2Fone/sub",
            cache.clone(),
        )
        .unwrap();
        assert!(source.lookup("/file", 0).is_some());
        let catalog = HfCacheMountSource::with_cache("hf-cache://", cache.clone()).unwrap();
        assert_eq!(
            catalog.list_dirents("/").unwrap()[0].name,
            "datasets--org--data"
        );
        assert!(catalog
            .list_dirents("/datasets--org--data")
            .unwrap()
            .is_empty());
        let error = HfCacheMountSource::with_cache("hf-cache://datasets/org/data@missing", cache)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("available revisions"));
        assert!(error.contains("feature/one"));
        assert!(error.contains(COMMIT));
    }

    /// Regression: cache opt-out and HF_HOME/XDG precedence must not create a new Hub cache by default.
    #[test]
    fn regression_hf_cache_environment_and_opt_in() {
        let dir = tempfile::tempdir().unwrap();
        let env = |key: &str| match key {
            "HOME" => Some(dir.path().to_string_lossy().into()),
            "HF_HOME" => Some("~/custom".into()),
            _ => None,
        };
        assert_eq!(
            HubCache::from_values(&env).root,
            dir.path().join("custom/hub")
        );
        assert!(HubCache::sharing(&env).is_none());
        assert!(!dir.path().join("custom").exists());
        let explicit = |key: &str| {
            if key == "RATARMOUNT_HF_SHARE_CACHE" {
                Some("1".into())
            } else {
                env(key)
            }
        };
        assert!(HubCache::sharing(&explicit).is_some());
        fs::create_dir_all(dir.path().join("custom/hub")).unwrap();
        assert!(HubCache::sharing(&env).is_some());
        let disabled = |key: &str| {
            if key == "RATARMOUNT_HF_SHARE_CACHE" {
                Some("0".into())
            } else {
                env(key)
            }
        };
        assert!(HubCache::sharing(&disabled).is_none());
        assert!(
            HubCache::from_values(&|key| if key == "HF_HUB_DISABLE_SYMLINKS" {
                Some("true".into())
            } else {
                env(key)
            })
            .disable_symlinks
        );
        let legacy = |key: &str| match key {
            "XDG_CACHE_HOME" => Some(dir.path().to_string_lossy().into()),
            _ => None,
        };
        assert_eq!(
            HubCache::from_values(&legacy).root,
            dir.path().join("huggingface/hub")
        );
        let legacy = |key: &str| {
            (key == "HUGGINGFACE_HUB_CACHE").then(|| dir.path().to_string_lossy().into())
        };
        assert_eq!(HubCache::from_values(&legacy).root, dir.path());
    }

    /// Regression: an installer bypassed huggingface_hub's existing per-blob flock.
    #[test]
    fn regression_hf_cache_installer_honors_blob_lock() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache(dir.path());
        let location = parse_hf_url("hf://org/model").unwrap();
        let mut source = tempfile::NamedTempFile::new().unwrap();
        source.write_all(b"lock me").unwrap();
        let etag = digest(source.as_file_mut(), &"0".repeat(64)).unwrap();
        let lockdir = dir.path().join(".locks/models--org--model");
        fs::create_dir_all(&lockdir).unwrap();
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .read(true)
            .open(lockdir.join(format!("{etag}.lock")))
            .unwrap();
        lock.lock().unwrap();
        let error = cache
            .install(&location, COMMIT, "weights", &etag, source.path(), 7)
            .err()
            .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        assert!(!dir.path().join("models--org--model/snapshots").exists());
        lock.unlock().unwrap();
        cache
            .install(&location, COMMIT, "weights", &etag, source.path(), 7)
            .unwrap();
    }

    /// Regression: missing Hub hash metadata hid an otherwise complete range-cache file.
    #[test]
    fn regression_hf_cache_missing_hash_keeps_completed_range_path() {
        let dir = tempfile::tempdir().unwrap();
        let ranges = RangeCache::with_dirs(
            dir.path().join("payload/range-v1"),
            dir.path().join("payload"),
            1024,
            4,
        );
        let token = ContentToken::Sha256 {
            sha256: hex::encode(Sha256::digest(b"whole")),
            size: 5,
        };
        ranges.put(&token, 0, b"whol").unwrap();
        ranges.put(&token, 1, b"e").unwrap();
        let bridge = HubCacheFile::new(
            cache(&dir.path().join("hub")),
            parse_hf_url("hf://org/model").unwrap(),
            COMMIT.into(),
            "file".into(),
            None,
            Some(5),
        );
        let complete = bridge.complete(&ranges, &token).unwrap();
        assert_eq!(fs::read(&complete).unwrap(), b"whole");
        assert!(complete.starts_with(ranges.dir()));
        assert!(!dir.path().join("hub").exists());
    }

    /// Regression: persisted 0600 blobs/refs denied other users in a group-shared Hub cache.
    #[cfg(unix)]
    #[test]
    fn regression_hf_cache_group_shared_umask_permissions() {
        use std::os::unix::fs::PermissionsExt;
        const CHILD: &str = "RATARMOUNT_HF3_UMASK_CHILD";
        if let Ok(mask) = std::env::var(CHILD) {
            let mask = u32::from_str_radix(&mask, 8).unwrap();
            // This process is an isolated one-test child, never the parallel test runner.
            unsafe {
                libc::umask(mask as libc::mode_t);
            }
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("hub");
            let (cache, location, _, blob) = fixture(&root, "sub/file", b"shared", true);
            let repo = cache.repo_dir(&location);
            for file in [&blob, &repo.join("refs/feature/one")] {
                assert_eq!(
                    fs::metadata(file).unwrap().permissions().mode() & 0o777,
                    0o666 & !mask
                );
            }
            for directory in [
                &root,
                &repo,
                &repo.join("blobs"),
                &repo.join("refs"),
                &repo.join("snapshots").join(COMMIT).join("sub"),
            ] {
                assert_eq!(
                    fs::metadata(directory).unwrap().permissions().mode() & 0o777,
                    0o777 & !mask
                );
            }
            return;
        }
        for mask in ["002", "027"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "hf_cache::tests::regression_hf_cache_group_shared_umask_permissions",
                    "--nocapture",
                ])
                .env(CHILD, mask)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    /// Regression: publishing from an old pinned mount rolled refs/main back after Python advanced it.
    #[test]
    fn regression_hf_cache_late_publish_preserves_newer_ref() {
        let dir = tempfile::tempdir().unwrap();
        let (cache, location, etag, blob) = fixture(dir.path(), "first", b"original", true);
        let observed = cache.observe_ref(&location).unwrap();
        let new = "b".repeat(40);
        cache.record_open(&location, &new, Some(&observed)).unwrap();
        cache
            .install(&location, COMMIT, "later", &etag, &blob, 8)
            .unwrap();
        assert_eq!(cache.observe_ref(&location).unwrap(), new);
        // Python moved the ref while the mount's revision API was in flight.
        cache
            .record_open(&location, COMMIT, Some(&observed))
            .unwrap();
        assert_eq!(cache.observe_ref(&location).unwrap(), new);
        cache.record_open(&location, COMMIT, None).unwrap();
        assert_eq!(cache.observe_ref(&location).unwrap(), new);
    }

    /// Regression: reaching 1024 verification entries cleared hot hashes and rehashed multi-GB weights.
    #[test]
    fn regression_hf_cache_verification_lru_keeps_hot_entry() {
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let cache = cache(dir.path());
        let hash = hex::encode(Sha256::digest(b"x"));
        for index in 0..VERIFY_MEMO_LIMIT {
            let path = dir.path().join(index.to_string());
            fs::write(&path, b"x").unwrap();
            assert!(cache.checked(&path, &hash, Some(1), true).is_some());
        }
        let hot = dir.path().join("0");
        assert!(cache.checked(&hot, &hash, Some(1), true).is_some());
        fs::write(dir.path().join("new"), b"x").unwrap();
        assert!(cache
            .checked(&dir.path().join("new"), &hash, Some(1), true)
            .is_some());
        let hashes = cache.stats.hashes.load(Ordering::Relaxed);
        assert!(cache.checked(&hot, &hash, Some(1), true).is_some());
        assert_eq!(cache.stats.hashes.load(Ordering::Relaxed), hashes);
        let memo = cache.verified.lock().unwrap();
        assert_eq!(memo.entries.len(), VERIFY_MEMO_LIMIT);
        assert!(memo.entries.contains_key(&hot));
        assert!(!memo.entries.contains_key(&dir.path().join("1")));
    }

    fn range_fixture(root: &Path, hash: &str) -> (RangeCache, ContentToken) {
        let ranges =
            RangeCache::with_dirs(root.join("payload/range-v1"), root.join("payload"), 1024, 4);
        let token = ContentToken::Sha256 {
            sha256: hash.into(),
            size: 8,
        };
        ranges.put(&token, 0, b"orig").unwrap();
        ranges.put(&token, 1, b"inal").unwrap();
        (ranges, token)
    }

    /// Regression: hashing/copying under the file mutex stalled concurrent reads until publication ended.
    #[test]
    fn regression_hf_cache_background_publish_does_not_stall_reads() {
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let cache = cache(&dir.path().join("hub"));
        let hash = hex::encode(Sha256::digest(b"original"));
        let bridge = HubCacheFile::new(
            cache.clone(),
            parse_hf_url("hf://org/model").unwrap(),
            COMMIT.into(),
            "weights".into(),
            Some(hash.clone()),
            Some(8),
        );
        bridge.initialize();
        let (ranges, token) = range_fixture(dir.path(), &hash);
        let started = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        *cache.stats.before_install.lock().unwrap() = Some((started.clone(), resume.clone()));
        bridge.observed(&ranges, &token, 0);
        bridge.observed(&ranges, &token, 1);
        started.wait();
        // Worker is paused before hash/copy; readers and scheduling stay responsive.
        let (done_tx, done_rx) = mpsc::channel();
        let reader_bridge = bridge.clone();
        let reader_ranges = ranges.clone();
        let reader_token = token.clone();
        let reader = std::thread::spawn(move || {
            assert!(reader_bridge.local().is_none());
            assert_eq!(reader_ranges.get(&reader_token, 0).unwrap(), b"orig");
            reader_bridge.observed(&reader_ranges, &reader_token, 0);
            done_tx.send(()).unwrap();
        });
        let responsive = done_rx.recv_timeout(Duration::from_secs(2)).is_ok();
        let hashes = cache.stats.hashes.load(Ordering::Relaxed);
        resume.wait();
        reader.join().unwrap();
        bridge.wait();
        assert!(responsive);
        assert_eq!(
            hashes, 0,
            "publication hashing must not run on the read caller"
        );
        let local = bridge.local().unwrap();
        let mut bytes = Vec::new();
        local.reader().read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original");
        assert!(ranges.complete_file(&token).is_none());
    }

    /// Regression: a busy Python blob lock blocked readers, and failed installs retried on every chunk.
    #[test]
    fn regression_hf_cache_busy_lock_and_failed_install_backoff() {
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let cache = cache(&dir.path().join("hub"));
        let hash = hex::encode(Sha256::digest(b"original"));
        let location = parse_hf_url("hf://org/model").unwrap();
        let locks = cache.root.join(".locks/models--org--model");
        directories(&cache.root, &locks, true).unwrap();
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(locks.join(format!("{hash}.lock")))
            .unwrap();
        lock.lock().unwrap();
        let bridge = HubCacheFile::new(
            cache.clone(),
            location,
            COMMIT.into(),
            "weights".into(),
            Some(hash.clone()),
            Some(8),
        );
        bridge.initialize();
        let (ranges, token) = range_fixture(dir.path(), &hash);
        bridge.observed(&ranges, &token, 0);
        bridge.observed(&ranges, &token, 1);
        bridge.wait();
        assert!(bridge.local().is_none());
        assert!(ranges.contains(&token, 0));
        let attempts = cache.stats.installs.load(Ordering::Relaxed);
        for _ in 0..20 {
            bridge.observed(&ranges, &token, 0);
        }
        bridge.wait();
        assert_eq!(cache.stats.installs.load(Ordering::Relaxed), attempts);
        lock.unlock().unwrap();
        bridge.state.0.lock().unwrap().retry_at = Some(Instant::now());
        bridge.observed(&ranges, &token, 0);
        bridge.wait();
        assert!(bridge.local().is_some());
        assert!(!ranges.contains(&token, 0));
    }

    /// Regression: misses walked/canonicalized the cache, and hits reopened and reverified it on every read.
    #[test]
    fn regression_hf_cache_read_lookup_memo_and_verified_fd_survive_path_swap() {
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let (cache, location, etag, blob) = fixture(dir.path(), "file", b"original", true);
        let absent = HubCacheFile::new(
            cache.clone(),
            location.clone(),
            COMMIT.into(),
            "missing".into(),
            None,
            Some(8),
        );
        absent.initialize();
        let finds = cache.stats.finds.load(Ordering::Relaxed);
        for _ in 0..100 {
            assert!(absent.local().is_none());
        }
        assert_eq!(cache.stats.finds.load(Ordering::Relaxed), finds);
        let bridge = HubCacheFile::new(
            cache.clone(),
            location,
            COMMIT.into(),
            "file".into(),
            Some(etag),
            Some(8),
        );
        bridge.initialize();
        let hashes = cache.stats.hashes.load(Ordering::Relaxed);
        let finds = cache.stats.finds.load(Ordering::Relaxed);
        fs::rename(&blob, dir.path().join("old-blob")).unwrap();
        fs::write(&blob, b"tampered").unwrap();
        for _ in 0..20 {
            let mut bytes = [0; 8];
            assert_eq!(bridge.local().unwrap().read_at(0, &mut bytes).unwrap(), 8);
            assert_eq!(&bytes, b"original");
        }
        let mut extent = bridge.local().unwrap().backing_file().unwrap();
        let mut bytes = Vec::new();
        extent.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"original");
        assert_eq!(cache.stats.hashes.load(Ordering::Relaxed), hashes);
        assert_eq!(cache.stats.finds.load(Ordering::Relaxed), finds);
    }

    /// Regression: reopening after successful verification served a path's replacement inode.
    #[test]
    fn regression_hf_cache_offline_open_and_extent_use_verified_handle() {
        let dir = tempfile::tempdir().unwrap();
        let (cache, _, _, blob) = fixture(dir.path(), "file", b"original", true);
        let source = HfCacheMountSource::with_cache(
            "hf-cache://datasets/org/data@feature%2Fone",
            cache.clone(),
        )
        .unwrap();
        let fi = source.lookup("/file", 0).unwrap();
        for extent in [false, true] {
            fs::write(&blob, b"original").unwrap();
            let moved = dir
                .path()
                .join(if extent { "old-extent" } else { "old-reader" });
            *cache.stats.after_find.lock().unwrap() = Some(Box::new(move |path| {
                fs::rename(path, moved).unwrap();
                fs::write(path, b"tampered").unwrap();
            }));
            let mut bytes = Vec::new();
            if extent {
                source
                    .backing_extent(&fi)
                    .unwrap()
                    .file
                    .read_to_end(&mut bytes)
                    .unwrap();
            } else {
                source
                    .open(&fi, 0)
                    .unwrap()
                    .read_to_end(&mut bytes)
                    .unwrap();
            }
            assert_eq!(bytes, b"original");
        }
    }

    /// Regression: disabled-symlink snapshots lost known hashes, and unknown hashes made strict mode unreadable.
    #[test]
    fn regression_hf_cache_plain_copy_known_tree_hash_and_unknown_size_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let mut cache = cache(dir.path());
        cache.disable_symlinks = true;
        cache.verify = Some(true);
        let location = parse_hf_url("hf://org/model").unwrap();
        cache.record_open(&location, COMMIT, None).unwrap();
        let source = dir.path().join("source");
        fs::write(&source, b"original").unwrap();
        let etag = hex::encode(Sha256::digest(b"original"));
        let blob = cache
            .install(&location, COMMIT, "weights", &etag, &source, 8)
            .unwrap();
        let repo = cache.repo_dir(&location);
        let snapshot = repo.join("snapshots").join(COMMIT);
        assert!(!fs::symlink_metadata(snapshot.join("weights"))
            .unwrap()
            .file_type()
            .is_symlink());
        fs::remove_file(blob.path).unwrap();
        let mounted =
            HfCacheMountSource::with_cache("hf-cache://org/model", cache.clone()).unwrap();
        assert!(mounted
            .open(&mounted.lookup("/weights", 0).unwrap(), 0)
            .is_ok());
        fs::write(snapshot.join("weights"), b"tampered").unwrap();
        assert!(mounted
            .open(&mounted.lookup("/weights", 0).unwrap(), 0)
            .is_err());
        // An existing Python-style tree supplies hashes for copied snapshots.
        fs::write(snapshot.join("regular"), b"regular").unwrap();
        let mut file = File::open(snapshot.join("regular")).unwrap();
        let git_hash = digest(&mut file, &"0".repeat(40)).unwrap();
        directories(&cache.root, &repo.join("trees"), true).unwrap();
        fs::write(repo.join("trees").join(format!("{COMMIT}.json")), serde_json::json!({"format_version":1,"files":{"regular":{"blob_id":git_hash,"size":7}}}).to_string()).unwrap();
        fs::write(snapshot.join("unknown"), b"no hash available").unwrap();
        let mounted = HfCacheMountSource::with_cache("hf-cache://org/model", cache).unwrap();
        for path in ["/regular", "/unknown"] {
            assert!(mounted.open(&mounted.lookup(path, 0).unwrap(), 0).is_ok());
        }
        fs::write(snapshot.join("regular"), b"corrupt").unwrap();
        assert!(mounted
            .open(&mounted.lookup("/regular", 0).unwrap(), 0)
            .is_err());
    }

    /// Regression: crashed writers left owned temporary files forever, or rename failure left temp snapshot links.
    #[cfg(unix)]
    #[test]
    fn regression_hf_cache_stale_temp_reclamation_and_failed_symlink_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let (cache, location, etag, blob) = fixture(dir.path(), "file", b"original", true);
        let blobs = blob.parent().unwrap();
        let stale = blobs.join(format!("{TEMP_PREFIX}2147483647-stale"));
        let fresh = blobs.join(format!("{TEMP_PREFIX}2147483647-fresh"));
        let live = blobs.join(format!("{TEMP_PREFIX}{}-active", std::process::id()));
        let python = blobs.join("python.incomplete");
        for path in [&stale, &fresh, &live, &python] {
            fs::write(path, b"partial").unwrap();
        }
        let old = SystemTime::now() - TEMP_MAX_AGE - Duration::from_secs(60);
        for path in [&stale, &live] {
            File::options()
                .write(true)
                .open(path)
                .unwrap()
                .set_times(fs::FileTimes::new().set_modified(old))
                .unwrap();
        }
        reclaim_temps(blobs, SystemTime::now());
        assert!(!stale.exists());
        assert!(fresh.exists() && live.exists() && python.exists());
        let snapshot = cache.repo_dir(&location).join("snapshots").join(COMMIT);
        fs::create_dir(snapshot.join("destination-directory")).unwrap();
        assert!(cache
            .install(&location, COMMIT, "destination-directory", &etag, &blob, 8)
            .is_err());
        for entry in fs::read_dir(snapshot).unwrap() {
            assert!(!entry
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(TEMP_PREFIX));
        }
    }

    /// Regression: absent HOME created a relative ~/ cache; commit prefixes and non-UTF-8 names broke offline browsing.
    #[cfg(unix)]
    #[test]
    fn regression_hf_cache_home_unset_short_commit_and_non_utf8_names() {
        use std::os::unix::ffi::OsStringExt;
        let absent = HubCache::from_values(&|_| None);
        assert!(absent.root.as_os_str().is_empty());
        assert!(HubCache::sharing(&|_| None).is_none());
        assert!(HfCacheMountSource::with_cache("hf-cache://", absent).is_err());
        let dir = tempfile::tempdir().unwrap();
        let (cache, location, _, _) = fixture(dir.path(), "file", b"original", true);
        let snapshots = cache.repo_dir(&location).join("snapshots");
        fs::write(
            snapshots
                .join(COMMIT)
                .join(std::ffi::OsString::from_vec(vec![0xff])),
            b"skip me",
        )
        .unwrap();
        let mounted =
            HfCacheMountSource::with_cache("hf-cache://datasets/org/data@0123456", cache.clone())
                .unwrap();
        assert!(mounted.lookup("/file", 0).is_some());
        assert_eq!(mounted.list_dirents("/").unwrap().len(), 1);
        fs::create_dir(snapshots.join(format!("0123456{}", "f".repeat(33)))).unwrap();
        assert!(
            HfCacheMountSource::with_cache("hf-cache://datasets/org/data@0123456", cache)
                .err()
                .unwrap()
                .to_string()
                .contains("ambiguous")
        );
    }

    /// Regression: buffered publication spooled complete responses into the system temporary directory.
    #[test]
    fn regression_hf_cache_buffered_spool_stays_in_hub_cache() {
        let dir = tempfile::tempdir().unwrap();
        let cache = cache(&dir.path().join("hub"));
        let location = parse_hf_url("hf://org/model").unwrap();
        let hash = hex::encode(Sha256::digest(b"buffered"));
        let bridge = HubCacheFile::new(
            cache.clone(),
            location.clone(),
            COMMIT.into(),
            "file".into(),
            Some(hash),
            Some(8),
        );
        let started = Arc::new(std::sync::Barrier::new(2));
        let resume = Arc::new(std::sync::Barrier::new(2));
        *cache.stats.before_install.lock().unwrap() = Some((started.clone(), resume.clone()));
        bridge.buffered(Arc::new(b"buffered".to_vec()), None);
        started.wait();
        let paths = cache.stats.spools.lock().unwrap().clone();
        let in_cache = paths.len() == 1
            && paths[0].parent() == Some(cache.repo_dir(&location).join("blobs").as_path())
            && paths[0].is_file();
        resume.wait();
        bridge.wait();
        assert!(in_cache);
        assert!(bridge.local().is_some());
        assert!(!paths[0].exists());
    }

    /// Regression: background publication outlived the reader's memory reservation.
    #[test]
    fn regression_hf_cache_publication_holds_memory_reservation() {
        use ratarmount_core::budget::{MemoryBudget, Priority};

        let budget = MemoryBudget::new(Some(64));
        let pool = budget.register("hf-fallback", 0, 64, Priority::Cache);
        let memory = Arc::new(pool.reserve(8).unwrap());
        let body = BufferedBody::Memory {
            bytes: Arc::new(b"buffered".to_vec()),
            _memory: Some(memory.clone()),
        };
        drop(memory);
        assert_eq!(budget.snapshot().reserved, 8);
        assert!(pool.reserve(1).is_none());
        let mut bytes = Vec::new();
        body.write_to(&mut bytes).unwrap();
        assert_eq!(bytes, b"buffered");
        drop(body);
        assert_eq!(budget.snapshot().reserved, 0);
    }

    /// Regression: disk publication held the reader lock and changed its cursor.
    #[cfg(any(unix, windows))]
    #[test]
    fn regression_hf_cache_spooled_publication_preserves_reader_cursor() {
        struct Writer {
            file: Arc<Mutex<File>>,
            bytes: Vec<u8>,
        }
        impl Write for Writer {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                let mut file = self
                    .file
                    .try_lock()
                    .expect("publication must not lock reads");
                assert_eq!(file.stream_position()?, 3);
                self.bytes.write(bytes)
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(b"spooled").unwrap();
        file.seek(SeekFrom::Start(3)).unwrap();
        let file = Arc::new(Mutex::new(file));
        let body = BufferedBody::Disk {
            file: file.clone(),
            size: 7,
        };
        let mut writer = Writer {
            file,
            bytes: Vec::new(),
        };
        body.write_to(&mut writer).unwrap();
        assert_eq!(writer.bytes, b"spooled");
        let file = writer.file.clone();
        let mut reader = SpoolReader {
            file: &file,
            pos: 0,
            size: 7,
        };
        writer.bytes.clear();
        io::copy(&mut reader, &mut writer).unwrap();
        assert_eq!(writer.bytes, b"spooled");
    }

    /// Regression: an unwritable cache retried a failed publication on every read instead of backing off.
    #[test]
    fn regression_hf_cache_unwritable_cache_install_backoff() {
        use std::sync::atomic::Ordering;
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("unwritable-cache");
        // A non-directory cache root is a deterministic write failure, including under root.
        fs::write(&root, b"cannot create a cache here").unwrap();
        let cache = cache(&root);
        let hash = hex::encode(Sha256::digest(b"original"));
        let bridge = HubCacheFile::new(
            cache.clone(),
            parse_hf_url("hf://org/model").unwrap(),
            COMMIT.into(),
            "file".into(),
            Some(hash.clone()),
            Some(8),
        );
        bridge.initialize();
        let (ranges, token) = range_fixture(dir.path(), &hash);
        bridge.observed(&ranges, &token, 0);
        bridge.observed(&ranges, &token, 1);
        bridge.wait();
        let attempts = cache.stats.installs.load(Ordering::Relaxed);
        assert_eq!(attempts, 1);
        for _ in 0..20 {
            bridge.observed(&ranges, &token, 0);
        }
        bridge.wait();
        assert_eq!(cache.stats.installs.load(Ordering::Relaxed), attempts);
        assert_eq!(ranges.get(&token, 0).unwrap(), b"orig");
        assert!(bridge.local().is_none());
    }

    /// Regression: Python must recognize Rust-installed blobs, snapshot pointers and branch refs.
    #[test]
    fn regression_hf_cache_python_hub_layout_compatibility() {
        let python =
            std::env::var("RATARMOUNT_TEST_HF_PYTHON").unwrap_or_else(|_| "python3".into());
        let available = std::process::Command::new(&python)
            .args(["-c", "import huggingface_hub, filelock"])
            .output();
        if !available.is_ok_and(|o| o.status.success()) {
            eprintln!(
                "skip: Python huggingface_hub/filelock unavailable; set RATARMOUNT_TEST_HF_PYTHON"
            );
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let (_, _, etag, blob) = fixture(dir.path(), "sub/file", b"Python-compatible", true);
        let lockpath = dir
            .path()
            .join(".locks/datasets--org--data")
            .join(format!("{etag}.lock"));
        let lock = OpenOptions::new()
            .write(true)
            .read(true)
            .open(lockpath)
            .unwrap();
        lock.lock().unwrap();
        let result = std::process::Command::new(python).args(["-c", r#"
import os, sys
from huggingface_hub import try_to_load_from_cache, scan_cache_dir
from filelock import FileLock, Timeout
root, commit, blob, etag = sys.argv[1:]
p = try_to_load_from_cache('org/data', 'sub/file', cache_dir=root, repo_type='dataset', revision='feature/one')
assert p and os.path.samefile(p, blob), p
info = scan_cache_dir(root)
assert not info.warnings, info.warnings
repo, = info.repos
assert repo.repo_id == 'org/data' and repo.repo_type == 'dataset'
revision, = repo.revisions
assert revision.commit_hash == commit and revision.refs == {'feature/one'}
file, = revision.files
assert file.size_on_disk == len(b'Python-compatible')
try:
    with FileLock(os.path.join(root, '.locks', 'datasets--org--data', etag + '.lock'), timeout=0):
        raise AssertionError('Rust and Python did not contend on the same lock')
except Timeout:
    pass
"#]).arg(dir.path()).arg(COMMIT).arg(blob).arg(etag).output().unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
    }
}
