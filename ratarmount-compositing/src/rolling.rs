//! Numbered TAR generations with UTC time buckets and host-file retention.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ratarmount_core::{
    ArchiveRead, CheapDirent, CheapSearchHit, FileInfo, ListResult, MountSource,
};

use crate::{maybe_create_empty_write_archive, OverlayError, UnionMountOptions, UnionMountSource};

type Result<T> = std::result::Result<T, OverlayError>;
type OpenArchive = dyn Fn(&Path) -> Result<Arc<dyn MountSource>> + Send + Sync;

/// Either limit starts a new generation before the next nonempty commit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RollPolicy {
    duration: Option<Duration>,
    size: Option<u64>,
}

impl FromStr for RollPolicy {
    type Err = String;

    fn from_str(value: &str) -> std::result::Result<Self, String> {
        let mut policy = Self {
            duration: None,
            size: None,
        };
        for part in value.split(',') {
            let part = part.trim();
            let end = part
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(part.len());
            let number = part[..end]
                .parse::<u64>()
                .map_err(|_| format!("invalid roll limit {part:?}"))?;
            if number == 0 {
                return Err("roll limits must be positive".into());
            }
            let (multiplier, time) = match &part[end..] {
                "s" => (1, true),
                "m" => (60, true),
                "h" => (3600, true),
                "d" => (86400, true),
                "B" => (1, false),
                "K" => (1024, false),
                "M" => (1024 * 1024, false),
                "G" => (1024 * 1024 * 1024, false),
                "T" => (1024u64.pow(4), false),
                _ => {
                    return Err(format!(
                        "invalid roll unit in {part:?}; use s/m/h/d or B/K/M/G/T"
                    ))
                }
            };
            let limit = number
                .checked_mul(multiplier)
                .ok_or("roll limit overflows u64")?;
            if time {
                if policy
                    .duration
                    .replace(Duration::from_secs(limit))
                    .is_some()
                {
                    return Err("duplicate roll duration".into());
                }
            } else if policy.size.replace(limit).is_some() {
                return Err("duplicate roll size".into());
            }
        }
        Ok(policy)
    }
}

impl RollPolicy {
    fn due(&self, size: u64, started: SystemTime, now: SystemTime) -> bool {
        self.size.is_some_and(|limit| size >= limit)
            || self.duration.is_some_and(|duration| {
                let bucket = |time: SystemTime| {
                    time.duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs()
                        / duration.as_secs()
                };
                bucket(now) > bucket(started)
            })
    }
}

/// Exact six-digit series names. The unnumbered base must not exist.
#[derive(Clone, Debug)]
pub struct SeriesName {
    parent: PathBuf,
    stem: String,
    suffix: String,
    base: PathBuf,
}

impl SeriesName {
    pub fn new(base: &Path) -> Result<Self> {
        let name = base
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| OverlayError::Msg("rolling archive name must be UTF-8".into()))?;
        let suffix = [".tar.zst", ".tar"]
            .into_iter()
            .find(|suffix| name.ends_with(suffix))
            .ok_or_else(|| {
                OverlayError::Msg(
                    "--roll-every requires a local .tar or .tar.zst series base".into(),
                )
            })?;
        if base.to_string_lossy().contains("://") {
            return Err(OverlayError::Msg(
                "rolling archives require local files".into(),
            ));
        }
        Ok(Self {
            parent: base
                .parent()
                .filter(|p| !p.as_os_str().is_empty())
                .unwrap_or(Path::new("."))
                .into(),
            stem: name[..name.len() - suffix.len()].into(),
            suffix: suffix.into(),
            base: base.into(),
        })
    }

    pub fn generation(&self, number: u32) -> Result<PathBuf> {
        if !(1..=999_999).contains(&number) {
            return Err(OverlayError::Msg(
                "rolling archive generation exceeds six digits".into(),
            ));
        }
        Ok(self
            .parent
            .join(format!("{}.{number:06}{}", self.stem, self.suffix)))
    }

    pub fn discover(&self) -> Result<Vec<(u32, PathBuf)>> {
        match fs::symlink_metadata(&self.base) {
            Ok(_) => {
                return Err(OverlayError::Msg(format!(
                    "rolling series base {} exists; rename it to generation 000001 first",
                    self.base.display()
                )))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.into()),
        }
        let prefix = format!("{}.", self.stem);
        let mut found = Vec::new();
        for entry in fs::read_dir(&self.parent)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(digits) = name
                .to_str()
                .and_then(|n| n.strip_prefix(&prefix))
                .and_then(|n| n.strip_suffix(&self.suffix))
            else {
                continue;
            };
            if digits.len() != 6 || !digits.bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let number: u32 = digits.parse().expect("six digits");
            if number == 0 {
                return Err(OverlayError::Msg("generation 000000 is reserved".into()));
            }
            if !entry.file_type()?.is_file() {
                return Err(OverlayError::Msg(format!(
                    "series member {} is not a regular file",
                    entry.path().display()
                )));
            }
            found.push((number, entry.path()));
        }
        found.sort_by_key(|(number, _)| *number);
        Ok(found)
    }
}

// Keep routing slots stable for FileInfos issued before retention deletes.
// Already opened readers pin their own archive fd; stale FileInfos fail with EIO.
struct Member {
    path: PathBuf,
    live: AtomicBool,
    source: RwLock<Arc<dyn MountSource>>,
}

impl MountSource for Member {
    fn list(&self, path: &str) -> Option<ListResult> {
        self.live
            .load(Ordering::SeqCst)
            .then(|| self.source.read().unwrap().list(path))
            .flatten()
    }
    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        self.live
            .load(Ordering::SeqCst)
            .then(|| self.source.read().unwrap().list_dirents(path))
            .flatten()
    }
    fn lookup(&self, path: &str, version: i32) -> Option<FileInfo> {
        self.live
            .load(Ordering::SeqCst)
            .then(|| self.source.read().unwrap().lookup(path, version))
            .flatten()
    }
    fn open(&self, fi: &FileInfo, buffering: i32) -> io::Result<Box<dyn ArchiveRead>> {
        self.source.read().unwrap().open(fi, buffering)
    }
    fn search_cheap(&self, pattern: &str) -> Option<Vec<CheapSearchHit>> {
        if self.live.load(Ordering::SeqCst) {
            self.source.read().unwrap().search_cheap(pattern)
        } else {
            Some(Vec::new())
        }
    }
    fn versions(&self, path: &str) -> u32 {
        if self.live.load(Ordering::SeqCst) {
            self.source.read().unwrap().versions(path)
        } else {
            0
        }
    }
    fn list_xattr(&self, fi: &FileInfo) -> Vec<String> {
        self.source.read().unwrap().list_xattr(fi)
    }
    fn get_xattr(&self, fi: &FileInfo, key: &str) -> Option<Vec<u8>> {
        self.source.read().unwrap().get_xattr(fi, key)
    }
    fn is_immutable(&self) -> bool {
        false
    }
}

struct RemovedArchive;

impl MountSource for RemovedArchive {
    fn list(&self, _: &str) -> Option<ListResult> {
        None
    }
    fn lookup(&self, _: &str, _: i32) -> Option<FileInfo> {
        None
    }
    fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ArchiveRead>> {
        Err(io::Error::from_raw_os_error(libc::EIO))
    }
    fn is_immutable(&self) -> bool {
        false
    }
}

struct State {
    number: u32,
    members: Vec<Arc<Member>>,
    union: Arc<UnionMountSource>,
    started: SystemTime,
    empty: bool,
}

/// A series opened once at mount. Retention deletes are polled at every access;
/// externally added generations are discovered on remount.
pub struct RollingMountSource {
    name: SeriesName,
    policy: RollPolicy,
    opener: Arc<OpenArchive>,
    clock: Arc<dyn Fn() -> SystemTime + Send + Sync>,
    state: Mutex<State>,
    generation: AtomicU64,
}

impl RollingMountSource {
    pub fn open(
        base: &Path,
        policy: RollPolicy,
        opener: impl Fn(&Path) -> Result<Arc<dyn MountSource>> + Send + Sync + 'static,
    ) -> Result<Self> {
        Self::open_with_recovery(base, policy, opener, true)
    }

    /// [`Self::open`] that recovers each generation's pending journal only
    /// when `recover` (a mount that classified its members first passes `false`).
    pub fn open_with_recovery(
        base: &Path,
        policy: RollPolicy,
        opener: impl Fn(&Path) -> Result<Arc<dyn MountSource>> + Send + Sync + 'static,
        recover: bool,
    ) -> Result<Self> {
        Self::with_clock(base, policy, opener, SystemTime::now, recover)
    }

    fn with_clock(
        base: &Path,
        policy: RollPolicy,
        opener: impl Fn(&Path) -> Result<Arc<dyn MountSource>> + Send + Sync + 'static,
        clock: impl Fn() -> SystemTime + Send + Sync + 'static,
        recover: bool,
    ) -> Result<Self> {
        let name = SeriesName::new(base)?;
        let mut found = name.discover()?;
        let empty = found.is_empty();
        if empty {
            let path = name.generation(1)?;
            maybe_create_empty_write_archive(&path)?;
            found.push((1, path));
        }
        let (number, active) = found.last().expect("one generation");
        let members: Vec<_> = found
            .iter()
            .map(|(_, path)| {
                if recover {
                    crate::journal_recovery::recover_journal_at(
                        path,
                        None,
                        crate::journal_recovery::Owner::Inode,
                    )
                    .map_err(ratarmount_compress::commit_journal::RecoverError::into_io)?;
                }
                Ok(Arc::new(Member {
                    path: path.clone(),
                    live: AtomicBool::new(true),
                    source: RwLock::new(opener(path)?),
                }))
            })
            .collect::<Result<_>>()?;
        let started = if empty {
            clock()
        } else {
            fs::metadata(active)?.modified()?
        };
        let union = make_union(&members);
        Ok(Self {
            name,
            policy,
            opener: Arc::new(opener),
            clock: Arc::new(clock),
            state: Mutex::new(State {
                number: *number,
                members,
                union,
                started,
                empty,
            }),
            generation: AtomicU64::new(0),
        })
    }

    fn rescan(&self, state: &State) {
        for (index, member) in state.members.iter().enumerate() {
            if !member.path.is_file() && member.live.swap(false, Ordering::SeqCst) {
                if index + 1 < state.members.len() {
                    *member.source.write().unwrap() = Arc::new(RemovedArchive);
                }
                self.generation.fetch_add(1, Ordering::SeqCst);
            }
        }
    }

    fn view(&self) -> Arc<UnionMountSource> {
        let state = self.state.lock().unwrap();
        self.rescan(&state);
        state.union.clone()
    }

    pub fn active_path(&self) -> PathBuf {
        self.state
            .lock()
            .unwrap()
            .members
            .last()
            .unwrap()
            .path
            .clone()
    }

    pub(crate) fn active_source(&self) -> Arc<dyn MountSource> {
        self.state
            .lock()
            .unwrap()
            .members
            .last()
            .unwrap()
            .source
            .read()
            .unwrap()
            .clone()
    }

    /// A delete would reveal an older copy after overlay cleanup, even when a
    /// newer generation currently shadows it. Refuse that case as well.
    pub(crate) fn sealed_contains(&self, path: &str) -> bool {
        let state = self.state.lock().unwrap();
        self.rescan(&state);
        state.members[..state.members.len() - 1]
            .iter()
            .any(|m| m.exists(path) || crate::FileVersionLayer::new(m.clone()).exists(path))
    }

    /// Called under WriteOverlay's exclusive commit gate after a nonempty plan.
    /// Deletions/metadata-only changes to the active generation defer rotation
    /// for this commit so they cannot become dangling tombstones in a new file.
    pub(crate) fn prepare_commit(&self, defer: bool) -> Result<PathBuf> {
        let mut state = self.state.lock().unwrap();
        self.rescan(&state);
        let active = state.members.last().unwrap();
        let missing = !active.live.load(Ordering::SeqCst);
        let now = (self.clock)();
        let due = missing
            || (!state.empty
                && !defer
                && self
                    .policy
                    .due(fs::metadata(&active.path)?.len(), state.started, now));
        if due {
            let number = state.number + 1;
            let path = self.name.generation(number)?;
            // Never take over an archive created by another process since mount.
            if fs::symlink_metadata(&path).is_ok() {
                return Err(OverlayError::Msg(format!(
                    "next rolling generation {} already exists; remount",
                    path.display()
                )));
            }
            maybe_create_empty_write_archive(&path)?;
            let source = (self.opener)(&path)?;
            state.members.push(Arc::new(Member {
                path,
                live: AtomicBool::new(true),
                source: RwLock::new(source),
            }));
            state.number = number;
            state.started = now;
            state.empty = true;
            state.union = make_union(&state.members);
            self.generation.fetch_add(1, Ordering::SeqCst);
        }
        Ok(state.members.last().unwrap().path.clone())
    }

    pub(crate) fn committed(&self, source: Option<Arc<dyn MountSource>>) {
        let mut state = self.state.lock().unwrap();
        if let Some(source) = source {
            *state.members.last().unwrap().source.write().unwrap() = source;
        }
        state.empty = false;
        self.generation.fetch_add(1, Ordering::SeqCst);
    }
}

fn make_union(members: &[Arc<Member>]) -> Arc<UnionMountSource> {
    Arc::new(UnionMountSource::new_with_options(
        members
            .iter()
            .map(|m| m.clone() as Arc<dyn MountSource>)
            .collect(),
        UnionMountOptions {
            max_cache_entries: 0,
            ..Default::default()
        },
    ))
}

impl MountSource for RollingMountSource {
    fn list(&self, path: &str) -> Option<ListResult> {
        self.view().list(path)
    }
    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        self.view().list_dirents(path)
    }
    fn lookup(&self, path: &str, version: i32) -> Option<FileInfo> {
        self.view().lookup(path, version)
    }
    fn open(&self, fi: &FileInfo, buffering: i32) -> io::Result<Box<dyn ArchiveRead>> {
        self.view().open(fi, buffering)
    }
    fn search_cheap(&self, pattern: &str) -> Option<Vec<CheapSearchHit>> {
        self.view().search_cheap(pattern)
    }
    fn versions(&self, path: &str) -> u32 {
        self.view().versions(path)
    }
    fn is_immutable(&self) -> bool {
        false
    }
    fn content_generation(&self) -> u64 {
        self.view();
        self.generation.load(Ordering::SeqCst)
    }
    fn list_xattr(&self, fi: &FileInfo) -> Vec<String> {
        self.view().list_xattr(fi)
    }
    fn get_xattr(&self, fi: &FileInfo, key: &str) -> Option<Vec<u8>> {
        self.view().get_xattr(fi, key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CommitKind, CommitMode, CommitOutcome, WriteOverlay};
    use ratarmount_core::OpenOptions;
    use ratarmount_formats_tar::{SqliteIndexedTar, UstarMember, UstarPayload};
    use std::io::{Read, Seek, SeekFrom};

    fn open_tar(path: &Path) -> Result<Arc<dyn MountSource>> {
        let opts = OpenOptions {
            index_in_memory: true,
            write_index: false,
            ignore_zeros: true,
            ..Default::default()
        };
        let tar = if path.extension().is_some_and(|e| e == "zst") {
            SqliteIndexedTar::create_index_body(
                path,
                ratarmount_compress::open_seekable_zstd(path).unwrap(),
                None,
                &opts,
                "test",
            )
        } else {
            SqliteIndexedTar::create_index(path, path, None, &opts, "test", &mut None)
        }
        .map_err(|e| OverlayError::Msg(e.to_string()))?;
        Ok(Arc::new(tar))
    }

    fn fixture(path: &Path, name: &str, bytes: &[u8]) {
        let member = UstarMember {
            path: name,
            payload: UstarPayload::File { bytes },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
            xattrs: Default::default(),
        };
        let mut out = Vec::new();
        ratarmount_formats_tar::write_ustar_members(&mut out, &[member]).unwrap();
        ratarmount_formats_tar::write_tar_eof(&mut out).unwrap();
        if path.extension().is_some_and(|extension| extension == "zst") {
            out = ratarmount_compress::encode_zstd_frame(&out, 3).unwrap();
        }
        fs::write(path, out).unwrap();
    }

    fn overlay(dir: &Path, series: &Arc<RollingMountSource>, mode: CommitMode) -> WriteOverlay {
        let mut overlay = WriteOverlay::new_for_tests(
            Arc::new(crate::FileVersionLayer::new(series.clone())),
            dir.join("overlay"),
        )
        .unwrap();
        overlay.set_rolling(series.clone());
        overlay.set_commit_mode(mode);
        overlay
    }

    fn commit(overlay: &WriteOverlay, base: &Path) {
        assert!(overlay.commit_live(base, open_tar).unwrap());
    }

    fn bytes(source: &dyn MountSource, path: &str) -> Vec<u8> {
        let fi = source.lookup(path, 0).unwrap();
        let mut out = Vec::new();
        source.open(&fi, 0).unwrap().read_to_end(&mut out).unwrap();
        out
    }

    /// Regression: invalid/overflowing roll limits must not silently disable rotation.
    #[test]
    fn rolling_invalid_limits_fail_closed() {
        for invalid in [
            "",
            "0s",
            "0B",
            "1d,2h",
            "1M,2G",
            "1",
            "-1h",
            "1d,",
            "18446744073709551615G",
        ] {
            assert!(invalid.parse::<RollPolicy>().is_err(), "{invalid}");
        }
        let policy: RollPolicy = "1d,20G".parse().unwrap();
        assert_eq!(policy.duration, Some(Duration::from_secs(86400)));
        assert_eq!(policy.size, Some(20 * 1024u64.pow(3)));
        assert!(!policy.due(0, UNIX_EPOCH, UNIX_EPOCH));
        assert!(policy.due(20 * 1024u64.pow(3), UNIX_EPOCH, UNIX_EPOCH));
        assert!(policy.due(0, UNIX_EPOCH, UNIX_EPOCH + Duration::from_secs(86400)));
    }

    /// Regression: discovery must sort numbered generations, tolerate gaps and ignore sidecars.
    #[test]
    fn rolling_remount_gaps_and_plain_base_refused() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("traces.tar");
        let names = SeriesName::new(&base).unwrap();
        fixture(&names.generation(1).unwrap(), "old", b"old");
        fixture(&names.generation(7).unwrap(), "new", b"new");
        for extra in [
            "traces.000002.tar.index.sqlite",
            "traces.000003.tar.manifest.jsonl",
            "traces.123.tar",
            "other.000099.tar",
        ] {
            fs::write(dir.path().join(extra), []).unwrap();
        }
        let series =
            Arc::new(RollingMountSource::open(&base, "1B".parse().unwrap(), open_tar).unwrap());
        assert_eq!(series.active_path(), names.generation(7).unwrap());
        let ov = overlay(dir.path(), &series, CommitMode::Append);
        fs::write(ov.root().join("next"), b"next").unwrap();
        let collision = names.generation(8).unwrap();
        fs::write(&collision, b"external archive").unwrap();
        assert!(ov.commit_live(&base, open_tar).is_err());
        assert_eq!(fs::read(&collision).unwrap(), b"external archive");
        fs::remove_file(collision).unwrap();
        commit(&ov, &base);
        assert_eq!(series.active_path(), names.generation(8).unwrap());
        assert_eq!(bytes(&ov, "/old"), b"old");
        assert_eq!(bytes(&ov, "/new"), b"new");
        drop(ov);
        drop(series);
        let remount = RollingMountSource::open(&base, "1G".parse().unwrap(), open_tar).unwrap();
        assert_eq!(bytes(&remount, "/next"), b"next");
        fs::write(&base, []).unwrap();
        assert!(names.discover().unwrap_err().to_string().contains("rename"));
        assert!(names.generation(1_000_000).is_err());
        assert!(SeriesName::new(&dir.path().join("a.zip")).is_err());
        assert!(SeriesName::new(Path::new("https://host/a.tar")).is_err());
        fs::remove_file(&base).unwrap();
        fs::write(dir.path().join("traces.000000.tar"), []).unwrap();
        assert!(names.discover().is_err());
    }

    /// Regression: the commit after crossing SIZE creates generation 2 and preserves the union.
    #[test]
    fn rolling_size_next_commit_union_and_append() {
        for (extension, mode) in [
            ("tar", CommitMode::Append),
            ("tar.zst", CommitMode::Copy),
            ("tar.zst", CommitMode::Append),
            ("tar.zst", CommitMode::Auto),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().join(format!("traces.{extension}"));
            let names = SeriesName::new(&base).unwrap();
            let series =
                Arc::new(RollingMountSource::open(&base, "1B".parse().unwrap(), open_tar).unwrap());
            let mut ov = overlay(dir.path(), &series, mode);
            ov.set_manifest_hashes(Some("new".into()));
            fs::write(ov.root().join("old"), b"generation-one").unwrap();
            commit(&ov, &base);
            let first = names.generation(1).unwrap();
            let sealed = fs::read(&first).unwrap();
            fs::write(ov.root().join("new"), b"generation-two").unwrap();
            commit(&ov, &base);
            assert_eq!(series.active_path(), names.generation(2).unwrap());
            assert_eq!(fs::read(&first).unwrap(), sealed);
            assert_eq!(bytes(&ov, "/old"), b"generation-one");
            assert_eq!(bytes(&ov, "/new"), b"generation-two");
            assert!(PathBuf::from(format!("{}.manifest.jsonl", first.display())).is_file());
            assert!(
                PathBuf::from(format!("{}.manifest.jsonl", series.active_path().display()))
                    .is_file()
            );
            assert_eq!(
                ov.enqueue_commit(&base, CommitKind::IntervalIdle(Duration::ZERO), open_tar)
                    .unwrap(),
                CommitOutcome::Nothing
            );
            assert!(
                !names.generation(3).unwrap().exists(),
                "empty ticks must not roll"
            );
        }
    }

    /// Regression: injected time crosses UTC buckets without sleeps or sensitivity to local timezone.
    #[test]
    fn rolling_time_injected_clock_utc_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("traces.tar");
        let clock = Arc::new(AtomicU64::new(3599));
        let now = clock.clone();
        let series = Arc::new(
            RollingMountSource::with_clock(
                &base,
                "1h".parse().unwrap(),
                open_tar,
                move || UNIX_EPOCH + Duration::from_secs(now.load(Ordering::SeqCst)),
                true,
            )
            .unwrap(),
        );
        let ov = overlay(dir.path(), &series, CommitMode::Append);
        fs::write(ov.root().join("before"), b"before").unwrap();
        commit(&ov, &base);
        clock.store(3600, Ordering::SeqCst);
        fs::write(ov.root().join("after"), b"after").unwrap();
        commit(&ov, &base);
        assert!(series.active_path().ends_with("traces.000002.tar"));
        assert_eq!(bytes(&ov, "/before"), b"before");
        assert_eq!(bytes(&ov, "/after"), b"after");
    }

    /// Regression: host retention removes old names without routing a held FileInfo into a sibling.
    #[test]
    fn rolling_deleted_archive_disappears_open_reader_survives() {
        for extension in ["tar", "tar.zst"] {
            let dir = tempfile::tempdir().unwrap();
            let base = dir.path().join(format!("traces.{extension}"));
            let names = SeriesName::new(&base).unwrap();
            fixture(&names.generation(1).unwrap(), "old", b"old bytes");
            fixture(&names.generation(3).unwrap(), "new", b"new bytes");
            let series =
                Arc::new(RollingMountSource::open(&base, "1G".parse().unwrap(), open_tar).unwrap());
            let union = UnionMountSource::new(vec![series.clone()]);
            let fi = union.lookup("/old", 0).unwrap();
            let mut held = union.open(&fi, 0).unwrap();
            assert_eq!(union.search_cheap("*").unwrap().len(), 2);
            let generation = union.content_generation();
            fs::remove_file(names.generation(1).unwrap()).unwrap();
            assert!(union.lookup("/old", 0).is_none());
            assert!(!union
                .list_dirents("/")
                .unwrap()
                .iter()
                .any(|d| d.name == "old"));
            assert!(union.content_generation() > generation);
            assert_eq!(union.search_cheap("*").unwrap().len(), 1);
            assert_eq!(bytes(&union, "/new"), b"new bytes");
            let mut out = String::new();
            held.read_to_string(&mut out).unwrap();
            assert_eq!(out, "old bytes");
            held.seek(SeekFrom::Start(0)).unwrap();
            assert_eq!(
                union.read(&fi, 9, 0).unwrap_err().raw_os_error(),
                Some(libc::EIO)
            );
            let mut reread = String::new();
            held.read_to_string(&mut reread).unwrap();
            assert_eq!(reread, "old bytes");
        }
    }

    /// Regression: sealed-file tombstones cannot be forgotten on commit and resurrect data.
    #[test]
    fn rolling_sealed_mutations_erofs_shadow_write_allowed() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("traces.tar.zst");
        let series =
            Arc::new(RollingMountSource::open(&base, "1B".parse().unwrap(), open_tar).unwrap());
        let ov = overlay(dir.path(), &series, CommitMode::Copy);
        fs::write(ov.root().join("old"), b"old").unwrap();
        fs::create_dir(ov.root().join("empty")).unwrap();
        commit(&ov, &base);
        fs::write(ov.root().join("new"), b"new").unwrap();
        commit(&ov, &base);
        for error in [
            ov.unlink("/old").unwrap_err(),
            ov.unlink("/old.versions/1").unwrap_err(),
            ov.unlink_parked("/old").err().unwrap(),
            ov.rename("/old", "/moved").unwrap_err(),
            ov.rmdir("/empty").unwrap_err(),
            ov.set_xattr("/old", "user.tag", b"x", 0).unwrap_err(),
        ] {
            assert!(matches!(error, OverlayError::Io(e) if e.raw_os_error() == Some(libc::EROFS)));
        }
        ov.truncate("/old", 1).unwrap();
        assert_eq!(bytes(&ov, "/old"), b"o");
        commit(&ov, &base);
        assert_eq!(bytes(&ov, "/old"), b"o");
        assert!(
            ov.lookup("/old.versions/1", 0).is_some(),
            "base wrappers must survive live commits"
        );
        assert!(
            ov.unlink("/old").is_err(),
            "deleting a shadow must not reveal its sealed copy"
        );
        let remount = RollingMountSource::open(&base, "1G".parse().unwrap(), open_tar).unwrap();
        assert_eq!(bytes(&remount, "/old"), b"o");
    }

    /// Regression: deletes queued before a roll must be applied to the archive that owns the name.
    #[test]
    fn rolling_active_delete_defers_roll() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("traces.tar.zst");
        let series =
            Arc::new(RollingMountSource::open(&base, "1B".parse().unwrap(), open_tar).unwrap());
        let ov = overlay(dir.path(), &series, CommitMode::Copy);
        fs::write(ov.root().join("remove"), b"delete me").unwrap();
        commit(&ov, &base);
        ov.unlink("/remove").unwrap();
        fs::write(ov.root().join("keep"), b"keep").unwrap();
        commit(&ov, &base);
        assert!(series.active_path().ends_with("traces.000001.tar.zst"));
        assert!(ov.lookup("/remove", 0).is_none());
        fs::write(ov.root().join("next"), b"next").unwrap();
        commit(&ov, &base);
        assert!(series.active_path().ends_with("traces.000002.tar.zst"));
        assert!(ov.lookup("/remove", 0).is_none());
    }

    /// Regression: on-exit must persist to the active generation after an earlier interval rolled.
    #[test]
    fn rolling_on_exit_uses_active_generation() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("traces.tar");
        let series =
            Arc::new(RollingMountSource::open(&base, "1B".parse().unwrap(), open_tar).unwrap());
        let ov = overlay(dir.path(), &series, CommitMode::Append);
        fs::write(ov.root().join("one"), b"one").unwrap();
        commit(&ov, &base);
        fs::write(ov.root().join("two"), b"two").unwrap();
        assert_eq!(
            ov.enqueue_commit(&base, CommitKind::OnExit, |_| unreachable!())
                .unwrap(),
            CommitOutcome::DidWork
        );
        let remount = RollingMountSource::open(&base, "1G".parse().unwrap(), open_tar).unwrap();
        assert_eq!(bytes(&remount, "/one"), b"one");
        assert_eq!(bytes(&remount, "/two"), b"two");
    }

    /// Regression: copy-mode TAR replacements must classify offsets in the active file, not a sealed sibling.
    #[test]
    fn rolling_copy_tar_shadow_does_not_rewrite_sealed() {
        if !std::process::Command::new("tar")
            .arg("--version")
            .output()
            .is_ok_and(|out| String::from_utf8_lossy(&out.stdout).contains("GNU tar"))
        {
            eprintln!("skip: GNU tar missing; rolling policy/append/zstd tests do not need it");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("traces.tar");
        let series =
            Arc::new(RollingMountSource::open(&base, "1B".parse().unwrap(), open_tar).unwrap());
        let ov = overlay(dir.path(), &series, CommitMode::Copy);
        fs::write(ov.root().join("old"), b"old").unwrap();
        commit(&ov, &base);
        let first = series.active_path();
        let sealed = fs::read(&first).unwrap();
        fs::write(ov.root().join("old"), b"new").unwrap();
        fs::write(ov.root().join("extra"), b"extra").unwrap();
        commit(&ov, &base);
        assert_eq!(fs::read(first).unwrap(), sealed);
        assert_eq!(bytes(&ov, "/old"), b"new");
        assert_eq!(bytes(&ov, "/extra"), b"extra");
        assert!(series.active_path().ends_with("traces.000002.tar"));
    }
}
