//! Negotiated backing files. The kernel cannot apply an archive byte offset.

#[cfg(any(target_os = "linux", test))]
use std::collections::HashMap;
use std::io;
#[cfg(any(target_os = "linux", test))]
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PassthroughMode {
    #[default]
    Auto,
    On,
    Off,
}

impl std::str::FromStr for PassthroughMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "auto" => Ok(Self::Auto),
            "on" => Ok(Self::On),
            "off" => Ok(Self::Off),
            _ => Err("expected auto, on, or off".into()),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct PassthroughOptions {
    pub mode: PassthroughMode,
    /// Copying requires both this switch and a nonzero per-member byte cap.
    pub copy: bool,
    pub copy_max: u64,
    /// Aggregate copied bytes retained by concurrently open backing files.
    pub copy_total_max: u64,
}

impl Default for PassthroughOptions {
    fn default() -> Self {
        Self {
            mode: PassthroughMode::Auto,
            copy: false,
            copy_max: 0,
            copy_total_max: 1 << 30,
        }
    }
}

pub(super) fn negotiate(
    mode: PassthroughMode,
    supported: bool,
    auto_eligible: bool,
) -> io::Result<bool> {
    match (mode, supported) {
        (PassthroughMode::Off, _) => Ok(false),
        (PassthroughMode::Auto, true) => Ok(auto_eligible),
        (PassthroughMode::On, true) => Ok(true),
        (PassthroughMode::Auto, false) => Ok(false),
        (PassthroughMode::On, false) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "--passthrough on requires Linux >= 6.9 with FUSE_PASSTHROUGH (ABI >= 7.40)",
        )),
    }
}

/// Both successful and failed registrations are sticky until the last release:
/// mixing passthrough and cached daemon opens on one inode is a kernel EIO.
#[cfg(any(target_os = "linux", test))]
pub(super) struct OpenBackings<B> {
    inodes: HashMap<u64, (usize, Option<Arc<B>>)>,
    handles: HashMap<u64, u64>,
}

#[cfg(any(target_os = "linux", test))]
impl<B> Default for OpenBackings<B> {
    fn default() -> Self {
        Self {
            inodes: HashMap::new(),
            handles: HashMap::new(),
        }
    }
}

#[cfg(any(target_os = "linux", test))]
impl<B> OpenBackings<B> {
    pub(super) fn open(
        &mut self,
        ino: u64,
        fh: u64,
        register: impl FnOnce() -> Option<B>,
    ) -> Option<Arc<B>> {
        let (refs, backing) = self
            .inodes
            .entry(ino)
            .or_insert_with(|| (0, register().map(Arc::new)));
        *refs += 1;
        self.handles.insert(fh, ino);
        backing.clone()
    }

    pub(super) fn release(&mut self, fh: u64) {
        if let Some(ino) = self.handles.remove(&fh) {
            if let Some((refs, _)) = self.inodes.get_mut(&ino) {
                *refs -= 1;
                if *refs == 0 {
                    self.inodes.remove(&ino);
                }
            }
        }
    }
}

#[cfg(target_os = "linux")]
pub(super) mod linux {
    use super::*;
    use ratarmount_core::BackingExtent;
    use std::collections::HashSet;
    use std::fs::File;
    use std::os::fd::{AsFd, AsRawFd};
    use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::Mutex;

    // USER_NS_INIT_INO in Linux's include/uapi/linux/nsfs.h. Comparing with
    // /proc/1 is insufficient when PID 1 belongs to a nested user namespace.
    const INITIAL_USER_NS: u64 = 0xeffffffd;

    fn privileged(status: &str, user_ns: u64) -> bool {
        user_ns == INITIAL_USER_NS
            && status
                .lines()
                .find_map(|line| {
                    line.strip_prefix("CapEff:")
                        .and_then(|caps| u64::from_str_radix(caps.trim(), 16).ok())
                })
                .is_some_and(|caps| caps & (1 << 21) != 0)
    }

    pub(crate) fn has_initial_sys_admin() -> bool {
        match (
            std::fs::read_to_string("/proc/self/status"),
            std::fs::metadata("/proc/self/ns/user"),
        ) {
            (Ok(status), Ok(ns)) => privileged(&status, ns.ino()),
            _ => false,
        }
    }

    pub(crate) struct CopyBudget {
        limit: u64,
        used: AtomicU64,
    }

    impl CopyBudget {
        fn reserve(self: &Arc<Self>, bytes: u64) -> Option<CopyReservation> {
            self.used
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |used| {
                    used.checked_add(bytes).filter(|&next| next <= self.limit)
                })
                .ok()?;
            Some(CopyReservation {
                budget: self.clone(),
                bytes,
            })
        }
    }

    struct CopyReservation {
        budget: Arc<CopyBudget>,
        bytes: u64,
    }

    impl Drop for CopyReservation {
        fn drop(&mut self) {
            self.budget.used.fetch_sub(self.bytes, Ordering::Relaxed);
        }
    }

    pub(crate) struct State {
        denied: AtomicBool,
        active: AtomicBool,
        filesystems: Mutex<HashSet<u64>>,
        clone_filesystems: Mutex<HashSet<u64>>,
        budget: Arc<CopyBudget>,
    }

    impl State {
        pub(crate) fn new(total: u64) -> Self {
            Self {
                denied: AtomicBool::new(false),
                active: AtomicBool::new(false),
                filesystems: Mutex::new(HashSet::new()),
                clone_filesystems: Mutex::new(HashSet::new()),
                budget: Arc::new(CopyBudget {
                    limit: total,
                    used: AtomicU64::new(0),
                }),
            }
        }

        pub(crate) fn denied(&self) -> bool {
            self.denied.load(Ordering::Relaxed)
        }

        fn allows(&self, dev: u64) -> bool {
            !self.denied() && !self.filesystems.lock().unwrap().contains(&dev)
        }

        fn clone_allowed(&self, dev: u64) -> bool {
            !self.clone_filesystems.lock().unwrap().contains(&dev)
        }

        fn clone_error(&self, dev: u64, error: &io::Error) {
            if matches!(error.raw_os_error(), Some(libc::ELOOP | libc::EXDEV)) {
                self.clone_filesystems.lock().unwrap().insert(dev);
            }
        }

        pub(crate) fn registration_error(&self, dev: u64, error: &io::Error) {
            match error.raw_os_error() {
                Some(libc::EPERM) => {
                    if !self.denied.swap(true, Ordering::Relaxed) {
                        log::warn!("FUSE I/O mode: daemon for new backings (passthrough registration denied; CAP_SYS_ADMIN in the initial user namespace is required); disabling further preparation");
                    }
                }
                Some(libc::ELOOP | libc::EXDEV) if self.filesystems.lock().unwrap().insert(dev) => {
                    log::debug!("FUSE passthrough disabled for backing filesystem {dev}: {error}");
                }
                _ => {}
            }
        }

        pub(crate) fn register<B>(
            &self,
            prepare: impl FnOnce() -> io::Result<Option<PreparedBacking>>,
            register: impl FnOnce(&File) -> io::Result<B>,
        ) -> io::Result<Option<(B, PreparedBacking)>> {
            if self.denied() {
                return Ok(None);
            }
            let Some(prepared) = prepare()? else {
                return Ok(None);
            };
            let dev = prepared.file.metadata()?.dev();
            if !self.allows(dev) {
                return Ok(None);
            }
            let id = register(&prepared.file)
                .inspect_err(|error| self.registration_error(dev, error))?;
            self.registered();
            Ok(Some((id, prepared)))
        }

        pub(crate) fn registered(&self) {
            if !self.active.swap(true, Ordering::Relaxed) {
                log::info!("FUSE I/O mode: passthrough for registered files (daemon fallback for other opens)");
            }
        }
    }

    pub(crate) struct PreparedBacking {
        pub file: File,
        _reservation: Option<CopyReservation>,
    }

    pub(crate) struct RegisteredBacking {
        pub id: fuser::BackingId,
        pub _prepared: PreparedBacking,
    }

    fn probe_error(error: io::Error) -> io::Error {
        let explanation = if error.raw_os_error() == Some(libc::EPERM) {
            "CAP_SYS_ADMIN in the initial user namespace is required"
        } else {
            "the kernel could not register a regular backing file"
        };
        io::Error::new(
            error.kind(),
            format!("--passthrough on registration probe failed: {explanation}: {error}"),
        )
    }

    /// INIT has completed, but request dispatch has not started. Use fuser's raw
    /// equivalent of ReplyOpen::open_backing, then close the temporary ID.
    pub(crate) fn probe(session: impl AsFd) -> io::Result<()> {
        let file = tempfile::tempfile().map_err(probe_error)?;
        let id = fuser::BackingId::create_raw(&session, &file).map_err(probe_error)?;
        // FUSE_DEV_IOC_BACKING_CLOSE from linux/fuse.h. fuser exposes raw open
        // but only closes managed IDs through a ReplyOpen, unavailable at INIT.
        if unsafe { libc::ioctl(session.as_fd().as_raw_fd(), libc::_IOW::<u32>(229, 2), &id) } != 0
        {
            return Err(probe_error(io::Error::last_os_error()));
        }
        log::info!("FUSE passthrough registration probe succeeded");
        Ok(())
    }

    pub(crate) fn cache_parent() -> io::Result<PathBuf> {
        let root = std::env::var_os("XDG_CACHE_HOME")
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".cache")))
            .ok_or_else(|| {
                io::Error::new(io::ErrorKind::NotFound, "no passthrough cache directory")
            })?;
        std::fs::create_dir_all(&root)?;
        Ok(root)
    }

    pub(crate) fn statfs(file: &File) -> io::Result<libc::statfs> {
        let mut stat = std::mem::MaybeUninit::uninit();
        if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { stat.assume_init() })
    }

    fn aligned(offset: u64, len: u64, block: u64) -> bool {
        block != 0 && len >= block && offset.is_multiple_of(block)
    }

    /// FICLONERANGE uses a fixed-width UAPI struct (including the signed fd).
    pub(crate) fn clone_range(src: &File, dst: &File, offset: u64, len: u64) -> io::Result<()> {
        // A zero length means "through EOF", which would expose later members.
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty clone range",
            ));
        }
        let range = libc::file_clone_range {
            src_fd: src.as_raw_fd().into(),
            src_offset: offset,
            src_length: len,
            dest_offset: 0,
        };
        if unsafe { libc::ioctl(dst.as_raw_fd(), libc::FICLONERANGE, &range) } != 0 {
            return Err(io::Error::last_os_error());
        }
        dst.set_len(len)
    }

    fn private_dir(parent: &Path) -> io::Result<tempfile::TempDir> {
        tempfile::Builder::new()
            .prefix("ratarmount-passthrough-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(parent)
    }

    fn temporary_in(parent: &Path) -> io::Result<File> {
        // No directory metadata write on filesystems supporting O_TMPFILE.
        if let Ok(file) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_TMPFILE)
            .mode(0o600)
            .open(parent)
        {
            return Ok(file);
        }
        let dir = private_dir(parent)?;
        tempfile::tempfile_in(dir.path())
    }

    fn same_filesystem_target(parent: &Path, dev: u64, state: &State) -> Option<File> {
        if std::fs::metadata(parent).ok()?.dev() != dev || !state.allows(dev) {
            return None;
        }
        let file = temporary_in(parent).ok()?;
        (file.metadata().ok()?.dev() == dev).then_some(file)
    }

    fn archive_parent(file: &File) -> Option<PathBuf> {
        std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .ok()?
            .parent()
            .map(Path::to_path_buf)
    }

    fn copy_range(extent: &BackingExtent, file: &File, start: u64) -> io::Result<()> {
        let mut offset = start;
        let mut buf = vec![0; 128 * 1024];
        while offset < extent.len {
            let n = (extent.len - offset).min(buf.len() as u64) as usize;
            extent
                .file
                .read_exact_at(&mut buf[..n], extent.offset + offset)?;
            file.write_all_at(&buf[..n], offset)?;
            offset += n as u64;
        }
        file.set_len(extent.len)
    }

    /// Return only complete backing files; failed preparations release their
    /// budget and unlink their output. Whole files do not consume copy budget.
    pub(crate) fn prepare(
        extent: BackingExtent,
        options: PassthroughOptions,
        state: &State,
        cache: impl FnOnce() -> io::Result<PathBuf>,
    ) -> io::Result<Option<PreparedBacking>> {
        if state.denied() {
            return Ok(None);
        }
        let meta = extent.file.metadata()?;
        if !state.allows(meta.dev())
            || !meta.is_file()
            || extent.len == 0
            || extent
                .offset
                .checked_add(extent.len)
                .is_none_or(|end| end > meta.len())
        {
            return Ok(None);
        }
        if extent.offset == 0 && extent.len == meta.len() {
            return Ok(Some(PreparedBacking {
                file: extent.file,
                _reservation: None,
            }));
        }
        let can_copy = options.copy && extent.len <= options.copy_max && options.copy_max != 0;
        let block = u64::try_from(statfs(&extent.file)?.f_bsize).unwrap_or(0);
        let can_clone =
            aligned(extent.offset, extent.len, block) && state.clone_allowed(meta.dev());
        if !can_clone && !can_copy {
            return Ok(None);
        }
        // Lazy: a successful clone beside the archive never creates ~/.cache.
        let mut cache = Some(cache);
        let mut cache_path = None;
        if can_clone {
            let prefix = extent.len / block * block;
            // A clone with an unaligned length only copies its final partial block.
            let reservation = state.budget.reserve(extent.len - prefix);
            if let Some(reservation) = reservation {
                let target = archive_parent(&extent.file)
                    .and_then(|dir| same_filesystem_target(&dir, meta.dev(), state))
                    .or_else(|| {
                        cache_path = cache.take().unwrap()().ok();
                        cache_path
                            .as_ref()
                            .and_then(|dir| same_filesystem_target(dir, meta.dev(), state))
                    })
                    .or_else(|| same_filesystem_target(&std::env::temp_dir(), meta.dev(), state));
                if let Some(file) = target {
                    match clone_range(&extent.file, &file, extent.offset, prefix) {
                        Ok(()) => {
                            copy_range(&extent, &file, prefix)?;
                            return Ok(Some(PreparedBacking {
                                file,
                                _reservation: Some(reservation),
                            }));
                        }
                        Err(e) => {
                            state.clone_error(meta.dev(), &e);
                            log::debug!("passthrough clone fallback: {e}");
                        }
                    }
                }
            }
        }
        if !can_copy {
            return Ok(None);
        }
        let Some(reservation) = state.budget.reserve(extent.len) else {
            return Ok(None);
        };
        let parent = match cache_path {
            Some(path) => path,
            None => match cache {
                Some(cache) => cache()?,
                None => return Ok(None),
            },
        };
        if !state.allows(std::fs::metadata(&parent)?.dev()) {
            return Ok(None);
        }
        let file = temporary_in(&parent)?;
        copy_range(&extent, &file, 0)?;
        Ok(Some(PreparedBacking {
            file,
            _reservation: Some(reservation),
        }))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn prepare(
            extent: BackingExtent,
            options: PassthroughOptions,
            cache: impl FnOnce() -> io::Result<PathBuf>,
        ) -> io::Result<Option<File>> {
            super::prepare(extent, options, &State::new(options.copy_total_max), cache)
                .map(|result| result.map(|prepared| prepared.file))
        }

        fn extent(dir: &Path, offset: u64, len: u64) -> BackingExtent {
            let file = tempfile::tempfile_in(dir).unwrap();
            file.write_all_at(&vec![0x55; 16384], 0).unwrap();
            file.write_all_at(&vec![0xa7; len as usize], offset)
                .unwrap();
            BackingExtent { file, offset, len }
        }

        /// Regression: user-namespace root and missing capabilities must not raise stack depth.
        #[test]
        fn passthrough_auto_requires_initial_namespace_sys_admin() {
            assert!(privileged(
                "Name:\ttest\nCapEff:\t0000000000200000\n",
                INITIAL_USER_NS
            ));
            assert!(!privileged("CapEff:\t0000000000000000", INITIAL_USER_NS));
            assert!(!privileged(
                "CapEff:\tffffffffffffffff",
                INITIAL_USER_NS + 1
            ));
            assert!(!privileged("CapEff:\tbroken", INITIAL_USER_NS));
            assert!(!privileged("CapPrm:\tffffffffffffffff", INITIAL_USER_NS));
        }

        /// Regression: forced-on permission failures must explain the startup failure.
        #[test]
        fn passthrough_on_probe_eperm_names_cap_sys_admin() {
            let error = probe_error(io::Error::from_raw_os_error(libc::EPERM));
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(error
                .to_string()
                .contains("--passthrough on registration probe failed"));
            assert!(error
                .to_string()
                .contains("CAP_SYS_ADMIN in the initial user namespace"));
            let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();
            assert!(probe(socket)
                .unwrap_err()
                .to_string()
                .contains("registration probe failed"));
        }

        /// Regression: EPERM must stop all preparation, including copies on other inodes.
        #[test]
        fn passthrough_eperm_latches_before_preparation() {
            let state = State::new(4096);
            let dir = tempfile::tempdir().unwrap();
            let error = state
                .register(
                    || {
                        super::prepare(
                            extent(dir.path(), 0, 16384),
                            Default::default(),
                            &state,
                            || panic!("no cache"),
                        )
                    },
                    |_| Err::<(), _>(io::Error::from_raw_os_error(libc::EPERM)),
                )
                .err()
                .unwrap();
            assert_eq!(error.raw_os_error(), Some(libc::EPERM));
            assert!(state.denied());
            for _ in 0..3 {
                assert!(state
                    .register::<()>(
                        || panic!("must not prepare after EPERM"),
                        |_| panic!("must not register")
                    )
                    .unwrap()
                    .is_none());
            }
            // Existing successful registrations remain pinned until their last release.
            let mut opens = OpenBackings::default();
            opens.open(1, 1, || Some(42));
            assert_eq!(
                *opens
                    .open(1, 2, || panic!("reuse even after denial"))
                    .unwrap(),
                42
            );
        }

        /// Regression: stack/cross-device failures must not retry clone/copy work per open.
        #[test]
        fn passthrough_eloop_exdev_cached_per_filesystem() {
            let dir = tempfile::tempdir().unwrap();
            for errno in [libc::ELOOP, libc::EXDEV] {
                let state = State::new(4096);
                let src = extent(dir.path(), 0, 16384);
                let dev = src.file.metadata().unwrap().dev();
                let result = state.register(
                    || super::prepare(src, Default::default(), &state, || panic!("no cache")),
                    |_| Err::<(), _>(io::Error::from_raw_os_error(errno)),
                );
                assert_eq!(result.err().unwrap().raw_os_error(), Some(errno));
                assert!(!state.denied());
                assert!(!state.allows(dev));
                assert!(state.allows(dev.wrapping_add(1)));
                let clone_state = State::new(4096);
                clone_state.clone_error(dev, &io::Error::from_raw_os_error(errno));
                assert!(!clone_state.clone_allowed(dev));
                assert!(clone_state.clone_allowed(dev.wrapping_add(1)));
                assert!(
                    clone_state.allows(dev),
                    "clone denial still permits bounded copying"
                );
                assert!(super::prepare(
                    extent(dir.path(), 512, 4096),
                    PassthroughOptions {
                        copy: true,
                        copy_max: 4096,
                        ..Default::default()
                    },
                    &state,
                    || panic!("blocked filesystem must not prepare")
                )
                .unwrap()
                .is_none());
            }
        }

        /// Regression: many simultaneously copied members must share one budget until RELEASE.
        #[test]
        fn passthrough_copy_total_budget_released_on_last_open() {
            let state = State::new(4096);
            let dir = tempfile::tempdir().unwrap();
            let options = PassthroughOptions {
                copy: true,
                copy_max: 4096,
                ..Default::default()
            };
            let prepared = super::prepare(extent(dir.path(), 512, 4096), options, &state, || {
                Ok(dir.path().into())
            })
            .unwrap()
            .unwrap();
            let mut opens = OpenBackings::default();
            drop(opens.open(1, 1, || Some(prepared)));
            drop(opens.open(1, 2, || panic!("same inode shares budget")));
            opens.release(1);
            assert_eq!(state.budget.used.load(Ordering::Relaxed), 4096);
            assert!(
                super::prepare(extent(dir.path(), 512, 1), options, &state, || panic!(
                    "exhausted budget must not allocate"
                ))
                .unwrap()
                .is_none()
            );
            opens.release(2);
            assert_eq!(state.budget.used.load(Ordering::Relaxed), 0);
            assert!(
                super::prepare(extent(dir.path(), 512, 4096), options, &state, || Ok(dir
                    .path()
                    .into()))
                .unwrap()
                .is_some()
            );
            assert_eq!(state.budget.used.load(Ordering::Relaxed), 0);
            let error = super::prepare(extent(dir.path(), 512, 4096), options, &state, || {
                Err(io::Error::other("cache unavailable"))
            });
            assert!(error.is_err());
            assert_eq!(state.budget.used.load(Ordering::Relaxed), 0);
            assert!(state.budget.reserve(u64::MAX).is_none());
        }

        /// Regression: clone lengths with a partial final block must copy only that tail.
        #[test]
        fn passthrough_clone_tail_copy_does_not_expose_next_member() {
            assert!(aligned(4096, 4097, 4096));
            assert!(!aligned(512, 4097, 4096));
            let dir = tempfile::tempdir().unwrap();
            let src = extent(dir.path(), 4096, 4097);
            let dst = tempfile::tempfile_in(dir.path()).unwrap();
            dst.write_all_at(&vec![0xa7; 4096], 0).unwrap();
            copy_range(&src, &dst, 4096).unwrap();
            let mut data = vec![0; 4098];
            assert_eq!(dst.read_at(&mut data, 0).unwrap(), 4097);
            assert_eq!(&data[..4097], vec![0xa7; 4097]);
            assert_eq!(data[4097], 0);
        }

        /// Regression: a different cache filesystem must not prevent same-filesystem reflinks.
        #[test]
        fn passthrough_clone_uses_archive_filesystem_and_copies_tail() {
            let root = std::env::var_os("RATARMOUNT_TEST_REFLINK_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")));
            let dir = tempfile::tempdir_in(root).unwrap();
            let src = extent(dir.path(), 4096, 4097);
            if !matches!(
                statfs(&src.file).unwrap().f_type,
                libc::BTRFS_SUPER_MAGIC | libc::XFS_SUPER_MAGIC
            ) {
                eprintln!("skip: real clone tail test requires btrfs/XFS");
                return;
            }
            let dev = src.file.metadata().unwrap().dev();
            let state = State::new(1);
            let prepared = super::prepare(src, Default::default(), &state, || {
                panic!("clone must use archive directory before cache")
            })
            .unwrap()
            .unwrap();
            assert_eq!(prepared.file.metadata().unwrap().dev(), dev);
            assert_eq!(prepared.file.metadata().unwrap().len(), 4097);
            let mut data = vec![0; 4097];
            prepared.file.read_exact_at(&mut data, 0).unwrap();
            assert_eq!(data, vec![0xa7; 4097]);
            assert_eq!(state.budget.used.load(Ordering::Relaxed), 1);
            drop(prepared);
            assert_eq!(state.budget.used.load(Ordering::Relaxed), 0);
            let wrong_dev = dev.wrapping_add(1);
            assert!(same_filesystem_target(dir.path(), wrong_dev, &state).is_none());
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        }

        /// Regression: temporary member directories must not inherit public permissions.
        #[test]
        fn passthrough_cache_directory_is_private() {
            let parent = tempfile::tempdir().unwrap();
            let dir = private_dir(parent.path()).unwrap();
            assert_eq!(
                dir.path().metadata().unwrap().permissions().mode() & 0o777,
                0o700
            );
            drop(dir);
            assert_eq!(std::fs::read_dir(parent.path()).unwrap().count(), 0);
        }

        /// Regression: invalid extents must not expose bytes beyond the member or overflow.
        #[test]
        fn passthrough_invalid_extent_returns_none() {
            let dir = tempfile::tempdir().unwrap();
            for (offset, len) in [(16380, 100), (u64::MAX, 1)] {
                let mut source = extent(dir.path(), 0, 4096);
                source.offset = offset;
                source.len = len;
                assert!(prepare(
                    source,
                    PassthroughOptions {
                        copy: true,
                        copy_max: 100,
                        ..Default::default()
                    },
                    || panic!("invalid range must not allocate")
                )
                .unwrap()
                .is_none());
            }
        }

        /// Regression: unaligned TAR members must not expose the archive header.
        #[test]
        fn passthrough_unaligned_member_without_copy_returns_none() {
            assert!(!aligned(512, 4096, 4096));
            assert!(!aligned(4096, 1, 4096));
            assert!(!aligned(4096, 0, 4096));
            assert!(!aligned(4096, 4096, 0));
            assert!(aligned(4096, 4096, 4096));
            let dir = tempfile::tempdir().unwrap();
            assert!(prepare(
                extent(dir.path(), 512, 4096),
                PassthroughOptions::default(),
                || panic!("must not allocate cache")
            )
            .unwrap()
            .is_none());
        }

        /// Regression: copying requires opt-in AND a cap; whole cache files need neither.
        #[test]
        fn passthrough_copy_cap_and_whole_file() {
            let dir = tempfile::tempdir().unwrap();
            for (copy, copy_max, allowed) in [
                (false, 8192, false),
                (true, 0, false),
                (true, 4095, false),
                (true, 4096, true),
            ] {
                let options = PassthroughOptions {
                    copy,
                    copy_max,
                    ..Default::default()
                };
                let result = prepare(extent(dir.path(), 512, 4096), options, || {
                    Ok(dir.path().into())
                })
                .unwrap();
                assert_eq!(result.is_some(), allowed);
                if let Some(file) = result {
                    assert_eq!(file.metadata().unwrap().len(), 4096);
                    let mut bytes = vec![0; 4096];
                    file.read_exact_at(&mut bytes, 0).unwrap();
                    assert_eq!(bytes, vec![0xa7; 4096]);
                }
            }
            let whole = extent(dir.path(), 0, 16384);
            assert!(prepare(whole, Default::default(), || panic!(
                "whole file needs no cache"
            ))
            .unwrap()
            .is_some());
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
        }

        /// Regression: unsupported reflinks fall back to daemon reads or a bounded copy.
        #[test]
        fn passthrough_clone_tmpfs_fallback() {
            let dir = match tempfile::tempdir() {
                Ok(dir) => dir,
                Err(e) => {
                    eprintln!("skip: tmpfs unavailable: {e}");
                    return;
                }
            };
            let src = extent(dir.path(), 4096, 4096);
            if statfs(&src.file).unwrap().f_type != libc::TMPFS_MAGIC {
                eprintln!("skip: temporary directory is not tmpfs");
                return;
            }
            let dst = tempfile::tempfile_in(dir.path()).unwrap();
            let error = clone_range(&src.file, &dst, 4096, 4096).unwrap_err();
            assert!(matches!(
                error.raw_os_error(),
                Some(libc::EOPNOTSUPP | libc::EXDEV | libc::ENOTTY)
            ));
            assert!(prepare(src, Default::default(), || Ok(dir.path().into()))
                .unwrap()
                .is_none());
            let copied = prepare(
                extent(dir.path(), 4096, 4096),
                PassthroughOptions {
                    copy: true,
                    copy_max: 4096,
                    ..Default::default()
                },
                || Ok(dir.path().into()),
            )
            .unwrap()
            .unwrap();
            let mut data = [0; 4096];
            copied.read_exact_at(&mut data, 0).unwrap();
            assert_eq!(data, [0xa7; 4096]);
        }

        /// Regression: reflinked backing starts at member byte zero and ends at its length.
        #[test]
        fn passthrough_clone_real_filesystem() {
            let root = std::env::var_os("RATARMOUNT_TEST_REFLINK_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")));
            let dir = tempfile::tempdir_in(root).unwrap();
            let src = extent(dir.path(), 4096, 4096);
            if !matches!(
                statfs(&src.file).unwrap().f_type,
                libc::BTRFS_SUPER_MAGIC | libc::XFS_SUPER_MAGIC
            ) {
                eprintln!("skip: real clone test requires btrfs/XFS");
                return;
            }
            let file = prepare(src, Default::default(), || Ok(dir.path().into()))
                .unwrap()
                .expect("reflink support required on test filesystem");
            let mut data = [0; 4096];
            file.read_exact_at(&mut data, 0).unwrap();
            assert_eq!(data, [0xa7; 4096]);
            assert_eq!(file.metadata().unwrap().len(), 4096);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: explicit on must fail when unsupported; auto and off fall back.
    #[test]
    fn passthrough_negotiation_modes() {
        assert!(negotiate(PassthroughMode::Auto, true, true).unwrap());
        assert!(negotiate(PassthroughMode::On, true, true).unwrap());
        assert!(negotiate(PassthroughMode::On, true, false).unwrap());
        assert!(!negotiate(PassthroughMode::Auto, true, false).unwrap());
        assert!(!negotiate(PassthroughMode::Auto, false, true).unwrap());
        for supported in [false, true] {
            assert!(!negotiate(PassthroughMode::Off, supported, true).unwrap());
        }
        assert!(negotiate(PassthroughMode::On, false, true)
            .unwrap_err()
            .to_string()
            .contains("--passthrough on requires"));
    }

    /// Regression: concurrent opens must reuse one ID and retain it until last RELEASE.
    #[test]
    fn passthrough_registration_lives_until_last_release() {
        let mut files = OpenBackings::default();
        let a = files.open(7, 1, || Some(42)).unwrap();
        let b = files
            .open(7, 2, || panic!("must reuse registration"))
            .unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        let weak = Arc::downgrade(&a);
        drop((a, b));
        files.release(1);
        assert!(weak.upgrade().is_some());
        files.release(2);
        assert!(weak.upgrade().is_none());
        assert_eq!(*files.open(7, 3, || Some(43)).unwrap(), 43);
    }

    /// Regression: retrying a failed registration while daemon handles exist causes EIO.
    #[test]
    fn passthrough_failed_open_stays_daemon_until_last_release() {
        let mut files = OpenBackings::<u32>::default();
        assert!(files.open(7, 1, || None).is_none());
        assert!(files.open(7, 2, || panic!("must remain daemon")).is_none());
        files.release(1);
        files.release(2);
        assert!(files.open(7, 3, || Some(42)).is_some());
    }
}
