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

#[derive(Clone, Copy, Debug, Default)]
pub struct PassthroughOptions {
    pub mode: PassthroughMode,
    /// Copying requires both this switch and a nonzero per-member byte cap.
    pub copy: bool,
    pub copy_max: u64,
}

pub(super) fn negotiate(mode: PassthroughMode, supported: bool) -> io::Result<bool> {
    match (mode, supported) {
        (PassthroughMode::Off, _) => Ok(false),
        (_, true) => Ok(true),
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
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::{FileExt, PermissionsExt};
    use std::path::{Path, PathBuf};

    pub(crate) struct RegisteredBacking {
        pub id: fuser::BackingId,
        pub _file: File,
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
        block != 0 && len != 0 && offset.is_multiple_of(block) && len.is_multiple_of(block)
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

    /// Return only complete backing files; partial copies are unlinked on error.
    pub(crate) fn prepare(
        extent: BackingExtent,
        options: PassthroughOptions,
        cache: impl FnOnce() -> io::Result<PathBuf>,
    ) -> io::Result<Option<File>> {
        let meta = extent.file.metadata()?;
        if !meta.is_file()
            || extent
                .offset
                .checked_add(extent.len)
                .is_none_or(|end| end > meta.len())
        {
            return Ok(None);
        }
        if extent.offset == 0 && extent.len == meta.len() {
            return Ok(Some(extent.file));
        }
        let can_copy = options.copy && extent.len <= options.copy_max && options.copy_max != 0;
        let block = u64::try_from(statfs(&extent.file)?.f_bsize).unwrap_or(0);
        let can_clone = aligned(extent.offset, extent.len, block);
        if !can_clone && !can_copy {
            return Ok(None);
        }
        // Private 0700 directory, then O_TMPFILE (tempfile's Linux implementation)
        // or an immediately unlinked file on filesystems without O_TMPFILE.
        let dir = private_dir(&cache()?)?;
        prepare_in(extent, options, dir.path(), can_clone)
    }

    fn private_dir(parent: &Path) -> io::Result<tempfile::TempDir> {
        tempfile::Builder::new()
            .prefix("ratarmount-passthrough-")
            .permissions(std::fs::Permissions::from_mode(0o700))
            .tempdir_in(parent)
    }

    fn prepare_in(
        extent: BackingExtent,
        options: PassthroughOptions,
        dir: &Path,
        can_clone: bool,
    ) -> io::Result<Option<File>> {
        let file = tempfile::tempfile_in(dir)?;
        if can_clone {
            match clone_range(&extent.file, &file, extent.offset, extent.len) {
                Ok(()) => return Ok(Some(file)),
                Err(e) => log::debug!("passthrough clone fallback: {e}"),
            }
        }
        if !options.copy || options.copy_max == 0 || extent.len > options.copy_max {
            return Ok(None);
        }
        file.set_len(0)?;
        let mut offset = 0;
        let mut buf = vec![0; 128 * 1024];
        while offset < extent.len {
            let n = (extent.len - offset).min(buf.len() as u64) as usize;
            extent
                .file
                .read_exact_at(&mut buf[..n], extent.offset + offset)?;
            file.write_all_at(&buf[..n], offset)?;
            offset += n as u64;
        }
        file.set_len(extent.len)?;
        Ok(Some(file))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn extent(dir: &Path, offset: u64, len: u64) -> BackingExtent {
            let file = tempfile::tempfile_in(dir).unwrap();
            file.write_all_at(&vec![0x55; 16384], 0).unwrap();
            file.write_all_at(&vec![0xa7; len as usize], offset)
                .unwrap();
            BackingExtent { file, offset, len }
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
        assert!(negotiate(PassthroughMode::Auto, true).unwrap());
        assert!(negotiate(PassthroughMode::On, true).unwrap());
        assert!(!negotiate(PassthroughMode::Auto, false).unwrap());
        for supported in [false, true] {
            assert!(!negotiate(PassthroughMode::Off, supported).unwrap());
        }
        assert!(negotiate(PassthroughMode::On, false)
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
