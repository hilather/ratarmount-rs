use super::*;
pub(super) use capabilities as snapshot;
use std::ffi::CString;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;

pub(super) const CASEFOLD: u32 = 0x4000_0000;
pub(super) fn case_mode(flags: u32) -> CaseMode {
    if flags & CASEFOLD == 0 {
        CaseMode::Sensitive
    } else {
        CaseMode::Insensitive
    }
}
pub(super) fn open_parent(path: &Path) -> Result<File, NativeFsError> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| error("parent", NativeFsErrorKind::InvalidComponent))?;
    // SAFETY: NUL-terminated path; only a read-only directory may be returned.
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-A1-LINUX-DIR","item":"ratarmount_index::checked_open::native_fs::linux::open_parent","disposition":"out-of-family","category":"directory-handle-or-durability","reason":"Own only O_DIRECTORY read-only CLOEXEC parent; follows parent aliases, never opens/closes a regular-file alias or creates a pathname.","creation":{"policy":"none","basis":"O_RDONLY|O_DIRECTORY|O_CLOEXEC without create/truncate; owned directory close cannot release a database inode lock."}}"###
    )]
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(last("open directory"));
    }
    // SAFETY: successful open transferred a unique descriptor.
    #[expect(
        clippy::disallowed_methods,
        reason = r###"internal-read:v1 {"id":"IR-A1-LINUX-OWN","item":"ratarmount_index::checked_open::native_fs::linux::open_parent","disposition":"out-of-family","category":"descriptor-handoff","reason":"Transfer the already inventoried O_DIRECTORY descriptor into unique directory-only File ownership, without any new open or regular-file alias close.","creation":{"policy":"none","basis":"from_raw_fd retypes the preceding successful read-only directory open; it creates no pathname or acquisition."}}"###
    )]
    let file = unsafe { File::from_raw_fd(fd) };
    Ok(file)
}

fn last(op: &'static str) -> NativeFsError {
    errno(
        op,
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO),
    )
}

#[allow(clippy::unnecessary_cast)] // Native stat fields may be narrower on 32-bit ABIs.
fn object(s: &libc::stat) -> Result<ExistingObject, NativeFsError> {
    let kind = match s.st_mode & libc::S_IFMT {
        libc::S_IFREG => ObjectKind::File,
        libc::S_IFDIR => ObjectKind::Directory,
        libc::S_IFLNK => return Err(error("stat kind", NativeFsErrorKind::LeafLinkOrReparse)),
        _ => return Err(error("stat kind", NativeFsErrorKind::WrongKind)),
    };
    Ok(ExistingObject {
        identity: Capability::Known(NativeIdentity::Linux {
            device: s.st_dev as u64,
            inode: s.st_ino as u64,
        }),
        kind,
        mac_objid: None,
    })
}

pub(super) fn identity(file: &File) -> Result<ExistingObject, NativeFsError> {
    // SAFETY: stat is initialized only after fstat succeeds; fd is borrowed.
    unsafe {
        let mut s = std::mem::zeroed();
        if libc::fstat(file.as_raw_fd(), &mut s) != 0 {
            return Err(last("fstat"));
        }
        object(&s)
    }
}

pub(super) fn lookup(file: &File, name: &OsStr) -> Result<Lookup, NativeFsError> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| error("component", NativeFsErrorKind::InvalidComponent))?;
    // SAFETY: validated single component; fstatat doesn't open/close the leaf.
    unsafe {
        let mut s = std::mem::zeroed();
        if libc::fstatat(
            file.as_raw_fd(),
            name.as_ptr(),
            &mut s,
            libc::AT_SYMLINK_NOFOLLOW,
        ) != 0
        {
            let e = last("fstatat nofollow");
            return if e.code == Some(NativeCode::Errno(libc::ENOENT)) {
                Ok(Lookup::Missing)
            } else {
                Err(e)
            };
        }
        object(&s).map(Lookup::Existing)
    }
}

pub(super) fn classify(magic: u32) -> LinuxFilesystem {
    match magic {
        0x0102_1994 => LinuxFilesystem::Tmpfs,
        0xef53 => LinuxFilesystem::ExtFamily,
        0x9123_683e => LinuxFilesystem::Btrfs,
        0x5846_5342 | 0x794c_7630 | 0x6969 | 0x6573_5546 => LinuxFilesystem::RecognizedUnreviewed,
        _ => LinuxFilesystem::Unknown,
    }
}

/// The one audited GETFLAGS ABI gate shared by every reviewed row.
const AUDITED_ABI: bool = cfg!(all(
    target_env = "gnu",
    target_pointer_width = "64",
    target_endian = "little",
    any(target_arch = "x86_64", target_arch = "aarch64")
));

pub(super) fn flags_with(
    abi: bool,
    mut ioctl: impl FnMut() -> Result<u32, i32>,
) -> Result<Capability<u32>, NativeFsError> {
    if !abi {
        return Ok(Capability::Unavailable(
            CapabilityUnavailable::UnsupportedAbi,
        ));
    }
    match ioctl() {
        Ok(flags) => Ok(Capability::Known(flags)),
        Err(e) if e == libc::ENOTTY || e == libc::EOPNOTSUPP || e == libc::ENOSYS => {
            Ok(Capability::Unavailable(
                CapabilityUnavailable::UnsupportedApi(Some(NativeCode::Errno(e))),
            ))
        }
        Err(e) => Err(errno("FS_IOC_GETFLAGS", e)),
    }
}

/// tmpfs/btrfs GETFLAGS: unlike the frozen ext row, every failure is a typed,
/// cause-preserving Unavailable at the capability boundary, never an error.
pub(super) fn flags_reviewed(
    abi: bool,
    mut ioctl: impl FnMut() -> Result<u32, i32>,
) -> Capability<u32> {
    if !abi {
        return Capability::Unavailable(CapabilityUnavailable::UnsupportedAbi);
    }
    match ioctl() {
        Ok(flags) => Capability::Known(flags),
        Err(e) if e == libc::ENOTTY || e == libc::EOPNOTSUPP || e == libc::ENOSYS => {
            Capability::Unavailable(CapabilityUnavailable::UnsupportedApi(Some(
                NativeCode::Errno(e),
            )))
        }
        Err(e) => Capability::Unavailable(CapabilityUnavailable::QueryFailed(NativeCode::Errno(e))),
    }
}

/// The only place where a kind selects its GETFLAGS path. ext keeps L2's frozen
/// behaviour (other errnos are errors); tmpfs/btrfs map every failure to Unavailable.
pub(super) fn flags_for(
    kind: LinuxFilesystem,
    abi: bool,
    ioctl: impl FnMut() -> Result<u32, i32>,
) -> Result<Capability<u32>, NativeFsError> {
    match kind {
        LinuxFilesystem::ExtFamily => flags_with(abi, ioctl),
        LinuxFilesystem::Tmpfs | LinuxFilesystem::Btrfs => Ok(flags_reviewed(abi, ioctl)),
        LinuxFilesystem::RecognizedUnreviewed | LinuxFilesystem::Unknown => Ok(
            Capability::Unavailable(CapabilityUnavailable::NotApplicable),
        ),
    }
}

fn unreviewed(kind: LinuxFilesystem) -> Option<CapabilityUnavailable> {
    match kind {
        LinuxFilesystem::Tmpfs | LinuxFilesystem::ExtFamily | LinuxFilesystem::Btrfs => None,
        LinuxFilesystem::RecognizedUnreviewed => Some(CapabilityUnavailable::UnreviewedFilesystem),
        LinuxFilesystem::Unknown => Some(CapabilityUnavailable::UnknownFilesystem),
    }
}

/// `case_sensitive` and `case_preserving` for one kind and its GETFLAGS outcome.
pub(super) fn modes(
    kind: LinuxFilesystem,
    flags: &Capability<u32>,
) -> (Capability<CaseMode>, Capability<bool>) {
    if let Some(cause) = unreviewed(kind) {
        return (
            Capability::Unavailable(cause),
            Capability::Unavailable(cause),
        );
    }
    let sensitive = match flags {
        Capability::Known(f) => Capability::Known(case_mode(*f)),
        Capability::Unavailable(cause) => Capability::Unavailable(*cause),
    };
    (sensitive, Capability::Known(true))
}

/// Reviewed byte-exact rule, decided in the order kind, flags, then `name_max`.
/// K-T: tmpfs matches names by bytes unless the directory has FS_CASEFOLD_FL
/// (v6.13+ `shmem_ci_dentry_ops`); directory GETFLAGS needs CONFIG_TMPFS_XATTR.
/// K-B: btrfs has no casefold and only `.d_delete` dentry ops (length plus memcmp,
/// dir-item.c). ext2/3/4 share 0xEF53; ext2 matches by length plus memcmp
/// (`ext2_match`). Upstream v6.8/v6.12/v6.13/v7.0 only; vendor kernels unreviewed.
pub(super) fn rule(
    kind: LinuxFilesystem,
    flags: &Capability<u32>,
    name_max: Option<u32>,
) -> AbsentNameCapability {
    if let Some(cause) = unreviewed(kind) {
        return AbsentNameCapability::Unavailable(NameEquivalenceUnavailable::Unreviewed(cause));
    }
    let flags = match flags {
        Capability::Known(f) => *f,
        Capability::Unavailable(cause) => {
            return AbsentNameCapability::Unavailable(NameEquivalenceUnavailable::Uninspectable(
                *cause,
            ));
        }
    };
    if flags & CASEFOLD != 0 {
        return AbsentNameCapability::Unavailable(NameEquivalenceUnavailable::Casefold);
    }
    match name_max {
        Some(name_max) if name_max > 0 => {
            AbsentNameCapability::Reviewed(ReviewedNameRule::LinuxByteExact {
                filesystem: kind,
                name_max,
            })
        }
        _ => AbsentNameCapability::Unavailable(NameEquivalenceUnavailable::Uninspectable(
            CapabilityUnavailable::UnsupportedApi(None),
        )),
    }
}

/// Private: reached only through `flags_for`'s audited-ABI gate in `capabilities`.
fn getflags(file: &File) -> Result<u32, i32> {
    // Linux UAPI encodes sizeof(long), but writes an int. Both audited
    // ABIs use the libc-generated request and a 32-bit output slot.
    let mut flags: libc::c_int = 0;
    // SAFETY: audited ABI checked before invocation, correctly sized output.
    if unsafe { libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags) } == 0 {
        Ok(flags as u32)
    } else {
        Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO))
    }
}

pub(super) fn capabilities(file: &File) -> Result<DirectoryCapabilities, NativeFsError> {
    // SAFETY: borrowed live directory descriptor; statfs is plain output data.
    let (magic, name_max) = unsafe {
        let mut s: libc::statfs = std::mem::zeroed();
        if libc::fstatfs(file.as_raw_fd(), &mut s) != 0 {
            return Err(last("fstatfs"));
        }
        // UAPI magic width, not sign-extended native long. f_namelen's native type
        // differs by ABI, so it is converted, never cast.
        (s.f_type as u32, u32::try_from(s.f_namelen).ok())
    };
    let kind = classify(magic);
    let flags = flags_for(kind, AUDITED_ABI, || getflags(file))?;
    let (case_sensitive, case_preserving) = modes(kind, &flags);
    Ok(DirectoryCapabilities {
        identity: identity(file)?.identity,
        filesystem: FilesystemKind::Linux { magic, kind },
        case_sensitive,
        case_preserving,
        existing_short_names: Capability::Unavailable(CapabilityUnavailable::NotApplicable),
        absent_names: rule(kind, &flags, name_max),
        linux_flags: flags,
    })
}

pub(super) fn short_names(
    _: &File,
    _: &OsStr,
) -> Result<Capability<Vec<ExistingShortName>>, NativeFsError> {
    Ok(Capability::Unavailable(
        CapabilityUnavailable::NotApplicable,
    ))
}
