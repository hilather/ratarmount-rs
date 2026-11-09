use super::*;
pub(super) use capabilities as snapshot;
use std::ffi::{CStr, CString};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;

pub(super) fn open_parent(path: &Path) -> Result<File, NativeFsError> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| error("parent", NativeFsErrorKind::InvalidComponent))?;
    // SAFETY: read-only directory acquisition only, never a regular-file alias.
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(last("open directory"));
    }
    // SAFETY: successful open transfers unique directory ownership.
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn last(op: &'static str) -> NativeFsError {
    errno(
        op,
        std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(libc::EIO),
    )
}

// Attribute packing is four-byte aligned, including the eight-byte FILEID.
// Decode native-endian bytes rather than casting packed buffers or private fsid_t.
pub(super) struct Attributes {
    bytes: [u8; 128],
    pos: usize,
    end: usize,
}

impl Attributes {
    fn take<const N: usize>(&mut self) -> Result<[u8; N], NativeFsError> {
        let data = self
            .bytes
            .get(self.pos..self.pos + N)
            .filter(|_| self.pos + N <= self.end)
            .ok_or_else(|| error("attribute bounds", NativeFsErrorKind::MalformedData))?;
        self.pos += N;
        Ok(data.try_into().unwrap())
    }
    pub(super) fn word(&mut self) -> Result<u32, NativeFsError> {
        Ok(u32::from_ne_bytes(self.take()?))
    }
    pub(super) fn checked(
        bytes: [u8; 128],
        common: u32,
        volume: u32,
    ) -> Result<Self, NativeFsError> {
        let volume = volume & !libc::ATTR_VOL_INFO; // Selector, not returned data.
        let end = u32::from_ne_bytes(bytes[..4].try_into().unwrap()) as usize;
        if !(24..=128).contains(&end) || !end.is_multiple_of(4) {
            return Err(error("attribute length", NativeFsErrorKind::MalformedData));
        }
        let mut r = Self { bytes, pos: 4, end };
        let returned = [r.word()?, r.word()?, r.word()?, r.word()?, r.word()?];
        let mut packed = 24;
        for (bit, size) in [
            (libc::ATTR_CMN_FSID, 8),
            (libc::ATTR_CMN_OBJTYPE, 4),
            (libc::ATTR_CMN_OBJID, 8),
            (libc::ATTR_CMN_FILEID, 8),
        ] {
            if returned[0] & bit != 0 {
                packed += size;
            }
        }
        if returned[1] & libc::ATTR_VOL_CAPABILITIES != 0 {
            packed += 32;
        }
        if end != packed {
            return Err(error(
                "packed attribute length",
                NativeFsErrorKind::MalformedData,
            ));
        }
        if returned != [common, volume, 0, 0, 0] {
            let missing_fileid = common & libc::ATTR_CMN_FILEID != 0
                && returned == [common & !libc::ATTR_CMN_FILEID, volume, 0, 0, 0];
            return Err(error(
                "returned attribute masks",
                if missing_fileid {
                    NativeFsErrorKind::UnsupportedApi
                } else {
                    NativeFsErrorKind::MalformedData
                },
            ));
        }
        Ok(r)
    }
}

fn request(
    file: &File,
    name: Option<&CStr>,
    common: u32,
    volume: u32,
) -> Result<Attributes, NativeFsError> {
    let common = common | libc::ATTR_CMN_RETURNED_ATTRS;
    let mut attrs = libc::attrlist {
        bitmapcount: 5,
        reserved: 0,
        commonattr: common,
        volattr: volume,
        dirattr: 0,
        fileattr: 0,
        forkattr: 0,
    };
    let mut bytes = [0; 128];
    // SAFETY: live borrowed fd, optional validated C component; bounded output.
    let rc = unsafe {
        if let Some(name) = name {
            libc::getattrlistat(
                file.as_raw_fd(),
                name.as_ptr(),
                (&mut attrs as *mut libc::attrlist).cast(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                libc::FSOPT_NOFOLLOW.into(),
            )
        } else {
            libc::fgetattrlist(
                file.as_raw_fd(),
                (&mut attrs as *mut libc::attrlist).cast(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                0,
            )
        }
    };
    if rc != 0 {
        return Err(last("getattrlist"));
    }
    Attributes::checked(bytes, common, volume)
}

fn unsupported(e: &NativeFsError) -> bool {
    e.kind == NativeFsErrorKind::UnsupportedApi
        || matches!(
            e.code,
            Some(NativeCode::Errno(libc::EINVAL | libc::ENOTSUP))
        )
}

#[cfg(test)]
std::thread_local! { pub(super) static FORCE_OBJID: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }

fn observe(file: &File, name: Option<&CStr>) -> Result<ExistingObject, NativeFsError> {
    let full = request(
        file,
        name,
        libc::ATTR_CMN_FSID | libc::ATTR_CMN_OBJTYPE | libc::ATTR_CMN_FILEID,
        0,
    );
    #[cfg(test)]
    let full = if FORCE_OBJID.get() {
        Err(error(
            "forced FILEID unsupported",
            NativeFsErrorKind::UnsupportedApi,
        ))
    } else {
        full
    };
    // Only unsupported attributes permit the legacy observation-only fallback.
    let (mut r, cause) = match full {
        Ok(r) => (r, None),
        Err(e) if unsupported(&e) => (
            request(file, name, libc::ATTR_CMN_OBJTYPE | libc::ATTR_CMN_OBJID, 0)?,
            Some(e.code),
        ),
        Err(e) => return Err(e),
    };
    let volume = if cause.is_none() {
        [r.word()? as i32, r.word()? as i32]
    } else {
        [0; 2]
    };
    let kind = match r.word()? {
        // Darwin vtype_t from sys/vnode.h
        1 => ObjectKind::File,
        2 => ObjectKind::Directory,
        5 => return Err(error("object type", NativeFsErrorKind::LeafLinkOrReparse)),
        _ => return Err(error("object type", NativeFsErrorKind::WrongKind)),
    };
    let (identity, mac_objid) = if let Some(code) = cause {
        (
            Capability::Unavailable(CapabilityUnavailable::FullIdentityUnavailable(code)),
            Some(MacObjIdObservation {
                object: r.word()?,
                generation: r.word()?,
            }),
        )
    } else {
        (
            Capability::Known(NativeIdentity::MacOs {
                volume,
                file_id: u64::from_ne_bytes(r.take()?),
            }),
            None,
        )
    };
    if r.pos != r.end {
        return Err(error(
            "attribute trailing data",
            NativeFsErrorKind::MalformedData,
        ));
    }
    Ok(ExistingObject {
        identity,
        kind,
        mac_objid,
    })
}

pub(super) fn identity(file: &File) -> Result<ExistingObject, NativeFsError> {
    observe(file, None)
}

pub(super) fn lookup(file: &File, name: &OsStr) -> Result<Lookup, NativeFsError> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| error("component", NativeFsErrorKind::InvalidComponent))?;
    match observe(file, Some(&name)) {
        Ok(o) => Ok(Lookup::Existing(o)),
        Err(e) if e.code == Some(NativeCode::Errno(libc::ENOENT)) => Ok(Lookup::Missing),
        Err(e) => Err(e),
    }
}

pub(super) fn capabilities(file: &File) -> Result<DirectoryCapabilities, NativeFsError> {
    // SAFETY: borrowed directory fd, plain statfs output, public type-name field.
    let name = unsafe {
        let mut s: libc::statfs = std::mem::zeroed();
        if libc::fstatfs(file.as_raw_fd(), &mut s) != 0 {
            return Err(last("fstatfs"));
        }
        let end = s
            .f_fstypename
            .iter()
            .position(|b| *b == 0)
            .ok_or_else(|| error("filesystem name", NativeFsErrorKind::MalformedData))?;
        s.f_fstypename[..end].iter().map(|b| *b as u8).collect()
    };
    // XNU resolves the volume root for a separate ATTR_VOL_INFO query.
    let facts = request(
        file,
        None,
        0,
        libc::ATTR_VOL_INFO | libc::ATTR_VOL_CAPABILITIES,
    );
    let (sensitive, preserving) = match facts {
        Ok(mut r) => {
            let mut caps = [0; 4];
            let mut valid = [0; 4];
            for v in &mut caps {
                *v = r.word()?;
            }
            for v in &mut valid {
                *v = r.word()?;
            }
            if r.pos != r.end {
                return Err(error(
                    "volume trailing data",
                    NativeFsErrorKind::MalformedData,
                ));
            }
            (
                volume_bit(caps[0], valid[0], libc::VOL_CAP_FMT_CASE_SENSITIVE),
                volume_bit(caps[0], valid[0], libc::VOL_CAP_FMT_CASE_PRESERVING),
            )
        }
        Err(e) if unsupported(&e) => {
            let u = Capability::Unavailable(CapabilityUnavailable::UnsupportedApi(e.code));
            (u.clone(), u)
        }
        Err(e) => return Err(e),
    };
    Ok(DirectoryCapabilities {
        identity: identity(file)?.identity,
        filesystem: FilesystemKind::MacOs { name },
        case_sensitive: match sensitive {
            Capability::Known(true) => Capability::Known(CaseMode::Sensitive),
            Capability::Known(false) => Capability::Known(CaseMode::Insensitive),
            Capability::Unavailable(e) => Capability::Unavailable(e),
        },
        case_preserving: preserving,
        existing_short_names: Capability::Unavailable(CapabilityUnavailable::NotApplicable),
        linux_flags: Capability::Unavailable(CapabilityUnavailable::NotApplicable),
        absent_names: AbsentNameCapability::default(),
    })
}

pub(super) fn volume_bit(caps: u32, valid: u32, bit: u32) -> Capability<bool> {
    if valid & bit == 0 {
        Capability::Unavailable(CapabilityUnavailable::UnsupportedApi(None))
    } else {
        Capability::Known(caps & bit != 0)
    }
}

pub(super) fn short_names(
    _: &File,
    _: &OsStr,
) -> Result<Capability<Vec<ExistingShortName>>, NativeFsError> {
    Ok(Capability::Unavailable(
        CapabilityUnavailable::NotApplicable,
    ))
}
