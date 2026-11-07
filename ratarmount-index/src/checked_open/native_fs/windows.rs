use super::*;
use std::mem::{offset_of, size_of};
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::ptr::{null, null_mut};
use windows_sys::Wdk::Foundation::OBJECT_ATTRIBUTES;
use windows_sys::Wdk::Storage::FileSystem::{
    NtCreateFile, FILE_DIRECTORY_FILE, FILE_OPEN, FILE_OPEN_REPARSE_POINT,
    FILE_SYNCHRONOUS_IO_NONALERT,
};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Storage::FileSystem::*;
use windows_sys::Win32::System::IO::IO_STATUS_BLOCK;

// Windows SDK winnt.h bits (SystemServices feature otherwise unused here).
const FILE_CS_FLAG_CASE_SENSITIVE_DIR: u32 = 1;
const FILE_CASE_PRESERVED_NAMES: u32 = 2;

pub(super) fn validate(name: &OsStr) -> Result<(), NativeFsError> {
    let w: Vec<u16> = name.encode_wide().collect();
    let invalid = || error("component", NativeFsErrorKind::InvalidComponent);
    if w.is_empty()
        || w.len() > 32767
        || w.iter()
            .any(|c| *c < 32 || b"\\/:<>\"|?*".iter().any(|v| u16::from(*v) == *c))
        || matches!(w.last(), Some(32 | 46))
    {
        return Err(invalid());
    }
    // Native UTF16, including unpaired units, is preserved. Text conversion is
    // only for recognizing reserved ASCII/superscript device syntax.
    let stem_end = w.iter().position(|c| *c == 46).unwrap_or(w.len());
    let text = String::from_utf16(&w[..stem_end]).unwrap_or_default();
    // Only reserved-device syntax is folded here; no filename comparison rule.
    let stem = text
        .split('.')
        .next()
        .unwrap()
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    let numbered = ["COM", "LPT"].iter().any(|p| {
        stem.strip_prefix(p).is_some_and(|s| {
            matches!(
                s,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    });
    if numbered
        || matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CLOCK$" | "CONIN$" | "CONOUT$"
        )
    {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn win_error(op: &'static str, code: u32) -> NativeFsError {
    let kind = match code {
        ERROR_ACCESS_DENIED => NativeFsErrorKind::Access,
        ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION => NativeFsErrorKind::Busy,
        ERROR_INVALID_FUNCTION
        | ERROR_NOT_SUPPORTED
        | ERROR_INVALID_PARAMETER
        | ERROR_CALL_NOT_IMPLEMENTED => NativeFsErrorKind::UnsupportedApi,
        _ => NativeFsErrorKind::Io,
    };
    NativeFsError {
        operation: op,
        kind,
        code: Some(NativeCode::Win32(code)),
    }
}

fn last(op: &'static str) -> NativeFsError {
    // SAFETY: retrieves this thread's last failing Win32 call.
    win_error(op, unsafe { GetLastError() })
}

pub(super) fn ordinary_open(path: &Path, leaf: bool) -> Result<File, NativeFsError> {
    let mut w: Vec<u16> = path.as_os_str().encode_wide().collect();
    if w.contains(&0) {
        return Err(error("parent path", NativeFsErrorKind::InvalidComponent));
    }
    w.push(0);
    // SAFETY: terminated path, OPEN_EXISTING, attribute-only access and all shares.
    let h = unsafe {
        CreateFileW(
            w.as_ptr(),
            FILE_READ_ATTRIBUTES | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS
                | if leaf {
                    FILE_FLAG_OPEN_REPARSE_POINT
                } else {
                    0
                },
            null_mut(),
        )
    };
    if h == INVALID_HANDLE_VALUE {
        return Err(last("CreateFileW"));
    }
    // SAFETY: unique successful file handle.
    Ok(unsafe { File::from_raw_handle(h) })
}

pub(super) fn open_parent(path: &Path) -> Result<File, NativeFsError> {
    ordinary_open(path, false)
}

fn info<T: Default>(file: &File, class: FILE_INFO_BY_HANDLE_CLASS) -> Result<T, NativeFsError> {
    let mut value = T::default();
    // SAFETY: internal callers pair class with its exact writable binding type.
    if unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle(),
            class,
            (&mut value as *mut T).cast(),
            size_of::<T>() as u32,
        )
    } == 0
    {
        return Err(last("GetFileInformationByHandleEx"));
    }
    Ok(value)
}

pub(super) fn identity(file: &File) -> Result<ExistingObject, NativeFsError> {
    // SAFETY: borrowed file handle, no duplication or close.
    if unsafe { GetFileType(file.as_raw_handle()) } != FILE_TYPE_DISK {
        return Err(error("file type", NativeFsErrorKind::WrongKind));
    }
    let tag: FILE_ATTRIBUTE_TAG_INFO = info(file, FileAttributeTagInfo)?;
    if tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(error("leaf reparse", NativeFsErrorKind::LeafLinkOrReparse));
    }
    let identity = match info::<FILE_ID_INFO>(file, FileIdInfo) {
        Ok(id) => Capability::Known(NativeIdentity::Windows {
            volume_serial: id.VolumeSerialNumber,
            file_id: id.FileId.Identifier,
        }),
        Err(e) if e.kind == NativeFsErrorKind::UnsupportedApi => {
            Capability::Unavailable(CapabilityUnavailable::FullIdentityUnavailable(e.code))
        }
        Err(e) => return Err(e),
    };
    Ok(ExistingObject {
        identity,
        kind: if tag.FileAttributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            ObjectKind::Directory
        } else {
            ObjectKind::File
        },
        mac_objid: None,
    })
}

fn relative(file: &File, name: &OsStr, list: bool) -> Result<Option<File>, NativeFsError> {
    let mut w: Vec<u16> = name.encode_wide().collect();
    let bytes = u16::try_from(w.len() * 2)
        .map_err(|_| error("UTF16 length", NativeFsErrorKind::ResourceLimit))?;
    let text = UNICODE_STRING {
        Length: bytes,
        MaximumLength: bytes,
        Buffer: w.as_mut_ptr(),
    };
    let attrs = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: file.as_raw_handle(),
        ObjectName: &text,
        Attributes: OBJ_CASE_INSENSITIVE,
        SecurityDescriptor: null(),
        SecurityQualityOfService: null(),
    };
    let mut h = null_mut();
    let mut status = IO_STATUS_BLOCK::default();
    // SAFETY: root-relative single UTF16 component, FILE_OPEN never creates.
    // Synchronous option is paired with SYNCHRONIZE; reparse leaf is opened itself.
    let rc = unsafe {
        NtCreateFile(
            &mut h,
            FILE_READ_ATTRIBUTES | SYNCHRONIZE | if list { FILE_LIST_DIRECTORY } else { 0 },
            &attrs,
            &mut status,
            null(),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            FILE_OPEN,
            FILE_OPEN_REPARSE_POINT
                | FILE_SYNCHRONOUS_IO_NONALERT
                | if list { FILE_DIRECTORY_FILE } else { 0 },
            null(),
            0,
        )
    };
    if rc == STATUS_OBJECT_NAME_NOT_FOUND {
        return Ok(None);
    }
    if rc < 0 {
        let kind = match rc {
            STATUS_ACCESS_DENIED => NativeFsErrorKind::Access,
            STATUS_SHARING_VIOLATION | STATUS_FILE_LOCK_CONFLICT | STATUS_LOCK_NOT_GRANTED => {
                NativeFsErrorKind::Busy
            }
            STATUS_INVALID_INFO_CLASS | STATUS_NOT_SUPPORTED | STATUS_NOT_IMPLEMENTED => {
                NativeFsErrorKind::UnsupportedApi
            }
            _ => NativeFsErrorKind::Io,
        };
        return Err(NativeFsError {
            operation: "NtCreateFile FILE_OPEN",
            kind,
            code: Some(NativeCode::NtStatus(rc)),
        });
    }
    // SAFETY: successful NtCreateFile transfers unique ownership.
    Ok(Some(unsafe { File::from_raw_handle(h) }))
}

pub(super) fn lookup(file: &File, name: &OsStr) -> Result<Lookup, NativeFsError> {
    relative(file, name, false)?.map_or(Ok(Lookup::Missing), |f| identity(&f).map(Lookup::Existing))
}

pub(super) fn capabilities(file: &File) -> Result<DirectoryCapabilities, NativeFsError> {
    let mut caps = snapshot(file)?;
    caps.existing_short_names = match enumerate(file) {
        Ok(_) => Capability::Known(()),
        Err(e) if e.kind == NativeFsErrorKind::UnsupportedApi => {
            Capability::Unavailable(CapabilityUnavailable::UnsupportedApi(e.code))
        }
        Err(e) => return Err(e),
    };
    Ok(caps)
}

// Basic W1/W2 queries require attributes only, never a listing ACL or cursor.
pub(super) fn snapshot(file: &File) -> Result<DirectoryCapabilities, NativeFsError> {
    let sensitive = match info::<FILE_CASE_SENSITIVE_INFO>(file, FileCaseSensitiveInfo) {
        Ok(v) if v.Flags & !FILE_CS_FLAG_CASE_SENSITIVE_DIR == 0 => {
            Capability::Known(if v.Flags & FILE_CS_FLAG_CASE_SENSITIVE_DIR != 0 {
                CaseMode::Sensitive
            } else {
                CaseMode::Insensitive
            })
        }
        Ok(_) => Capability::Unavailable(CapabilityUnavailable::UnsupportedApi(None)),
        Err(e) if e.kind == NativeFsErrorKind::UnsupportedApi => {
            Capability::Unavailable(CapabilityUnavailable::UnsupportedApi(e.code))
        }
        Err(e) => return Err(e),
    };
    let mut name = [0; 256];
    let mut flags = 0;
    // SAFETY: bounded UTF16 filesystem-name output and flags, borrowed fd.
    if unsafe {
        GetVolumeInformationByHandleW(
            file.as_raw_handle(),
            null_mut(),
            0,
            null_mut(),
            null_mut(),
            &mut flags,
            name.as_mut_ptr(),
            name.len() as u32,
        )
    } == 0
    {
        return Err(last("GetVolumeInformationByHandleW"));
    }
    let end = name
        .iter()
        .position(|v| *v == 0)
        .ok_or_else(|| error("volume name", NativeFsErrorKind::MalformedData))?;
    Ok(DirectoryCapabilities {
        identity: identity(file)?.identity,
        filesystem: FilesystemKind::Windows {
            name: name[..end].to_vec(),
        },
        case_sensitive: sensitive,
        case_preserving: Capability::Known(flags & FILE_CASE_PRESERVED_NAMES != 0),
        existing_short_names: Capability::Unavailable(CapabilityUnavailable::NotQueried),
        linux_flags: Capability::Unavailable(CapabilityUnavailable::NotApplicable),
        absent_names: AbsentNameCapability::default(),
    })
}

pub(super) fn short_length(n: i8) -> Result<usize, NativeFsError> {
    if !(0..=24).contains(&n) || n % 2 != 0 {
        return Err(error(
            "short-name byte length",
            NativeFsErrorKind::MalformedData,
        ));
    }
    Ok(n as usize / 2)
}

type Spellings = Vec<(std::ffi::OsString, Option<std::ffi::OsString>)>;
fn enumerate(file: &File) -> Result<Spellings, NativeFsError> {
    let listing = relative(file, OsStr::new("."), true)?
        .ok_or_else(|| error("listing parent", NativeFsErrorKind::ChangedDuringQuery))?;
    let mut result = Vec::new();
    // u64 storage supplies the binding's eight-byte alignment; never cast Vec<u8>.
    let mut buffer = [0u64; 8192];
    for page in 0..128 {
        buffer.fill(0);
        // SAFETY: aligned 64KiB output, separately owned enumeration cursor.
        if unsafe {
            GetFileInformationByHandleEx(
                listing.as_raw_handle(),
                if page == 0 {
                    FileIdBothDirectoryRestartInfo
                } else {
                    FileIdBothDirectoryInfo
                },
                buffer.as_mut_ptr().cast(),
                size_of_val(&buffer) as u32,
            )
        } == 0
        {
            let e = last("directory enumeration");
            if e.code == Some(NativeCode::Win32(ERROR_NO_MORE_FILES)) {
                return Ok(result);
            }
            return Err(e);
        }
        // SAFETY: view of initialized storage; records are bounds-checked below.
        let bytes = unsafe {
            std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), size_of_val(&buffer))
        };
        parse_records(bytes, &mut result)?;
    }
    Err(error(
        "directory enumeration pages",
        NativeFsErrorKind::ResourceLimit,
    ))
}

pub(super) fn parse_records(bytes: &[u8], out: &mut Spellings) -> Result<(), NativeFsError> {
    let mut offset = 0;
    let header = offset_of!(FILE_ID_BOTH_DIR_INFO, FileName);
    loop {
        let bad = || error("directory record", NativeFsErrorKind::MalformedData);
        let record = bytes
            .get(offset..)
            .filter(|b| b.len() >= size_of::<FILE_ID_BOTH_DIR_INFO>())
            .ok_or_else(bad)?;
        // SAFETY: full fixed binding in bounds; unaligned read also serves test buffers.
        let r =
            unsafe { std::ptr::read_unaligned(record.as_ptr().cast::<FILE_ID_BOTH_DIR_INFO>()) };
        let next = r.NextEntryOffset as usize;
        let limit = if next == 0 { record.len() } else { next };
        if limit > record.len()
            || limit < header
            || (next != 0 && next % 8 != 0)
            || r.FileNameLength % 2 != 0
            || r.FileNameLength as usize > limit - header
        {
            return Err(bad());
        }
        let n = short_length(r.ShortNameLength)?;
        let units: Vec<u16> = record[header..header + r.FileNameLength as usize]
            .chunks_exact(2)
            .map(|v| u16::from_le_bytes([v[0], v[1]]))
            .collect();
        let long = std::ffi::OsString::from_wide(&units);
        if long != "." && long != ".." {
            // Stored native spellings bypass caller rules and go unchanged to lookup.
            let short = (n != 0).then(|| std::ffi::OsString::from_wide(&r.ShortName[..n]));
            out.push((long, short));
        }
        if next == 0 {
            return Ok(());
        }
        offset = offset.checked_add(next).ok_or_else(bad)?;
    }
}

pub(super) fn short_names(
    file: &File,
    name: &OsStr,
) -> Result<Capability<Vec<ExistingShortName>>, NativeFsError> {
    let target = match lookup(file, name)? {
        Lookup::Existing(o) => full_identity(&o.identity)?,
        Lookup::Missing => {
            return Err(error(
                "alias target missing",
                NativeFsErrorKind::ChangedDuringQuery,
            ))
        }
    };
    let records = match enumerate(file) {
        Ok(v) => v,
        Err(e) if e.kind == NativeFsErrorKind::UnsupportedApi => {
            return Ok(Capability::Unavailable(
                CapabilityUnavailable::UnsupportedApi(e.code),
            ))
        }
        Err(e) => return Err(e),
    };
    let mut result = Vec::new();
    for (long, short) in records {
        let observed = match lookup(file, &long) {
            Err(e)
                if matches!(
                    e.kind,
                    NativeFsErrorKind::LeafLinkOrReparse | NativeFsErrorKind::WrongKind
                ) =>
            {
                continue
            }
            other => other?,
        };
        if let Lookup::Existing(o) = observed {
            if full_identity(&o.identity)? != target {
                continue;
            }
            if let Some(s) = &short {
                if !matches!(lookup(file, s)?, Lookup::Existing(o) if full_identity(&o.identity)? == target)
                {
                    return Err(error(
                        "alias identity changed",
                        NativeFsErrorKind::ChangedDuringQuery,
                    ));
                }
            }
            result.push(ExistingShortName {
                long,
                short,
                identity: target,
            });
        } else {
            return Err(error(
                "enumerated name vanished",
                NativeFsErrorKind::ChangedDuringQuery,
            ));
        }
    }
    if result.is_empty() {
        return Err(error(
            "alias target vanished",
            NativeFsErrorKind::ChangedDuringQuery,
        ));
    }
    Ok(Capability::Known(result))
}
