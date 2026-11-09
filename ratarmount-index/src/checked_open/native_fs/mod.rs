//! Native existing-object queries plus one name-only family query. No namespace
//! writes, accepted comparator, acquisition provenance, lease or durability guarantee.
//! `compare_existing` decides existing objects by full IDs and never consumes the
//! absent-name rule; `compare_families` applies the reviewed rule to names only,
//! with no lookup, open or create, and nothing uses it yet.
//! Parent rechecks bound observed drift; they cannot detect every child replacement
//! or ID reuse and do not provide an atomic snapshot. Unavailable mode facts stay unknown.

use ratarmount_core::native_fs::*;
use std::ffi::OsStr;
use std::fs::File;
use std::path::Path;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
use linux as imp;

fn error(operation: &'static str, kind: NativeFsErrorKind) -> NativeFsError {
    NativeFsError {
        operation,
        kind,
        code: None,
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn errno(operation: &'static str, code: i32) -> NativeFsError {
    let kind = match code {
        libc::EACCES | libc::EPERM => NativeFsErrorKind::Access,
        libc::ENOTDIR => NativeFsErrorKind::WrongKind,
        libc::ELOOP => NativeFsErrorKind::LeafLinkOrReparse,
        libc::ENOTSUP | libc::ENOSYS => NativeFsErrorKind::UnsupportedApi,
        _ => NativeFsErrorKind::Io,
    };
    NativeFsError {
        operation,
        kind,
        code: Some(NativeCode::Errno(code)),
    }
}

/// Borrows the file without duplicating/closing it; attests no acquisition provenance.
pub fn identity_from_file(file: &File) -> Result<ExistingObject, NativeFsError> {
    imp::identity(file)
}

/// Owns directory handles only. Parent aliases are followed; leaves are not.
pub struct NativeDirectory {
    file: File,
}

impl NativeDirectory {
    pub fn open_parent(path: &Path) -> Result<Self, NativeFsError> {
        let file = imp::open_parent(path)?;
        if identity_from_file(&file)?.kind != ObjectKind::Directory {
            return Err(error("open_parent", NativeFsErrorKind::WrongKind));
        }
        Ok(Self { file })
    }

    pub fn capabilities(&self) -> Result<DirectoryCapabilities, NativeFsError> {
        self.query(|| imp::capabilities(&self.file))
    }

    pub fn lookup_existing(&self, name: &OsStr) -> Result<Lookup, NativeFsError> {
        validate(name)?;
        self.query(|| imp::lookup(&self.file, name))
    }

    pub fn compare_existing(
        &self,
        a: &OsStr,
        b: &OsStr,
    ) -> Result<ExistingNameComparison, NativeFsError> {
        validate(a)?;
        validate(b)?;
        self.query(|| {
            Ok(compare(
                imp::lookup(&self.file, a)?,
                imp::lookup(&self.file, b)?,
            ))
        })
    }

    pub fn existing_short_names(
        &self,
        name: &OsStr,
    ) -> Result<Capability<Vec<ExistingShortName>>, NativeFsError> {
        validate(name)?;
        self.query(|| imp::short_names(&self.file, name))
    }

    /// Name-only: applies the parent's reviewed rule to both complete families.
    pub fn compare_families(
        &self,
        a: &OsStr,
        b: &OsStr,
    ) -> Result<FamilyComparison, NativeFsError> {
        families(
            a,
            b,
            || imp::snapshot(&self.file),
            || imp::capabilities(&self.file),
        )
    }

    fn query<T>(
        &self,
        action: impl FnMut() -> Result<T, NativeFsError>,
    ) -> Result<T, NativeFsError> {
        stable(|| imp::snapshot(&self.file), action)
    }
}

fn stable<T>(
    mut snapshot: impl FnMut() -> Result<DirectoryCapabilities, NativeFsError>,
    mut action: impl FnMut() -> Result<T, NativeFsError>,
) -> Result<T, NativeFsError> {
    for _ in 0..3 {
        let before = snapshot()?;
        full_identity(&before.identity)?;
        let value = action()?;
        let after = snapshot()?;
        full_identity(&after.identity)?;
        if before == after {
            return Ok(value);
        }
    }
    Err(error(
        "parent revalidation",
        NativeFsErrorKind::ChangedDuringQuery,
    ))
}

/// Reservation, then a decision only when `before`, the decided capabilities and
/// `after` are all equal.
fn families(
    a: &OsStr,
    b: &OsStr,
    mut snapshot: impl FnMut() -> Result<DirectoryCapabilities, NativeFsError>,
    mut caps: impl FnMut() -> Result<DirectoryCapabilities, NativeFsError>,
) -> Result<FamilyComparison, NativeFsError> {
    validate(a)?;
    validate(b)?;
    reserved(a, b)?;
    let before = std::cell::RefCell::new(None);
    stable(
        || {
            let value = snapshot()?;
            *before.borrow_mut() = Some(value.clone());
            Ok(value)
        },
        || {
            let value = caps()?;
            if before.borrow().as_ref() != Some(&value) {
                return Err(error(
                    "family capabilities",
                    NativeFsErrorKind::ChangedDuringQuery,
                ));
            }
            decide(value.absent_names, a, b)
        },
    )
}

const INSTALL_STATE: &[u8] = b".ratarmount-install-state";
const FAMILY: [(FamilyRole, &[u8]); 5] = [
    (FamilyRole::Main, b""),
    (FamilyRole::Wal, b"-wal"),
    (FamilyRole::Shm, b"-shm"),
    (FamilyRole::Journal, b"-journal"),
    (FamilyRole::InstallState, INSTALL_STATE),
];

/// A requested main with a nonempty stem may not end with the install-state suffix.
/// Only the suffix is compared ASCII case-insensitively; no other name is folded.
fn reserved(a: &OsStr, b: &OsStr) -> Result<(), NativeFsError> {
    for (name, operation) in [(a, "family a reserved"), (b, "family b reserved")] {
        let name = name.as_encoded_bytes();
        if name
            .len()
            .checked_sub(INSTALL_STATE.len())
            .is_some_and(|stem| stem > 0 && name[stem..].eq_ignore_ascii_case(INSTALL_STATE))
        {
            return Err(error(operation, NativeFsErrorKind::ReservedName));
        }
    }
    Ok(())
}

/// Literal suffix bytes appended to the untouched requested names, length checked
/// before any byte comparison.
fn decide(
    absent: AbsentNameCapability,
    a: &OsStr,
    b: &OsStr,
) -> Result<FamilyComparison, NativeFsError> {
    let rule = match absent {
        AbsentNameCapability::Reviewed(rule) => rule,
        AbsentNameCapability::Unavailable(cause) => {
            return Ok(FamilyComparison::Unavailable(cause))
        }
        AbsentNameCapability::Pending { decision } => {
            return Ok(FamilyComparison::Pending { decision });
        }
    };
    let ReviewedNameRule::LinuxByteExact { name_max, .. } = rule;
    let family = |name: &OsStr, operation: &'static str| {
        FAMILY
            .iter()
            .map(|(role, suffix)| {
                let member = [name.as_encoded_bytes(), *suffix].concat();
                if u32::try_from(member.len()).is_ok_and(|length| length <= name_max) {
                    Ok((*role, member))
                } else {
                    Err(error(operation, NativeFsErrorKind::NameTooLong))
                }
            })
            .collect::<Result<Vec<_>, _>>()
    };
    let a = family(a, "family a length")?;
    let b = family(b, "family b length")?;
    for (a_role, a_member) in &a {
        for (b_role, b_member) in &b {
            if a_member == b_member {
                return Ok(FamilyComparison::Overlapping {
                    rule,
                    a: *a_role,
                    b: *b_role,
                });
            }
        }
    }
    Ok(FamilyComparison::Disjoint { rule })
}

fn full_identity(value: &Capability<NativeIdentity>) -> Result<NativeIdentity, NativeFsError> {
    match value {
        Capability::Known(id) => Ok(*id),
        Capability::Unavailable(cause) => Err(NativeFsError {
            operation: "full identity",
            kind: NativeFsErrorKind::FullIdentityUnavailable,
            code: match cause {
                CapabilityUnavailable::FullIdentityUnavailable(code) => *code,
                _ => None,
            },
        }),
    }
}

fn compare(a: Lookup, b: Lookup) -> ExistingNameComparison {
    let reason = match (&a, &b) {
        (Lookup::Existing(a), Lookup::Existing(b)) => match (&a.identity, &b.identity) {
            (Capability::Known(x), Capability::Known(y)) => {
                if std::mem::discriminant(x) != std::mem::discriminant(y) {
                    UndecidedReason::IncomparableDomains
                } else if x == y {
                    return ExistingNameComparison::SameObject {
                        a: Lookup::Existing(a.clone()),
                        b: Lookup::Existing(b.clone()),
                    };
                } else {
                    return ExistingNameComparison::DifferentObjects {
                        a: Lookup::Existing(a.clone()),
                        b: Lookup::Existing(b.clone()),
                    };
                }
            }
            _ => UndecidedReason::FullIdentityUnavailable,
        },
        _ => UndecidedReason::AbsentName(AbsentNameDecision::Adr1),
    };
    ExistingNameComparison::Undecided { a, b, reason }
}

fn validate(name: &OsStr) -> Result<(), NativeFsError> {
    let _ = name; // Other targets dispatch to the typed unsupported backend.
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        let b = name.as_bytes();
        if b.is_empty() || b == b"." || b == b".." || b.contains(&0) || b.contains(&b'/') {
            return Err(error("component", NativeFsErrorKind::InvalidComponent));
        }
    }
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod imp {
    use super::*;
    pub(super) use capabilities as snapshot;
    fn unavailable<T>() -> Result<T, NativeFsError> {
        Err(error(
            "native filesystem",
            NativeFsErrorKind::UnsupportedPlatform,
        ))
    }
    pub(super) fn identity(_: &File) -> Result<ExistingObject, NativeFsError> {
        unavailable()
    }
    pub(super) fn open_parent(_: &Path) -> Result<File, NativeFsError> {
        unavailable()
    }
    pub(super) fn capabilities(_: &File) -> Result<DirectoryCapabilities, NativeFsError> {
        unavailable()
    }
    pub(super) fn lookup(_: &File, _: &OsStr) -> Result<Lookup, NativeFsError> {
        unavailable()
    }
    pub(super) fn short_names(
        _: &File,
        _: &OsStr,
    ) -> Result<Capability<Vec<ExistingShortName>>, NativeFsError> {
        unavailable()
    }
}

#[cfg(test)]
mod tests;
