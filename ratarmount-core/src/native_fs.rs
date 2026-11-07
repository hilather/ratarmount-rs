//! Observations of existing objects, not content IDs, leases or name comparators.
//! IDs may be reused after deletion. No absent-name rule has been accepted (ADR-1).

use std::ffi::OsString;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeIdentity {
    Linux {
        device: u64,
        inode: u64,
    },
    MacOs {
        volume: [i32; 2],
        file_id: u64,
    },
    Windows {
        volume_serial: u64,
        file_id: [u8; 16],
    },
}

/// Legacy, potentially truncated and link-specific. Never identity authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MacObjIdObservation {
    pub object: u32,
    pub generation: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeCode {
    Errno(i32),
    Win32(u32),
    NtStatus(i32),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityUnavailable {
    UnknownFilesystem,
    UnreviewedFilesystem,
    UnsupportedAbi,
    UnsupportedApi(Option<NativeCode>),
    FullIdentityUnavailable(Option<NativeCode>),
    NotApplicable,
    NotQueried,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Capability<T> {
    Known(T),
    Unavailable(CapabilityUnavailable),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObjectKind {
    File,
    Directory,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExistingObject {
    pub identity: Capability<NativeIdentity>,
    pub kind: ObjectKind,
    pub mac_objid: Option<MacObjIdObservation>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Lookup {
    Existing(ExistingObject),
    Missing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinuxFilesystem {
    Tmpfs,
    /// Shared ext2/3/4 magic; this alone does not establish ext4.
    ExtFamily,
    RecognizedUnreviewed,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FilesystemKind {
    Linux { magic: u32, kind: LinuxFilesystem },
    MacOs { name: Vec<u8> },
    Windows { name: Vec<u16> },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaseMode {
    Sensitive,
    Insensitive,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbsentNameDecision {
    Adr1,
}

/// Deliberately has no supported/Boolean/comparison-key outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbsentNameCapability {
    Pending { decision: AbsentNameDecision },
}

impl Default for AbsentNameCapability {
    fn default() -> Self {
        Self::Pending {
            decision: AbsentNameDecision::Adr1,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryCapabilities {
    pub identity: Capability<NativeIdentity>,
    pub filesystem: FilesystemKind,
    pub case_sensitive: Capability<CaseMode>,
    pub case_preserving: Capability<bool>,
    pub existing_short_names: Capability<()>,
    pub linux_flags: Capability<u32>,
    pub absent_names: AbsentNameCapability,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UndecidedReason {
    AbsentName(AbsentNameDecision),
    FullIdentityUnavailable,
    IncomparableDomains,
}

/// Both observations are retained, including the causes of unavailable IDs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExistingNameComparison {
    SameObject {
        a: Lookup,
        b: Lookup,
    },
    DifferentObjects {
        a: Lookup,
        b: Lookup,
    },
    Undecided {
        a: Lookup,
        b: Lookup,
        reason: UndecidedReason,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExistingShortName {
    pub long: OsString,
    pub short: Option<OsString>,
    pub identity: NativeIdentity,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeFsErrorKind {
    InvalidComponent,
    WrongKind,
    LeafLinkOrReparse,
    Access,
    Busy,
    UnsupportedAbi,
    UnsupportedPlatform,
    UnsupportedApi,
    FullIdentityUnavailable,
    MalformedData,
    ChangedDuringQuery,
    ResourceLimit,
    Io,
}

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[error("native filesystem {operation}: {kind:?} ({code:?})")]
pub struct NativeFsError {
    pub operation: &'static str,
    pub kind: NativeFsErrorKind,
    pub code: Option<NativeCode>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: full object/volume/domain IDs must not collapse to content or low bits.
    #[test]
    fn regression_235_part2_a1_identity_domains() {
        let a = NativeIdentity::MacOs {
            volume: [1, 2],
            file_id: 0x1_0000_002a,
        };
        assert_ne!(
            a,
            NativeIdentity::MacOs {
                volume: [1, 2],
                file_id: 0x2_0000_002a
            }
        );
        assert_ne!(
            a,
            NativeIdentity::MacOs {
                volume: [2, 1],
                file_id: 0x1_0000_002a
            }
        );
        assert_ne!(
            a,
            NativeIdentity::Linux {
                device: 1,
                inode: 0x1_0000_002a
            }
        );
        assert_ne!(
            NativeIdentity::Windows {
                volume_serial: 1,
                file_id: [42; 16]
            },
            NativeIdentity::Windows {
                volume_serial: 2,
                file_id: [42; 16]
            }
        );
    }

    /// Regression: unresolved absent-name rules are pending, never platform support.
    #[test]
    fn regression_235_part2_a1_absent_capability_pending() {
        assert_eq!(
            AbsentNameCapability::default(),
            AbsentNameCapability::Pending {
                decision: AbsentNameDecision::Adr1
            }
        );
    }
}
