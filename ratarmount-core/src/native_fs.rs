//! Observations of existing objects, not content IDs, leases or name comparators.
//! IDs may be reused after deletion. Reviewed Linux byte-exact absent-name rules
//! exist as an inactive capability with no consumer; other platforms stay pending
//! (ADR-1). There is no Boolean or comparison-key outcome, and a rule is neither an
//! acquisition nor an admission.

use std::ffi::OsString;

/// Observations only, never durable or persistent keys: btrfs devices are
/// per-mount anonymous devices, and IDs can be reused.
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
    /// A reviewed query failed with this native code; it is not a filesystem fact.
    QueryFailed(NativeCode),
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
    /// Its rule is reviewed against upstream source only; native qualification is
    /// pending, and any activation needs native evidence.
    Btrfs,
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

/// A reviewed rule for names that do not exist yet. Inactive: nothing consumes it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReviewedNameRule {
    /// Names match only as identical bytes, each at most `name_max` bytes.
    LinuxByteExact {
        filesystem: LinuxFilesystem,
        name_max: u32,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NameEquivalenceUnavailable {
    Casefold,
    Uninspectable(CapabilityUnavailable),
    Unreviewed(CapabilityUnavailable),
}

/// Deliberately has no Boolean or comparison-key outcome. Linux reports reviewed
/// byte-exact rules as an inactive capability; other platforms stay pending (ADR-1).
/// A rule is not an acquisition or an admission.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbsentNameCapability {
    Pending { decision: AbsentNameDecision },
    Reviewed(ReviewedNameRule),
    Unavailable(NameEquivalenceUnavailable),
}

impl Default for AbsentNameCapability {
    fn default() -> Self {
        Self::Pending {
            decision: AbsentNameDecision::Adr1,
        }
    }
}

/// Members of a protected family, each the requested main name plus a literal suffix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FamilyRole {
    Main,
    Wal,
    Shm,
    Journal,
    InstallState,
}

/// A name-only decision over two complete families. Nothing is looked up or created.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FamilyComparison {
    Disjoint {
        rule: ReviewedNameRule,
    },
    Overlapping {
        rule: ReviewedNameRule,
        a: FamilyRole,
        b: FamilyRole,
    },
    Unavailable(NameEquivalenceUnavailable),
    Pending {
        decision: AbsentNameDecision,
    },
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
    /// The reviewed rule says a derived family member cannot be represented. This is
    /// a name-only decision with no native code; a kernel refusal of an actual call
    /// stays `Io` with `ENAMETOOLONG`.
    NameTooLong,
    /// A requested main name ends with the reserved install-state suffix.
    ReservedName,
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
        eprintln!("A1_GROUP_COMPLETE core.identity_domains");
        eprintln!("A1_TEST_COMPLETE native_fs::tests::regression_235_part2_a1_identity_domains");
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
        eprintln!("A1_GROUP_COMPLETE core.absent_pending");
        eprintln!(
            "A1_TEST_COMPLETE native_fs::tests::regression_235_part2_a1_absent_capability_pending"
        );
    }
}
