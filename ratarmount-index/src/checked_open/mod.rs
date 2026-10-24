//! Checked SQLite acquisition (#151).
//!
//! Overlay databases must be opened so that the inode SQLite actually acquired
//! is known, not a pathname observed before or after the open. The facility
//! wraps the `open` and `stat` system calls of SQLite's `"unix"` VFS (one
//! syscall table serves every `unix-*` VFS) through `xSetSystemCall`.
//!
//! That setter writes a plain, unsynchronized C pointer, so the wrappers are
//! installed only while nothing else can use this SQLite instance:
//!
//! * by a load-time constructor, when the process has exactly one thread
//!   ([`InstallWhy::SingleThread`]); or
//! * by [`install_private_instance`], the first operation of an artifact whose
//!   SQLite is private to it and not yet reachable
//!   ([`InstallWhy::PrivateInstance`]), after a loader check that this module,
//!   the module anchor and SQLite live in one non-executable image and (on
//!   Linux) that image exports no `sqlite3*` dynamic symbol.
//!
//! A database open never installs anything. [`installed`] reports the terminal
//! result or why nothing was installed. The installed wrappers forward every
//! call unchanged unless the calling thread is inside [`open_checked`], or
//! the process has latched an overlay database ([`latch_overlay_nocreate`])
//! and this `open` would create that file or its `-wal` / `-shm`.
//! [`open_checked`] refuses with [`AcquireError::Unavailable`] when nothing
//! is installed.
//!
//! The constructor runs in every binary that reaches `checked_open`
//! ([`installed`] references the constructor, so the linker keeps it; a binary
//! that never names this module may run no constructor). Only a constructor
//! that saw exactly one thread calls `sqlite3_initialize()`; an abstaining one
//! does not touch SQLite (a private-instance installation calls it then).
//! No code may call `sqlite3_config` (rusqlite's `config_log` included) or
//! `sqlite3_shutdown` afterwards; a test pins that.

// Unverified targets keep the state machines (and their tests) but never
// call them: the acquisition evidence is only fed by the installed wrappers.
#[cfg_attr(
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_endian = "little",
        any(all(target_os = "linux", target_env = "gnu"), target_os = "macos")
    )),
    allow(dead_code)
)]
mod acquire;
// The live image is read only on 64-bit little-endian Linux glibc; elsewhere
// the parser is exercised by its synthetic tests alone.
#[cfg_attr(
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_endian = "little",
        target_os = "linux",
        target_env = "gnu"
    )),
    allow(dead_code)
)]
mod elf;
mod host;
#[cfg_attr(
    not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_endian = "little",
        any(all(target_os = "linux", target_env = "gnu"), target_os = "macos")
    )),
    allow(dead_code)
)]
mod install;
mod nocreate;

/// Thread-local seams inside the acquisition, for other crates' tests
/// (`test-hooks` feature; never in a normal build).
#[cfg(all(
    feature = "test-hooks",
    target_pointer_width = "64",
    any(target_arch = "x86_64", target_arch = "aarch64"),
    target_endian = "little",
    any(all(target_os = "linux", target_env = "gnu"), target_os = "macos")
))]
pub use acquire::imp::seams as test_seams;
pub use acquire::{
    immutable_uri, open_checked, AcquireError, Acquired, DbId, Expect, NameMode, Refusal,
    Verification,
};
pub use elf::{ElfError, SymbolName};

/// Whether this thread is inside [`open_checked`] (a managed byte read there
/// would be taken for SQLite's own `open`).
#[cfg_attr(not(unix), allow(dead_code))]
pub(crate) fn thread_is_acquiring() -> bool {
    #[cfg(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_endian = "little",
        any(all(target_os = "linux", target_env = "gnu"), target_os = "macos")
    ))]
    {
        acquire::imp::thread_is_acquiring()
    }
    #[cfg(not(all(
        target_pointer_width = "64",
        any(target_arch = "x86_64", target_arch = "aarch64"),
        target_endian = "little",
        any(all(target_os = "linux", target_env = "gnu"), target_os = "macos")
    )))]
    {
        false
    }
}
pub use host::{HostFailure, ImageIdentity};
pub use install::{
    constructor_observation, install_private_instance, installed, CtorObservation, InstallFailure,
    InstallStatus, InstallWhy, Witness, VERIFIED_TARGET,
};
pub use nocreate::latch_overlay_nocreate;
