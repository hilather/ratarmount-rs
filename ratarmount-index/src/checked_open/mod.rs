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
//!   the module anchor and SQLite live in one non-executable image.
//!
//! A database open never installs anything. [`installed`] reports the terminal
//! result or why nothing was installed. The installed wrappers currently
//! forward every call unchanged.
//!
//! The constructor calls `sqlite3_initialize()` in every binary that reaches
//! `checked_open` ([`installed`] references the constructor, so the linker
//! keeps it; a binary that never names this module may run no constructor).
//! No code may call `sqlite3_config` (rusqlite's `config_log` included) or
//! `sqlite3_shutdown` afterwards; a test pins that.

mod host;
// Unverified targets keep the state machine (and its tests) but never call it.
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

pub use host::{HostFailure, ImageIdentity};
pub use install::{
    constructor_observation, install_private_instance, installed, CtorObservation, InstallFailure,
    InstallStatus, InstallWhy, Witness,
};
