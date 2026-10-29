//! Test-only coordination between child spawning and close-based lock probes.
//!
//! A child inherits open lock descriptions until exec or exit, even with
//! CLOEXEC. Regression: #242 post-drop lock probes could observe another
//! test's child retaining their lock. Take `exclusive` before opening the
//! holder and keep it through the final probe; spawning tests take `spawning`
//! until exec/exit (or for the whole test, including cleanup).
//!
//! Guards must not be nested: a queued writer can block a recursive read.

use std::sync::{PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard};

static CHILD_PROCESSES: RwLock<()> = RwLock::new(());

/// Permit child spawning concurrently with other spawning tests.
pub fn spawning() -> RwLockReadGuard<'static, ()> {
    CHILD_PROCESSES
        .read()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Exclude child spawning throughout a close-based lock test.
pub fn exclusive() -> RwLockWriteGuard<'static, ()> {
    CHILD_PROCESSES
        .write()
        .unwrap_or_else(PoisonError::into_inner)
}
