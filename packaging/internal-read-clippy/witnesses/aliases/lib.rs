#![forbid(unused_macros)]

// Regression: both configured spellings of the reexported core wrappers must
// resolve to the real definition, including its private defining module.
pub fn witnesses() {
    let _ = ratarmount_core::db_inodes::open_admitted;
    let _ = ratarmount_core::db_inodes::openat_admitted;
}
