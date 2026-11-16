#![forbid(unused_macros)]
pub mod io { pub use std::fs::read as acquire; }
#[cfg(windows)]
pub fn probe() { let _ = crate::io::acquire("fixture"); }
