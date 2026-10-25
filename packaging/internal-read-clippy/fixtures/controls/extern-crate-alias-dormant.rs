#![forbid(unused_macros)]
pub extern crate std as io;
pub use io::fs::read as acquire;
#[macro_export]
macro_rules! dormant { () => { $crate::acquire("fixture") }; }
