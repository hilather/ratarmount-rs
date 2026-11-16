#![forbid(unused_macros)]
pub mod inner { unsafe extern "C" { pub fn acquire(path: *const std::ffi::c_char, flags: i32) -> i32; } }
pub mod c {
    #[cfg(windows)] pub use crate::inner::acquire;
    #[cfg(not(windows))] pub use std::mem::drop as acquire;
}
pub unsafe fn probe() -> i32 { unsafe { inner::acquire(c"fixture".as_ptr(), 0) } }
