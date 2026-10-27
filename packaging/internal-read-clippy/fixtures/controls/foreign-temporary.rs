#![forbid(unused_macros)]
unsafe extern "C" {
    #[link_name = "mkstemp"] fn acquire_one(template: *mut std::ffi::c_char) -> i32;
    #[link_name = "mkostemp"] fn acquire_two(template: *mut std::ffi::c_char, flags: i32) -> i32;
}
pub unsafe fn probe(p: *mut std::ffi::c_char) { unsafe { let _ = acquire_one(p); let _ = acquire_two(p, 0); } }
