//! No-panic `print!` / `println!` / `eprintln!` (#93, #102).
//!
//! `std`'s macros panic when the write fails (EPIPE once a launcher, `head`, or
//! a closed pipe drops the reader, and also EIO / ENOSPC). That exits 101 in
//! the middle of a mount, a foreground (`-f`) `-c` index, or a session-factory
//! message.
//!
//! These are `#[macro_export]`. A dependent crate shadows `std` for every one
//! of its modules with:
//!
//! ```rust,ignore
//! #[macro_use]
//! extern crate ratarmount_core;
//! ```
//!
//! A normal `use ratarmount_core::MountSource` does not import them. The text
//! and the trailing newline match `std`. Write errors are dropped. Unlike
//! `std`'s macros, these bypass libtest output capture.

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        let _ = ::std::write!(::std::io::stdout().lock(), $($arg)*);
    }};
}

#[macro_export]
macro_rules! println {
    () => {{
        use ::std::io::Write as _;
        let _ = ::std::writeln!(::std::io::stdout().lock());
    }};
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        let _ = ::std::writeln!(::std::io::stdout().lock(), $($arg)*);
    }};
}

#[macro_export]
macro_rules! eprintln {
    () => {{
        use ::std::io::Write as _;
        let _ = ::std::writeln!(::std::io::stderr().lock());
    }};
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        let _ = ::std::writeln!(::std::io::stderr().lock(), $($arg)*);
    }};
}
