//! No-panic `println!` / `eprintln!` for the ratarmount binary (#93 follow-up).
//!
//! `std`'s macros panic when the write fails (EPIPE once a launcher or `head`
//! closes the pipe, EIO, ENOSPC), which exits 101 in the middle of a mount,
//! a foreground (`-f`) session or an on-exit commit. These shadow them for
//! every module of this crate (declared first in `main.rs`) with the same
//! text and line ending, and drop write errors. Exit codes are unchanged:
//! error paths call `std::process::exit` themselves.
//!
//! `ratarmount-compositing` has its own crate-wide copy (commit plan, confirm
//! prompt, GNU tar stderr relay and create-if-missing prints). Not covered: the format crates' progress lines
//! and session factory messages still use `std` and can panic if the reader
//! goes away after startup; `neutralize_dead_stdio` covers a reader that is
//! already gone.
//!
//! Unlike `std`'s macros these bypass libtest output capture.

macro_rules! println {
    () => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout().lock());
    }};
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stdout().lock(), $($arg)*);
    }};
}

macro_rules! eprintln {
    () => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr().lock());
    }};
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr().lock(), $($arg)*);
    }};
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::fd::AsRawFd;

    const CHILD_ENV: &str = "RATARMOUNT_QUIET_PRINT_CHILD";

    /// Regression: #93 follow-up, a foreground print after startup panicked
    /// (exit 101) once the reader of stdout/stderr went away.
    #[test]
    fn quiet_print_survives_dead_stdout_and_stderr() {
        if std::env::var_os(CHILD_ENV).is_some() {
            // Live stdio so far (libtest printed its banner). Now widow both.
            let (r1, w1) = std::io::pipe().unwrap();
            let (r2, w2) = std::io::pipe().unwrap();
            drop(r1);
            drop(r2);
            let ok =
                unsafe { libc::dup2(w1.as_raw_fd(), 1) == 1 && libc::dup2(w2.as_raw_fd(), 2) == 2 };
            if !ok {
                std::process::exit(3);
            }
            drop((w1, w2));
            // Real foreground printers in main.rs: they only survive if the
            // `#[macro_use]` shadow reaches call sites outside this module.
            crate::print_features();
            crate::print_oss_attributions(true);
            println!();
            println!("quiet print {}", 1);
            eprintln!();
            eprintln!("quiet eprint {}", 2);
            // Skip libtest's result line, which would hit the dead stdout.
            std::process::exit(0);
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .env(CHILD_ENV, "1")
            .args([
                "quiet_print::tests::quiet_print_survives_dead_stdout_and_stderr",
                "--exact",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert_eq!(
            out.status.code(),
            Some(0),
            "child stderr: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("running 1 test"),
            "child must have run the test"
        );
    }
}
