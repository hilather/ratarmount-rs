//! No-panic `print!` / `println!` / `eprintln!` for this crate (#93 follow-up).
//!
//! `std`'s macros panic when the write fails (EPIPE once the terminal or pipe
//! is gone, EIO, ENOSPC). Offline `--commit-overlay` prints its plan, the
//! confirm prompt and `Committed successfully`; on-exit and offline commits
//! relay unexpected GNU tar stderr; `-w` create-if-missing prints
//! `created empty archive`. A panic there exits 101 partway through a commit.
//! The test drives create-if-missing, the plan, the prompt and both outcome
//! lines; the tar relay uses the same `eprintln!` shadow. These shadow `std`'s macros for every module
//! of this crate (declared first in `lib.rs`) with the same text and line
//! ending, and drop write errors. Unlike `std`'s macros they bypass libtest
//! output capture.

macro_rules! print {
    ($($arg:tt)*) => {{
        use ::std::io::Write as _;
        let _ = ::std::write!(::std::io::stdout().lock(), $($arg)*);
    }};
}

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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::fd::AsRawFd;

    const CHILD_ENV: &str = "RATARMOUNT_COMPOSITING_QUIET_CHILD";

    fn have_gnu_tar() -> bool {
        std::process::Command::new("tar")
            .arg("--version")
            .output()
            .is_ok_and(|o| String::from_utf8_lossy(&o.stdout).contains("GNU tar"))
    }

    /// Regression: #93 follow-up, an offline/on-exit commit (and `-w`
    /// create-if-missing) panicked (exit 101) partway through once its
    /// terminal or pipe was gone.
    #[test]
    fn commit_prints_survive_dead_stdout_and_stderr() {
        if std::env::var_os(CHILD_ENV).is_some() {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join("a.tar");
            let overlay = dir.path().join("ov");
            std::fs::create_dir(&overlay).unwrap();
            std::fs::write(overlay.join("new.txt"), b"hello").unwrap();
            // Live stdio so far (libtest printed its banner). Now widow both,
            // and give stdin an immediate EOF so the confirm prompt cancels.
            let (r1, w1) = std::io::pipe().unwrap();
            let (r2, w2) = std::io::pipe().unwrap();
            let (r0, w0) = std::io::pipe().unwrap();
            drop((r1, r2, w0));
            let ok = unsafe {
                libc::dup2(w1.as_raw_fd(), 1) == 1
                    && libc::dup2(w2.as_raw_fd(), 2) == 2
                    && libc::dup2(r0.as_raw_fd(), 0) == 0
            };
            if !ok {
                drop(dir);
                std::process::exit(3);
            }
            drop((w1, w2, r0));
            let code = child_body(&archive, &overlay);
            // `exit` skips destructors; remove the temp dir first.
            drop(dir);
            std::process::exit(code);
        }
        if !have_gnu_tar() {
            eprintln!("skip: GNU tar missing");
            return;
        }
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .env(CHILD_ENV, "1")
            .args([
                "quiet_print::tests::commit_prints_survive_dead_stdout_and_stderr",
                "--exact",
                "--nocapture",
            ])
            .output()
            .unwrap();
        if out.status.code() == Some(SOFT_SKIP) {
            eprintln!("skip: GNU tar commit failed on this host (prints before it survived)");
            return;
        }
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

    /// Child exit code when GNU tar itself failed (as `soft_skip_gnu_tar_commit`).
    const SOFT_SKIP: i32 = 7;

    /// Runs on dead stdout/stderr; returns the child's exit code.
    fn child_body(archive: &std::path::Path, overlay: &std::path::Path) -> i32 {
        // `-w` create-if-missing: `created empty archive` on stderr.
        if crate::maybe_create_empty_write_archive(archive).is_err() {
            return 4;
        }
        // Interactive path: plan lines, `print!` confirm prompt, `Canceled`.
        let ask = crate::CommitOverlayOptions {
            yes: false,
            debug: 1,
            ..Default::default()
        };
        if !matches!(
            crate::commit_overlay_raw_dir(overlay, archive, &ask).map(|done| done.committed),
            Ok(false)
        ) {
            return 5;
        }
        // `--yes` path: plan lines, GNU tar, `Committed successfully`.
        let yes = crate::CommitOverlayOptions { yes: true, ..ask };
        match crate::commit_overlay_raw_dir(overlay, archive, &yes).map(|done| done.committed) {
            Ok(true) => 0,
            Err(e)
                if {
                    let m = e.to_string();
                    m.contains("GNU tar")
                        || m.contains("lseek")
                        || m.contains("Value too large for defined data type")
                } =>
            {
                SOFT_SKIP
            }
            _ => 6,
        }
    }
}

#[cfg(test)]
mod hygiene_tests {
    /// Regression: the quiet printers must ignore write/writeln macros defined
    /// by their caller, for both empty and formatted arms.
    #[test]
    fn regression_quiet_print_macro_shadowing() {
        macro_rules! write {
            (@mark_used) => {};
            ($($arg:tt)*) => {
                compile_error!("quiet print resolved the caller's write macro");
            };
        }
        macro_rules! writeln {
            (@mark_used) => {};
            ($($arg:tt)*) => {
                compile_error!("quiet print resolved the caller's writeln macro");
            };
        }
        write!(@mark_used);
        writeln!(@mark_used);
        print!("{}", "");
        println!();
        println!("{}", "");
        eprintln!();
        eprintln!("{}", "");
    }
}
