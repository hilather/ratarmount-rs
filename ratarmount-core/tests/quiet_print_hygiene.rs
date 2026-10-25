#![forbid(unused_macros)]

/// Regression: caller-local write/writeln macros must not capture the exported
/// quiet printers' internal writes. Both empty and formatted arms must compile.
#[test]
fn regression_downstream_quiet_print_macro_shadowing() {
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
    ratarmount_core::print!("{}", "");
    ratarmount_core::println!();
    ratarmount_core::println!("{}", "");
    ratarmount_core::eprintln!();
    ratarmount_core::eprintln!("{}", "");
}
