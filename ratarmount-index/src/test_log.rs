//! Test-only `log` capture shared by this crate's unit tests.
//!
//! The logger is process-global and can be installed once, so every test
//! module that inspects log output goes through [`capture_logs`]. Messages
//! are kept per thread: a test sees only what its own thread logged.

use std::cell::RefCell;

thread_local! {
    pub(crate) static MESSAGES: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

struct TestLog;

impl log::Log for TestLog {
    fn enabled(&self, _: &log::Metadata<'_>) -> bool {
        true
    }
    fn log(&self, record: &log::Record<'_>) {
        MESSAGES.with(|m| m.borrow_mut().push(record.args().to_string()));
    }
    fn flush(&self) {}
}

/// Install the capture logger (once) and clear this thread's messages.
pub(crate) fn capture_logs() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        log::set_logger(&TestLog).unwrap();
        log::set_max_level(log::LevelFilter::Debug);
    });
    MESSAGES.with(|m| m.borrow_mut().clear());
}

/// Messages this thread logged since its last [`capture_logs`].
pub(crate) fn messages() -> Vec<String> {
    MESSAGES.with(|m| m.borrow().clone())
}
