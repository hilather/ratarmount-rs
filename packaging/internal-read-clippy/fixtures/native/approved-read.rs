// Regression: deny honors a reviewed per-site expectation.
pub fn reviewed_read() {
    #[expect(
        clippy::disallowed_methods,
        reason = "Regression: reviewed fixture input"
    )]
    let _ = std::fs::read("fixture");
}
