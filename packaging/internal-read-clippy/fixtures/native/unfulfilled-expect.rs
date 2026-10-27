// Regression: removing an approved operation must fail with the unfulfilled diagnostic.
pub fn removed_read() {
    #[expect(
        clippy::disallowed_methods,
        reason = "Regression: reviewed operation removed"
    )]
    let _ = 1;
}
