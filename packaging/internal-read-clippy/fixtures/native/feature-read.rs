// Regression: an all-features-only check misses the no-backend acquisition.
#[cfg(not(feature = "backend"))]
pub fn unreviewed_without_backend() {
    let _ = std::fs::read("fixture");
}
