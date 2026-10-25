#![forbid(unused_macros)]
macro_rules! guarded { ($guard:meta, $expr:expr) => { #[$guard] pub fn probe() { let _ = $expr; } }; }
guarded!(cfg(not(clippy)), std::fs::read("fixture"));
