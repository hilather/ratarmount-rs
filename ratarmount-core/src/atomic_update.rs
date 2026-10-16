//! Compare-exchange update loops for atomics.
//!
//! `Atomic*::fetch_update` is deprecated on current stable (renamed `try_update`),
//! and `try_update` does not exist on the workspace MSRV, so both spellings break
//! one of the CI toolchains under `-D warnings`.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

macro_rules! try_update_fn {
    ($name:ident, $atomic:ty, $int:ty) => {
        /// Applies `f` until it returns `None` or the compare-exchange succeeds.
        /// Returns the previous value on success, or the value `f` rejected.
        pub fn $name(
            atomic: &$atomic,
            set_order: Ordering,
            fetch_order: Ordering,
            mut f: impl FnMut($int) -> Option<$int>,
        ) -> Result<$int, $int> {
            let mut prev = atomic.load(fetch_order);
            loop {
                let next = f(prev).ok_or(prev)?;
                match atomic.compare_exchange_weak(prev, next, set_order, fetch_order) {
                    Ok(previous) => return Ok(previous),
                    Err(actual) => prev = actual,
                }
            }
        }
    };
}

try_update_fn!(try_update_u64, AtomicU64, u64);
try_update_fn!(try_update_usize, AtomicUsize, usize);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_update_applies_and_rejects() {
        let a = AtomicU64::new(3);
        assert_eq!(
            try_update_u64(&a, Ordering::AcqRel, Ordering::Acquire, |v| Some(v + 2)),
            Ok(3)
        );
        assert_eq!(a.load(Ordering::Acquire), 5);
        assert_eq!(
            try_update_u64(&a, Ordering::AcqRel, Ordering::Acquire, |_| None),
            Err(5)
        );
        let b = AtomicUsize::new(1);
        assert_eq!(
            try_update_usize(&b, Ordering::Relaxed, Ordering::Relaxed, |v| (v < 1)
                .then_some(v + 1)),
            Err(1)
        );
    }

    #[test]
    fn try_update_counts_exactly_under_contention() {
        let a = std::sync::Arc::new(AtomicU64::new(0));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let a = a.clone();
                std::thread::spawn(move || {
                    for _ in 0..1000 {
                        try_update_u64(&a, Ordering::AcqRel, Ordering::Acquire, |v| Some(v + 1))
                            .unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        assert_eq!(a.load(Ordering::Acquire), 8000);
    }
}
