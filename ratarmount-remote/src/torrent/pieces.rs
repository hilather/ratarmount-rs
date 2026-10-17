//! Small verified working set and per-piece single-flight fetches.
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::sync::{Arc, Condvar, Mutex};

use super::Piece;

type Bytes = Arc<Vec<u8>>;
type Outcome = Result<Bytes, (io::ErrorKind, String)>;

pub(super) struct Flight {
    result: Mutex<Option<Outcome>>,
    ready: Condvar,
    pub allow_swarm: bool,
    #[cfg(test)]
    pub waiting: std::sync::atomic::AtomicBool,
}
impl Flight {
    pub fn new(allow_swarm: bool) -> Self {
        Self {
            result: Mutex::new(None),
            ready: Condvar::new(),
            allow_swarm,
            #[cfg(test)]
            waiting: std::sync::atomic::AtomicBool::new(false),
        }
    }
    pub fn wait(&self) -> io::Result<Bytes> {
        #[cfg(test)]
        self.waiting
            .store(true, std::sync::atomic::Ordering::Release);
        let mut value = self.result.lock().unwrap_or_else(|e| e.into_inner());
        while value.is_none() {
            value = self.ready.wait(value).unwrap_or_else(|e| e.into_inner());
        }
        value
            .as_ref()
            .unwrap()
            .clone()
            .map_err(|(kind, message)| io::Error::new(kind, message))
    }
    pub fn finish(&self, value: &io::Result<Bytes>) {
        *self.result.lock().unwrap_or_else(|e| e.into_inner()) = Some(
            value
                .as_ref()
                .map(Arc::clone)
                .map_err(|e| (e.kind(), e.to_string())),
        );
        self.ready.notify_all();
    }
}

#[derive(Default)]
pub(super) struct Pieces {
    values: VecDeque<(Piece, Bytes)>,
    bytes: usize,
    pub flights: BTreeMap<Piece, Arc<Flight>>,
}
impl Pieces {
    pub fn get(&mut self, key: Piece) -> Option<Bytes> {
        let index = self.values.iter().position(|(k, _)| *k == key)?;
        let entry = self.values.remove(index)?;
        let bytes = entry.1.clone();
        self.values.push_back(entry);
        Some(bytes)
    }
    pub fn insert(&mut self, key: Piece, bytes: Bytes) {
        const CAP: usize = 256 * 1024 * 1024;
        if bytes.len() > CAP {
            return;
        }
        if let Some(index) = self
            .values
            .iter()
            .position(|(existing, _)| *existing == key)
        {
            if let Some((_, old)) = self.values.remove(index) {
                self.bytes -= old.len();
            }
        }
        while self.values.len() >= 4 || self.bytes + bytes.len() > CAP {
            if let Some((_, bytes)) = self.values.pop_front() {
                self.bytes -= bytes.len();
            }
        }
        self.bytes += bytes.len();
        self.values.push_back((key, bytes));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    /// Regression: concurrent seed/cache checks duplicated a piece and inflated the working-set byte count.
    #[test]
    fn regression_seed_cache_insert_replaces_existing_piece() {
        let key = Piece {
            file: None,
            index: 0,
        };
        let mut pieces = Pieces::default();
        pieces.insert(key, Arc::new(vec![1; 7]));
        pieces.insert(key, Arc::new(vec![2; 3]));
        assert_eq!(pieces.bytes, 3);
        assert_eq!(pieces.values.len(), 1);
        assert_eq!(pieces.get(key).unwrap().as_slice(), &[2; 3]);
    }
}
