//! Per-fileid reader LRU + fill-loop / readahead (copied from FUSE).
//!
//! NFSv3 has no open/close. A live `ArchiveRead` per fileid is required so
//! gzip / solid 7z `cat` does not reopen from 0 on every READ.

use std::collections::HashMap;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use ratarmount_core::{FileInfo, MountSource};

use crate::inode::InodeTable;

/// Hard cap on live member readers (same ballpark as 7z window LRU).
pub const DEFAULT_READER_SLOTS: usize = 64;

/// Fill `buf` by looping `Read::read` until full or true EOF.
///
/// A short `Read::read` from gzip/rapidgzip is **not** EOF. NFS READ treats
/// a short reply as end-of-file — same contract as FUSE.
pub fn fill_read_for_nfs(r: &mut dyn std::io::Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match std::io::Read::read(r, &mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

#[derive(Clone, Debug, Default)]
struct ReadAheadWindow {
    start: u64,
    data: Vec<u8>,
    hit_eof: bool,
}

impl ReadAheadWindow {
    fn end_offset(&self) -> u64 {
        self.start.saturating_add(self.data.len() as u64)
    }

    fn try_serve(&self, offset: u64, size: usize) -> Option<Vec<u8>> {
        if size == 0 {
            return Some(Vec::new());
        }
        if self.hit_eof && offset >= self.end_offset() {
            return Some(Vec::new());
        }
        if offset < self.start {
            return None;
        }
        let i = match usize::try_from(offset - self.start) {
            Ok(i) => i,
            Err(_) => return None,
        };
        if i >= self.data.len() {
            return None;
        }
        let end = i.saturating_add(size).min(self.data.len());
        let slice = &self.data[i..end];
        if slice.len() == size {
            return Some(slice.to_vec());
        }
        if self.hit_eof && end == self.data.len() {
            return Some(slice.to_vec());
        }
        None
    }
}

#[derive(Clone, Debug, Default)]
struct ReadaheadState {
    window: Option<ReadAheadWindow>,
    cursor: Option<u64>,
    last_end: Option<u64>,
}

impl ReadaheadState {
    fn clear(&mut self) {
        self.window = None;
        self.cursor = None;
        self.last_end = None;
    }

    fn is_sequential_miss(&self, offset: u64) -> bool {
        if self.window.is_none() && self.last_end.is_none() {
            return true;
        }
        if self.last_end == Some(offset) {
            return true;
        }
        if let Some(w) = self.window.as_ref() {
            if offset == w.end_offset() {
                return true;
            }
        }
        false
    }
}

/// Serve a read, optionally retaining a sequential readahead window.
fn readahead_fill(
    reader: &mut dyn ratarmount_core::ArchiveRead,
    state: &mut ReadaheadState,
    readahead_bytes: usize,
    offset: u64,
    size: usize,
) -> io::Result<Vec<u8>> {
    if readahead_bytes == 0 {
        state.clear();
        reader.seek(io::SeekFrom::Start(offset))?;
        let mut buf = vec![0u8; size];
        let n = fill_read_for_nfs(reader, &mut buf)?;
        buf.truncate(n);
        return Ok(buf);
    }
    if size == 0 {
        return Ok(Vec::new());
    }
    if let Some(w) = state.window.as_ref() {
        if let Some(out) = w.try_serve(offset, size) {
            state.last_end = Some(offset.saturating_add(out.len() as u64));
            return Ok(out);
        }
    }
    let sequential = state.is_sequential_miss(offset);
    let want = if sequential {
        size.max(readahead_bytes)
    } else {
        size
    };
    if state.cursor != Some(offset) {
        reader.seek(io::SeekFrom::Start(offset))?;
        state.cursor = Some(offset);
    }
    let mut data = vec![0u8; want];
    let n = fill_read_for_nfs(reader, &mut data)?;
    data.truncate(n);
    state.cursor = Some(offset.saturating_add(n as u64));
    let hit_eof = n < want;
    let out_len = n.min(size);
    let out = data[..out_len].to_vec();
    state.last_end = Some(offset.saturating_add(out_len as u64));
    state.window = Some(ReadAheadWindow {
        start: offset,
        data,
        hit_eof,
    });
    Ok(out)
}

pub(crate) struct SourceReadState {
    reader: Box<dyn ratarmount_core::ArchiveRead>,
    readahead: ReadaheadState,
}

struct ReaderSlot {
    fi: FileInfo,
    state: Arc<Mutex<SourceReadState>>,
    last_used: Instant,
    pin: bool,
}

/// Live `source.open` handles keyed by fileid.
pub struct ReaderLru {
    slots: Mutex<HashMap<u64, ReaderSlot>>,
    cap: usize,
}

impl ReaderLru {
    pub fn new(cap: usize) -> Self {
        Self {
            slots: Mutex::new(HashMap::new()),
            cap: cap.max(1),
        }
    }

    /// Lookup-sourced `FileInfo` + handle. Never uses cheap readdir stubs.
    ///
    /// Unknown fileid (and lookup miss for a known id) is [`io::ErrorKind::NotFound`]
    /// so a v4 adapter can map it to `Stale` without depending on `nfsstat3`.
    pub(crate) fn get_or_open(
        &self,
        source: &dyn MountSource,
        inodes: &InodeTable,
        id: u64,
    ) -> io::Result<(FileInfo, Arc<Mutex<SourceReadState>>)> {
        {
            let mut map = self.slots.lock().expect("reader lru");
            if let Some(slot) = map.get_mut(&id) {
                slot.last_used = Instant::now();
                return Ok((slot.fi.clone(), Arc::clone(&slot.state)));
            }
        }

        let path = inodes
            .path_for_id(id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "stale fileid"))?;
        let fi = if path == "/" {
            ratarmount_core::create_root_file_info()
        } else if let Some(c) = inodes.cached_lookup_fi(id) {
            c
        } else {
            source
                .lookup(&path, 0)
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "stale fileid"))?
        };
        inodes.store_lookup_fi(id, fi.clone());

        if fi.size == 0 {
            // Empty sentinel — no `open` (FUSE `OpenBackend::Empty`).
            let state = Arc::new(Mutex::new(SourceReadState {
                reader: Box::new(io::Cursor::new(Vec::<u8>::new())),
                readahead: ReadaheadState::default(),
            }));
            return Ok((fi, state));
        }

        let reader = source.open(&fi, 0)?;
        let pin = !source.member_seek_is_cheap(&fi);
        let state = Arc::new(Mutex::new(SourceReadState {
            reader,
            readahead: ReadaheadState::default(),
        }));

        let mut map = self.slots.lock().expect("reader lru");
        if let Some(slot) = map.get_mut(&id) {
            slot.last_used = Instant::now();
            return Ok((slot.fi.clone(), Arc::clone(&slot.state)));
        }
        map.insert(
            id,
            ReaderSlot {
                fi: fi.clone(),
                state: Arc::clone(&state),
                last_used: Instant::now(),
                pin,
            },
        );
        while map.len() > self.cap {
            evict_one(&mut map);
        }
        Ok((fi, state))
    }

    /// Drop a live reader so the next read cannot serve pre-mutation bytes.
    pub(crate) fn invalidate(&self, id: u64) {
        self.slots.lock().expect("reader lru").remove(&id);
    }
}

fn evict_one(map: &mut HashMap<u64, ReaderSlot>) {
    let unpinned = map
        .iter()
        .filter(|(_, s)| !s.pin)
        .min_by_key(|(_, s)| s.last_used)
        .map(|(&k, _)| k);
    let victim = unpinned.or_else(|| map.iter().min_by_key(|(_, s)| s.last_used).map(|(&k, _)| k));
    if let Some(k) = victim {
        map.remove(&k);
    }
}

pub(crate) fn fill_from_state(
    state: &Arc<Mutex<SourceReadState>>,
    readahead_bytes: usize,
    offset: u64,
    size: usize,
) -> io::Result<Vec<u8>> {
    let mut g = state.lock().expect("reader slot");
    let SourceReadState { reader, readahead } = &mut *g;
    readahead_fill(reader.as_mut(), readahead, readahead_bytes, offset, size)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read, Seek};

    /// One-byte `Read::read` — would become false EOF without the fill loop.
    struct ShortRead(Cursor<Vec<u8>>);
    impl Read for ShortRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            self.0.read(&mut buf[..1])
        }
    }
    impl Seek for ShortRead {
        fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
            self.0.seek(pos)
        }
    }

    #[test]
    fn fill_loops_until_full() {
        let mut r = ShortRead(Cursor::new(b"abcdef".to_vec()));
        let mut buf = [0u8; 6];
        let n = fill_read_for_nfs(&mut r, &mut buf).unwrap();
        assert_eq!(n, 6);
        assert_eq!(&buf, b"abcdef");
    }

    #[test]
    fn readahead_sequential_hits_window() {
        let mut r = ShortRead(Cursor::new((0u8..200).collect()));
        let mut st = ReadaheadState::default();
        let a = readahead_fill(&mut r, &mut st, 64, 0, 8).unwrap();
        assert_eq!(a, (0u8..8).collect::<Vec<_>>());
        let b = readahead_fill(&mut r, &mut st, 64, 8, 8).unwrap();
        assert_eq!(b, (8u8..16).collect::<Vec<_>>());
    }

    struct EmptySource;

    impl MountSource for EmptySource {
        fn list(&self, _: &str) -> Option<ratarmount_core::ListResult> {
            None
        }

        fn lookup(&self, _: &str, _: i32) -> Option<FileInfo> {
            None
        }

        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
            Err(io::Error::new(io::ErrorKind::NotFound, "empty"))
        }

        fn is_immutable(&self) -> bool {
            true
        }
    }

    /// Regression: unknown fileid is NotFound so v3 can map STALE and v4 Stale.
    #[test]
    fn get_or_open_unknown_id_is_not_found() {
        let lru = ReaderLru::new(8);
        let inodes = InodeTable::new();
        match lru.get_or_open(&EmptySource, &inodes, 99) {
            Err(e) => assert_eq!(e.kind(), io::ErrorKind::NotFound),
            Ok(_) => panic!("unknown fileid should be NotFound"),
        }
    }
}
