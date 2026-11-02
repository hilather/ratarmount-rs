//! The durable append-log engine behind the supervisor's state files (R1c-1
//! §5.2): `requests.jsonl` (protocol v2 request IDs, R1a) and
//! `retained.jsonl` (retained attempts) are its two instances, never copies.
//!
//! The engine owns the file: the checked open, the open-time file and
//! directory syncs, the bounded streaming replay with torn-tail truncation
//! and damage refusal, the leftover sweep, append-then-`sync_data` with
//! truncation, `Broken`, verbatim compaction with backoff, the fault points
//! and events, and `sync_dir`. A [`Records`] instance owns what a line means:
//! parsing, applying it (eviction, reservation), the live lines in file
//! order, the compaction precondition, the file's messages and its line bound.
//!
//! A line is written by one `write_all` and synced before memory changes, so
//! while a log is open memory equals a replay of the file.

use super::protocol::ApiError;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, ApiError>;

/// Test-only fault points; each armed point fails its next hit once.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    OpenSyncFile,
    OpenSyncDir,
    OpenTruncate,
    RemoveLeftover,
    /// A short write: half the line reaches the file, then the write fails.
    Write(Append),
    /// After the whole line was written.
    Sync(Append),
    Truncate,
    CompactSync,
    CompactDirSync,
}

/// Which append a line is, for messages and fault points.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Append {
    /// `requests.jsonl`: a request starts.
    Running,
    /// `requests.jsonl`: a request's outcome.
    Outcome,
    /// `requests.jsonl`: a restart resolves a cut-off request.
    Resolution,
    /// `requests.jsonl`: a pinned finalize record's line appended again so a
    /// new line does not evict it (approval note (a)).
    Rotation,
    /// `retained.jsonl`: a commit records a retained attempt.
    Retained,
    /// `retained.jsonl`: a commit whose rename did not happen ends its record.
    Aborted,
}

/// Why open refused a line.
pub enum LineError {
    /// Not valid JSON (a short write, or zero-filled pages after a crash).
    Damaged,
    /// Valid JSON with another schema: corruption or a later release.
    Schema(String),
}

/// What one state file's records supply to the engine.
pub trait Records {
    /// What a parsed line carries to [`Records::apply`].
    type Parsed;
    /// The file's name in the state directory.
    const NAME: &'static str;
    /// Longest line open reads, newline included. It is fixed per file rather
    /// than derived from caps, so other caps never turn a valid older line
    /// into damage.
    const LINE_BOUND: u64;
    /// What a damage or schema refusal calls one line.
    const RECORD: &'static str;
    /// What a damage or schema refusal advises.
    const ADVICE: &'static str;
    /// What the `Broken` refusal calls the file.
    const LOG: &'static str;

    fn parse(line: &[u8]) -> std::result::Result<Self::Parsed, LineError>;
    /// Applies a durable line, at replay and after an append.
    fn apply(&mut self, parsed: Self::Parsed, line: Vec<u8>);
    /// The live last lines, in file order: what compaction writes.
    fn live_lines(&self) -> Vec<&[u8]>;
    fn live_bytes(&self) -> u64;
    /// Whether the records allow a compaction now (R1a: no record running).
    fn may_compact(&self) -> bool;
    /// No compaction while the file is at most this long.
    fn compaction_floor(&self) -> u64;
    /// This file's one-shot fault points, armed on this thread for its next
    /// open; each file has its own, so one log's faults never reach another.
    #[cfg(test)]
    fn take_test_faults() -> Vec<Fault>;
}

pub struct StateLog<R: Records> {
    path: PathBuf,
    dir: PathBuf,
    /// `None` only after a compaction published the new file but could not
    /// sync its directory; the log is then `Broken` until a restart.
    file: Option<File>,
    /// End of the last durable line.
    len: u64,
    pub(super) records: R,
    /// Why appends are refused until a restart (`Broken`).
    pub(super) broken: Option<String>,
    /// Bytes appended since a compaction failed before its rename (backoff).
    since_failed_compaction: Option<u64>,
    #[cfg(test)]
    pub faults: Vec<Fault>,
    #[cfg(test)]
    pub events: std::cell::RefCell<Vec<&'static str>>,
    #[cfg(test)]
    pub line_high_water: usize,
}

/// Opens the log at `path` without following symlinks, creating it if
/// missing, and checks the descriptor as `daemon::lock` does.
fn open_checked(path: &Path, name: &str) -> Result<File> {
    let file = {
        #[expect(
            clippy::disallowed_types,
            reason = r###"internal-read:v1 {"id":"IR-E0143-T01","item":"ratarmount::sandbox::state_log::open_checked","disposition":"support","category":"builder-type-support","reason":"Builder type support: Open a sandbox state log (requests.jsonl or retained.jsonl) for append.","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
        )]
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0143-M01","item":"ratarmount::sandbox::state_log::open_checked","disposition":"support","category":"builder-setup","reason":"Prepare the builder for this item's separately reviewed open/create leaf.","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open/create leaf owns pathname acquisition and permissions."}}"###
        )]
        let mut __inventory_value_0 = fs::OpenOptions::new();
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0143-M02","item":"ratarmount::sandbox::state_log::open_checked","disposition":"output-owner","category":"request-log","reason":"Permit creating a sandbox state log (requests.jsonl or retained.jsonl) while preserving an existing log inode.","creation":{"policy":"append-or-create","basis":"Read and append with NOFOLLOW/CLOEXEC, 0600 and truncate(false); owner/type/mode/nlink checks run on the acquired descriptor."}}"###
        )]
        let __inventory_value_1 = __inventory_value_0.read(true).append(true).create(true);
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0143-M03","item":"ratarmount::sandbox::state_log::open_checked","disposition":"output-owner","category":"request-log","reason":"Open a sandbox state log (requests.jsonl or retained.jsonl) once per daemon start; compaction keeps its own persisted descriptor.","creation":{"policy":"append-or-create","basis":"Read and append with NOFOLLOW/CLOEXEC, 0600 and truncate(false); owner/type/mode/nlink checks run on the acquired descriptor."}}"###
        )]
        let __inventory_value_2 = __inventory_value_1
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path);
        __inventory_value_2
    }
    .map_err(|e| failure(path, "cannot open", e))?;
    let meta = file
        .metadata()
        .map_err(|e| failure(path, "cannot stat", e))?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
    {
        return Err(ApiError::new(
            "unsafe_path",
            format!("{name} must be a private, owned regular file"),
        ));
    }
    Ok(file)
}

/// Makes a state directory's entries durable (a log's creation or a
/// compaction rename). This is the logs' mode of the engine's directory
/// fsync: it consults no poisoned filesystem and marks none, so a failure is
/// the log's own (`Broken`), never a finalize's refusal (§5.6).
pub(super) fn sync_dir(dir: &Path) -> io::Result<()> {
    open_dir(dir)?.sync_all()
}

/// The engine's directory open for an fsync: `O_RDONLY | O_DIRECTORY |
/// O_NOFOLLOW | O_CLOEXEC`, so a symlink or anything but a directory put in
/// its place is refused. [`sync_dir`] fsyncs it at once; finalize's step S
/// and its commit first check the descriptor (its device and filesystem)
/// and then fsync it, poisoning the filesystem on a failure (§5.6).
pub(super) fn open_dir(dir: &Path) -> io::Result<File> {
    let directory = {
        #[expect(
            clippy::disallowed_types,
            reason = r###"internal-read:v1 {"id":"IR-E0145-T01","item":"ratarmount::sandbox::state_log::open_dir","disposition":"support","category":"builder-type-support","reason":"Builder type support: Open a directory of the sandbox state, or the parent or an ancestor of a tree a finalize syncs, only to fsync it.","creation":{"policy":"none","basis":"This is a type/import reference; it acquires no file or directory."}}"###
        )]
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0145-M02","item":"ratarmount::sandbox::state_log::open_dir","disposition":"support","category":"builder-setup","reason":"Prepare the builder for this item's separately reviewed open leaf.","creation":{"policy":"none","basis":"Builder construction/setup only; the separate open leaf owns pathname acquisition."}}"###
        )]
        let mut __inventory_value_0 = fs::OpenOptions::new();
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0145-M01","item":"ratarmount::sandbox::state_log::open_dir","disposition":"out-of-family","category":"directory-handle-or-durability","reason":"fsync a directory of the state, attempts/, retained/, or the parent or an ancestor of a tree a finalize syncs; O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC handle, no content read","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this site creates no pathname."}}"###
        )]
        let __inventory_value_1 = __inventory_value_0
            .read(true)
            .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(dir);
        __inventory_value_1
    }?;
    Ok(directory)
}

pub(super) fn failure(path: &Path, what: &str, error: io::Error) -> ApiError {
    ApiError::new("io", format!("{}: {what}: {error}", path.display()))
}

/// Skips the rest of an over-long line, returning the bytes skipped.
fn skip_line(reader: &mut impl BufRead) -> io::Result<u64> {
    let mut skipped = 0;
    loop {
        let buffer = reader.fill_buf()?;
        if buffer.is_empty() {
            return Ok(skipped);
        }
        match buffer.iter().position(|c| *c == b'\n') {
            Some(end) => {
                reader.consume(end + 1);
                return Ok(skipped + end as u64 + 1);
            }
            None => {
                let n = buffer.len();
                reader.consume(n);
                skipped += n as u64;
            }
        }
    }
}

impl<R: Records> StateLog<R> {
    /// Opens the log of the state directory `dir`: the checked open, file and
    /// directory syncs before anything is acted on, the streaming replay with
    /// torn-tail truncation, then removal of leftover compaction temp files.
    /// Every refusal comes before `reconcile`.
    pub fn open_with(dir: &Path, records: R) -> Result<Self> {
        let path = dir.join(R::NAME);
        let file = open_checked(&path, R::NAME)?;
        let mut log = Self {
            path,
            dir: dir.into(),
            file: Some(file),
            len: 0,
            records,
            broken: None,
            since_failed_compaction: None,
            #[cfg(test)]
            faults: R::take_test_faults(),
            #[cfg(test)]
            events: Default::default(),
            #[cfg(test)]
            line_high_water: 0,
        };
        // Make durable whatever a killed daemon left visible but unsynced (a
        // line whose sync never ran, a compaction rename whose directory sync
        // never ran, the file's creation) before acting on it (codex-9 #2).
        log.sync_file()
            .map_err(|e| failure(&log.path, "cannot sync", e))?;
        log.event("file_sync");
        log.sync_state_dir()
            .map_err(|e| failure(&log.path, "cannot sync the directory of", e))?;
        log.event("dir_sync");
        let file = log.file.take().expect("the log was just opened");
        let replayed = log.replay(&file);
        log.file = Some(file);
        replayed?;
        log.remove_leftovers();
        Ok(log)
    }

    /// Reads one line at a time through the checked descriptor and replays
    /// each valid line with the append rule, so memory holds the live set and
    /// one line buffer however much history the file has.
    fn replay(&mut self, file: &File) -> Result<()> {
        let mut reader = BufReader::with_capacity(64 << 10, file);
        let mut line = Vec::new();
        let mut offset = 0;
        loop {
            line.clear();
            let read = (&mut reader)
                .take(R::LINE_BOUND)
                .read_until(b'\n', &mut line)
                .map_err(|e| failure(&self.path, "cannot read", e))?;
            if read == 0 {
                break;
            }
            if offset == 0 {
                self.event("read");
            }
            #[cfg(test)]
            {
                self.line_high_water = self.line_high_water.max(line.len());
            }
            let start = offset;
            offset += read as u64;
            let terminated = line.ends_with(b"\n");
            if !terminated && read as u64 == R::LINE_BOUND {
                offset +=
                    skip_line(&mut reader).map_err(|e| failure(&self.path, "cannot read", e))?;
            }
            let last = reader
                .fill_buf()
                .map_err(|e| failure(&self.path, "cannot read", e))?
                .is_empty();
            let parsed = if terminated {
                R::parse(&line)
            } else {
                Err(LineError::Damaged)
            };
            match parsed {
                Ok(parsed) => self.records.apply(parsed, std::mem::take(&mut line)),
                // Every append is synced before the next starts, so only the
                // last line can be physically damaged: it is torn.
                Err(LineError::Damaged) if last => {
                    self.truncate_tail(file, start)
                        .map_err(|e| failure(&self.path, "cannot truncate the torn tail of", e))?;
                    self.event("truncate");
                    offset = start;
                    break;
                }
                Err(LineError::Damaged) => {
                    return Err(ApiError::new(
                        "invalid_request",
                        format!(
                            "{}: damaged {} at byte {start}; {}",
                            self.path.display(),
                            R::RECORD,
                            R::ADVICE
                        ),
                    ))
                }
                Err(LineError::Schema(why)) => {
                    return Err(ApiError::new(
                        "invalid_request",
                        format!(
                            "{}: unsupported {} at byte {start} ({why}); {}",
                            self.path.display(),
                            R::RECORD,
                            R::ADVICE
                        ),
                    ))
                }
            }
        }
        self.len = offset;
        Ok(())
    }

    /// Removes leftover compaction temp files (regular files only). A
    /// leftover is harmless, so a failed removal is logged and ignored.
    fn remove_leftovers(&mut self) {
        let entries = match fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(error) => {
                log::warn!(
                    "cannot list {} for compaction leftovers: {error}",
                    self.dir.display()
                );
                return;
            }
        };
        let prefix = format!("{}.", R::NAME);
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !(name.len() > prefix.len() + ".compact".len()
                && name.starts_with(&prefix)
                && name.ends_with(".compact"))
            {
                continue;
            }
            let path = entry.path();
            if !fs::symlink_metadata(&path).is_ok_and(|m| m.is_file()) {
                continue;
            }
            if let Err(error) = self.remove_leftover(&path) {
                log::warn!(
                    "cannot remove compaction leftover {}: {error}",
                    path.display()
                );
            }
        }
    }

    fn file(&self) -> io::Result<&File> {
        self.file
            .as_ref()
            .ok_or_else(|| io::Error::other(format!("the {} is not open", R::LOG)))
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }

    // Each fault point is one `#[cfg(test)]` statement in a small helper.

    fn sync_file(&mut self) -> io::Result<()> {
        #[cfg(test)]
        self.check_fault(Fault::OpenSyncFile)?;
        self.file()?.sync_all()
    }

    fn sync_state_dir(&mut self) -> io::Result<()> {
        #[cfg(test)]
        self.check_fault(Fault::OpenSyncDir)?;
        sync_dir(&self.dir)
    }

    fn truncate_tail(&mut self, file: &File, start: u64) -> io::Result<()> {
        #[cfg(test)]
        self.check_fault(Fault::OpenTruncate)?;
        file.set_len(start)?;
        file.sync_data()
    }

    fn remove_leftover(&mut self, path: &Path) -> io::Result<()> {
        #[cfg(test)]
        self.check_fault(Fault::RemoveLeftover)?;
        fs::remove_file(path)
    }

    fn sync_compacted_dir(&mut self) -> io::Result<()> {
        #[cfg(test)]
        self.check_fault(Fault::CompactDirSync)?;
        sync_dir(&self.dir)
    }

    #[cfg(test)]
    fn check_fault(&mut self, point: Fault) -> io::Result<()> {
        match self.faults.iter().position(|armed| *armed == point) {
            Some(i) => {
                self.faults.remove(i);
                Err(io::Error::other(format!("injected {point:?} failure")))
            }
            None => Ok(()),
        }
    }

    pub(super) fn event(&self, _name: &'static str) {
        #[cfg(test)]
        self.events.borrow_mut().push(_name);
    }

    /// The refusal while the log is `Broken`.
    pub fn unavailable(&self) -> ApiError {
        ApiError::new(
            "io",
            format!(
                "{} unavailable since {}; restart the daemon",
                R::LOG,
                self.broken.as_deref().unwrap_or("an append failed")
            ),
        )
    }

    /// One `write_all` of the whole line, then `sync_data`; on failure the line
    /// is truncated away when possible: `Err((error, truncated))`. Only the
    /// log's length changes here; callers change memory after this returns.
    pub(super) fn write(
        &mut self,
        line: &[u8],
        append: Append,
    ) -> std::result::Result<(), (io::Error, bool)> {
        self.event("append");
        if let Err(error) = self.write_and_sync(line, append) {
            let truncated = self.truncate(self.len).is_ok();
            return Err((error, truncated));
        }
        self.len += line.len() as u64;
        if let Some(appended) = &mut self.since_failed_compaction {
            *appended += line.len() as u64;
        }
        Ok(())
    }

    fn write_and_sync(&mut self, line: &[u8], _append: Append) -> io::Result<()> {
        #[cfg(test)]
        if self.check_fault(Fault::Write(_append)).is_err() {
            self.file()?.write_all(&line[..line.len() / 2])?;
            return Err(io::Error::other("injected short write"));
        }
        self.file()?.write_all(line)?;
        #[cfg(test)]
        self.check_fault(Fault::Sync(_append))?;
        self.file()?.sync_data()
    }

    fn truncate(&mut self, len: u64) -> io::Result<()> {
        #[cfg(test)]
        self.check_fault(Fault::Truncate)?;
        let file = self.file()?;
        file.set_len(len)?;
        file.sync_data()
    }

    /// Compacts when the file is over twice the live bytes and over the
    /// floor, the records allow it, and any backoff after a failure before
    /// the rename has passed.
    pub(super) fn maybe_compact(&mut self) {
        let live = self.records.live_bytes();
        if self.broken.is_some()
            || self.len <= 2 * live
            || self.len <= self.records.compaction_floor()
            || !self.records.may_compact()
            || self
                .since_failed_compaction
                .is_some_and(|appended| appended < live)
        {
            return;
        }
        self.event("compact");
        let (temp, written) = match self.write_compacted() {
            Ok(written) => written,
            Err(error) => {
                log::warn!("cannot compact {}: {error}", self.path.display());
                self.since_failed_compaction = Some(0);
                return;
            }
        };
        let file = match temp.persist(&self.path) {
            Ok(file) => file,
            Err(error) => {
                // Dropping the returned temp file removes it.
                log::warn!("cannot compact {}: {}", self.path.display(), error.error);
                self.since_failed_compaction = Some(0);
                return;
            }
        };
        // The old descriptor now names an unlinked inode: drop it at once so
        // nothing lands there, and refuse appends until the rename is durable.
        self.broken = Some(format!(
            "a compaction of {} published the file before its directory was synced",
            self.path.display()
        ));
        self.file = None;
        match self.sync_compacted_dir() {
            Ok(()) => {
                // `persist` returned the temp file's own O_APPEND descriptor of the
                // published inode, so a failed append's truncation leaves no gap.
                self.file = Some(file);
                self.len = written;
                self.broken = None;
                self.since_failed_compaction = None;
            }
            Err(error) => {
                self.broken = Some(format!(
                    "a compaction could not sync the directory of {} ({error})",
                    self.path.display()
                ));
            }
        }
    }

    /// Writes every live last line, byte for byte and in file order, to a
    /// synced temp file beside the log.
    fn write_compacted(&mut self) -> io::Result<(tempfile::NamedTempFile, u64)> {
        #[expect(
            clippy::disallowed_methods,
            reason = r###"internal-read:v1 {"id":"IR-E0144-M01","item":"<ratarmount::sandbox::state_log::StateLog<T0>>::write_compacted","disposition":"output-owner","category":"request-log-compaction","reason":"Stage a compacted sandbox state log (requests.jsonl or retained.jsonl) beside it before an atomic rename.","creation":{"policy":"exclusive-new-file","basis":"tempfile creates the name with O_EXCL, mode 0600 and append inside the 0700 state directory; persist renames it over the log."}}"###
        )]
        let mut temp = tempfile::Builder::new()
            .prefix(&format!("{}.", R::NAME))
            .suffix(".compact")
            .append(true)
            .tempfile_in(&self.dir)?;
        let mut written = 0;
        for line in self.records.live_lines() {
            temp.write_all(line)?;
            written += line.len() as u64;
        }
        #[cfg(test)]
        self.check_fault(Fault::CompactSync)?;
        temp.as_file().sync_all()?;
        Ok((temp, written))
    }

    #[cfg(test)]
    pub fn live_lines(&self) -> Vec<Vec<u8>> {
        self.records
            .live_lines()
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect()
    }

    #[cfg(test)]
    pub fn is_broken(&self) -> bool {
        self.broken.is_some()
    }

    #[cfg(test)]
    pub fn descriptor(&self) -> Option<&File> {
        self.file.as_ref()
    }
}
