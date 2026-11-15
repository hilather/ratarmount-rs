//! Offline streaming operation-journal summaries and the mount-root mark protocol.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::fs::File;
use std::io::{self, BufRead, BufReader, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Parser)]
#[command(
    name = "ratarmount journal",
    about = "Inspect operation journals or mark an agent turn",
    after_help = "Exit status:\n  0  Success.\n  2  Invalid arguments, journal data, or I/O error."
)]
pub struct JournalArgs {
    #[command(subcommand)]
    pub command: JournalCommand,
}

#[derive(Debug, Subcommand)]
pub enum JournalCommand {
    /// Summarize JSONL records, keeping only a per-path table in memory.
    ///
    /// Classify file reads and writes from an operation journal, optionally restricting the summary to a range of marks.
    #[command(
        after_help = "Example: ratarmount journal summarize attempt.jsonl --json\n\nExit status:\n  0  Summary written.\n  2  Invalid arguments, journal data, marks, or I/O error."
    )]
    Summarize {
        file: PathBuf,
        #[arg(long)]
        json: bool,
        /// Start after the first matching mark.
        #[arg(long)]
        since_mark: Option<String>,
        /// Stop before the first matching mark after the start.
        #[arg(long)]
        until_mark: Option<String>,
    },
    /// Append a UTF-8 label (at most 4096 bytes) through the mount-root xattr.
    ///
    /// Send a turn label to a live journaled mount using user.ratarmount.mark on its root.
    #[command(
        after_help = "Example: ratarmount journal mark mnt turn-1\n\nExit status:\n  0  Mark appended.\n  2  Invalid arguments, label, mount, or I/O error."
    )]
    Mark { mount: PathBuf, label: String },
}

#[derive(Debug, Default, Serialize)]
pub struct PathSummary {
    pub first_read_ts: Option<u64>,
    pub first_write_ts: Option<u64>,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub read_count: u64,
    pub layer: Option<String>,
    pub comm: BTreeSet<String>,
    #[serde(skip)]
    first_read_order: Option<(u64, u64)>,
    #[serde(skip)]
    first_write_order: Option<(u64, u64)>,
}

#[derive(Debug, Default, Serialize)]
pub struct Summary {
    pub paths: BTreeMap<String, PathSummary>,
    pub files_read: Vec<String>,
    pub files_read_then_written: Vec<String>,
    pub files_written_blind: Vec<String>,
    pub reads_by_mark: BTreeMap<String, BTreeSet<String>>,
    pub coverage: Coverage,
}

/// How a segment (one mount's records, from its header) ended.
pub const ENDED_CLEAN: &str = "clean";
pub const ENDED_MISSING_END: &str = "missing_end";
pub const ENDED_TRUNCATED_TAIL: &str = "truncated_tail";
pub const ENDED_CLOSED_BY_MARK: &str = "closed_by_mark";

/// The closed set of reasons a window is not `complete`.
pub const REASON_MISSING_END: &str = "missing_end";
pub const REASON_TRUNCATED_TAIL: &str = "truncated_tail";
pub const REASON_RECORD_COUNT_MISMATCH: &str = "record_count_mismatch";
pub const REASON_PRE_COVERAGE_JOURNAL: &str = "pre_coverage_journal";

/// One mount's records: its header and how they ended.
#[derive(Debug, Serialize)]
pub struct Segment {
    pub mount: Value,
    pub t0: Value,
    /// The header's observation settings; `null` for a journal written
    /// before they were recorded.
    pub observation: Value,
    pub ended: &'static str,
    /// Records read after the header, `end` excluded.
    pub records: u64,
    /// Whether `end`'s count equals `records`; `null` without `end`.
    pub records_match: Option<bool>,
    /// Records `--journal-exclude` suppressed, from `end`; `null` without it.
    pub excluded: Option<u64>,
    /// Whether any part of the selected window lies in this segment.
    pub in_window: bool,
}

/// What the summary can and cannot show (fixed strings, so a consumer
/// never has to parse prose).
#[derive(Debug, Serialize)]
pub struct Semantics {
    /// `complete` means the file holds every record the daemon emitted for
    /// the window; it is never negative evidence of reads.
    pub complete: &'static str,
    /// A path missing from `files_read` is always unknown as a read:
    /// page-cache and mmap hits produce no READ callback.
    pub read_absence: &'static str,
    /// `bytes_read` counts only reads that reached the mount.
    pub bytes_read: &'static str,
    /// `conclusive` only over a complete, unwindowed window whose segments
    /// all excluded nothing: then a path absent from `paths` had no
    /// successful OPEN through this mount. Otherwise `unknown`.
    pub open_absence: &'static str,
}

impl Default for Semantics {
    fn default() -> Self {
        Self {
            complete: "every_emitted_record_present",
            read_absence: "unknown",
            bytes_read: "lower_bound",
            open_absence: "unknown",
        }
    }
}

/// The journal's observation coverage for the selected window.
#[derive(Debug, Default, Serialize)]
pub struct Coverage {
    /// True only if every segment overlapping the window recorded its
    /// observation settings and ended `clean` with a matching count, or, for
    /// the segment holding the `--until-mark`, that mark is present.
    pub complete: bool,
    pub reasons: BTreeSet<&'static str>,
    /// Whether `--since-mark` or `--until-mark` selected a window.
    pub windowed: bool,
    /// Unions over the segments in the window.
    pub excluded_globs: BTreeSet<String>,
    pub reads_mode: BTreeSet<String>,
    pub segments: Vec<Segment>,
    pub semantics: Semantics,
}

/// The segment being read.
struct Open {
    segment: Segment,
    end: Option<(Option<u64>, Option<u64>)>,
    until_here: bool,
}

impl Open {
    fn new(header: &Value, in_window: bool) -> Self {
        let observation = match header.get("observation") {
            Some(observation @ Value::Object(_)) => observation.clone(),
            _ => Value::Null,
        };
        Self {
            segment: Segment {
                mount: header.get("mount").cloned().unwrap_or(Value::Null),
                t0: header.get("t0").cloned().unwrap_or(Value::Null),
                observation,
                ended: ENDED_MISSING_END,
                records: 0,
                records_match: None,
                excluded: None,
                in_window,
            },
            end: None,
            until_here: false,
        }
    }

    fn close(mut self, truncated: bool, coverage: &mut Coverage) {
        let segment = &mut self.segment;
        segment.ended = if truncated {
            ENDED_TRUNCATED_TAIL
        } else if self.end.is_some() {
            ENDED_CLEAN
        } else {
            ENDED_MISSING_END
        };
        if let Some((records, excluded)) = self.end {
            segment.records_match = Some(records == Some(segment.records));
            segment.excluded = excluded;
        }
        // Marks share the writer's FIFO queue with every other record, so a
        // present until-mark proves everything emitted before it was written.
        if self.until_here && segment.ended != ENDED_CLEAN {
            segment.ended = ENDED_CLOSED_BY_MARK;
        }
        if segment.in_window {
            let reasons = &mut coverage.reasons;
            if segment.observation.is_null() {
                reasons.insert(REASON_PRE_COVERAGE_JOURNAL);
            } else {
                let observation = &segment.observation;
                if let Some(reads) = observation["reads"].as_str() {
                    coverage.reads_mode.insert(reads.into());
                }
                for glob in observation["exclude"].as_array().into_iter().flatten() {
                    if let Some(glob) = glob.as_str() {
                        coverage.excluded_globs.insert(glob.into());
                    }
                }
            }
            match segment.ended {
                ENDED_MISSING_END => {
                    reasons.insert(REASON_MISSING_END);
                }
                ENDED_TRUNCATED_TAIL => {
                    reasons.insert(REASON_TRUNCATED_TAIL);
                }
                _ => {}
            }
            if segment.records_match == Some(false) {
                reasons.insert(REASON_RECORD_COUNT_MISMATCH);
            }
        }
        coverage.segments.push(self.segment);
    }
}

pub fn summarize(
    mut input: impl BufRead,
    since: Option<&str>,
    until: Option<&str>,
) -> io::Result<Summary> {
    let mut summary = Summary::default();
    summary.reads_by_mark.entry(String::new()).or_default();
    let mut active = since.is_none();
    let mut found_since = active;
    let mut found_until = until.is_none();
    let mut mark = String::new();
    let mut line = Vec::new();
    let mut line_number = 0;
    let mut session = 0;
    let mut opened: BTreeMap<String, (Option<String>, Option<String>)> = BTreeMap::new();
    let mut header = false;
    let mut segment: Option<Open> = None;
    // An interrupted append may precede the next mount's header. Only an EOF
    // parse error is deferred; malformed complete records are always errors.
    let mut truncated = false;
    // After the until-mark the scan continues only to judge its segment; a
    // record it cannot read there ends the scan instead of failing it.
    let mut closed = false;
    loop {
        line.clear();
        let bytes = input.read_until(b'\n', &mut line)?;
        if bytes == 0 {
            break;
        }
        line_number += 1;
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let record: Value = match serde_json::from_slice(&line) {
            Ok(record) => record,
            Err(error) if error.is_eof() && !truncated => {
                truncated = true;
                continue;
            }
            Err(error) => {
                if closed {
                    break;
                }
                return Err(invalid(format!("journal line {line_number}: {error}")));
            }
        };
        if let Some(version) = record["journal"].as_u64() {
            if version > JOURNAL_VERSION {
                {
                    if closed {
                        break;
                    }
                    return Err(invalid(format!(
                    "journal version {version} is newer than supported ({JOURNAL_VERSION}); upgrade ratarmount"
                )));
                };
            }
        }
        if record["journal"] == 1 {
            if let Some(open) = segment.take() {
                open.close(truncated, &mut summary.coverage);
            }
            segment = Some(Open::new(&record, active));
            header = true;
            session += 1;
            truncated = false;
            mark.clear();
            opened.clear();
            continue;
        }
        if truncated {
            {
                if closed {
                    break;
                }
                return Err(invalid(format!(
                    "truncated journal record before line {line_number}"
                )));
            };
        }
        let Some(open) = segment.as_mut() else {
            return Err(invalid("missing journal header"));
        };
        let op = match record["op"].as_str() {
            Some(op) => op,
            None => {
                if closed {
                    break;
                }
                return Err(invalid("record missing op"));
            }
        };
        if op == "end" {
            open.end = Some((record["records"].as_u64(), record["excluded"].as_u64()));
            continue;
        }
        open.segment.records += 1;
        if closed {
            continue;
        }
        if op == "mark" {
            let label = record["label"]
                .as_str()
                .ok_or_else(|| invalid("mark missing label"))?;
            if !found_since && since == Some(label) {
                found_since = true;
                active = true;
                open.segment.in_window = true;
            } else if active && until == Some(label) {
                found_until = true;
                open.until_here = true;
                closed = true;
                active = false;
                continue;
            }
            mark = label.into();
            if active {
                summary.reads_by_mark.entry(mark.clone()).or_default();
            }
            continue;
        }
        if !matches!(op, "open" | "read" | "write") {
            continue;
        }
        let path = if let Some(path) = record["path"].as_str() {
            path.to_owned()
        } else if let Some(path) = record["path_b64"].as_str() {
            format!("path_b64:{path}")
        } else {
            return Err(invalid("file record missing path/path_b64"));
        };
        if op == "open" {
            opened.insert(
                path.clone(),
                (
                    record["layer"].as_str().map(str::to_owned),
                    record["comm"].as_str().map(str::to_owned),
                ),
            );
        }
        if !active {
            continue;
        }
        let entry = summary.paths.entry(path.clone()).or_default();
        if let Some((layer, comm)) = opened.get(&path) {
            if entry.layer.is_none() {
                entry.layer.clone_from(layer);
            }
            if let Some(comm) = comm {
                entry.comm.insert(comm.clone());
            }
        }
        if let Some(layer) = record["layer"].as_str() {
            // Prefer the layer of the first read over a later copy-up open.
            if entry.first_read_ts.is_none() {
                entry.layer = Some(layer.into());
            }
        }
        if let Some(comm) = record["comm"].as_str() {
            entry.comm.insert(comm.into());
        }
        if op == "open" {
            continue;
        }
        let ts = record
            .get("first_ts")
            .unwrap_or(&record["ts"])
            .as_u64()
            .ok_or_else(|| invalid("read/write missing unsigned timestamp"))?;
        let bytes = record["bytes"]
            .as_u64()
            .ok_or_else(|| invalid("read/write missing unsigned bytes"))?;
        let order = (session, ts);
        if op == "read" {
            if entry.first_read_order.is_none_or(|old| order < old) {
                entry.first_read_order = Some(order);
                entry.first_read_ts = Some(ts);
            }
            entry.bytes_read = entry.bytes_read.saturating_add(bytes);
            entry.read_count = entry
                .read_count
                .saturating_add(record["count"].as_u64().unwrap_or(1));
            summary
                .reads_by_mark
                .entry(mark.clone())
                .or_default()
                .insert(path);
        } else {
            if entry.first_write_order.is_none_or(|old| order < old) {
                entry.first_write_order = Some(order);
                entry.first_write_ts = Some(ts);
            }
            entry.bytes_written = entry.bytes_written.saturating_add(bytes);
        }
    }
    if !header {
        return Err(invalid("missing journal header"));
    }
    if let Some(open) = segment.take() {
        open.close(truncated, &mut summary.coverage);
    }
    if !found_since {
        return Err(invalid(format!("start mark not found: {}", since.unwrap())));
    }
    if !found_until {
        return Err(invalid(format!("end mark not found: {}", until.unwrap())));
    }
    for (path, entry) in &summary.paths {
        match (entry.first_read_order, entry.first_write_order) {
            (Some(_), None) => summary.files_read.push(path.clone()),
            (Some(read), Some(write)) if read <= write => {
                summary.files_read_then_written.push(path.clone())
            }
            (_, Some(_)) => summary.files_written_blind.push(path.clone()),
            _ => {}
        }
    }
    let coverage = &mut summary.coverage;
    coverage.windowed = since.is_some() || until.is_some();
    coverage.complete = coverage.reasons.is_empty();
    if coverage.complete
        && !coverage.windowed
        && coverage
            .segments
            .iter()
            .all(|segment| segment.excluded == Some(0))
    {
        coverage.semantics.open_absence = "conclusive";
    }
    Ok(summary)
}

/// The journal format this reader understands (`{"journal":N}` header).
const JOURNAL_VERSION: u64 = 1;

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

pub fn mark(mount: &Path, label: &str) -> io::Result<()> {
    if label.len() > 4096 {
        return Err(invalid("mark label exceeds 4096 UTF-8 bytes"));
    }
    let mount = CString::new(mount.as_os_str().as_bytes())
        .map_err(|_| invalid("mount path contains NUL"))?;
    let key = c"user.ratarmount.mark";
    #[cfg(target_os = "linux")]
    let result = unsafe {
        libc::setxattr(
            mount.as_ptr(),
            key.as_ptr(),
            label.as_ptr().cast(),
            label.len(),
            0,
        )
    };
    #[cfg(target_os = "macos")]
    let result = unsafe {
        libc::setxattr(
            mount.as_ptr(),
            key.as_ptr(),
            label.as_ptr().cast(),
            label.len(),
            0,
            0,
        )
    };
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let result = {
        let _ = (mount, key);
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "journal mark requires Linux or macOS",
        ));
    };
    if result == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub fn run(args: &JournalArgs) -> io::Result<()> {
    match &args.command {
        JournalCommand::Mark { mount, label } => mark(mount, label),
        JournalCommand::Summarize {
            file,
            json,
            since_mark,
            until_mark,
        } => {
            #[expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0020-M01","item":"ratarmount::journal_cmd::run","disposition":"out-of-family","category":"structured-control-record","reason":"operation journal JSONL","creation":{"policy":"none","basis":"Existing input, admitted descriptor, or descriptor handoff; this baseline site creates no pathname."}}"###
            )]
            let summary = summarize(
                BufReader::new(File::open(file)?),
                since_mark.as_deref(),
                until_mark.as_deref(),
            )?;
            let mut output = io::stdout().lock();
            if *json {
                serde_json::to_writer(&mut output, &summary)?;
                writeln!(output)?;
            } else {
                for (name, paths) in [
                    ("Files read", &summary.files_read),
                    ("Files read then written", &summary.files_read_then_written),
                    ("Files written blind", &summary.files_written_blind),
                ] {
                    writeln!(output, "{name}: {}", paths.len())?;
                    for path in paths {
                        writeln!(output, "  {path}")?;
                    }
                }
                writeln!(output, "Per-path activity:")?;
                for (path, entry) in &summary.paths {
                    writeln!(output, "  {path}: first_read={:?} first_write={:?} read={} written={} reads={} layer={} comm={:?}", entry.first_read_ts, entry.first_write_ts, entry.bytes_read, entry.bytes_written, entry.read_count, entry.layer.as_deref().unwrap_or(""), entry.comm)?;
                }
                for (label, paths) in &summary.reads_by_mark {
                    writeln!(
                        output,
                        "Mark {label:?}: {}",
                        paths.iter().cloned().collect::<Vec<_>>().join(", ")
                    )?;
                }
                let coverage = &summary.coverage;
                if coverage.complete {
                    writeln!(output, "Coverage: complete")?;
                } else {
                    writeln!(
                        output,
                        "Coverage: incomplete ({})",
                        coverage
                            .reasons
                            .iter()
                            .copied()
                            .collect::<Vec<_>>()
                            .join(", ")
                    )?;
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const JOURNAL: &str = concat!(
        "{\"journal\":1}\n",
        "{\"op\":\"open\",\"path\":\"a\",\"layer\":\"lower:1\",\"comm\":\"cc\"}\n",
        "{\"op\":\"read\",\"path\":\"a\",\"bytes\":4,\"ts\":1}\n",
        "{\"op\":\"mark\",\"label\":\"turn1\"}\n",
        "{\"op\":\"read\",\"path\":\"b\",\"bytes\":3,\"ts\":2,\"count\":2}\n",
        "{\"op\":\"write\",\"path\":\"b\",\"bytes\":2,\"ts\":3}\n",
        "{\"op\":\"write\",\"path\":\"c\",\"bytes\":9,\"ts\":4}\n",
        "{\"op\":\"mark\",\"label\":\"turn2\"}\n",
        "{\"op\":\"read\",\"path\":\"c\",\"bytes\":5,\"ts\":5}\n",
    );

    /// Regression: a `{"journal":2}` header fell through to "missing journal
    /// header" (or a record error) instead of naming the version problem.
    #[test]
    fn regression_journal_newer_version_is_refused_by_name() {
        for newer in [
            "{\"journal\":2}\n{\"op\":\"read\",\"path\":\"a\",\"bytes\":1,\"ts\":1}\n",
            "{\"journal\":1}\n{\"op\":\"read\",\"path\":\"a\",\"bytes\":1,\"ts\":1}\n{\"journal\":99}\n",
        ] {
            let error = summarize(newer.as_bytes(), None, None).unwrap_err();
            let text = error.to_string();
            assert!(
                text.contains("is newer than supported (1); upgrade ratarmount"),
                "{text}"
            );
            assert!(text.starts_with("journal version "), "{text}");
        }
        assert!(summarize(JOURNAL.as_bytes(), None, None).is_ok());
    }

    #[test]
    fn regression_journal_summary_classifies_reads_writes_and_marks() {
        let summary = summarize(JOURNAL.as_bytes(), None, None).unwrap();
        assert_eq!(summary.files_read, ["a"]);
        assert_eq!(summary.files_read_then_written, ["b"]);
        assert_eq!(summary.files_written_blind, ["c"]);
        assert_eq!(summary.paths["a"].layer.as_deref(), Some("lower:1"));
        assert!(summary.paths["a"].comm.contains("cc"));
        assert_eq!(summary.paths["b"].read_count, 2);
        assert_eq!(summary.paths["c"].bytes_written, 9);
        for (label, path) in [("", "a"), ("turn1", "b"), ("turn2", "c")] {
            assert_eq!(summary.reads_by_mark[label], BTreeSet::from([path.into()]));
        }
    }

    #[test]
    fn regression_journal_summary_since_until_marks_and_missing_labels() {
        let summary = summarize(JOURNAL.as_bytes(), Some("turn1"), Some("turn2")).unwrap();
        assert!(!summary.paths.contains_key("a"));
        assert_eq!(summary.paths["c"].bytes_read, 0);
        assert_eq!(summary.files_read_then_written, ["b"]);
        assert!(summarize(JOURNAL.as_bytes(), Some("absent"), None).is_err());
        assert!(summarize(JOURNAL.as_bytes(), None, Some("absent")).is_err());
    }

    #[test]
    fn regression_journal_summary_tolerates_only_truncated_tail_or_session_boundary() {
        let input = format!("{JOURNAL}{{\"op\":\"read\"");
        assert_eq!(
            summarize(input.as_bytes(), None, None).unwrap().files_read,
            ["a"]
        );
        let resumed = format!("{input}\n{{\"journal\":1}}\n{{\"op\":\"write\",\"path\":\"a\",\"ts\":0,\"bytes\":2}}\n");
        assert_eq!(
            summarize(resumed.as_bytes(), None, None)
                .unwrap()
                .files_read_then_written,
            ["a", "b"]
        );
        assert!(summarize(format!("{JOURNAL}{{oops}}\n").as_bytes(), None, None).is_err());
        assert!(summarize(
            format!("{input}\n{{\"op\":\"mark\",\"label\":\"x\"}}\n").as_bytes(),
            None,
            None
        )
        .is_err());
        assert!(summarize(b"".as_slice(), None, None).is_err());
    }

    #[test]
    fn regression_journal_summary_since_mark_keeps_earlier_open_layer() {
        let input = b"{\"journal\":1}\n{\"op\":\"open\",\"path\":\"a\",\"layer\":\"lower:2\",\"comm\":\"cc\"}\n{\"op\":\"mark\",\"label\":\"start\"}\n{\"op\":\"read\",\"path\":\"a\",\"ts\":1,\"bytes\":0}\n";
        let summary = summarize(input.as_slice(), Some("start"), None).unwrap();
        assert_eq!(summary.paths["a"].layer.as_deref(), Some("lower:2"));
        assert!(summary.paths["a"].comm.contains("cc"));
        assert_eq!(summary.files_read, ["a"]);
    }

    #[test]
    fn regression_journal_summary_uses_io_time_when_handles_release_out_of_order() {
        let input = b"{\"journal\":1}\n{\"op\":\"write\",\"path\":\"a\",\"ts\":8,\"first_ts\":2,\"bytes\":1}\n{\"op\":\"read\",\"path\":\"a\",\"ts\":9,\"first_ts\":1,\"bytes\":1}";
        assert_eq!(
            summarize(input.as_slice(), None, None)
                .unwrap()
                .files_read_then_written,
            ["a"]
        );
    }

    /// A coverage-era header with `reads` and `exclude`.
    fn header(reads: &str, exclude: &[&str]) -> String {
        serde_json::json!({"journal": 1, "mount": "/m", "t0": "2026-11-15T00:00:00Z",
            "clock": "monotonic_ns", "observation": {"reads": reads, "exclude": exclude,
            "sync": false, "not_observed": ["lookup"]}})
        .to_string()
            + "\n"
    }

    const READ_A: &str =
        "{\"op\":\"open\",\"path\":\"a\"}\n{\"op\":\"read\",\"path\":\"a\",\"bytes\":1,\"ts\":1}\n";

    fn end(records: u64, excluded: u64) -> String {
        format!("{{\"op\":\"end\",\"ts\":9,\"records\":{records},\"excluded\":{excluded}}}\n")
    }

    fn coverage(input: &str, since: Option<&str>, until: Option<&str>) -> serde_json::Value {
        serde_json::to_value(summarize(input.as_bytes(), since, until).unwrap().coverage).unwrap()
    }

    /// Regression (observation coverage): `summarize` could not tell a clean
    /// unmount from a killed mount, a writer that failed part-way, or a
    /// journal written before observation settings were recorded. The
    /// `coverage` object judges every segment in the window, with the exact
    /// JSON shape pinned for a clean journal.
    #[test]
    fn regression_journal_coverage_table() {
        let h = header("all", &["t/**"]);
        let clean = format!("{h}{READ_A}{}", end(2, 0));
        assert_eq!(
            coverage(&clean, None, None),
            serde_json::json!({"complete": true, "reasons": [], "windowed": false,
                "excluded_globs": ["t/**"], "reads_mode": ["all"],
                "segments": [{"mount": "/m", "t0": "2026-11-15T00:00:00Z",
                    "observation": {"reads": "all", "exclude": ["t/**"], "sync": false,
                        "not_observed": ["lookup"]},
                    "ended": "clean", "records": 2, "records_match": true, "excluded": 0,
                    "in_window": true}],
                "semantics": {"complete": "every_emitted_record_present",
                    "read_absence": "unknown", "bytes_read": "lower_bound",
                    "open_absence": "conclusive"}})
        );
        let pre = format!("{{\"journal\":1}}\n{READ_A}{}", end(2, 0));
        let mixed = format!("{h}{READ_A}{h}{READ_A}{}", end(2, 0));
        for (case, input, complete, reasons, ended, open_absence) in [
            // Something was hidden: absence of a path proves nothing.
            (
                "excluded",
                format!("{h}{READ_A}{}", end(2, 1)),
                true,
                vec![],
                vec!["clean"],
                "unknown",
            ),
            (
                "missing_end",
                format!("{h}{READ_A}"),
                false,
                vec!["missing_end"],
                vec!["missing_end"],
                "unknown",
            ),
            (
                "truncated_tail",
                format!("{h}{READ_A}{{\"op\":\"re"),
                false,
                vec!["truncated_tail"],
                vec!["truncated_tail"],
                "unknown",
            ),
            (
                "count_mismatch",
                format!("{h}{READ_A}{}", end(5, 0)),
                false,
                vec!["record_count_mismatch"],
                vec!["clean"],
                "unknown",
            ),
            (
                "record_after_end",
                format!("{h}{READ_A}{}{READ_A}", end(2, 0)),
                false,
                vec!["record_count_mismatch"],
                vec!["clean"],
                "unknown",
            ),
            (
                "pre_coverage",
                pre,
                false,
                vec!["pre_coverage_journal"],
                vec!["clean"],
                "unknown",
            ),
            (
                "mixed",
                mixed,
                false,
                vec!["missing_end"],
                vec!["missing_end", "clean"],
                "unknown",
            ),
            (
                "truncated_then_clean",
                format!("{h}{READ_A}{{\"op\":\"read\"\n{h}{READ_A}{}", end(2, 0)),
                false,
                vec!["truncated_tail"],
                vec!["truncated_tail", "clean"],
                "unknown",
            ),
        ] {
            let coverage = coverage(&input, None, None);
            assert_eq!(coverage["complete"], complete, "{case}: {coverage}");
            assert_eq!(coverage["reasons"], serde_json::json!(reasons), "{case}");
            let got: Vec<_> = coverage["segments"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s["ended"].as_str().unwrap().to_owned())
                .collect();
            assert_eq!(got, ended, "{case}");
            assert_eq!(
                coverage["semantics"]["open_absence"], open_absence,
                "{case}"
            );
        }
        // Unions over the segments: excludes and read modes.
        let input = format!(
            "{}{READ_A}{}{}{READ_A}{}",
            header("all", &["t/**"]),
            end(2, 0),
            header("first", &["blib/**"]),
            end(2, 0)
        );
        let coverage = coverage(&input, None, None);
        assert_eq!(
            coverage["excluded_globs"],
            serde_json::json!(["blib/**", "t/**"])
        );
        assert_eq!(coverage["reads_mode"], serde_json::json!(["all", "first"]));
        // `complete: false` is still a successful summary (exit 0).
        assert!(summarize(format!("{h}{READ_A}").as_bytes(), None, None).is_ok());
    }

    /// Regression (observation coverage): a window is judged only by the
    /// segments it overlaps, and a `--until-mark` window on a live journal
    /// (no `end` yet) is complete once the until-mark is present, because
    /// marks share the writer's FIFO queue with every other record.
    #[test]
    fn regression_journal_coverage_windows() {
        let h = header("all", &[]);
        let mark = |label: &str| format!("{{\"op\":\"mark\",\"label\":\"{label}\"}}\n");
        // A killed first mount, then a clean one holding the since-mark.
        let input = format!("{h}{READ_A}{h}{}{READ_A}{}", mark("s"), end(3, 0));
        let since = coverage(&input, Some("s"), None);
        assert_eq!(since["complete"], true, "{since}");
        assert_eq!(since["windowed"], true);
        assert_eq!(since["segments"][0]["in_window"], false);
        assert_eq!(since["segments"][0]["ended"], "missing_end");
        assert_eq!(since["segments"][1]["in_window"], true);
        // Windowed: never conclusive about absent opens.
        assert_eq!(since["semantics"]["open_absence"], "unknown");
        // The whole journal is not complete.
        assert_eq!(coverage(&input, None, None)["complete"], false);
        // A live journal, closed by its until-mark: complete, even with an
        // unreadable record after the mark (the scan stops there, as the old
        // `break` did, so the summary still succeeds).
        let live = format!("{h}{READ_A}{}{READ_A}", mark("u"));
        for tail in ["", "{oops}\n", "{\"journal\":2}\n", "{\"no_op\":1}\n"] {
            let input = format!("{live}{tail}");
            let until = coverage(&input, None, Some("u"));
            assert_eq!(until["complete"], true, "{tail}: {until}");
            assert_eq!(until["segments"][0]["ended"], "closed_by_mark");
            assert_eq!(
                until["segments"][0]["records_match"],
                serde_json::Value::Null
            );
            let summary = summarize(input.as_bytes(), None, Some("u")).unwrap();
            assert_eq!(summary.paths["a"].read_count, 1);
        }
        // The until-mark segment ended cleanly: clean, its count is judged.
        let ended = format!("{live}{}", end(5, 0));
        let until = coverage(&ended, None, Some("u"));
        assert_eq!(until["segments"][0]["ended"], "clean");
        assert_eq!(until["segments"][0]["records_match"], true);
        // A since-mark in a killed segment and the until-mark in the next:
        // the killed segment overlaps the window.
        let input = format!("{h}{}{READ_A}{h}{READ_A}{}", mark("s"), mark("u"));
        let window = coverage(&input, Some("s"), Some("u"));
        assert_eq!(window["complete"], false);
        assert_eq!(window["reasons"], serde_json::json!(["missing_end"]));
        assert_eq!(window["segments"][1]["ended"], "closed_by_mark");
        // Segments after the until-mark are outside the window.
        let input = format!("{h}{}{h}{READ_A}", mark("u"));
        let window = coverage(&input, None, Some("u"));
        assert_eq!(window["complete"], true, "{window}");
        assert_eq!(window["segments"][1]["in_window"], false);
        // The until-mark proves flushing, not observation settings.
        let input = format!("{{\"journal\":1}}\n{READ_A}{}", mark("u"));
        let window = coverage(&input, None, Some("u"));
        assert_eq!(window["complete"], false);
        assert_eq!(
            window["reasons"],
            serde_json::json!(["pre_coverage_journal"])
        );
        // Inside the window, malformed records still fail the summary.
        assert!(summarize(
            format!("{h}{{oops}}\n{}", mark("u")).as_bytes(),
            None,
            Some("u")
        )
        .is_err());
    }

    #[test]
    fn regression_journal_cli_verbs_and_flags_preserve_positionals() {
        use crate::parse_args_from;
        let args =
            parse_args_from(["ratarmount", "journal", "summarize", "file", "--json"]).unwrap();
        assert!(
            matches!(args.journal_command.unwrap().command, JournalCommand::Summarize { file, json: true, .. } if file == Path::new("file"))
        );
        let args = parse_args_from(["ratarmount", "journal", "mark", "mnt", "turn 1"]).unwrap();
        assert!(
            matches!(args.journal_command.unwrap().command, JournalCommand::Mark { mount, label } if mount == Path::new("mnt") && label == "turn 1")
        );
        let args = parse_args_from([
            "ratarmount",
            "--journal",
            "trace.jsonl",
            "--journal-exclude",
            ".git/**",
            "--journal-reads",
            "first",
            "--journal-sync",
            "base.tar",
            "mnt",
        ])
        .unwrap();
        assert_eq!(
            args.paths,
            [PathBuf::from("base.tar"), PathBuf::from("mnt")]
        );
        assert_eq!(args.journal, Some(PathBuf::from("trace.jsonl")));
        for argv in [
            vec!["ratarmount", "--journal-sync", "base.tar", "mnt"],
            vec![
                "ratarmount",
                "--journal",
                "f",
                "--journal-reads",
                "wrong",
                "base.tar",
                "mnt",
            ],
        ] {
            assert!(parse_args_from(argv).is_err());
        }
    }
}
