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
    // An interrupted append may precede the next mount's header. Only an EOF
    // parse error is deferred; malformed complete records are always errors.
    let mut truncated = false;
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
            Err(error) => return Err(invalid(format!("journal line {line_number}: {error}"))),
        };
        if let Some(version) = record["journal"].as_u64() {
            if version > JOURNAL_VERSION {
                return Err(invalid(format!(
                    "journal version {version} is newer than supported ({JOURNAL_VERSION}); upgrade ratarmount"
                )));
            }
        }
        if record["journal"] == 1 {
            header = true;
            session += 1;
            truncated = false;
            mark.clear();
            opened.clear();
            continue;
        }
        if truncated {
            return Err(invalid(format!(
                "truncated journal record before line {line_number}"
            )));
        }
        if !header {
            return Err(invalid("missing journal header"));
        }
        let op = record["op"]
            .as_str()
            .ok_or_else(|| invalid("record missing op"))?;
        if op == "mark" {
            let label = record["label"]
                .as_str()
                .ok_or_else(|| invalid("mark missing label"))?;
            if !found_since && since == Some(label) {
                found_since = true;
                active = true;
            } else if active && until == Some(label) {
                found_until = true;
                break;
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
