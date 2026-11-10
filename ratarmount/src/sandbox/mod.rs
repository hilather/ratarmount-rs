//! A local supervisor; each attempt owns a foreground ratarmount child.

#[cfg(target_os = "linux")]
mod bench;
mod client;
mod daemon;
mod finalize;
#[cfg(test)]
mod finalize_tests;
mod inspection;
#[cfg(test)]
mod restart_tests;
pub(crate) use inspection::start as start_inspection;
mod lowers;
#[cfg(test)]
mod lowers_tests;
pub(crate) mod process;
mod protocol;
mod requests;
#[cfg(test)]
mod requests_tests;
mod retained;
mod run;
mod state_log;
#[cfg(test)]
mod tests;

use clap::{Parser, Subcommand};
#[cfg(test)]
use protocol::VERSION;
use protocol::{
    BaseOptions, JournalReads, JournalSpec, Op, Operation, OperationV2, Overlay, Request, Response,
};
use std::io::Write;
#[cfg(test)]
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Parser)]
#[command(
    name = "ratarmount sandbox",
    about = "Supervise isolated write-overlay attempts"
)]
pub struct SandboxArgs {
    #[arg(long, global = true)]
    socket: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Validate a Perl benchmark manifest or emit a dry-run schedule (Linux only).
    #[cfg(target_os = "linux")]
    #[command(hide = true)]
    Bench(bench::BenchArgs),
    /// Run one container command against a write-overlay stack.
    ///
    /// Mount the stack, run a container, unmount, repair and hash the result, and optionally seal or pack it. Stdout is a JSON report.
    #[command(
        after_help = "Example: ratarmount sandbox run --base base.tar.zst --top attempt --image busybox -- sh -c 'echo hello > /repo/result'\n\nExit status:\n  0  Pipeline completed, even if the container failed. Inspect JSON exit_code:\n     runtime status, 124 for timeout, or 128 + signal for interruption.\n  2  Invalid arguments or harness failure (setup, cleanup, or reporting)."
    )]
    Run(Box<run::RunArgs>),
    Daemon {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, default_value_t = 256, value_parser = clap::value_parser!(u32).range(1..=4096))]
        max_attempts: u32,
        #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..=3600))]
        timeout: u64,
        /// Most attempt IDs retained records may hold (0 refuses `retain`).
        #[arg(long, default_value_t = retained::MAX_RETAINED as u32, value_parser = clap::value_parser!(u32).range(0..=retained::MAX_RETAINED as i64))]
        max_retained: u32,
    },
    CreateBase {
        name: String,
        source: String,
        /// JSON object; see docs/sandbox.md for keys.
        #[arg(long, default_value = "{}")]
        options: String,
    },
    New {
        base: String,
        #[arg(long, default_value_t = 1)]
        count: usize,
        #[arg(long, value_enum, default_value_t = Overlay::Disk)]
        overlay: Overlay,
        #[arg(long, value_parser = ratarmount_compositing::parse_overlay_size)]
        quota: Option<u64>,
        #[arg(long = "readonly", value_delimiter = ',')]
        readonly_globs: Vec<String>,
        /// Retry-safe ID (protocol version 2): the same ID and body never start a second batch.
        #[arg(long)]
        request_id: Option<String>,
        /// Sealed layer directory or bundle under each attempt (repeatable, bottom first; protocol version 2). Absolute paths only; the path is sent unchanged.
        #[arg(long = "lower", value_name = "PATH")]
        lowers: Vec<String>,
        /// Record each attempt's operation journal in attempts/ID/journal.jsonl (protocol version 2).
        #[arg(long)]
        journal: bool,
        /// Journal exclusion glob, as --journal-exclude of the mount (repeatable).
        #[arg(long, value_name = "GLOB", requires = "journal")]
        journal_exclude: Vec<String>,
        /// Record all coalesced read ranges, or only the first per handle.
        #[arg(long, value_enum, requires = "journal")]
        journal_reads: Option<JournalReads>,
        /// Fsync the journal at unmount.
        #[arg(long, requires = "journal")]
        journal_sync: bool,
        /// Keep each attempt in retained/ID once a finalize succeeds (protocol version 2; Linux, TAR, directory and git:/// bases).
        #[arg(long)]
        retain: bool,
    },
    /// Stop, check, seal and hash an attempt, optionally packing it (protocol version 2; Linux only).
    ///
    /// Unmounts the attempt with a normal unmount (never lazy or forced), fscks, seals and hashes its layer, syncs everything it references, and prints the JSON report. An attempt created with --retain is then kept in retained/ID. A busy mount answers writers_active: stop the processes using it (its container) and retry after at least a second, backing off.
    #[command(
        after_help = "Example: ratarmount sandbox --socket api.sock finalize attempt-a1B2c3 --pack --request-id run-17-final\n\nExit status:\n  0  Finalized (or retained); stdout is the JSON report.\n  1  Refused or failed (see the JSON error: writers_active, lower_changed,\n     invalid_request, not_found, io, ...); retry writers_active."
    )]
    Finalize {
        id: String,
        /// Also pack the layer into attempts/ID/bundle.tar.zst.
        #[arg(long)]
        pack: bool,
        /// Retry-safe ID: the same ID and body act only on the attempt the first try resolved.
        #[arg(long)]
        request_id: Option<String>,
    },
    List {
        #[arg(long)]
        base: Option<String>,
        /// Also list served retained attempts (protocol version 2).
        #[arg(long)]
        all: bool,
    },
    Diff {
        id: String,
        #[arg(long)]
        git: bool,
    },
    Stats {
        id: String,
    },
    Destroy {
        #[arg(required_unless_present = "base", conflicts_with = "base")]
        id: Option<String>,
        #[arg(long)]
        base: Option<String>,
    },
    Shutdown,
}

pub fn run_cli(args: &SandboxArgs) -> Result<i32, String> {
    #[cfg(target_os = "linux")]
    if let Command::Bench(bench) = &args.command {
        return self::bench::run(bench, args.socket.as_deref());
    }
    run(args).map(|()| 0)
}

pub fn run(args: &SandboxArgs) -> Result<(), String> {
    if let Command::Run(run) = &args.command {
        return self::run::run(run).map_err(|e| e.to_string());
    }
    let socket = args.socket.as_deref().ok_or("--socket PATH is required")?;
    let operation: Op = match &args.command {
        #[cfg(target_os = "linux")]
        Command::Bench(_) => return Err("bench requires run_cli".into()),
        Command::Run(_) => unreachable!("handled before daemon socket lookup"),
        Command::Daemon {
            state_dir,
            max_attempts,
            timeout,
            max_retained,
        } => {
            return daemon::serve(
                socket,
                state_dir,
                *max_attempts as usize,
                Duration::from_secs(*timeout),
                *max_retained as usize,
            )
            .map_err(|e| format!("{}: {}", e.code, e.message));
        }
        Command::CreateBase {
            name,
            source,
            options,
        } => Operation::CreateBase {
            name: name.clone(),
            source: source.clone(),
            options: serde_json::from_str::<BaseOptions>(options).map_err(|e| e.to_string())?,
        }
        .into(),
        // Without --request-id, --lower, --journal and --retain `new` sends
        // exactly the v1 bytes.
        Command::New {
            base,
            count,
            overlay,
            quota,
            readonly_globs,
            request_id,
            lowers,
            journal,
            journal_exclude,
            journal_reads,
            journal_sync,
            retain,
        } => {
            let journal = journal.then(|| JournalSpec {
                exclude: journal_exclude.clone(),
                reads: journal_reads.unwrap_or_default(),
                sync: *journal_sync,
            });
            if request_id.is_none() && lowers.is_empty() && journal.is_none() && !retain {
                Operation::New {
                    base: base.clone(),
                    count: *count,
                    overlay: *overlay,
                    quota: *quota,
                    readonly_globs: readonly_globs.clone(),
                }
                .into()
            } else {
                OperationV2::New {
                    base: base.clone(),
                    count: *count,
                    overlay: *overlay,
                    quota: *quota,
                    readonly_globs: readonly_globs.clone(),
                    request_id: request_id.clone(),
                    lowers: lowers.clone(),
                    journal,
                    retain: *retain,
                }
                .into()
            }
        }
        Command::Finalize {
            id,
            pack,
            request_id,
        } => OperationV2::Finalize {
            id: id.clone(),
            pack: *pack,
            request_id: request_id.clone(),
        }
        .into(),
        // Without --all, today's v1 bytes.
        Command::List { base, all: false } => Operation::List { base: base.clone() }.into(),
        Command::List { base, all: true } => OperationV2::List {
            base: base.clone(),
            all: true,
        }
        .into(),
        Command::Diff { id, git } => Operation::Diff {
            id: id.clone(),
            git: *git,
        }
        .into(),
        Command::Stats { id } => Operation::Stats { id: id.clone() }.into(),
        Command::Destroy { id, base } => Operation::Destroy {
            id: id.clone(),
            base: base.clone(),
        }
        .into(),
        Command::Shutdown => Operation::Shutdown.into(),
    };
    let response = call(socket, Request::new(operation))?;
    let output = serde_json::to_vec(&response).map_err(|e| e.to_string())?;
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(&output)
        .and_then(|_| stdout.write_all(b"\n"))
        .map_err(|e| e.to_string())?;
    if response.ok {
        Ok(())
    } else {
        Err("request failed (see JSON error)".into())
    }
}

pub fn error_exit_code(args: &SandboxArgs) -> i32 {
    if matches!(args.command, Command::Run(_)) {
        2
    } else {
        1
    }
}

fn call(socket: &std::path::Path, request: Request) -> Result<Response, String> {
    client::call(socket, request)
}
