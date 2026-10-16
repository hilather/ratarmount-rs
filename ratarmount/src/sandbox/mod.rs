//! A local supervisor; each attempt owns a foreground ratarmount child.

mod daemon;
mod inspection;
pub(crate) use inspection::start as start_inspection;
mod process;
mod protocol;
#[cfg(test)]
mod tests;

use clap::{Parser, Subcommand};
use protocol::{BaseOptions, Operation, Overlay, Request, Response, VERSION};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
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
    Daemon {
        #[arg(long)]
        state_dir: PathBuf,
        #[arg(long, default_value_t = 256, value_parser = clap::value_parser!(u32).range(1..=4096))]
        max_attempts: u32,
        #[arg(long, default_value_t = 120, value_parser = clap::value_parser!(u64).range(1..=3600))]
        timeout: u64,
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
    },
    List {
        #[arg(long)]
        base: Option<String>,
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

pub fn run(args: &SandboxArgs) -> Result<(), String> {
    let socket = args.socket.as_deref().ok_or("--socket PATH is required")?;
    let operation = match &args.command {
        Command::Daemon {
            state_dir,
            max_attempts,
            timeout,
        } => {
            return daemon::serve(
                socket,
                state_dir,
                *max_attempts as usize,
                Duration::from_secs(*timeout),
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
        },
        Command::New {
            base,
            count,
            overlay,
            quota,
            readonly_globs,
        } => Operation::New {
            base: base.clone(),
            count: *count,
            overlay: *overlay,
            quota: *quota,
            readonly_globs: readonly_globs.clone(),
        },
        Command::List { base } => Operation::List { base: base.clone() },
        Command::Diff { id, git } => Operation::Diff {
            id: id.clone(),
            git: *git,
        },
        Command::Stats { id } => Operation::Stats { id: id.clone() },
        Command::Destroy { id, base } => Operation::Destroy {
            id: id.clone(),
            base: base.clone(),
        },
        Command::Shutdown => Operation::Shutdown,
    };
    let response = call(socket, operation)?;
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

fn call(socket: &std::path::Path, operation: Operation) -> Result<Response, String> {
    let mut stream = UnixStream::connect(socket).map_err(|e| e.to_string())?;
    // Includes queued requests and cleanup of a full batch; callers can retry reads,
    // but must not blindly retry mutations after a transport failure.
    let timeout = Some(Duration::from_secs(3600));
    stream
        .set_read_timeout(timeout)
        .and_then(|_| stream.set_write_timeout(timeout))
        .map_err(|e| e.to_string())?;
    let mut request = serde_json::to_vec(&Request {
        version: VERSION,
        operation,
    })
    .map_err(|e| e.to_string())?;
    request.push(b'\n');
    stream.write_all(&request).map_err(|e| e.to_string())?;
    let mut line = Vec::new();
    BufReader::new(stream)
        .take((protocol::MAX_RESPONSE + 1) as u64)
        .read_until(b'\n', &mut line)
        .map_err(|e| e.to_string())?;
    if line.len() > protocol::MAX_RESPONSE || !line.ends_with(b"\n") {
        return Err("oversized or incomplete sandbox response".into());
    }
    let response: Response = serde_json::from_slice(&line).map_err(|e| e.to_string())?;
    if response.version != VERSION {
        return Err("unsupported response version".into());
    }
    Ok(response)
}
