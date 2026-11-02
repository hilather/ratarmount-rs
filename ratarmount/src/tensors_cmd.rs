//! Byte manifests for local safetensors and GGUF checkpoints.

use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use ratarmount_formats_tensors::{
    build_manifest, compile_expert_pattern, write_jsonl, ManifestOptions, Result, TensorsError,
};

#[derive(Debug, Parser)]
#[command(
    name = "ratarmount tensors",
    about = "Inspect local tensor checkpoints",
    after_help = "Exit status:\n  0  Success.\n  2  Invalid arguments, checkpoint data, or I/O error."
)]
pub struct TensorsArgs {
    #[command(subcommand)]
    pub command: TensorsCommand,
}

#[derive(Debug, Subcommand)]
pub enum TensorsCommand {
    /// Write a deterministic JSONL byte map, splitting merged experts into slices.
    #[command(
        after_help = "Example: ratarmount tensors manifest model.safetensors.index.json --hash -o manifest.jsonl\n\nExit status:\n  0  Manifest written.\n  2  Invalid arguments, checkpoint data, or I/O error."
    )]
    Manifest {
        /// Local checkpoint files or safetensors index JSON files.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Create a new output file; refuse an existing file.
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,
        /// Stream each tensor slice through SHA-256.
        #[arg(long)]
        hash: bool,
        /// Replace per-expert naming rules; requires layer, expert and role groups.
        #[arg(long)]
        expert_pattern: Option<String>,
    },
}

pub fn run(args: &TensorsArgs) -> Result<()> {
    let TensorsCommand::Manifest {
        paths,
        output,
        hash,
        expert_pattern,
    } = &args.command;
    let options = ManifestOptions {
        hash: *hash,
        expert_pattern: expert_pattern
            .as_deref()
            .map(compile_expert_pattern)
            .transpose()?,
    };
    let manifest = build_manifest(paths, &options)?;
    let generator = concat!("ratarmount ", env!("CARGO_PKG_VERSION"));
    if let Some(path) = output {
        write_output(path, |out| write_jsonl(&manifest, generator, out))
    } else {
        let stdout = io::stdout();
        let mut out = BufWriter::new(stdout.lock());
        write_jsonl(&manifest, generator, &mut out)?;
        out.flush()?;
        Ok(())
    }
}

/// Stage beside the output, then publish complete, synced bytes without clobbering.
/// Cleanup only unlinks our private temporary path, never the requested output.
/// The closure supplies a deterministic failure seam for the command's helper.
pub(crate) fn write_output(
    path: &Path,
    write: impl FnOnce(&mut dyn Write) -> Result<()>,
) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    #[expect(
        clippy::disallowed_methods,
        reason = r#"internal-read:v1 {"id":"IR-R2-OUT-M04","item":"ratarmount::tensors_cmd::write_output","disposition":"output-owner","category":"tensor-manifest-output","reason":"Stage the validated manifest privately beside its requested output before no-clobber hard-link publication.","creation":{"policy":"exclusive-new-file","basis":"tempfile uses OpenOptions create_new with mode 0600 subject to umask and an unpredictable name; cleanup only removes this temporary path."}}"#
    )]
    let mut temp = tempfile::Builder::new()
        .prefix(".ratarmount-tensors-")
        .rand_bytes(16)
        .tempfile_in(parent)
        .map_err(|error| output_error(path, error))?;
    let result: Result<()> = (|| {
        let mut out = BufWriter::new(temp.as_file_mut());
        write(&mut out)?;
        out.flush()?;
        drop(out);
        temp.as_file().sync_all()?;
        std::fs::hard_link(temp.path(), path).map_err(|error| {
            TensorsError::Invalid(format!(
                "output was not published: hard-link publication failed: {error}"
            ))
        })?;
        Ok(())
    })();
    // close removes the private name without reopening it for reading.
    match (result, temp.close()) {
        (Err(error), cleanup) => {
            let detail = match cleanup {
                Ok(()) => String::new(),
                Err(error) => format!("; temporary output cleanup failed: {error}"),
            };
            return Err(TensorsError::Invalid(format!(
                "{}: {error}{detail}",
                path.display()
            )));
        }
        (Ok(()), Err(error)) => {
            return Err(TensorsError::Invalid(format!(
                "{}: output was published but temporary output cleanup failed: {error}",
                path.display()
            )));
        }
        (Ok(()), Ok(())) => {}
    }
    // A failure here leaves the complete published output intact, but cannot
    // promise that publication is durable across a crash.
    #[expect(
        clippy::disallowed_methods,
        reason = r#"internal-read:v1 {"id":"IR-R2-OUT-M05","item":"ratarmount::tensors_cmd::write_output","disposition":"output-owner","category":"tensor-manifest-output","reason":"Open the manifest output parent only to sync publication and temporary-name removal.","creation":{"policy":"none","basis":"Open an existing directory after successful hard-link publication; errors preserve the published output."}}"#
    )]
    let directory = std::fs::File::open(parent);
    directory
        .and_then(|directory| directory.sync_all())
        .map_err(|error| {
            TensorsError::Invalid(format!(
                "{}: output was published but parent directory sync failed: {error}",
                path.display()
            ))
        })
}

fn output_error(path: &Path, error: io::Error) -> TensorsError {
    TensorsError::Invalid(format!("{}: {error}", path.display()))
}
