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

/// Create only after input validation, and remove an incomplete output on every
/// write, flush or sync error. The closure also supplies a deterministic failure
/// seam for testing the same helper used by the command.
pub(crate) fn write_output(
    path: &Path,
    write: impl FnOnce(&mut dyn Write) -> Result<()>,
) -> Result<()> {
    #[expect(
        clippy::disallowed_types,
        reason = r#"internal-read:v1 {"id":"IR-R2-OUT-T01","item":"ratarmount::tensors_cmd::write_output","disposition":"support","category":"builder-type-support","reason":"OpenOptions builder for the explicit manifest output file.","creation":{"policy":"none","basis":"Type reference only; the separately reviewed open leaf creates the output."}}"#
    )]
    #[expect(
        clippy::disallowed_methods,
        reason = r#"internal-read:v1 {"id":"IR-R2-OUT-M01","item":"ratarmount::tensors_cmd::write_output","disposition":"support","category":"builder-setup","reason":"Prepare exclusive creation of an explicitly requested manifest output.","creation":{"policy":"none","basis":"Builder construction only; the open leaf owns output creation."}}"#
    )]
    let mut options = std::fs::OpenOptions::new();
    options.write(true);
    #[expect(
        clippy::disallowed_methods,
        reason = r#"internal-read:v1 {"id":"IR-R2-OUT-M02","item":"ratarmount::tensors_cmd::write_output","disposition":"output-owner","category":"tensor-manifest-output","reason":"Refuse replacing an existing manifest output.","creation":{"policy":"exclusive-new-file","basis":"create_new uses exclusive creation with default process permissions and never overwrites an existing path."}}"#
    )]
    options.create_new(true);
    #[expect(
        clippy::disallowed_methods,
        reason = r#"internal-read:v1 {"id":"IR-R2-OUT-M03","item":"ratarmount::tensors_cmd::write_output","disposition":"output-owner","category":"tensor-manifest-output","reason":"Create the manifest output requested with -o after validating all inputs.","creation":{"policy":"exclusive-new-file","basis":"The builder is write-only with create_new; failed writes remove the newly created output."}}"#
    )]
    let mut file = options
        .open(path)
        .map_err(|error| output_error(path, error))?;
    let result = (|| {
        let mut out = BufWriter::new(&mut file);
        write(&mut out)?;
        out.flush()?;
        drop(out);
        file.sync_all()?;
        Ok(())
    })();
    drop(file);
    if result.is_err() {
        let _ = std::fs::remove_file(path);
    }
    result.map_err(|error: TensorsError| {
        TensorsError::Invalid(format!("{}: {error}", path.display()))
    })
}

fn output_error(path: &Path, error: io::Error) -> TensorsError {
    TensorsError::Invalid(format!("{}: {error}", path.display()))
}
