//! Offline overlay statistics; no mount or writable database connection.

use std::path::PathBuf;

use clap::Parser;
use ratarmount_compositing::{OverlayStats, OverlayUsage};

#[derive(Debug, Parser)]
#[command(
    name = "ratarmount overlay-stats",
    about = "Inspect an existing write overlay offline"
)]
pub struct StatsArgs {
    pub directory: PathBuf,
    #[arg(long)]
    pub json: bool,
}

pub fn render(stats: OverlayStats, json: bool) -> String {
    let OverlayStats {
        usage:
            OverlayUsage {
                bytes,
                files,
                directories,
                symlinks,
            },
        files_deleted,
    } = stats;
    let files_present = files - symlinks;
    if json {
        format!("{{\"bytes_in_overlay\":{bytes},\"files_present\":{files_present},\"files_deleted\":{files_deleted},\"directories_created\":{directories},\"symlinks\":{symlinks}}}\n")
    } else {
        format!("Bytes in overlay: {bytes}\nFiles added/modified: {files_present}\nFiles deleted (tombstones): {files_deleted}\nDirectories created: {directories}\nSymlinks: {symlinks}\n")
    }
}

pub fn run(args: &StatsArgs) -> Result<String, String> {
    let stats = OverlayStats::read(&args.directory).map_err(|e| {
        if matches!(&e, ratarmount_compositing::OverlayError::Io(error) if error.kind() == std::io::ErrorKind::NotFound) {
            format!("error opening write overlay database {}: {e}; overlay-stats requires an existing database", args.directory.join(ratarmount_compositing::HIDDEN_DB).display())
        } else {
            super::overlay_open_error(&args.directory, &e)
        }
    })?;
    Ok(render(stats, args.json))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression: overlay-stats JSON keys and human counts must be stable.
    #[test]
    fn regression_overlay_stats_json_keys() {
        let stats = OverlayStats {
            usage: OverlayUsage {
                bytes: 11,
                files: 3,
                directories: 1,
                symlinks: 1,
            },
            files_deleted: 2,
        };
        assert_eq!(render(stats, true), "{\"bytes_in_overlay\":11,\"files_present\":2,\"files_deleted\":2,\"directories_created\":1,\"symlinks\":1}\n");
        assert_eq!(render(stats, false), "Bytes in overlay: 11\nFiles added/modified: 2\nFiles deleted (tombstones): 2\nDirectories created: 1\nSymlinks: 1\n");
    }
    /// Regression: a missing stats database names its path and is never created.
    #[test]
    fn regression_overlay_stats_missing_db_error() {
        let root = tempfile::tempdir().unwrap();
        let args = StatsArgs {
            directory: root.path().into(),
            json: true,
        };
        let error = run(&args).unwrap_err();
        assert!(error.contains(
            &root
                .path()
                .join(ratarmount_compositing::HIDDEN_DB)
                .display()
                .to_string()
        ));
        assert!(error.contains("requires an existing database"));
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    }
}
