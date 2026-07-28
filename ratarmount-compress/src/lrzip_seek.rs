//! lrzip outer compression: detect + CLI materialize.
//!
//! Python keeps pure random-access on **libarchive only** for lrzip. This crate
//! detects magic `LRZI\x00` / extensions `.lrz` / `.lrzip` and can materialize via
//! the external `lrzip` (or `lrunzip`) binary when present on `PATH`.
//!
//! There is no in-process seekable decoder and **no libarchive dependency** here.
//! When the CLI is missing, the factory should fall back to
//! `ratarmount_formats_libarchive::try_open_lrzip_via_libarchive` (filter_all /
//! raw stream path). `materialize_lrzip` only shells to the CLI.

use std::io::{self, Seek, SeekFrom};
use std::path::Path;
use std::process::Command;

use log::debug;
use tempfile::NamedTempFile;

use crate::{CompressError, Result};

/// lrzip magic: `LRZI` + version major byte `0x00` (see Python `FID.LRZIP`).
pub const LRZIP_MAGIC: &[u8; 5] = b"LRZI\x00";

/// Clear error when neither CLI nor (caller) libarchive path can decompress.
pub const LRZIP_CLI_MISSING_MSG: &str = "lrzip not installed: need `lrzip` or `lrunzip` on PATH \
to decompress .lrz/.lrzip (factory may still open via libarchive lrzip filter)";

/// True if `magic` starts with the lrzip file magic.
pub fn looks_like_lrzip(magic: &[u8]) -> bool {
    magic.len() >= LRZIP_MAGIC.len() && &magic[..LRZIP_MAGIC.len()] == LRZIP_MAGIC
}

/// Whether an `lrzip` or `lrunzip` binary is available on `PATH`.
///
/// Alias of [`lrzip_cli_available`] — name kept for existing call sites.
pub fn lrzip_available() -> bool {
    lrzip_cli_available()
}

/// Whether the external `lrzip` / `lrunzip` CLI is on `PATH`.
///
/// This is independent of libarchive's lrzip filter (which also typically shells
/// out to `lrzip -d` at runtime). Prefer this name when documenting the CLI path.
pub fn lrzip_cli_available() -> bool {
    find_lrzip_bin().is_some()
}

fn which_exists(name: &str) -> bool {
    let Ok(path) = std::env::var("PATH") else {
        return false;
    };
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(name);
        if candidate.is_file() {
            return true;
        }
    }
    false
}

fn find_lrzip_bin() -> Option<&'static str> {
    // Prefer `lrzip` (supports `-d -f -o`); fall back to `lrunzip`.
    ["lrzip", "lrunzip"]
        .into_iter()
        .find(|&name| which_exists(name))
}

/// Decompress lrzip into a persistent temp file via external CLI only.
///
/// Uses `lrzip -d -f -o <out> <in>` when `lrzip` is available, else
/// `lrunzip -f -o <out> <in>`. Does **not** call libarchive — when the CLI is
/// missing, callers should use the formats-libarchive lrzip open path instead.
pub fn materialize_lrzip(path: &Path) -> Result<(NamedTempFile, u64)> {
    let bin = find_lrzip_bin().ok_or_else(|| CompressError::Msg(LRZIP_CLI_MISSING_MSG.into()))?;

    let tmp = NamedTempFile::new()?;
    let out_path = tmp.path().to_path_buf();

    let mut cmd = Command::new(bin);
    if bin == "lrzip" {
        cmd.args(["-d", "-f", "-o"]);
    } else {
        // lrunzip decompresses by default; -f overwrites the empty NamedTempFile.
        cmd.args(["-f", "-o"]);
    }
    cmd.arg(&out_path).arg(path);

    let status = cmd.status().map_err(|e| {
        if e.kind() == io::ErrorKind::NotFound {
            CompressError::Msg(LRZIP_CLI_MISSING_MSG.into())
        } else {
            CompressError::Msg(format!("failed to run {bin}: {e}"))
        }
    })?;

    if !status.success() {
        return Err(CompressError::Msg(format!(
            "{bin} failed to decompress {} (exit {:?})",
            path.display(),
            status.code()
        )));
    }

    let n = std::fs::metadata(&out_path)
        .map_err(|e| CompressError::Msg(format!("{bin} output stat failed: {e}")))?
        .len();
    tmp.as_file().seek(SeekFrom::Start(0))?;

    debug!(
        "materialized lrzip {} -> {} ({} bytes) via {}",
        path.display(),
        out_path.display(),
        n,
        bin
    );
    Ok((tmp, n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;
    use std::path::PathBuf;

    fn py_test(name: &str) -> PathBuf {
        let root = std::env::var("RATARMOUNT_PY_ROOT")
            .unwrap_or_else(|_| "/home/mbrewer/projects/ratarmount".into());
        PathBuf::from(root).join("tests").join(name)
    }

    #[test]
    fn detect_lrzip_magic() {
        assert!(looks_like_lrzip(b"LRZI\x00\x06"));
        assert!(!looks_like_lrzip(b"LRZI")); // too short
        assert!(!looks_like_lrzip(b"LZIP\x01"));
        assert!(!looks_like_lrzip(b""));
    }

    #[test]
    fn detect_simple_lrz_file_magic() {
        let path = py_test("simple.lrz");
        if !path.exists() {
            return;
        }
        let mut magic = [0u8; 5];
        let mut f = File::open(&path).unwrap();
        f.read_exact(&mut magic).unwrap();
        assert!(looks_like_lrzip(&magic));
    }

    #[test]
    fn materialize_simple_lrz() {
        if !lrzip_cli_available() {
            eprintln!("skip: lrzip/lrunzip not on PATH");
            return;
        }
        let path = py_test("simple.lrz");
        if !path.exists() {
            eprintln!("skip: missing {}", path.display());
            return;
        }
        let (tmp, size) = materialize_lrzip(&path).unwrap();
        assert_eq!(size, 12);
        let text = std::fs::read_to_string(tmp.path()).unwrap();
        assert_eq!(text, "foo fighter\n");
    }

    #[test]
    fn materialize_missing_binary_errors_clearly() {
        if lrzip_cli_available() {
            return;
        }
        let path = py_test("simple.lrz");
        if !path.exists() {
            return;
        }
        let err = materialize_lrzip(&path).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("lrzip not installed")
                || msg.contains("PATH")
                || msg.contains("libarchive"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn lrzip_cli_available_matches_available() {
        assert_eq!(lrzip_available(), lrzip_cli_available());
    }
}
