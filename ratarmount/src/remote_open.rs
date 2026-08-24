//! Remote URL open helpers (HTTP/S3 Range, materialize, Dropbox folders).
//!
//! Extracted from [`super`] so later protocol PRs can add directory vs file
//! dispatch here without growing `factory.rs`.

use std::path::PathBuf;
use std::sync::Arc;

use ratarmount_core::{MountSource, OpenOptions};

use super::{open_from_live_range, open_path};

/// Materialize a remote URL to a local path and open it.
pub(super) fn materialize_remote_input(
    input: &str,
    opts: &OpenOptions,
    recreate: bool,
    remotes: &mut Vec<ratarmount_remote::RemoteLocal>,
) -> Result<(PathBuf, Arc<dyn MountSource>), String> {
    let remote = ratarmount_remote::resolve_to_local(input).map_err(|e| e.to_string())?;
    let path = remote.path().to_path_buf();
    remotes.push(remote);
    let src = open_path(&path, opts, recreate)?;
    Ok((path, src))
}

/// Open a remote URL: prefer live HTTP/S3 Range for TAR/ZIP/codecs; else materialize.
pub(super) fn open_remote_input(
    input: &str,
    opts: &OpenOptions,
    recreate: bool,
    remotes: &mut Vec<ratarmount_remote::RemoteLocal>,
) -> Result<(PathBuf, Arc<dyn MountSource>), String> {
    use ratarmount_remote::{open_s3_range, resolve_access, RemoteAccess, RemoteHttp};

    // F-1 directory mounts (s3 / ssh / webdav / http only). Files fall through.
    if let Some(ms) = try_open_f1_folder(input)? {
        return Ok((PathBuf::from(input), ms));
    }

    // Live S3 Range I/O (parallel to HTTP Range) when GetObject Range works.
    if input.starts_with("s3://") {
        match open_s3_range(input) {
            Ok(range) if range.uses_ranges() => {
                let len = range.len();
                eprintln!("S3 Range: {input} ({len} bytes, live Range GetObject)");
                let input_owned = input.to_string();
                match open_from_live_range(range, len, input, opts, recreate, "S3 Range", || {
                    open_s3_range(&input_owned)
                        .map_err(|e| e.to_string())
                        .and_then(|r| {
                            if r.uses_ranges() {
                                Ok(r)
                            } else {
                                Err("S3 Range reopen lost live Range support".into())
                            }
                        })
                })? {
                    Some(opened) => return Ok(opened),
                    None => {
                        eprintln!("info: S3 Range format unsupported for {input}; materializing");
                        return materialize_remote_input(input, opts, recreate, remotes);
                    }
                }
            }
            Ok(_) => {
                eprintln!(
                    "info: S3 Range unavailable for {input} (full body buffered); materializing"
                );
                return materialize_remote_input(input, opts, recreate, remotes);
            }
            Err(e) => {
                eprintln!("info: S3 Range open failed for {input}: {e}; materializing");
                return materialize_remote_input(input, opts, recreate, remotes);
            }
        }
    }

    let access = resolve_access(input).map_err(|e| e.to_string())?;
    match access {
        RemoteAccess::Http(RemoteHttp::Range(range)) => {
            let len = range.len();
            let input_owned = input.to_string();
            match open_from_live_range(range, len, input, opts, recreate, "HTTP Range", || {
                // Buffered fallback is still Read+Seek-usable for rebuild.
                ratarmount_remote::open_http_range(&input_owned).map_err(|e| e.to_string())
            })? {
                Some(opened) => Ok(opened),
                None => materialize_remote_input(input, opts, recreate, remotes),
            }
        }
        RemoteAccess::Http(RemoteHttp::Materialized(remote)) | RemoteAccess::Path(remote) => {
            let path = remote.path().to_path_buf();
            remotes.push(remote);
            let src = open_path(&path, opts, recreate)?;
            Ok((path, src))
        }
    }
}

/// F-1 remote directory probe (`s3` / `ssh` / `webdav` / `http` only).
///
/// Returns `Ok(None)` for other schemes and for file URLs of those schemes.
fn try_open_f1_folder(input: &str) -> Result<Option<Arc<dyn MountSource>>, String> {
    let scheme = input
        .split_once("://")
        .map(|(s, _)| s)
        .unwrap_or("")
        .to_ascii_lowercase();
    if !matches!(
        scheme.as_str(),
        "s3" | "ssh" | "sftp" | "scp" | "webdav" | "webdavs" | "http" | "https"
    ) {
        return Ok(None);
    }
    ratarmount_remote::try_open_remote_folder(input).map_err(|e| e.to_string())
}

/// Dropbox folders: browse via API (list + download-on-open).
///
/// Returns `Ok(None)` when `input` is not a Dropbox URL, or when it names a
/// Dropbox *file* (caller should fall through to Range/materialize).
pub(super) fn try_open_dropbox_folder(input: &str) -> Result<Option<Arc<dyn MountSource>>, String> {
    if !(input.starts_with("dropbox://") || input.starts_with("dropbox:")) {
        return Ok(None);
    }
    match ratarmount_remote::DropboxMountSource::open(input) {
        Ok(ms) => Ok(Some(Arc::new(ms))),
        Err(e) => {
            let msg = e.to_string();
            // File paths: materialize via resolve_to_local below.
            if !msg.contains("is a file, not a folder") {
                return Err(msg);
            }
            Ok(None)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_open_dropbox_folder_ignores_non_dropbox() {
        for input in [
            "https://example.com/a.tar",
            "s3://bucket/key",
            "/local/path",
            "ssh://host/path",
            "webdav://host/dir/",
        ] {
            assert!(
                try_open_dropbox_folder(input).unwrap().is_none(),
                "{input} must not be treated as a Dropbox folder"
            );
        }
    }

    #[test]
    fn try_open_f1_folder_ignores_non_f1_schemes() {
        for input in [
            "dropbox:///vault",
            "smb://host/share/a.tar",
            "ftp://host/dir/",
            "/local/path",
            "file:///tmp/x",
        ] {
            assert!(
                try_open_f1_folder(input).unwrap().is_none(),
                "{input} must not be probed as an F-1 folder"
            );
        }
    }
}
