//! Remote URL open helpers (HTTP/S3 Range, materialize, Dropbox/F-1 folders, OCI).
//!
//! Extracted from [`super`] so protocol PRs can add directory vs file
//! dispatch here without growing `factory.rs`.

use std::io::{Read, Seek};
use std::path::PathBuf;
use std::sync::Arc;

use ratarmount_compositing::OciImageMountSource;
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

/// Open a remote URL: folder probe, live Range, OCI layer union, else materialize.
pub(super) fn open_remote_input(
    input: &str,
    opts: &OpenOptions,
    recreate: bool,
    remotes: &mut Vec<ratarmount_remote::RemoteLocal>,
) -> Result<(PathBuf, Arc<dyn MountSource>), String> {
    use ratarmount_remote::{
        open_azure_range, open_ftp_range, open_gcs_range, open_ipfs, open_rclone, open_s3_range,
        resolve_access, RemoteAccess, RemoteHttp,
    };

    if let Some(ms) = try_open_remote_folder_url(input)? {
        return Ok((PathBuf::from(input), ms));
    }

    if is_oci_scheme(input) {
        return open_oci_image(input, opts, recreate);
    }

    // Live S3 Range I/O (parallel to HTTP Range) when GetObject Range works.
    if input.starts_with("s3://") {
        return open_s3_like(
            input,
            opts,
            recreate,
            remotes,
            "S3 Range",
            open_s3_range(input),
            || open_s3_range(input),
        );
    }
    if input.starts_with("gs://") {
        return open_s3_like(
            input,
            opts,
            recreate,
            remotes,
            "GCS Range",
            open_gcs_range(input),
            || open_gcs_range(input),
        );
    }
    if input.starts_with("az://") || input.starts_with("azure://") {
        return open_s3_like(
            input,
            opts,
            recreate,
            remotes,
            "Azure Range",
            open_azure_range(input),
            || open_azure_range(input),
        );
    }
    if input.starts_with("ftp://") || input.starts_with("ftps://") {
        return open_s3_like(
            input,
            opts,
            recreate,
            remotes,
            "FTP Range",
            open_ftp_range(input),
            || open_ftp_range(input),
        );
    }
    if input.starts_with("ipfs://") || input.starts_with("ipns://") {
        return open_s3_like(
            input,
            opts,
            recreate,
            remotes,
            "IPFS Range",
            open_ipfs(input),
            || open_ipfs(input),
        );
    }
    if input.starts_with("rclone://") {
        match open_rclone(input) {
            Ok(handle) => {
                let len = handle.len();
                eprintln!("rclone: {input} ({len} bytes, materialized cat)");
                let input_owned = input.to_string();
                match open_from_live_range(
                    handle,
                    len,
                    input,
                    opts,
                    recreate,
                    "rclone",
                    move || open_rclone(&input_owned).map_err(|e| e.to_string()),
                )? {
                    Some(opened) => return Ok(opened),
                    None => {
                        eprintln!("info: rclone format unsupported for {input}; materializing");
                        return materialize_remote_input(input, opts, recreate, remotes);
                    }
                }
            }
            Err(e) => {
                eprintln!("info: rclone open failed for {input}: {e}; materializing");
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

/// Shared Range-or-materialize path for S3-shaped readers (`uses_ranges` + `len`).
fn open_s3_like<R, Reopen>(
    input: &str,
    opts: &OpenOptions,
    recreate: bool,
    remotes: &mut Vec<ratarmount_remote::RemoteLocal>,
    transport: &str,
    opened: ratarmount_remote::Result<R>,
    reopen: Reopen,
) -> Result<(PathBuf, Arc<dyn MountSource>), String>
where
    R: Read + Seek + Send + 'static + LiveRange,
    Reopen: FnOnce() -> ratarmount_remote::Result<R>,
{
    match opened {
        Ok(range) if range.live_ranges() => {
            let len = range.body_len();
            eprintln!("{transport}: {input} ({len} bytes, live Range)");
            match open_from_live_range(range, len, input, opts, recreate, transport, || {
                reopen().map_err(|e| e.to_string())
            })? {
                Some(opened) => Ok(opened),
                None => {
                    eprintln!("info: {transport} format unsupported for {input}; materializing");
                    materialize_remote_input(input, opts, recreate, remotes)
                }
            }
        }
        Ok(_) => {
            eprintln!(
                "info: {transport} unavailable for {input} (full body buffered); materializing"
            );
            materialize_remote_input(input, opts, recreate, remotes)
        }
        Err(e) => {
            eprintln!("info: {transport} open failed for {input}: {e}; materializing");
            materialize_remote_input(input, opts, recreate, remotes)
        }
    }
}

trait LiveRange {
    fn live_ranges(&self) -> bool;
    fn body_len(&self) -> u64;
}

macro_rules! impl_live_range {
    ($t:ty) => {
        impl LiveRange for $t {
            fn live_ranges(&self) -> bool {
                self.uses_ranges()
            }
            fn body_len(&self) -> u64 {
                self.len()
            }
        }
    };
}

impl_live_range!(ratarmount_remote::S3RangeFile);
impl_live_range!(ratarmount_remote::GcsRangeFile);
impl_live_range!(ratarmount_remote::AzureRangeFile);
impl_live_range!(ratarmount_remote::FtpRangeFile);
impl_live_range!(ratarmount_remote::IpfsHandle);

fn is_oci_scheme(input: &str) -> bool {
    matches!(
        ratarmount_remote::remote_url_scheme(input).as_deref(),
        Some("oci") | Some("docker") | Some("ghcr")
    )
}

/// Fetch OCI manifests and open each layer via live Range + overlayfs union.
fn open_oci_image(
    input: &str,
    opts: &OpenOptions,
    recreate: bool,
) -> Result<(PathBuf, Arc<dyn MountSource>), String> {
    let image = ratarmount_remote::fetch_oci_image(input).map_err(|e| e.to_string())?;
    if image.layers.is_empty() {
        return Err(format!("oci image {input} has no layers"));
    }
    let mut layers: Vec<Arc<dyn MountSource>> = Vec::with_capacity(image.layers.len());
    for layer in &image.layers {
        eprintln!(
            "OCI layer {} ({} bytes, {})",
            layer.digest, layer.size, layer.media_type
        );
        let label = format!("oci:{}", layer.digest);
        let body = layer.open_blob().map_err(|e| e.to_string())?;
        let reopen_layer = layer.clone();
        match open_from_live_range(
            body,
            layer.size,
            &label,
            opts,
            recreate,
            "OCI layer",
            move || reopen_layer.open_blob().map_err(|e| e.to_string()),
        )? {
            Some((_, src)) => layers.push(src),
            None => {
                return Err(format!(
                    "unsupported OCI layer {} ({})",
                    layer.digest, layer.media_type
                ));
            }
        }
    }
    let src = OciImageMountSource::new(layers);
    Ok((PathBuf::from(input), Arc::new(src)))
}

/// F-1 (`s3` / `ssh` / `webdav` / `http`) plus later-scheme folder openers.
///
/// Returns `Ok(None)` for other schemes and for file URLs of those schemes.
fn try_open_remote_folder_url(input: &str) -> Result<Option<Arc<dyn MountSource>>, String> {
    let scheme = ratarmount_remote::remote_url_scheme(input).unwrap_or_default();
    match scheme.as_str() {
        "s3" | "ssh" | "sftp" | "scp" | "webdav" | "webdavs" | "http" | "https" => {
            ratarmount_remote::try_open_remote_folder(input).map_err(|e| e.to_string())
        }
        "gs" => ratarmount_remote::open_gcs_folder(input).map_err(|e| e.to_string()),
        "az" | "azure" => ratarmount_remote::open_azure_folder(input).map_err(|e| e.to_string()),
        "rclone" => ratarmount_remote::open_rclone_folder(input).map_err(|e| e.to_string()),
        "ipfs" | "ipns" => ratarmount_remote::open_ipfs_folder(input).map_err(|e| e.to_string()),
        _ => Ok(None),
    }
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
    use ratarmount_compositing::{FolderMountSource, OciImageMountSource};
    use std::fs;
    use std::io::Cursor;
    use std::process::Command;

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
    fn try_open_remote_folder_url_ignores_non_folder_schemes() {
        for input in [
            "dropbox:///vault",
            "smb://host/share/a.tar",
            "ftp://host/dir/",
            "/local/path",
            "file:///tmp/x",
            "docker://ubuntu:24.04",
            "oci://ghcr.io/org/img:tag",
        ] {
            assert!(
                try_open_remote_folder_url(input).unwrap().is_none(),
                "{input} must not be probed as a remote folder"
            );
        }
    }

    /// Regression: docker://ubuntu:24.04 is not a local path.
    #[test]
    fn docker_ubuntu_is_oci_scheme_not_local() {
        assert!(is_oci_scheme("docker://ubuntu:24.04"));
        assert!(is_oci_scheme("oci://ghcr.io/org/img:tag"));
        assert!(is_oci_scheme("ghcr://org/img:tag"));
        assert!(!is_oci_scheme("https://example.com/a.tar"));
        assert!(ratarmount_remote::is_remote_url("docker://ubuntu:24.04"));
        assert!(
            url::Url::parse("docker://ubuntu:24.04").is_err(),
            "precondition: WHATWG parse fails"
        );
    }

    #[test]
    fn oci_image_mount_source_new_unions_folder_layers() {
        let dir = tempfile::tempdir().unwrap();
        let bottom = dir.path().join("bottom");
        let top = dir.path().join("top");
        fs::create_dir_all(&bottom).unwrap();
        fs::create_dir_all(&top).unwrap();
        fs::write(bottom.join("from-bottom.txt"), b"lower").unwrap();
        fs::write(top.join("from-top.txt"), b"upper").unwrap();
        let img = OciImageMountSource::new(vec![
            Arc::new(FolderMountSource::new(&bottom).unwrap()),
            Arc::new(FolderMountSource::new(&top).unwrap()),
        ]);
        assert!(img.lookup("/from-top.txt", 0).is_some());
        assert!(img.lookup("/from-bottom.txt", 0).is_some());
        assert_eq!(img.layers().len(), 2);
    }

    #[test]
    fn open_from_live_range_gzip_layer_uses_oci_digest_label() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        fs::create_dir_all(&data).unwrap();
        fs::write(data.join("hello.txt"), b"hello-oci-layer\n").unwrap();
        let tar_gz = dir.path().join("layer.tar.gz");
        let status = Command::new("tar")
            .args(["-czf"])
            .arg(&tar_gz)
            .arg("-C")
            .arg(&data)
            .arg("hello.txt")
            .status()
            .expect("spawn tar");
        if !status.success() {
            eprintln!("skip: tar -czf unavailable");
            return;
        }
        let bytes = fs::read(&tar_gz).unwrap();
        let len = bytes.len() as u64;
        let label = "oci:sha256:deadbeef";
        let opts = OpenOptions {
            index_in_memory: true,
            write_index: false,
            ..OpenOptions::default()
        };
        let reopen_bytes = bytes.clone();
        let opened = open_from_live_range(
            Cursor::new(bytes),
            len,
            label,
            &opts,
            false,
            "OCI layer",
            move || Ok(Cursor::new(reopen_bytes)),
        )
        .expect("open gzip layer")
        .expect("gzip live range supported");
        assert_eq!(opened.0, PathBuf::from(label));
        let fi = opened.1.lookup("/hello.txt", 0).expect("layer member");
        let mut r = opened.1.open(&fi, 0).expect("open member");
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut r, &mut buf).unwrap();
        assert_eq!(buf, b"hello-oci-layer\n");
    }
}
