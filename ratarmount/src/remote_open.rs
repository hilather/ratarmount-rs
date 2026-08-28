//! Remote URL open helpers (HTTP/S3 Range, materialize, Dropbox/F-1 folders, OCI).
//!
//! Extracted from [`super`] so protocol PRs can add directory vs file
//! dispatch here without growing `factory.rs`.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use ratarmount_compositing::OciImageMountSource;
use ratarmount_core::{MountSource, OpenOptions};
use ratarmount_index::{
    check_tarstats_matches_remote, hash_hex, maybe_fetch_index_url, parse_link_describedby,
    resolve_index_location, sha256_hex_stream, sibling_index_candidates, SqliteIndex,
    TARSTATS_FULL_HASH_MAX, TARSTATS_SAMPLE_BYTES,
};

use super::{open_from_live_range, open_path};

/// K12: explicit `--index-file` / local folder candidates (including `oci:{digest}`
/// cache) then HTTP `Link` on archive HEAD, http(s) sibling GET, OCI referrer on
/// local miss. Fail-open. No S3 sibling GET. Wrong-size sidecar is not used.
fn apply_remote_index_discovery(
    input: &str,
    opts: &mut OpenOptions,
    recreate: bool,
    archive_size: u64,
    oci: Option<(
        &ratarmount_remote::OciLocation,
        &ratarmount_remote::OciLayer,
    )>,
) {
    if recreate || opts.clear_index_cache || opts.index_in_memory {
        return;
    }
    if opts.index_file_path.is_some() {
        return;
    }
    let loc = resolve_index_location(Path::new(input), None, &opts.index_folders, false);
    if let Some(p) = loc.as_path() {
        if path_is_nonempty_file(p) {
            log::debug!("local index cache hit; skip remote discovery ({input})");
            return;
        }
    }
    let cache_dest = loc.as_path().map(Path::to_path_buf);

    if input.starts_with("http://") || input.starts_with("https://") {
        match ratarmount_remote::probe_http(input) {
            Ok(probe) => {
                if let Some(header) = probe.link.as_deref() {
                    if let Some(url) = parse_link_describedby(header, input) {
                        log::debug!("index Link describedby={url}");
                        if try_fetch_http_index(
                            opts,
                            &url,
                            archive_size,
                            input,
                            cache_dest.as_deref(),
                        ) {
                            return;
                        }
                    }
                }
                for cand in sibling_index_candidates(input) {
                    if try_fetch_http_index(opts, &cand, archive_size, input, cache_dest.as_deref())
                    {
                        return;
                    }
                    log::debug!("index sibling unusable: {cand}");
                }
            }
            Err(e) => log::debug!("archive HEAD for index discovery failed: {e}"),
        }
        return;
    }

    if let Some((oloc, layer)) = oci {
        match ratarmount_remote::fetch_oci_index_referrer(
            oloc,
            &layer.digest,
            layer.bearer(),
            cache_dest.as_deref(),
        ) {
            Ok(Some(path)) => {
                let (prefix, suffix, full) = oci_fingerprint(layer, archive_size);
                let _ = try_install_remote_index(
                    opts,
                    path,
                    archive_size,
                    prefix.as_deref(),
                    suffix.as_deref(),
                    full.as_deref(),
                    cache_dest.as_deref(),
                );
            }
            Ok(None) => {}
            Err(e) => log::debug!("OCI referrer miss: {e}"),
        }
    }
}

fn path_is_nonempty_file(path: &Path) -> bool {
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.len() > 0)
        .unwrap_or(false)
}

fn try_fetch_http_index(
    opts: &mut OpenOptions,
    index_url: &str,
    archive_size: u64,
    archive_url: &str,
    cache_dest: Option<&Path>,
) -> bool {
    match maybe_fetch_index_url(index_url) {
        Ok(path) => {
            let (prefix, suffix, full) = http_fingerprint(archive_url, archive_size);
            try_install_remote_index(
                opts,
                path,
                archive_size,
                prefix.as_deref(),
                suffix.as_deref(),
                full.as_deref(),
                cache_dest,
            )
        }
        Err(e) => {
            log::debug!("index fetch {index_url}: {e}");
            false
        }
    }
}

fn try_install_remote_index(
    opts: &mut OpenOptions,
    fetched: PathBuf,
    archive_size: u64,
    prefix: Option<&str>,
    suffix: Option<&str>,
    full: Option<&str>,
    cache_dest: Option<&Path>,
) -> bool {
    let stored = match SqliteIndex::open_read_only(&fetched).and_then(|idx| idx.tarstats()) {
        Ok(Some(s)) => s,
        Ok(None) => {
            log::warn!("remote index missing tarstats; not using sidecar");
            let _ = std::fs::remove_file(&fetched);
            return false;
        }
        Err(e) => {
            log::debug!("remote index open failed: {e}");
            let _ = std::fs::remove_file(&fetched);
            return false;
        }
    };
    if let Err(e) = check_tarstats_matches_remote(&stored, archive_size, prefix, suffix, full) {
        log::warn!("remote archive fingerprint mismatch ({e}); cold index");
        let _ = std::fs::remove_file(&fetched);
        return false;
    }
    let dest = match cache_dest {
        Some(d) if d != fetched.as_path() => {
            if let Some(parent) = d.parent() {
                if !parent.as_os_str().is_empty() {
                    let _ = std::fs::create_dir_all(parent);
                }
            }
            match std::fs::copy(&fetched, d) {
                Ok(_) => {
                    let _ = std::fs::remove_file(&fetched);
                    d.to_path_buf()
                }
                Err(_) => fetched,
            }
        }
        _ => fetched,
    };
    opts.index_file_path = Some(dest);
    true
}

fn http_fingerprint(url: &str, size: u64) -> (Option<String>, Option<String>, Option<String>) {
    if size == 0 {
        return (None, None, None);
    }
    let prefix_end = (TARSTATS_SAMPLE_BYTES as u64)
        .saturating_sub(1)
        .min(size.saturating_sub(1));
    let prefix = ratarmount_remote::fetch_http_range_bytes(url, 0, prefix_end)
        .ok()
        .and_then(|b| hash_hex("sha256", &b));
    let suffix = if size as usize <= TARSTATS_SAMPLE_BYTES {
        prefix.clone()
    } else {
        let start = size.saturating_sub(TARSTATS_SAMPLE_BYTES as u64);
        ratarmount_remote::fetch_http_range_bytes(url, start, size.saturating_sub(1))
            .ok()
            .and_then(|b| hash_hex("sha256", &b))
    };
    let full = if size <= TARSTATS_FULL_HASH_MAX {
        ratarmount_remote::hash_http_range_sha256(url, 0, size.saturating_sub(1)).ok()
    } else {
        None
    };
    (prefix, suffix, full)
}

fn oci_fingerprint(
    layer: &ratarmount_remote::OciLayer,
    size: u64,
) -> (Option<String>, Option<String>, Option<String>) {
    if size == 0 {
        return (None, None, None);
    }
    let Ok(mut blob) = layer.open_blob() else {
        return (None, None, None);
    };
    let prefix_n = TARSTATS_SAMPLE_BYTES.min(size as usize);
    let mut prefix_buf = vec![0u8; prefix_n];
    if blob.read_exact(&mut prefix_buf).is_err() {
        return (None, None, None);
    }
    let prefix = hash_hex("sha256", &prefix_buf);
    let suffix = if size as usize <= TARSTATS_SAMPLE_BYTES {
        prefix.clone()
    } else {
        let mut suffix_buf = vec![0u8; TARSTATS_SAMPLE_BYTES];
        match blob.seek(SeekFrom::End(-(TARSTATS_SAMPLE_BYTES as i64))) {
            Ok(_) if blob.read_exact(&mut suffix_buf).is_ok() => hash_hex("sha256", &suffix_buf),
            _ => None,
        }
    };
    let full = if size <= TARSTATS_FULL_HASH_MAX {
        if blob.seek(SeekFrom::Start(0)).is_ok() {
            sha256_hex_stream(&mut blob).ok()
        } else {
            None
        }
    } else {
        None
    };
    (prefix, suffix, full)
}

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
            let mut opts = opts.clone();
            apply_remote_index_discovery(input, &mut opts, recreate, len, None);
            let input_owned = input.to_string();
            match open_from_live_range(range, len, input, &opts, recreate, "HTTP Range", || {
                // Buffered fallback is still Read+Seek-usable for rebuild.
                ratarmount_remote::open_http_range(&input_owned).map_err(|e| e.to_string())
            })? {
                Some(opened) => Ok(opened),
                None => materialize_remote_input(input, &opts, recreate, remotes),
            }
        }
        RemoteAccess::Http(RemoteHttp::Materialized(remote)) => {
            let path = remote.path().to_path_buf();
            let len = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            let mut opts = opts.clone();
            apply_remote_index_discovery(input, &mut opts, recreate, len, None);
            remotes.push(remote);
            let src = open_path(&path, &opts, recreate)?;
            Ok((path, src))
        }
        RemoteAccess::Path(remote) => {
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
        let mut layer_opts = opts.clone();
        apply_remote_index_discovery(
            &label,
            &mut layer_opts,
            recreate,
            layer.size,
            Some((&image.location, layer)),
        );
        let body = layer.open_blob().map_err(|e| e.to_string())?;
        let reopen_layer = layer.clone();
        match open_from_live_range(
            body,
            layer.size,
            &label,
            &layer_opts,
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

/// F-1 (`s3` / `ssh` / `webdav` / `http`) plus later-scheme folder openers
/// (`gs` / `az` / `rclone` / `ipfs` / `ftp` / `ftps`).
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
        "ftp" | "ftps" => ratarmount_remote::open_ftp_folder(input).map_err(|e| e.to_string()),
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

    /// Regression: `ftp://` / `ftps://` directory URLs dispatch to `open_ftp_folder`
    /// (file URLs still return `Ok(None)` from that opener; live LIST is crate-tested).
    #[test]
    fn try_open_remote_folder_url_dispatches_ftp_scheme() {
        for input in ["ftp://", "ftps://"] {
            assert!(
                try_open_remote_folder_url(input).is_err(),
                "{input} must hit the FTP folder arm (error), not Ok(None)"
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

    /// Regression: inbound HEAD of an **archive** URL with `Link: describedby`
    /// fetches the sidecar when local folder candidates miss.
    #[test]
    fn apply_remote_index_discovery_follows_archive_link() {
        use ratarmount_index::{SqliteIndex, INDEX_LINK_REL, INDEX_MEDIA_TYPE};
        use std::io::{BufRead, BufReader, Write as IoWrite};
        use std::net::TcpListener;
        use std::thread;

        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("archive.tar");
        let archive_bytes = vec![b'A'; 1024];
        fs::write(&archive, &archive_bytes).unwrap();
        let idx_path = dir.path().join("sidecar.sqlite");
        {
            let idx = SqliteIndex::create_writable(Some(&idx_path)).unwrap();
            idx.store_tarstats_for_path(&archive).unwrap();
        }
        let index_bytes = fs::read(&idx_path).unwrap();
        let folders = vec![dir.path().join("empty-index-folders")];
        fs::create_dir_all(&folders[0]).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let archive_body = archive_bytes.clone();
        let index_body = index_bytes.clone();
        let join = thread::spawn(move || {
            listener.set_nonblocking(false).ok();
            for stream in listener.incoming().take(32) {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() {
                    continue;
                }
                let mut range_hdr: Option<String> = None;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).is_err() {
                        break;
                    }
                    if line == "\r\n" || line == "\n" || line.is_empty() {
                        break;
                    }
                    if let Some(v) = line.strip_prefix("Range:") {
                        range_hdr = Some(v.trim().to_string());
                    }
                }
                let path = request_line.split_whitespace().nth(1).unwrap_or("");
                let is_head = request_line.starts_with("HEAD ");
                let is_index = path.contains("index.sqlite");
                let body: &[u8] = if is_index { &index_body } else { &archive_body };
                let mut range_off: Option<(usize, usize)> = None;
                if let Some(r) = range_hdr.as_deref().and_then(|r| r.strip_prefix("bytes=")) {
                    let parts: Vec<&str> = r.splitn(2, '-').collect();
                    if parts.len() == 2 {
                        let start: usize = parts[0].parse().unwrap_or(0);
                        let end: usize = if parts[1].is_empty() {
                            body.len().saturating_sub(1)
                        } else {
                            parts[1]
                                .parse()
                                .unwrap_or(0)
                                .min(body.len().saturating_sub(1))
                        };
                        if start < body.len() && start <= end {
                            range_off = Some((start, end));
                        }
                    }
                }
                let slice = match range_off {
                    Some((s, e)) => &body[s..=e],
                    None => body,
                };
                let status = if range_off.is_some() {
                    "206 Partial Content"
                } else {
                    "200 OK"
                };
                let mut hdr = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n",
                    slice.len()
                );
                if let Some((start, end)) = range_off {
                    hdr.push_str(&format!(
                        "Content-Range: bytes {start}-{end}/{}\r\n",
                        body.len()
                    ));
                }
                if !is_index {
                    hdr.push_str(&format!(
                        "Link: </archive.tar.index.sqlite>; rel=\"{INDEX_LINK_REL}\"; type=\"{INDEX_MEDIA_TYPE}\"\r\n"
                    ));
                }
                hdr.push_str("\r\n");
                let _ = stream.write_all(hdr.as_bytes());
                if !is_head {
                    let _ = stream.write_all(slice);
                }
            }
        });

        let url = format!("http://{addr}/archive.tar");
        let mut opts = OpenOptions {
            index_folders: folders,
            write_index: false,
            ..OpenOptions::default()
        };
        apply_remote_index_discovery(&url, &mut opts, false, archive_bytes.len() as u64, None);
        drop(join);
        let got = opts
            .index_file_path
            .as_ref()
            .expect("Link describedby must install a sidecar");
        assert!(got.is_file(), "{}", got.display());
        assert_eq!(fs::metadata(got).unwrap().len(), index_bytes.len() as u64);
    }
}
