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
    check_tarstats_matches_remote, hash_hex, invalidate_meta_cache_file,
    invalidate_meta_cache_identity, is_meta_cache_path, materialize_index_file,
    maybe_fetch_index_url, object_store_sibling_index_candidates, parse_index_pointer_json,
    parse_link_describedby, resolve_index_location, sha256_hex_stream, sibling_index_candidates,
    sibling_index_id_candidates, sibling_index_pointer_url, SqliteIndex, TARSTATS_FULL_HASH_MAX,
    TARSTATS_SAMPLE_BYTES,
};

use super::{open_from_live_range, open_path};

/// K12: explicit `--index-file` / local folder candidates (including `oci:{digest}`
/// cache) then GET `{url}.index.ptr` + immutable blob, HTTP `Link` on archive HEAD,
/// http(s) well-known sibling GET, S3/GCS/Azure well-known sibling GET, OCI
/// referrer on local miss. Fail-open. Pointer/blob/tarstats failure continues.
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
        if try_http_pointer_then_blob(opts, input, archive_size, cache_dest.as_deref()) {
            return;
        }
        match ratarmount_remote::probe_http(input) {
            Ok(probe) => {
                if let Some(header) = probe.link.as_deref() {
                    if let Some(url) = parse_link_describedby(header, input) {
                        log::debug!("index Link describedby={}", redact_remote_url(&url));
                        if try_fetch_http_index(
                            opts,
                            &url,
                            archive_size,
                            input,
                            cache_dest.as_deref(),
                            None,
                        ) {
                            return;
                        }
                    }
                }
                for cand in sibling_index_candidates(input) {
                    if try_fetch_http_index(
                        opts,
                        &cand,
                        archive_size,
                        input,
                        cache_dest.as_deref(),
                        None,
                    ) {
                        return;
                    }
                    log::debug!("index sibling unusable: {}", redact_remote_url(&cand));
                }
            }
            Err(e) => log::debug!("archive HEAD for index discovery failed: {e}"),
        }
        return;
    }

    if ratarmount_remote::is_object_store_archive_url(input) {
        if try_object_store_pointer_then_blob(opts, input, archive_size, cache_dest.as_deref()) {
            return;
        }
        for cand in object_store_sibling_index_candidates(input) {
            if try_fetch_object_store_index(
                opts,
                &cand,
                archive_size,
                input,
                cache_dest.as_deref(),
                None,
            ) {
                return;
            }
            log::debug!("index sibling unusable: {}", redact_remote_url(&cand));
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

/// `{url}.index.ptr` is JSON; reject unbounded GETs on a cache-miss remount.
const INDEX_POINTER_MAX_BYTES: u64 = 64 * 1024;

enum PointerErr {
    /// 404 / empty / NoSuchKey — common when no pointer was published.
    Miss(String),
    /// Schema / id / oversized body — attacker-controlled or corrupt pointer.
    Invalid(String),
}

fn redact_remote_url(s: &str) -> String {
    let Some((scheme, rest)) = s.split_once("://") else {
        return s.to_string();
    };
    let Some(at) = rest.find('@') else {
        return s.to_string();
    };
    let userinfo = &rest[..at];
    let hostpart = &rest[at + 1..];
    if let Some((user, _)) = userinfo.split_once(':') {
        format!("{scheme}://{user}:***@{hostpart}")
    } else {
        s.to_string()
    }
}

fn pointer_err_is_miss(msg: &str) -> bool {
    let l = msg.to_ascii_lowercase();
    l.contains("404")
        || l.contains("nosuchkey")
        || l.contains("not found")
        || l.contains("empty pointer")
}

fn log_pointer_err(url: &str, err: PointerErr) {
    let url = redact_remote_url(url);
    match err {
        PointerErr::Miss(e) => {
            log::debug!("index pointer GET {url}: {e}; continue discovery");
        }
        PointerErr::Invalid(e) => {
            log::warn!("index pointer GET {url}: {e}; continue discovery");
        }
    }
}

fn try_http_pointer_then_blob(
    opts: &mut OpenOptions,
    archive_url: &str,
    archive_size: u64,
    cache_dest: Option<&Path>,
) -> bool {
    let Some(ptr_url) = sibling_index_pointer_url(archive_url) else {
        return false;
    };
    match fetch_http_pointer(&ptr_url) {
        Ok(ptr) => {
            for cand in sibling_index_id_candidates(archive_url, &ptr.index_id) {
                if try_fetch_http_index(
                    opts,
                    &cand,
                    archive_size,
                    archive_url,
                    cache_dest,
                    Some(&ptr.index_id),
                ) {
                    return true;
                }
            }
            log::warn!(
                "index pointer blob unusable for {}; continue discovery",
                ptr.index_id
            );
            false
        }
        Err(e) => {
            log_pointer_err(&ptr_url, e);
            false
        }
    }
}

fn fetch_http_pointer(
    url: &str,
) -> std::result::Result<ratarmount_index::IndexPointer, PointerErr> {
    let bytes =
        ratarmount_remote::fetch_http_bytes_capped(url, INDEX_POINTER_MAX_BYTES).map_err(|e| {
            let msg = e.to_string();
            if pointer_err_is_miss(&msg) {
                PointerErr::Miss(msg)
            } else if msg.contains("exceeds") {
                PointerErr::Invalid(msg)
            } else {
                PointerErr::Miss(msg)
            }
        })?;
    if bytes.is_empty() {
        return Err(PointerErr::Miss("empty pointer body".into()));
    }
    let s = String::from_utf8(bytes)
        .map_err(|e| PointerErr::Invalid(format!("pointer is not utf-8: {e}")))?;
    parse_index_pointer_json(&s).map_err(|e| PointerErr::Invalid(e.to_string()))
}

fn try_object_store_pointer_then_blob(
    opts: &mut OpenOptions,
    archive_url: &str,
    archive_size: u64,
    cache_dest: Option<&Path>,
) -> bool {
    let Some(ptr_url) = sibling_index_pointer_url(archive_url) else {
        return false;
    };
    match fetch_object_store_pointer(&ptr_url) {
        Ok(ptr) => {
            for cand in sibling_index_id_candidates(archive_url, &ptr.index_id) {
                if try_fetch_object_store_index(
                    opts,
                    &cand,
                    archive_size,
                    archive_url,
                    cache_dest,
                    Some(&ptr.index_id),
                ) {
                    return true;
                }
            }
            log::warn!(
                "index pointer blob unusable for {}; continue discovery",
                ptr.index_id
            );
            false
        }
        Err(e) => {
            log_pointer_err(&ptr_url, e);
            false
        }
    }
}

fn fetch_object_store_pointer(
    url: &str,
) -> std::result::Result<ratarmount_index::IndexPointer, PointerErr> {
    let bytes = fetch_object_store_pointer_bytes(url)?;
    if bytes.is_empty() {
        return Err(PointerErr::Miss("empty pointer body".into()));
    }
    let s = String::from_utf8(bytes)
        .map_err(|e| PointerErr::Invalid(format!("pointer is not utf-8: {e}")))?;
    parse_index_pointer_json(&s).map_err(|e| PointerErr::Invalid(e.to_string()))
}

fn fetch_object_store_pointer_bytes(url: &str) -> std::result::Result<Vec<u8>, PointerErr> {
    let end = INDEX_POINTER_MAX_BYTES.saturating_sub(1);
    let ranged = if url.starts_with("s3://") {
        ratarmount_remote::fetch_s3_range_bytes(url, 0, end)
    } else if url.starts_with("gs://") {
        ratarmount_remote::fetch_gcs_range_bytes(url, 0, end)
    } else if url.starts_with("az://") || url.starts_with("azure://") {
        ratarmount_remote::fetch_azure_range_bytes(url, 0, end)
    } else {
        Err(ratarmount_remote::RemoteError::UnsupportedScheme(
            url.to_string(),
        ))
    };
    match ranged {
        Ok(b) => {
            if b.len() as u64 >= INDEX_POINTER_MAX_BYTES {
                return Err(PointerErr::Invalid("pointer body too large".into()));
            }
            Ok(b)
        }
        Err(e) => {
            let msg = e.to_string();
            if pointer_err_is_miss(&msg) {
                return Err(PointerErr::Miss(msg));
            }
            let path = ratarmount_remote::fetch_index_sibling_to_temp(url).map_err(|e2| {
                let m = e2.to_string();
                if pointer_err_is_miss(&m) {
                    PointerErr::Miss(m)
                } else {
                    PointerErr::Invalid(m)
                }
            })?;
            let n = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            if n > INDEX_POINTER_MAX_BYTES {
                let _ = std::fs::remove_file(&path);
                return Err(PointerErr::Invalid("pointer body too large".into()));
            }
            let bytes = std::fs::read(&path);
            let _ = std::fs::remove_file(&path);
            bytes.map_err(|e| PointerErr::Invalid(e.to_string()))
        }
    }
}

fn keep_http_index_temp(tmp: tempfile::NamedTempFile) -> std::result::Result<PathBuf, String> {
    tmp.into_temp_path().keep().map_err(|e| e.error.to_string())
}

fn materialize_fetched_index(path: PathBuf) -> std::result::Result<PathBuf, String> {
    match materialize_index_file(&path) {
        Ok(p) => {
            if p != path {
                let _ = std::fs::remove_file(&path);
            }
            Ok(p)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&path);
            Err(e.to_string())
        }
    }
}

fn blob_matches_index_id(path: &Path, expected: &str) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    match sha256_hex_stream(&mut f) {
        Ok(got) => got.eq_ignore_ascii_case(expected),
        Err(_) => false,
    }
}

fn try_fetch_http_index(
    opts: &mut OpenOptions,
    index_url: &str,
    archive_size: u64,
    archive_url: &str,
    cache_dest: Option<&Path>,
    expected_id: Option<&str>,
) -> bool {
    match ratarmount_remote::fetch_http_to_temp(index_url) {
        Ok((tmp, n)) => {
            if n == 0 {
                log::debug!("index fetch {}: empty body", redact_remote_url(index_url));
                return false;
            }
            let path = match keep_http_index_temp(tmp).and_then(materialize_fetched_index) {
                Ok(p) => p,
                Err(e) => {
                    log::debug!("index fetch {}: {e}", redact_remote_url(index_url));
                    return false;
                }
            };
            if let Some(id) = expected_id {
                if !blob_matches_index_id(&path, id) {
                    log::warn!("index blob sha256 != pointer {id}; continue discovery");
                    let _ = std::fs::remove_file(&path);
                    return false;
                }
            }
            let (prefix, suffix, full) = http_fingerprint(archive_url, archive_size);
            let ok = try_install_remote_index(
                opts,
                path,
                archive_size,
                prefix.as_deref(),
                suffix.as_deref(),
                full.as_deref(),
                cache_dest,
            );
            if !ok {
                // Wire blob may be gzip/zstd in meta-v3 while `path` is a
                // decompressed tempfile — invalidate by URL, not opened path.
                invalidate_meta_cache_identity("http", index_url);
            }
            ok
        }
        Err(e) => {
            log::debug!("index fetch {}: {e}", redact_remote_url(index_url));
            false
        }
    }
}

fn try_fetch_object_store_index(
    opts: &mut OpenOptions,
    index_url: &str,
    archive_size: u64,
    archive_url: &str,
    cache_dest: Option<&Path>,
    expected_id: Option<&str>,
) -> bool {
    match ratarmount_remote::fetch_index_sibling_to_temp(index_url) {
        Ok(path) => {
            let path = match materialize_fetched_index(path) {
                Ok(p) => p,
                Err(e) => {
                    log::debug!("index materialize {}: {e}", redact_remote_url(index_url));
                    return false;
                }
            };
            if let Some(id) = expected_id {
                if !blob_matches_index_id(&path, id) {
                    log::warn!("index blob sha256 != pointer {id}; continue discovery");
                    let _ = std::fs::remove_file(&path);
                    return false;
                }
            }
            let (prefix, suffix, full) = object_store_fingerprint(archive_url, archive_size);
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
            log::debug!("index fetch {}: {e}", redact_remote_url(index_url));
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
            drop_fetched_sidecar(&fetched);
            return false;
        }
        Err(e) => {
            log::debug!("remote index open failed: {e}");
            drop_fetched_sidecar(&fetched);
            return false;
        }
    };
    if let Err(e) = check_tarstats_matches_remote(&stored, archive_size, prefix, suffix, full) {
        log::warn!("remote archive fingerprint mismatch ({e}); cold index");
        drop_fetched_sidecar(&fetched);
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
                    // Keep the V-3 XDG blob so a remount without the local
                    // well-known copy (and without `.ptr`) still cache-hits.
                    if !is_meta_cache_path(&fetched) {
                        let _ = std::fs::remove_file(&fetched);
                    }
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

fn drop_fetched_sidecar(fetched: &Path) {
    if is_meta_cache_path(fetched) {
        invalidate_meta_cache_file(fetched);
    } else {
        let _ = std::fs::remove_file(fetched);
    }
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

fn object_store_fingerprint(
    url: &str,
    size: u64,
) -> (Option<String>, Option<String>, Option<String>) {
    if size == 0 {
        return (None, None, None);
    }
    let fetch = |start: u64, end: u64| -> Option<Vec<u8>> {
        if url.starts_with("s3://") {
            ratarmount_remote::fetch_s3_range_bytes(url, start, end).ok()
        } else if url.starts_with("gs://") {
            ratarmount_remote::fetch_gcs_range_bytes(url, start, end).ok()
        } else if url.starts_with("az://") || url.starts_with("azure://") {
            ratarmount_remote::fetch_azure_range_bytes(url, start, end).ok()
        } else {
            None
        }
    };
    let prefix_end = (TARSTATS_SAMPLE_BYTES as u64)
        .saturating_sub(1)
        .min(size.saturating_sub(1));
    let prefix = fetch(0, prefix_end).and_then(|b| hash_hex("sha256", &b));
    let suffix = if size as usize <= TARSTATS_SAMPLE_BYTES {
        prefix.clone()
    } else {
        let start = size.saturating_sub(TARSTATS_SAMPLE_BYTES as u64);
        fetch(start, size.saturating_sub(1)).and_then(|b| hash_hex("sha256", &b))
    };
    let full = if size <= TARSTATS_FULL_HASH_MAX {
        fetch(0, size.saturating_sub(1)).and_then(|b| hash_hex("sha256", &b))
    } else {
        None
    };
    if prefix.is_none() && size <= TARSTATS_FULL_HASH_MAX {
        if let Some(bytes) = object_store_full_bytes(url, size) {
            let prefix_n = TARSTATS_SAMPLE_BYTES.min(bytes.len());
            let prefix = hash_hex("sha256", &bytes[..prefix_n]);
            let suffix = if bytes.len() <= TARSTATS_SAMPLE_BYTES {
                prefix.clone()
            } else {
                hash_hex(
                    "sha256",
                    &bytes[bytes.len().saturating_sub(TARSTATS_SAMPLE_BYTES)..],
                )
            };
            let full = hash_hex("sha256", &bytes);
            return (prefix, suffix, full);
        }
    }
    (prefix, suffix, full)
}

fn object_store_full_bytes(url: &str, size: u64) -> Option<Vec<u8>> {
    if size == 0 || size > TARSTATS_FULL_HASH_MAX {
        return None;
    }
    let (mut tmp, n) = if url.starts_with("s3://") {
        ratarmount_remote::fetch_s3_to_temp(url).ok()?
    } else if url.starts_with("gs://") {
        ratarmount_remote::fetch_gcs_to_temp(url).ok()?
    } else if url.starts_with("az://") || url.starts_with("azure://") {
        ratarmount_remote::fetch_azure_to_temp(url).ok()?
    } else {
        return None;
    };
    if n != size {
        return None;
    }
    let mut buf = Vec::with_capacity(n as usize);
    tmp.read_to_end(&mut buf).ok()?;
    Some(buf)
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
            let mut opts = opts.clone();
            apply_remote_index_discovery(input, &mut opts, recreate, len, None);
            match open_from_live_range(range, len, input, &opts, recreate, transport, || {
                reopen().map_err(|e| e.to_string())
            })? {
                Some(opened) => Ok(opened),
                None => {
                    eprintln!("info: {transport} format unsupported for {input}; materializing");
                    materialize_remote_input(input, &opts, recreate, remotes)
                }
            }
        }
        Ok(range) => {
            let len = range.body_len();
            eprintln!(
                "info: {transport} unavailable for {input} (full body buffered); materializing"
            );
            let mut opts = opts.clone();
            apply_remote_index_discovery(input, &mut opts, recreate, len, None);
            drop(range);
            materialize_remote_input(input, &opts, recreate, remotes)
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

    static REMOTE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_isolated_xdg<R>(f: impl FnOnce() -> R) -> R {
        let _g = REMOTE_ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let old_xdg = std::env::var_os("XDG_CACHE_HOME");
        let old_cap = std::env::var_os(ratarmount_index::META_CACHE_BYTES_ENV);
        std::env::set_var("XDG_CACHE_HOME", dir.path());
        std::env::remove_var(ratarmount_index::META_CACHE_BYTES_ENV);
        let r = f();
        match old_xdg {
            Some(v) => std::env::set_var("XDG_CACHE_HOME", v),
            None => std::env::remove_var("XDG_CACHE_HOME"),
        }
        match old_cap {
            Some(v) => std::env::set_var(ratarmount_index::META_CACHE_BYTES_ENV, v),
            None => std::env::remove_var(ratarmount_index::META_CACHE_BYTES_ENV),
        }
        r
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

    fn make_sidecar_for(archive: &Path) -> Vec<u8> {
        let dir = archive.parent().unwrap();
        let idx_path = dir.join(format!(
            "{}.sidecar.sqlite",
            archive.file_name().unwrap().to_string_lossy()
        ));
        {
            let mut idx = SqliteIndex::create_writable(Some(&idx_path)).unwrap();
            idx.store_tarstats_for_path(archive).unwrap();
            idx.publish_tmp().unwrap();
        }
        fs::read(&idx_path).unwrap()
    }

    fn pointer_json_for_blob(blob: &[u8]) -> Vec<u8> {
        use ratarmount_index::{INDEX_ID_HEX_LEN, INDEX_POINTER_SCHEMA};
        let id = ratarmount_index::sha256_hex(blob);
        assert_eq!(id.len(), INDEX_ID_HEX_LEN);
        format!(
            r#"{{"schema":"{INDEX_POINTER_SCHEMA}","index_id":"{id}","etag_sha256":"{id}","generated_at":"2026-01-01T00:00:00Z"}}"#
        )
        .into_bytes()
    }

    struct IndexHttp {
        addr: std::net::SocketAddr,
        gets: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        _join: std::thread::JoinHandle<()>,
    }

    fn spawn_index_http(
        archive_path: &str,
        archive_bytes: Vec<u8>,
        objects: std::collections::HashMap<String, Vec<u8>>,
        link_on_archive: Option<String>,
        require_cookie: Option<String>,
    ) -> IndexHttp {
        use std::io::{BufRead, BufReader, Write as IoWrite};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let gets = Arc::new(Mutex::new(Vec::new()));
        let gets_c = Arc::clone(&gets);
        let archive_path = archive_path.to_string();
        let join = thread::spawn(move || {
            listener.set_nonblocking(false).ok();
            for stream in listener.incoming().take(64) {
                let Ok(mut stream) = stream else { continue };
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut request_line = String::new();
                if reader.read_line(&mut request_line).is_err() {
                    continue;
                }
                let mut range_hdr: Option<String> = None;
                let mut cookie_hdr: Option<String> = None;
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
                    if let Some(v) = line.strip_prefix("Cookie:") {
                        cookie_hdr = Some(v.trim().to_string());
                    }
                }
                if let Some(ref want) = require_cookie {
                    if cookie_hdr.as_deref() != Some(want.as_str()) {
                        let msg = b"Unauthorized";
                        let _ = write!(
                            stream,
                            "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            msg.len()
                        );
                        let _ = stream.write_all(msg);
                        continue;
                    }
                }
                let path = request_line
                    .split_whitespace()
                    .nth(1)
                    .unwrap_or("")
                    .split('?')
                    .next()
                    .unwrap_or("")
                    .to_string();
                {
                    gets_c.lock().unwrap().push(path.clone());
                }
                let is_head = request_line.starts_with("HEAD ");
                let is_archive = path == archive_path;
                let body: &[u8] = if is_archive {
                    &archive_bytes
                } else if let Some(b) = objects.get(&path) {
                    b
                } else {
                    let msg = b"not found";
                    let _ = write!(
                        stream,
                        "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        msg.len()
                    );
                    if !is_head {
                        let _ = stream.write_all(msg);
                    }
                    continue;
                };
                let body_owned = body.to_vec();
                let mut range_off: Option<(usize, usize)> = None;
                if let Some(r) = range_hdr.as_deref().and_then(|r| r.strip_prefix("bytes=")) {
                    let parts: Vec<&str> = r.splitn(2, '-').collect();
                    if parts.len() == 2 {
                        let start: usize = parts[0].parse().unwrap_or(0);
                        let end: usize = if parts[1].is_empty() {
                            body_owned.len().saturating_sub(1)
                        } else {
                            parts[1]
                                .parse()
                                .unwrap_or(0)
                                .min(body_owned.len().saturating_sub(1))
                        };
                        if start < body_owned.len() && start <= end {
                            range_off = Some((start, end));
                        }
                    }
                }
                let slice = match range_off {
                    Some((s, e)) => &body_owned[s..=e],
                    None => body_owned.as_slice(),
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
                        body_owned.len()
                    ));
                }
                if is_archive {
                    if let Some(ref link) = link_on_archive {
                        hdr.push_str(&format!("Link: {link}\r\n"));
                    }
                }
                hdr.push_str("\r\n");
                let _ = stream.write_all(hdr.as_bytes());
                if !is_head {
                    let _ = stream.write_all(slice);
                }
            }
        });
        IndexHttp {
            addr,
            gets,
            _join: join,
        }
    }

    fn empty_index_folders(dir: &Path) -> Vec<PathBuf> {
        let folders = vec![dir.join("empty-index-folders")];
        fs::create_dir_all(&folders[0]).unwrap();
        folders
    }

    fn well_known_get_logged(gets: &[String], archive_path: &str) -> bool {
        let well = format!("{archive_path}.index.sqlite");
        gets.iter()
            .any(|g| g == &well || g.starts_with(&format!("{well}.")))
    }

    /// Regression: inbound HEAD of an **archive** URL with `Link: describedby`
    /// fetches the sidecar when local folder candidates miss (pointer 404 continues).
    #[test]
    fn apply_remote_index_discovery_follows_archive_link() {
        use ratarmount_index::{INDEX_LINK_REL, INDEX_MEDIA_TYPE};

        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("archive.tar");
        let archive_bytes = vec![b'A'; 1024];
        fs::write(&archive, &archive_bytes).unwrap();
        let index_bytes = make_sidecar_for(&archive);
        let folders = empty_index_folders(dir.path());
        let link = format!(
            "</archive.tar.index.sqlite>; rel=\"{INDEX_LINK_REL}\"; type=\"{INDEX_MEDIA_TYPE}\""
        );
        let mut objects = std::collections::HashMap::new();
        objects.insert("/archive.tar.index.sqlite".into(), index_bytes.clone());
        let http = spawn_index_http(
            "/archive.tar",
            archive_bytes.clone(),
            objects,
            Some(link),
            None,
        );

        let url = format!("http://{}/archive.tar", http.addr);
        let mut opts = OpenOptions {
            index_folders: folders,
            write_index: false,
            ..OpenOptions::default()
        };
        apply_remote_index_discovery(&url, &mut opts, false, archive_bytes.len() as u64, None);
        drop(http._join);
        let got = opts
            .index_file_path
            .as_ref()
            .expect("Link describedby must install a sidecar");
        assert!(got.is_file(), "{}", got.display());
        assert_eq!(fs::metadata(got).unwrap().len(), index_bytes.len() as u64);
        let gets = http.gets.lock().unwrap().clone();
        assert!(
            gets.iter().any(|g| g.ends_with(".index.ptr")),
            "pointer is an additional candidate (404 continues); gets={gets:?}"
        );
    }

    /// Regression: pointer + blob + tarstats success skips well-known GET.
    #[test]
    fn apply_remote_index_discovery_pointer_blob_skips_well_known() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("archive.tar");
        let archive_bytes = vec![b'B'; 1024];
        fs::write(&archive, &archive_bytes).unwrap();
        let index_bytes = make_sidecar_for(&archive);
        let id = ratarmount_index::sha256_hex(&index_bytes);
        let ptr = pointer_json_for_blob(&index_bytes);
        let folders = empty_index_folders(dir.path());
        let mut objects = std::collections::HashMap::new();
        objects.insert("/archive.tar.index.ptr".into(), ptr);
        objects.insert(
            format!("/archive.tar.index.{id}.sqlite"),
            index_bytes.clone(),
        );
        objects.insert(
            "/archive.tar.index.sqlite".into(),
            b"SQLite format 3\0must-not-fetch".to_vec(),
        );
        let http = spawn_index_http("/archive.tar", archive_bytes.clone(), objects, None, None);

        let url = format!("http://{}/archive.tar", http.addr);
        let mut opts = OpenOptions {
            index_folders: folders,
            write_index: false,
            ..OpenOptions::default()
        };
        apply_remote_index_discovery(&url, &mut opts, false, archive_bytes.len() as u64, None);
        drop(http._join);
        let got = opts
            .index_file_path
            .as_ref()
            .expect("pointer blob must install a sidecar");
        assert_eq!(fs::metadata(got).unwrap().len(), index_bytes.len() as u64);
        let gets = http.gets.lock().unwrap().clone();
        assert!(
            !well_known_get_logged(&gets, "/archive.tar"),
            "well-known GET must be skipped on pointer+blob+tarstats hit; gets={gets:?}"
        );
    }

    /// Regression: pointer 404 still finds describedby.
    #[test]
    fn apply_remote_index_discovery_pointer_404_falls_back_describedby() {
        use ratarmount_index::{INDEX_LINK_REL, INDEX_MEDIA_TYPE};

        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("archive.tar");
        let archive_bytes = vec![b'C'; 1024];
        fs::write(&archive, &archive_bytes).unwrap();
        let index_bytes = make_sidecar_for(&archive);
        let folders = empty_index_folders(dir.path());
        let link = format!(
            "</archive.tar.index.sqlite>; rel=\"{INDEX_LINK_REL}\"; type=\"{INDEX_MEDIA_TYPE}\""
        );
        let mut objects = std::collections::HashMap::new();
        objects.insert("/archive.tar.index.sqlite".into(), index_bytes.clone());
        let http = spawn_index_http(
            "/archive.tar",
            archive_bytes.clone(),
            objects,
            Some(link),
            None,
        );

        let url = format!("http://{}/archive.tar", http.addr);
        let mut opts = OpenOptions {
            index_folders: folders,
            write_index: false,
            ..OpenOptions::default()
        };
        apply_remote_index_discovery(&url, &mut opts, false, archive_bytes.len() as u64, None);
        drop(http._join);
        assert!(
            opts.index_file_path.is_some(),
            "describedby must still install after pointer 404"
        );
    }

    /// Regression: pointer blob tarstats mismatch continues to well-known sibling.
    #[test]
    fn apply_remote_index_discovery_pointer_tarstats_fail_falls_back_well_known() {
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("good.tar");
        let bad = dir.path().join("bad.tar");
        let archive_bytes = vec![b'D'; 1024];
        fs::write(&good, &archive_bytes).unwrap();
        fs::write(&bad, vec![b'X'; 64]).unwrap();
        let good_idx = make_sidecar_for(&good);
        let bad_idx = make_sidecar_for(&bad);
        let bad_id = ratarmount_index::sha256_hex(&bad_idx);
        let ptr = pointer_json_for_blob(&bad_idx);
        let folders = empty_index_folders(dir.path());
        let mut objects = std::collections::HashMap::new();
        objects.insert("/archive.tar.index.ptr".into(), ptr);
        objects.insert(format!("/archive.tar.index.{bad_id}.sqlite"), bad_idx);
        objects.insert("/archive.tar.index.sqlite".into(), good_idx.clone());
        let http = spawn_index_http("/archive.tar", archive_bytes.clone(), objects, None, None);

        let url = format!("http://{}/archive.tar", http.addr);
        let mut opts = OpenOptions {
            index_folders: folders,
            write_index: false,
            ..OpenOptions::default()
        };
        apply_remote_index_discovery(&url, &mut opts, false, archive_bytes.len() as u64, None);
        drop(http._join);
        let got = opts
            .index_file_path
            .as_ref()
            .expect("well-known must install after pointer tarstats fail");
        assert_eq!(fs::metadata(got).unwrap().len(), good_idx.len() as u64);
        let gets = http.gets.lock().unwrap().clone();
        assert!(
            well_known_get_logged(&gets, "/archive.tar"),
            "well-known GET after tarstats fail; gets={gets:?}"
        );
    }

    /// Regression: HTTP pointer + blob use the authenticated client (Cookie).
    #[test]
    fn apply_remote_index_discovery_http_cookie_pointer_and_blob() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("archive.tar");
        let archive_bytes = vec![b'K'; 1024];
        fs::write(&archive, &archive_bytes).unwrap();
        let index_bytes = make_sidecar_for(&archive);
        let id = ratarmount_index::sha256_hex(&index_bytes);
        let ptr = pointer_json_for_blob(&index_bytes);
        let folders = empty_index_folders(dir.path());
        let mut objects = std::collections::HashMap::new();
        objects.insert("/archive.tar.index.ptr".into(), ptr);
        objects.insert(
            format!("/archive.tar.index.{id}.sqlite"),
            index_bytes.clone(),
        );
        let cookie = "session=index-secret";
        let http = spawn_index_http(
            "/archive.tar",
            archive_bytes.clone(),
            objects,
            None,
            Some(cookie.into()),
        );
        let _g = EnvGuard::acquire(&[
            ratarmount_remote::HTTP_COOKIE_ENV,
            ratarmount_remote::HTTP_COOKIE_FILE_ENV,
        ]);
        _g.set(ratarmount_remote::HTTP_COOKIE_ENV, cookie);

        let url = format!("http://{}/archive.tar", http.addr);
        let mut opts = OpenOptions {
            index_folders: folders,
            write_index: false,
            ..OpenOptions::default()
        };
        apply_remote_index_discovery(&url, &mut opts, false, archive_bytes.len() as u64, None);
        drop(http._join);
        assert!(
            opts.index_file_path.is_some(),
            "cookie-gated pointer+blob must install"
        );
    }

    /// Regression: pointer blob sha256 ≠ index_id continues to well-known.
    #[test]
    fn apply_remote_index_discovery_pointer_blob_id_mismatch_falls_back_well_known() {
        let dir = tempfile::tempdir().unwrap();
        let good = dir.path().join("good.tar");
        let other = dir.path().join("other.tar");
        let archive_bytes = vec![b'M'; 1024];
        fs::write(&good, &archive_bytes).unwrap();
        fs::write(&other, vec![b'Y'; 64]).unwrap();
        let good_idx = make_sidecar_for(&good);
        let other_idx = make_sidecar_for(&other);
        let fake_id = "a".repeat(64);
        let ptr = format!(
            r#"{{"schema":"{}","index_id":"{fake_id}","etag_sha256":"{fake_id}","generated_at":"2026-01-01T00:00:00Z"}}"#,
            ratarmount_index::INDEX_POINTER_SCHEMA
        )
        .into_bytes();
        let folders = empty_index_folders(dir.path());
        let mut objects = std::collections::HashMap::new();
        objects.insert("/archive.tar.index.ptr".into(), ptr);
        objects.insert(format!("/archive.tar.index.{fake_id}.sqlite"), other_idx);
        objects.insert("/archive.tar.index.sqlite".into(), good_idx.clone());
        let http = spawn_index_http("/archive.tar", archive_bytes.clone(), objects, None, None);

        let url = format!("http://{}/archive.tar", http.addr);
        let mut opts = OpenOptions {
            index_folders: folders,
            write_index: false,
            ..OpenOptions::default()
        };
        apply_remote_index_discovery(&url, &mut opts, false, archive_bytes.len() as u64, None);
        drop(http._join);
        let got = opts
            .index_file_path
            .as_ref()
            .expect("well-known after blob id mismatch");
        assert_eq!(fs::metadata(got).unwrap().len(), good_idx.len() as u64);
    }

    #[test]
    fn redact_remote_url_strips_userinfo_password() {
        assert_eq!(
            redact_remote_url("https://user:secret@host/a.tar.index.ptr"),
            "https://user:***@host/a.tar.index.ptr"
        );
        assert_eq!(
            redact_remote_url("s3://bucket/key.index.ptr"),
            "s3://bucket/key.index.ptr"
        );
    }

    struct S3Index {
        addr: std::net::SocketAddr,
        gets: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        _join: std::thread::JoinHandle<()>,
    }

    fn spawn_s3_index(
        objects: std::collections::HashMap<String, Vec<u8>>,
        honor_range: bool,
    ) -> S3Index {
        use std::io::{BufRead, BufReader, Write as IoWrite};
        use std::net::TcpListener;
        use std::sync::{Arc, Mutex};
        use std::thread;

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let gets = Arc::new(Mutex::new(Vec::new()));
        let gets_c = Arc::clone(&gets);
        let join = thread::spawn(move || {
            for stream in listener.incoming().take(64) {
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
                let key = path
                    .trim_start_matches('/')
                    .split_once('/')
                    .map(|(_, k)| k.split('?').next().unwrap_or(k).to_string())
                    .unwrap_or_default();
                gets_c.lock().unwrap().push(key.clone());
                let Some(body) = objects.get(&key) else {
                    let msg = b"NoSuchKey";
                    let _ = write!(
                        stream,
                        "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        msg.len()
                    );
                    let _ = stream.write_all(msg);
                    continue;
                };
                let mut range_off = None;
                if honor_range {
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
                }
                let slice = match range_off {
                    Some((s, e)) => &body[s..=e],
                    None => body.as_slice(),
                };
                if let Some((s, e)) = range_off {
                    let _ = write!(
                        stream,
                        "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {s}-{e}/{}\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                        body.len(),
                        slice.len()
                    );
                } else {
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                        slice.len()
                    );
                }
                let _ = stream.write_all(slice);
            }
        });
        S3Index {
            addr,
            gets,
            _join: join,
        }
    }

    const AWS_TEST_ENV: &[&str] = &[
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_ENDPOINT_URL",
        "S3_ENDPOINT_URL",
        "AWS_ANONYMOUS",
        "RATARMOUNT_S3_ANONYMOUS",
        "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
        "AWS_CONTAINER_CREDENTIALS_FULL_URI",
        "RATARMOUNT_IMDS_BASE",
    ];

    fn bind_anon_s3(endpoint: &str) -> EnvGuard {
        let g = EnvGuard::acquire(AWS_TEST_ENV);
        g.set("AWS_ANONYMOUS", "1");
        g.set("AWS_ENDPOINT_URL", endpoint);
        g.set("RATARMOUNT_IMDS_BASE", "http://127.0.0.1:1");
        g
    }

    /// Regression: S3 pointer + blob + tarstats success skips well-known GET.
    #[test]
    fn apply_remote_index_discovery_s3_pointer_blob_skips_well_known() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        let archive_bytes = vec![b'S'; 1024];
        fs::write(&archive, &archive_bytes).unwrap();
        let index_bytes = make_sidecar_for(&archive);
        let id = ratarmount_index::sha256_hex(&index_bytes);
        let ptr = pointer_json_for_blob(&index_bytes);
        let folders = empty_index_folders(dir.path());

        let mut objects = std::collections::HashMap::new();
        objects.insert("data/a.tar".into(), archive_bytes.clone());
        objects.insert("data/a.tar.index.ptr".into(), ptr);
        objects.insert(format!("data/a.tar.index.{id}.sqlite"), index_bytes.clone());
        objects.insert(
            "data/a.tar.index.sqlite".into(),
            b"SQLite format 3\0s3-well-known".to_vec(),
        );
        let s3 = spawn_s3_index(objects, true);
        let _g = bind_anon_s3(&format!("http://{}", s3.addr));

        let url = "s3://bucket/data/a.tar";
        let mut opts = OpenOptions {
            index_folders: folders,
            write_index: false,
            ..OpenOptions::default()
        };
        apply_remote_index_discovery(url, &mut opts, false, archive_bytes.len() as u64, None);
        drop(s3._join);
        let got = opts
            .index_file_path
            .as_ref()
            .expect("S3 pointer blob must install a sidecar");
        assert_eq!(fs::metadata(got).unwrap().len(), index_bytes.len() as u64);
        let logged = s3.gets.lock().unwrap().clone();
        assert!(
            !logged.iter().any(|k| k == "data/a.tar.index.sqlite"),
            "S3 well-known GET must be skipped; gets={logged:?}"
        );
    }

    /// Regression: S3 pointer 404 still installs well-known `{url}.index.sqlite`.
    #[test]
    fn apply_remote_index_discovery_s3_pointer_404_falls_back_well_known() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        let archive_bytes = vec![b'W'; 1024];
        fs::write(&archive, &archive_bytes).unwrap();
        let index_bytes = make_sidecar_for(&archive);
        let folders = empty_index_folders(dir.path());

        let mut objects = std::collections::HashMap::new();
        objects.insert("data/a.tar".into(), archive_bytes.clone());
        objects.insert("data/a.tar.index.sqlite".into(), index_bytes.clone());
        let s3 = spawn_s3_index(objects, true);
        let _g = bind_anon_s3(&format!("http://{}", s3.addr));

        let url = "s3://bucket/data/a.tar";
        let mut opts = OpenOptions {
            index_folders: folders,
            write_index: false,
            ..OpenOptions::default()
        };
        apply_remote_index_discovery(url, &mut opts, false, archive_bytes.len() as u64, None);
        drop(s3._join);
        let got = opts
            .index_file_path
            .as_ref()
            .expect("S3 well-known must install after pointer 404");
        assert_eq!(fs::metadata(got).unwrap().len(), index_bytes.len() as u64);
        let logged = s3.gets.lock().unwrap().clone();
        assert!(
            logged.iter().any(|k| k == "data/a.tar.index.sqlite"),
            "well-known GET after pointer 404; gets={logged:?}"
        );
    }

    /// Regression: Range-ignored S3 still fingerprints via full GET when size is small.
    #[test]
    fn apply_remote_index_discovery_s3_range_ignored_full_hash() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("a.tar");
        let archive_bytes = vec![b'R'; 1024];
        fs::write(&archive, &archive_bytes).unwrap();
        let index_bytes = make_sidecar_for(&archive);
        let id = ratarmount_index::sha256_hex(&index_bytes);
        let ptr = pointer_json_for_blob(&index_bytes);
        let folders = empty_index_folders(dir.path());

        let mut objects = std::collections::HashMap::new();
        objects.insert("data/a.tar".into(), archive_bytes.clone());
        objects.insert("data/a.tar.index.ptr".into(), ptr);
        objects.insert(format!("data/a.tar.index.{id}.sqlite"), index_bytes.clone());
        let s3 = spawn_s3_index(objects, false);
        let _g = bind_anon_s3(&format!("http://{}", s3.addr));

        let url = "s3://bucket/data/a.tar";
        let mut opts = OpenOptions {
            index_folders: folders,
            write_index: false,
            ..OpenOptions::default()
        };
        apply_remote_index_discovery(url, &mut opts, false, archive_bytes.len() as u64, None);
        drop(s3._join);
        assert!(
            opts.index_file_path.is_some(),
            "pointer blob must install when Range is ignored (full GET hash)"
        );
    }

    static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvGuard {
        saved: Vec<(String, Option<String>)>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn acquire(keys: &[&str]) -> Self {
            let lock = TEST_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let mut saved = Vec::new();
            for &k in keys {
                saved.push((k.to_string(), std::env::var(k).ok()));
                std::env::remove_var(k);
            }
            Self { saved, _lock: lock }
        }

        fn set(&self, key: &str, val: &str) {
            std::env::set_var(key, val);
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in self.saved.drain(..) {
                match v {
                    Some(val) => std::env::set_var(&k, val),
                    None => std::env::remove_var(&k),
                }
            }
        }
    }
    #[test]
    fn apply_remote_index_well_known_sidecar_cache_hit() {
        with_isolated_xdg(|| {
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

            let http = SidecarHttp::spawn(archive_bytes.clone(), index_bytes.clone());
            let mut opts = OpenOptions {
                index_folders: folders.clone(),
                write_index: false,
                ..OpenOptions::default()
            };
            apply_remote_index_discovery(
                &http.url,
                &mut opts,
                false,
                archive_bytes.len() as u64,
                None,
            );
            let first = opts
                .index_file_path
                .take()
                .expect("well-known sibling must install a sidecar");
            assert!(first.is_file(), "{}", first.display());
            let gets1 = http.sidecar_gets();
            assert!(gets1 >= 1, "first remount must GET the sidecar");

            // Drop the local well-known copy so the second discovery cannot
            // `path_is_nonempty_file` short-circuit. No `.ptr` is published.
            let _ = fs::remove_file(&first);
            apply_remote_index_discovery(
                &http.url,
                &mut opts,
                false,
                archive_bytes.len() as u64,
                None,
            );
            let second = opts
                .index_file_path
                .as_ref()
                .expect("V-3 cache hit must reinstall without .ptr");
            assert!(second.is_file(), "{}", second.display());
            assert_eq!(
                http.sidecar_gets(),
                gets1,
                "second remount must not GET the sidecar again"
            );
        });
    }

    /// Regression: local `path_is_nonempty_file` still skips network (no double-cache).
    #[test]
    fn apply_remote_index_local_copy_skips_network() {
        with_isolated_xdg(|| {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join("archive.tar");
            let archive_bytes = vec![b'B'; 1024];
            fs::write(&archive, &archive_bytes).unwrap();
            let idx_path = dir.path().join("sidecar.sqlite");
            {
                let idx = SqliteIndex::create_writable(Some(&idx_path)).unwrap();
                idx.store_tarstats_for_path(&archive).unwrap();
            }
            let index_bytes = fs::read(&idx_path).unwrap();
            let folders = vec![dir.path().join("idx-folders")];
            fs::create_dir_all(&folders[0]).unwrap();

            let http = SidecarHttp::spawn(archive_bytes.clone(), index_bytes.clone());
            let mut opts = OpenOptions {
                index_folders: folders,
                write_index: false,
                ..OpenOptions::default()
            };
            apply_remote_index_discovery(
                &http.url,
                &mut opts,
                false,
                archive_bytes.len() as u64,
                None,
            );
            assert!(opts.index_file_path.as_ref().unwrap().is_file());
            let gets1 = http.sidecar_gets();
            opts.index_file_path = None;
            apply_remote_index_discovery(
                &http.url,
                &mut opts,
                false,
                archive_bytes.len() as u64,
                None,
            );
            assert_eq!(
                http.sidecar_gets(),
                gets1,
                "local nonempty sidecar must skip remote GET"
            );
        });
    }

    /// Regression: gzip sibling tarstats mismatch must drop the XDG wire blob
    /// so the next discovery GETs again (not a sticky decompressed-temp miss).
    #[test]
    fn apply_remote_index_gzip_tarstats_mismatch_refetches() {
        with_isolated_xdg(|| {
            let dir = tempfile::tempdir().unwrap();
            let archive = dir.path().join("archive.tar");
            let archive_bytes = vec![b'C'; 1024];
            fs::write(&archive, &archive_bytes).unwrap();
            let idx_path = dir.path().join("sidecar.sqlite");
            {
                let idx = SqliteIndex::create_writable(Some(&idx_path)).unwrap();
                idx.store_tarstats_for_path(&archive).unwrap();
            }
            let gz = Command::new("gzip")
                .arg("-c")
                .arg(&idx_path)
                .output()
                .expect("spawn gzip");
            if !gz.status.success() {
                eprintln!("skip: gzip CLI unavailable");
                return;
            }
            let folders = vec![dir.path().join("idx-folders")];
            fs::create_dir_all(&folders[0]).unwrap();
            let http = SidecarHttp::spawn_gzip(archive_bytes.clone(), gz.stdout);
            let mut opts = OpenOptions {
                index_folders: folders,
                write_index: false,
                ..OpenOptions::default()
            };
            // Wrong archive size → tarstats fail after decompress.
            apply_remote_index_discovery(&http.url, &mut opts, false, 2048, None);
            assert!(
                opts.index_file_path.is_none(),
                "mismatched gzip sidecar must not install"
            );
            let gets1 = http.sidecar_gets();
            assert!(gets1 >= 1, "first discovery must GET the gzip sidecar");
            apply_remote_index_discovery(&http.url, &mut opts, false, 2048, None);
            assert_eq!(
                http.sidecar_gets(),
                gets1 + 1,
                "gzip tarstats fail must invalidate XDG and GET again"
            );
        });
    }

}
