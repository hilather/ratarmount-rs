//! Sibling index objects for S3/GCS/Azure (V-2c GET + S3 PUT primitive).
//!
//! Pointer `{url}.index.ptr` and immutable `{url}.index.{id}.sqlite` are extra
//! GET candidates. S3 PUT of blob-then-pointer is [`publish_index_to_s3`]
//! (F-7 primitive; live overlay commit and CLI `--publish-index` wiring are later).
//! GCS/Azure PUT is residual.

use std::io::Write;
use std::path::{Path, PathBuf};

use tempfile::NamedTempFile;

use crate::{
    fetch_azure_bytes_capped, fetch_azure_to_temp, fetch_gcs_bytes_capped, fetch_gcs_to_temp,
    fetch_s3_bytes_capped, fetch_s3_to_temp, remote_url_scheme, RemoteError, Result,
};

/// G-2 pointer schema (`ratarmount.index.pointer.v1`). Not SOCI; not `INDEX_VERSION`.
pub const INDEX_POINTER_SCHEMA: &str = "ratarmount.index.pointer.v1";

/// SQLite blob media type for `{url}.index.{id}.sqlite` PUT.
pub const INDEX_MEDIA_TYPE: &str = "application/vnd.ratarmount.index.v1+sqlite";

/// V-2 pointer payload for S3 PUT (schema [`INDEX_POINTER_SCHEMA`]).
///
/// Callers typically serialize `ratarmount_index::IndexPointer` into [`Self::json`].
#[derive(Debug, Clone)]
pub struct S3IndexPointer {
    /// 64 lowercase hex SHA-256 of the SQLite blob (`index_id`).
    pub index_id: String,
    /// Pretty-printed pointer JSON (already validated by [`publish_index_to_s3`]).
    pub json: Vec<u8>,
}

/// True for `s3://` / `gs://` / `az://` / `azure://` archive URLs.
pub fn is_object_store_archive_url(url: &str) -> bool {
    let s = url.trim();
    s.starts_with("s3://")
        || s.starts_with("gs://")
        || s.starts_with("az://")
        || s.starts_with("azure://")
}

/// Download a sibling index object to a kept tempfile. GET only — no PUT.
pub fn fetch_index_sibling_to_temp(url: &str) -> Result<PathBuf> {
    let (tmp, _) = fetch_object_store_to_temp(url)?;
    keep_tempfile(tmp)
}

/// Full GET of at most `max_bytes` (no Range). Errors if the body is larger.
///
/// Pointer JSON uses this so a cache-miss remount cannot slurp an unbounded object,
/// including on Range-ignoring gateways.
pub fn fetch_index_sibling_bytes_capped(url: &str, max_bytes: u64) -> Result<Vec<u8>> {
    let s = url.trim();
    if s.starts_with("s3://") {
        fetch_s3_bytes_capped(s, max_bytes)
    } else if s.starts_with("gs://") {
        fetch_gcs_bytes_capped(s, max_bytes)
    } else if s.starts_with("az://") || s.starts_with("azure://") {
        fetch_azure_bytes_capped(s, max_bytes)
    } else {
        Err(RemoteError::UnsupportedScheme(
            remote_url_scheme(s).unwrap_or_else(|| s.to_string()),
        ))
    }
}

fn fetch_object_store_to_temp(url: &str) -> Result<(NamedTempFile, u64)> {
    let s = url.trim();
    if s.starts_with("s3://") {
        fetch_s3_to_temp(s)
    } else if s.starts_with("gs://") {
        fetch_gcs_to_temp(s)
    } else if s.starts_with("az://") || s.starts_with("azure://") {
        fetch_azure_to_temp(s)
    } else {
        Err(RemoteError::UnsupportedScheme(
            remote_url_scheme(s).unwrap_or_else(|| s.to_string()),
        ))
    }
}

fn keep_tempfile(tmp: NamedTempFile) -> Result<PathBuf> {
    tmp.into_temp_path()
        .keep()
        .map_err(|e| RemoteError::Io(e.error))
}

fn parse_index_id(s: &str) -> Result<String> {
    let t = s.trim().to_ascii_lowercase();
    if t.len() != 64 || !t.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(RemoteError::S3(format!(
            "index_id must be 64 lowercase hex sha256(blob), not {s:?}"
        )));
    }
    Ok(t)
}

fn validate_s3_index_pointer(pointer: &S3IndexPointer) -> Result<String> {
    let id = parse_index_id(&pointer.index_id)?;
    let v: serde_json::Value = serde_json::from_slice(&pointer.json)
        .map_err(|e| RemoteError::S3(format!("index pointer JSON: {e}")))?;
    let schema = v.get("schema").and_then(|x| x.as_str()).unwrap_or("");
    if schema != INDEX_POINTER_SCHEMA {
        return Err(RemoteError::S3(format!(
            "index pointer schema {schema:?} (expected {INDEX_POINTER_SCHEMA})"
        )));
    }
    let json_id = v.get("index_id").and_then(|x| x.as_str()).unwrap_or("");
    let json_id = parse_index_id(json_id)?;
    if json_id != id {
        return Err(RemoteError::S3(
            "index pointer JSON index_id must equal pointer.index_id".into(),
        ));
    }
    Ok(id)
}

/// PUT the immutable sqlite blob, then `{url}.index.ptr`. Never pointer-first.
///
/// If the pointer PUT fails after a successful blob PUT, returns `Err` and does
/// **not** claim success. The leftover `{url}.index.{id}.sqlite` is not deleted
/// (documented in the error). Overlay / CLI `--publish-index` wiring is F-7 PR 7.
pub fn publish_index_to_s3(
    archive_url: &str,
    sqlite_path: &Path,
    pointer: &S3IndexPointer,
) -> Result<()> {
    let archive = archive_url.trim();
    if !archive.starts_with("s3://") {
        return Err(RemoteError::S3(
            "publish_index_to_s3 is S3-only in v1 (GCS/Azure PUT residual)".into(),
        ));
    }
    let id = validate_s3_index_pointer(pointer)?;
    if !sqlite_path.is_file() {
        return Err(RemoteError::S3(format!(
            "publish_index_to_s3: {} is not a file",
            sqlite_path.display()
        )));
    }
    let blob_url = format!("{archive}.index.{id}.sqlite");
    let ptr_url = format!("{archive}.index.ptr");
    crate::s3::put_s3_file(&blob_url, sqlite_path, INDEX_MEDIA_TYPE)?;
    let mut tmp = NamedTempFile::new()?;
    tmp.write_all(&pointer.json)?;
    if !pointer.json.ends_with(b"\n") {
        tmp.write_all(b"\n")?;
    }
    tmp.flush()?;
    if let Err(e) = crate::s3::put_s3_file(&ptr_url, tmp.path(), "application/json") {
        return Err(RemoteError::S3(format!(
            "pointer PUT failed after blob PUT of {blob_url} (leftover blob not deleted): {e}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Read, Write as IoWrite};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex as StdMutex};
    use std::thread;

    static ENV_LOCK: StdMutex<()> = StdMutex::new(());

    struct EnvGuard {
        saved: Vec<(String, Option<String>)>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn acquire(keys: &[&str]) -> Self {
            let lock = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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

    const AWS_ENV_KEYS: &[&str] = &[
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
        "AWS_CONTAINER_AUTHORIZATION_TOKEN",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE",
        "RATARMOUNT_IMDS_BASE",
        "AWS_EC2_METADATA_SERVICE_ENDPOINT",
    ];

    /// Path-style mock: GET `/{bucket}/{key}` looks up `key` in `objects`.
    struct MockS3Map {
        base_url: String,
        gets: Arc<StdMutex<Vec<String>>>,
        _join: Option<thread::JoinHandle<()>>,
    }

    impl MockS3Map {
        fn spawn(objects: HashMap<String, Vec<u8>>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base_url = format!("http://{}", listener.local_addr().unwrap());
            let gets = Arc::new(StdMutex::new(Vec::new()));
            let gets_c = Arc::clone(&gets);
            let join = thread::spawn(move || {
                for stream in listener.incoming().take(64) {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).is_err() {
                        continue;
                    }
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).is_err() {
                            break;
                        }
                        if line == "\r\n" || line == "\n" || line.is_empty() {
                            break;
                        }
                    }
                    let path = request_line.split_whitespace().nth(1).unwrap_or("");
                    let key = path
                        .trim_start_matches('/')
                        .split_once('/')
                        .map(|(_, k)| percent_decode(k.split('?').next().unwrap_or(k)))
                        .unwrap_or_default();
                    {
                        gets_c.lock().unwrap().push(key.clone());
                    }
                    if !request_line.starts_with("GET ") {
                        let _ = write!(
                            stream,
                            "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        continue;
                    }
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
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nAccept-Ranges: bytes\r\nConnection: close\r\n\r\n",
                        body.len()
                    );
                    let _ = stream.write_all(body);
                }
            });
            Self {
                base_url,
                gets,
                _join: Some(join),
            }
        }
    }

    fn percent_decode(s: &str) -> String {
        let mut out = Vec::new();
        let b = s.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                if let Ok(v) =
                    u8::from_str_radix(std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or(""), 16)
                {
                    out.push(v);
                    i += 3;
                    continue;
                }
            }
            out.push(b[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn is_object_store_archive_url_schemes() {
        assert!(is_object_store_archive_url("s3://b/k"));
        assert!(is_object_store_archive_url("gs://b/o"));
        assert!(is_object_store_archive_url("az://c/blob"));
        assert!(is_object_store_archive_url("azure://c/blob"));
        assert!(!is_object_store_archive_url("http://h/a.tar"));
        assert!(!is_object_store_archive_url("/local/a.tar"));
    }

    #[test]
    fn fetch_index_sibling_rejects_http() {
        let err = fetch_index_sibling_to_temp("http://example.com/a.tar.index.ptr")
            .unwrap_err()
            .to_string();
        assert!(err.contains("unsupported") || err.contains("http"), "{err}");
    }

    /// Regression: pointer GET then blob GET; well-known sibling is not fetched
    /// unless the caller asks for it.
    #[test]
    fn fetch_s3_pointer_and_blob_skips_well_known() {
        let id = "a".repeat(64);
        let ptr_key = "data/a.tar.index.ptr".to_string();
        let blob_key = format!("data/a.tar.index.{id}.sqlite");
        let well_known = "data/a.tar.index.sqlite".to_string();
        let mut objects = HashMap::new();
        objects.insert(ptr_key, b"{\"schema\":\"ptr\"}".to_vec());
        objects.insert(blob_key, b"SQLite format 3\0blob".to_vec());
        objects.insert(well_known.clone(), b"SQLite format 3\0well-known".to_vec());
        let mock = MockS3Map::spawn(objects);

        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        _g.set("AWS_ANONYMOUS", "1");
        _g.set("AWS_ENDPOINT_URL", &mock.base_url);
        _g.set("RATARMOUNT_IMDS_BASE", "http://127.0.0.1:1");

        let ptr_path = fetch_index_sibling_to_temp("s3://bucket/data/a.tar.index.ptr").unwrap();
        assert_eq!(std::fs::read(&ptr_path).unwrap(), b"{\"schema\":\"ptr\"}");
        let _ = std::fs::remove_file(&ptr_path);

        let blob_url = format!("s3://bucket/data/a.tar.index.{id}.sqlite");
        let blob_path = fetch_index_sibling_to_temp(&blob_url).unwrap();
        assert!(std::fs::read(&blob_path)
            .unwrap()
            .starts_with(b"SQLite format 3\0blob"));
        let _ = std::fs::remove_file(&blob_path);

        let gets = mock.gets.lock().unwrap().clone();
        assert!(
            !gets.iter().any(|k| k == &well_known),
            "well-known GET must not run when only pointer+blob were requested; gets={gets:?}"
        );

        let err = fetch_index_sibling_to_temp("s3://bucket/data/missing.index.ptr")
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("404") || err.contains("NoSuchKey") || err.contains("GetObject"),
            "{err}"
        );
    }

    /// Regression: pointer GET is a capped full GET (`take`), not a 64 KiB Range
    /// that misses short 206 and slurps on HTTP 200.
    #[test]
    fn fetch_s3_pointer_bytes_capped_rejects_oversize() {
        let small = b"{\"schema\":\"ptr\"}".to_vec();
        let huge = vec![b'x'; 80 * 1024];
        let mut objects = HashMap::new();
        objects.insert("data/a.tar.index.ptr".into(), small.clone());
        objects.insert("data/huge.index.ptr".into(), huge);
        let mock = MockS3Map::spawn(objects);

        let _g = EnvGuard::acquire(AWS_ENV_KEYS);
        _g.set("AWS_ANONYMOUS", "1");
        _g.set("AWS_ENDPOINT_URL", &mock.base_url);
        _g.set("RATARMOUNT_IMDS_BASE", "http://127.0.0.1:1");

        let got = fetch_index_sibling_bytes_capped("s3://bucket/data/a.tar.index.ptr", 64 * 1024)
            .unwrap();
        assert_eq!(got, small);
        let err = fetch_index_sibling_bytes_capped("s3://bucket/data/huge.index.ptr", 64 * 1024)
            .unwrap_err()
            .to_string();
        assert!(err.contains("exceeds"), "{err}");
    }

    /// Path-style PUT mock. `fail_ptr` returns HTTP 500 on `{key}.index.ptr`.
    struct MockS3Put {
        base_url: String,
        puts: Arc<StdMutex<Vec<String>>>,
        objects: Arc<StdMutex<HashMap<String, Vec<u8>>>>,
        _join: Option<thread::JoinHandle<()>>,
    }

    impl MockS3Put {
        fn spawn(fail_ptr: bool) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base_url = format!("http://{}", listener.local_addr().unwrap());
            let puts = Arc::new(StdMutex::new(Vec::new()));
            let objects = Arc::new(StdMutex::new(HashMap::new()));
            let puts_c = Arc::clone(&puts);
            let objects_c = Arc::clone(&objects);
            let join = thread::spawn(move || {
                for stream in listener.incoming().take(32) {
                    let Ok(mut stream) = stream else { continue };
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).is_err() {
                        continue;
                    }
                    let mut content_length: u64 = 0;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).is_err() {
                            break;
                        }
                        if line == "\r\n" || line == "\n" || line.is_empty() {
                            break;
                        }
                        let lower = line.to_ascii_lowercase();
                        if let Some(rest) = lower.strip_prefix("content-length:") {
                            content_length = rest.trim().parse().unwrap_or(0);
                        }
                    }
                    let path = request_line.split_whitespace().nth(1).unwrap_or("");
                    let path = path.split('?').next().unwrap_or(path);
                    let key = path
                        .trim_start_matches('/')
                        .split_once('/')
                        .map(|(_, k)| percent_decode(k))
                        .unwrap_or_default();
                    let mut body = vec![0u8; content_length.min(8 * 1024 * 1024) as usize];
                    if !body.is_empty() {
                        let _ = reader.read_exact(&mut body);
                    }
                    if !request_line.starts_with("PUT ") {
                        let _ = write!(
                            stream,
                            "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        continue;
                    }
                    {
                        puts_c.lock().unwrap().push(key.clone());
                    }
                    if fail_ptr && key.ends_with(".index.ptr") {
                        let msg = b"InternalError";
                        let _ = write!(
                            stream,
                            "HTTP/1.1 500 Internal Server Error\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                            msg.len()
                        );
                        let _ = stream.write_all(msg);
                        continue;
                    }
                    objects_c.lock().unwrap().insert(key, body);
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nETag: \"ok\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                }
            });
            Self {
                base_url,
                puts,
                objects,
                _join: Some(join),
            }
        }
    }

    fn sha256_hex_bytes(b: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        format!("{:x}", Sha256::digest(b))
    }

    fn pointer_json(id: &str) -> Vec<u8> {
        format!(
            r#"{{"schema":"{INDEX_POINTER_SCHEMA}","index_id":"{id}","etag_sha256":"{id}","generated_at":"2026-01-01T00:00:00Z"}}"#
        )
        .into_bytes()
    }

    fn env_signed_s3(endpoint: &str) -> EnvGuard {
        let g = EnvGuard::acquire(AWS_ENV_KEYS);
        g.set("AWS_ACCESS_KEY_ID", "AKIAEXAMPLE");
        g.set("AWS_SECRET_ACCESS_KEY", "secretsecretsecretsecretsecr");
        g.set("AWS_ENDPOINT_URL", endpoint);
        g.set("AWS_REGION", "us-east-1");
        g.set("RATARMOUNT_IMDS_BASE", "http://127.0.0.1:1");
        g
    }

    /// Regression: pointer flips only after blob PUT 200 (blob then pointer).
    #[test]
    fn s3_publish_index_blob_then_pointer() {
        let mock = MockS3Put::spawn(false);
        let _g = env_signed_s3(&mock.base_url);
        let blob = b"SQLite format 3\0index-blob";
        let id = sha256_hex_bytes(blob);
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(blob).unwrap();
        tmp.flush().unwrap();
        let pointer = S3IndexPointer {
            index_id: id.clone(),
            json: pointer_json(&id),
        };
        publish_index_to_s3("s3://bucket/data/a.tar", tmp.path(), &pointer).unwrap();
        let puts = mock.puts.lock().unwrap().clone();
        let blob_key = format!("data/a.tar.index.{id}.sqlite");
        assert_eq!(
            puts,
            vec![blob_key.clone(), "data/a.tar.index.ptr".to_string()],
            "blob must PUT before pointer; puts={puts:?}"
        );
        let objects = mock.objects.lock().unwrap();
        assert_eq!(
            objects.get(&blob_key).map(|v| v.as_slice()),
            Some(&blob[..])
        );
        assert!(
            objects.get("data/a.tar.index.ptr").is_some_and(|v| v
                .windows(INDEX_POINTER_SCHEMA.len())
                .any(|w| w == INDEX_POINTER_SCHEMA.as_bytes())),
            "pointer JSON missing schema"
        );
    }

    /// Regression: blob PUT 200 + pointer PUT 500 does not claim success (leftover blob).
    #[test]
    fn s3_publish_index_fail_closed() {
        let mock = MockS3Put::spawn(true);
        let _g = env_signed_s3(&mock.base_url);
        let blob = b"SQLite format 3\0fail-closed";
        let id = sha256_hex_bytes(blob);
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(blob).unwrap();
        tmp.flush().unwrap();
        let pointer = S3IndexPointer {
            index_id: id.clone(),
            json: pointer_json(&id),
        };
        let err = publish_index_to_s3("s3://bucket/data/a.tar", tmp.path(), &pointer)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("leftover blob") && err.contains(".index.") && err.contains(".sqlite"),
            "got: {err}"
        );
        let puts = mock.puts.lock().unwrap().clone();
        let blob_key = format!("data/a.tar.index.{id}.sqlite");
        assert_eq!(puts.first().map(String::as_str), Some(blob_key.as_str()));
        assert!(
            puts.iter().any(|k| k.ends_with(".index.ptr")),
            "pointer PUT must still be attempted; puts={puts:?}"
        );
        let objects = mock.objects.lock().unwrap();
        assert!(
            objects.contains_key(&blob_key),
            "blob must remain after pointer failure"
        );
        assert!(
            !objects.contains_key("data/a.tar.index.ptr"),
            "pointer must not be stored on 500"
        );
    }
}
