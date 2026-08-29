//! GET-only sibling index objects for S3/GCS/Azure (V-2c).
//!
//! Pointer `{url}.index.ptr` and immutable `{url}.index.{id}.sqlite` are extra
//! candidates. Object-store PUT is F-7.

use std::path::PathBuf;

use tempfile::NamedTempFile;

use crate::{
    fetch_azure_bytes_capped, fetch_azure_to_temp, fetch_gcs_bytes_capped, fetch_gcs_to_temp,
    fetch_s3_bytes_capped, fetch_s3_to_temp, remote_url_scheme, RemoteError, Result,
};

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::{BufRead, BufReader, Write as IoWrite};
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
}
