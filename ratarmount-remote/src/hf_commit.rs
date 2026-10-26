//! Blocking Hub commits using preupload and Git LFS basic/multipart transfers.
//! Blob and pointer operations share one atomic commit; failed uploads never publish names.

use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::Path;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{hf::encode, http_pool, HfRepo, RemoteError, Result, USER_AGENT};

const LFS_JSON: &str = "application/vnd.git-lfs+json";
const MAX_RESPONSE: u64 = 4 * 1024 * 1024;

/// One complete file to add to a Hub commit, in operation order.
pub struct HfCommitFile<'a> {
    pub path: &'a str,
    pub content: &'a [u8],
}

trait UploadReader: Read + Seek {}
impl<T: Read + Seek> UploadReader for T {}

struct UploadFile<'a> {
    path: &'a str,
    reader: Box<dyn UploadReader + 'a>,
    len: u64,
    id: String,
    sample: String,
    force_lfs: bool,
}

impl<'a> UploadFile<'a> {
    fn new(path: &'a str, mut reader: Box<dyn UploadReader + 'a>, force_lfs: bool) -> Result<Self> {
        let mut sample = Vec::new();
        reader.by_ref().take(512).read_to_end(&mut sample)?;
        reader.seek(SeekFrom::Start(0))?;
        let mut digest = Sha256::new();
        let mut buffer = [0; 64 * 1024];
        let mut len = 0;
        loop {
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
            len += count as u64;
        }
        reader.seek(SeekFrom::Start(0))?;
        Ok(Self {
            path,
            reader,
            len,
            id: hex::encode(digest.finalize()),
            sample: STANDARD.encode(sample),
            force_lfs,
        })
    }
}

#[derive(Debug)]
pub struct HfCommitResult {
    pub commit: String,
    pub pull_request_url: Option<String>,
}

fn error(message: impl Into<String>) -> RemoteError {
    RemoteError::Hf(message.into())
}

fn write_error(repo: &str, stage: &str, err: ureq::Error) -> RemoteError {
    match err {
        ureq::Error::Status(status, _) => error(format!(
            "Hub {stage} HTTP {status} for {repo}; publishing requires a token with write scope and repository write access; if this repository requires Xet and refuses LFS, Xet uploads are unsupported"
        )),
        _ => error(format!("Hub {stage} request failed for {repo}")),
    }
}

fn read_json(response: ureq::Response) -> Result<Value> {
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_RESPONSE + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RESPONSE {
        return Err(error("Hub upload response exceeds limit"));
    }
    serde_json::from_slice(&bytes).map_err(|_| error("invalid Hub upload JSON response"))
}

fn valid_path(path: &str) -> bool {
    !path.is_empty()
        && !path.contains(['\\', '\r', '\n'])
        && path
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != ".." && p != ".git")
}

impl HfRepo {
    /// Preupload, upload LFS objects, then atomically commit all file names.
    /// `parent_commit` protects a previously validated archive snapshot against concurrent writes.
    /// No request is retried: a lost commit response may already have created a commit/PR.
    pub fn commit_files(
        &self,
        files: &[HfCommitFile<'_>],
        revision: Option<&str>,
        create_pr: bool,
        parent_commit: Option<&str>,
    ) -> Result<HfCommitResult> {
        self.require_publish_token()?;
        let mut uploads = files
            .iter()
            .map(|f| UploadFile::new(f.path, Box::new(Cursor::new(f.content)), false))
            .collect::<Result<Vec<_>>>()?;
        self.commit_uploads(&mut uploads, revision, create_pr, parent_commit)
    }

    /// Stream an archive through LFS and publish its index siblings in the same commit.
    /// Archive memory use is bounded for both basic and multipart uploads.
    pub fn commit_archive(
        &self,
        archive: &Path,
        siblings: &[HfCommitFile<'_>],
        revision: &str,
        create_pr: bool,
        parent_commit: &str,
    ) -> Result<HfCommitResult> {
        self.require_publish_token()?;
        // Managed (#151): the staged archive may be a database open in this
        // process; the one reader is sampled, hashed, rewound and kept through
        // the LFS uploads and their retries.
        let mut files = vec![UploadFile::new(
            &self.location.path,
            Box::new(ratarmount_index::managed_read::ManagedReadCursor::open(
                archive,
            )?),
            true,
        )?];
        for file in siblings {
            files.push(UploadFile::new(
                file.path,
                Box::new(Cursor::new(file.content)),
                false,
            )?);
        }
        self.commit_uploads(&mut files, Some(revision), create_pr, Some(parent_commit))
    }

    /// Live write-back must target the mounted branch; tags and SHAs never fall back to main.
    pub fn live_commit_branch(&self) -> Result<String> {
        self.require_publish_token()?;
        let revision = &self.location.revision;
        let refs: Value =
            serde_json::from_slice(&self.fetch_bytes(&self.api_url("refs"), MAX_RESPONSE)?)
                .map_err(|_| error("invalid Hub refs response"))?;
        if !refs["branches"].as_array().is_some_and(|branches| {
            branches
                .iter()
                .any(|b| b["name"].as_str() == Some(revision))
        }) {
            return Err(error(
                "hf:// live commit requires a branch revision, not a commit SHA or tag",
            ));
        }
        Ok(revision.clone())
    }

    fn commit_uploads(
        &self,
        files: &mut [UploadFile<'_>],
        revision: Option<&str>,
        create_pr: bool,
        parent_commit: Option<&str>,
    ) -> Result<HfCommitResult> {
        if files.is_empty() || files.iter().any(|f| !valid_path(f.path)) {
            return Err(error("Hub commit requires files with safe relative paths"));
        }
        let mut paths = std::collections::BTreeSet::new();
        if files.iter().any(|f| !paths.insert(f.path)) {
            return Err(error("duplicate Hub commit path"));
        }
        let revision = self.publish_branch(revision)?;
        let suffix = if create_pr { "?create_pr=1" } else { "" };
        let encoded_revision = encode(&revision);
        let payload = json!({"files": files.iter().map(|f| json!({
            "path": f.path, "sample": f.sample, "size": f.len, "sha": f.id
        })).collect::<Vec<_>>()});
        let response = self
            .write_request(
                "POST",
                &self.api_url(&format!("preupload/{encoded_revision}{suffix}")),
            )?
            .set("Content-Type", "application/json")
            .send_string(&payload.to_string())
            .map_err(|e| write_error(&self.location.repo, "preupload", e))?;
        let modes = read_json(response)?;
        let modes = modes["files"]
            .as_array()
            .ok_or_else(|| error("Hub preupload response has no files"))?;
        let mut operations = Vec::new();
        let summary = if files.iter().any(|f| f.force_lfs) {
            "Publish ratarmount archive and index"
        } else {
            "Publish ratarmount archive index"
        };
        let mut header = json!({"summary": summary, "description": format!("Archive snapshot {} (index fingerprints validate archive bytes).", self.commit)});
        if let Some(parent) = parent_commit {
            header["parentCommit"] = json!(parent);
        }
        operations.push(json!({"key": "header", "value": header}));
        for file in files {
            let matching: Vec<_> = modes
                .iter()
                .filter(|m| m["path"].as_str() == Some(file.path))
                .collect();
            if matching.len() != 1 {
                return Err(error("Hub preupload omitted or duplicated a file"));
            }
            let mode = matching[0];
            if mode["shouldIgnore"].as_bool() == Some(true) {
                return Err(error("Hub gitignore excludes a published file"));
            }
            match mode["uploadMode"].as_str() {
                Some("regular") if !file.force_lfs => {
                    if file.len > 64 * 1024 * 1024 {
                        return Err(error("regular Hub commit file exceeds 64 MiB; configure LFS"));
                    }
                    let mut bytes = Vec::new();
                    file.reader.by_ref().take(file.len + 1).read_to_end(&mut bytes)?;
                    if bytes.len() as u64 != file.len { return Err(error("Hub upload file changed size")); }
                    operations.push(json!({"key": "file", "value": {
                        "path": file.path, "content": STANDARD.encode(bytes), "encoding": "base64"
                    }}));
                }
                Some("lfs" | "regular") => {
                    self.upload_lfs(file.reader.as_mut(), file.len, &file.id, &revision)?;
                    operations.push(json!({"key": "lfsFile", "value": {
                        "path": file.path, "algo": "sha256", "oid": file.id, "size": file.len
                    }}));
                }
                _ => return Err(error("unsupported Hub upload mode (Xet-only uploads are unsupported; LFS basic/multipart required)")),
            }
        }
        let ndjson = operations
            .iter()
            .map(|op| format!("{op}\n"))
            .collect::<String>();
        let response = self
            .write_request(
                "POST",
                &self.api_url(&format!("commit/{encoded_revision}{suffix}")),
            )?
            .set("Content-Type", "application/x-ndjson")
            .send_string(&ndjson)
            .map_err(|e| write_error(&self.location.repo, "commit", e))?;
        let value = read_json(response)?;
        let commit = value["commitOid"]
            .as_str()
            .filter(|s| s.len() == 40 && s.bytes().all(|c| c.is_ascii_hexdigit()))
            .ok_or_else(|| {
                error("Hub commit response has no valid commitOid; commit may have succeeded")
            })?;
        Ok(HfCommitResult {
            commit: commit.to_ascii_lowercase(),
            pull_request_url: value["pullRequestUrl"].as_str().map(str::to_owned),
        })
    }

    fn upload_lfs(
        &self,
        reader: &mut dyn UploadReader,
        len: u64,
        id: &str,
        revision: &str,
    ) -> Result<()> {
        let payload = json!({"operation": "upload", "transfers": ["basic", "multipart"], "hash_algo": "sha256", "ref": {"name": revision}, "objects": [{"oid": id, "size": len}]});
        let response = self
            .write_request("POST", &self.lfs_batch_url())?
            .set("Accept", LFS_JSON)
            .set("Content-Type", LFS_JSON)
            .send_string(&payload.to_string())
            .map_err(|e| write_error(&self.location.repo, "LFS batch", e))?;
        let value = read_json(response)?;
        if !matches!(
            value["transfer"].as_str(),
            None | Some("basic" | "multipart")
        ) {
            return Err(error(
                "Hub requires an unsupported LFS transfer (Xet-only uploads are unsupported)",
            ));
        }
        let objects = value["objects"]
            .as_array()
            .ok_or_else(|| error("LFS batch has no objects"))?;
        if objects.len() != 1
            || objects[0]["oid"].as_str() != Some(id)
            || objects[0]["size"].as_u64() != Some(len)
        {
            return Err(error("LFS batch returned a different object"));
        }
        let object = &objects[0];
        if !object["error"].is_null() {
            return Err(error("Hub refused LFS upload; check token write scope; Xet-only repositories are unsupported"));
        }
        let actions = &object["actions"];
        if actions.is_null() {
            return Ok(());
        } // Already stored.
        let upload = &actions["upload"];
        if let Some(chunk) = upload.get("header").and_then(|h| h.get("chunk_size")) {
            let chunk = chunk
                .as_str()
                .and_then(|s| s.parse::<u64>().ok())
                .or(chunk.as_u64())
                .filter(|n| *n > 0)
                .ok_or_else(|| error("invalid LFS multipart chunk size"))?;
            let headers = upload["header"]
                .as_object()
                .ok_or_else(|| error("invalid LFS multipart headers"))?;
            let count = len.div_ceil(chunk);
            if headers
                .keys()
                .filter(|k| k.bytes().all(|b| b.is_ascii_digit()))
                .count() as u64
                != count
            {
                return Err(error("LFS multipart response has wrong part count"));
            }
            let mut parts = Vec::new();
            for n in 0..count {
                let part_len = chunk.min(len - n * chunk);
                let href = headers
                    .get(&(n + 1).to_string())
                    .and_then(Value::as_str)
                    .ok_or_else(|| error("LFS multipart response missing part URL"))?;
                let response = action_request("PUT", href, None)?
                    .set("Content-Length", &part_len.to_string())
                    .send_reader((&mut *reader).take(part_len))
                    .map_err(|e| write_error(&self.location.repo, "LFS part", e))?;
                let etag = response
                    .header("ETag")
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| error("LFS part response missing ETag"))?;
                parts.push(json!({"partNumber": n + 1, "etag": etag}));
            }
            let completion_headers = Value::Object(
                headers
                    .iter()
                    .filter(|(name, _)| {
                        name.as_str() != "chunk_size" && !name.bytes().all(|b| b.is_ascii_digit())
                    })
                    .map(|(name, value)| (name.clone(), value.clone()))
                    .collect(),
            );
            action_request("POST", href(upload)?, Some(&completion_headers))?
                .set("Content-Type", LFS_JSON)
                .send_string(&json!({"oid": id, "parts": parts}).to_string())
                .map_err(|e| write_error(&self.location.repo, "LFS completion", e))?;
        } else {
            action_request("PUT", href(upload)?, upload.get("header"))?
                .set("Content-Length", &len.to_string())
                .send_reader((&mut *reader).take(len))
                .map_err(|e| write_error(&self.location.repo, "LFS upload", e))?;
        }
        if let Some(verify) = actions.get("verify").filter(|v| !v.is_null()) {
            let url = href(verify)?;
            let has_auth = verify["header"].as_object().is_some_and(|headers| {
                headers
                    .keys()
                    .any(|k| k.eq_ignore_ascii_case("authorization"))
            });
            // The Hub verify action normally needs its token. Never add it to storage hosts.
            let req = if !has_auth {
                if let Ok(authenticated) = self.write_request("POST", url) {
                    apply_action_headers(authenticated, verify.get("header"))?
                } else {
                    action_request("POST", url, verify.get("header"))?
                }
            } else {
                action_request("POST", url, verify.get("header"))?
            };
            req.set("Content-Type", LFS_JSON)
                .send_string(&json!({"oid": id, "size": len}).to_string())
                .map_err(|e| write_error(&self.location.repo, "LFS verify", e))?;
        }
        Ok(())
    }
}

fn href(action: &Value) -> Result<&str> {
    action["href"]
        .as_str()
        .ok_or_else(|| error("LFS action missing href"))
}

fn action_request(
    method: &str,
    href: &str,
    headers: Option<&Value>,
) -> Result<http_pool::HttpRequest> {
    let url = url::Url::parse(href).map_err(|_| error("invalid LFS action URL"))?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
    {
        return Err(error("invalid LFS action URL"));
    }
    let req = http_pool::request(method, href)
        .set("User-Agent", USER_AGENT)
        .timeout(Duration::from_secs(300));
    apply_action_headers(req, headers)
}

fn apply_action_headers(
    mut req: http_pool::HttpRequest,
    headers: Option<&Value>,
) -> Result<http_pool::HttpRequest> {
    if let Some(headers) = headers.filter(|v| !v.is_null()) {
        for (name, value) in headers
            .as_object()
            .ok_or_else(|| error("invalid LFS action headers"))?
        {
            req = req.set(
                name,
                value
                    .as_str()
                    .ok_or_else(|| error("invalid LFS action header value"))?,
            );
        }
    }
    Ok(req)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };
    use std::thread;

    #[derive(Clone, Debug)]
    struct Request {
        method: String,
        path: String,
        headers: BTreeMap<String, String>,
        body: Vec<u8>,
    }
    struct Server {
        url: String,
        stop: Arc<AtomicBool>,
        join: Option<thread::JoinHandle<()>>,
    }
    impl Server {
        fn spawn(
            handler: impl Fn(Request) -> (u16, Vec<(String, String)>, Vec<u8>) + Send + 'static,
        ) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            listener.set_nonblocking(true).unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let stop = Arc::new(AtomicBool::new(false));
            let stopped = stop.clone();
            let join = thread::spawn(move || {
                while !stopped.load(Ordering::Relaxed) {
                    let (mut stream, _) = match listener.accept() {
                        Ok(s) => s,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(2));
                            continue;
                        }
                        Err(_) => break,
                    };
                    // Darwin accept inherits O_NONBLOCK from the listener; Linux does not.
                    // Request bodies (especially the multi-MiB LFS fixture) need blocking reads.
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 {
                        continue;
                    }
                    let fields: Vec<_> = line.split_whitespace().collect();
                    let method = fields[0].into();
                    let path = fields[1].into();
                    let mut headers = BTreeMap::new();
                    loop {
                        let mut line = String::new();
                        reader.read_line(&mut line).unwrap();
                        if line == "\r\n" || line.is_empty() {
                            break;
                        }
                        let (k, v) = line.trim().split_once(':').unwrap();
                        headers.insert(k.to_ascii_lowercase(), v.trim().to_string());
                    }
                    let len = headers
                        .get("content-length")
                        .and_then(|s| s.parse().ok())
                        .unwrap_or(0);
                    let mut body = vec![0; len];
                    reader.read_exact(&mut body).unwrap();
                    let (status, headers, body) = handler(Request {
                        method,
                        path,
                        headers,
                        body,
                    });
                    write!(
                        stream,
                        "HTTP/1.1 {status} Mock\r\nContent-Length: {}\r\nConnection: close\r\n",
                        body.len()
                    )
                    .unwrap();
                    for (k, v) in headers {
                        write!(stream, "{k}: {v}\r\n").unwrap();
                    }
                    stream.write_all(b"\r\n").unwrap();
                    stream.write_all(&body).unwrap();
                }
            });
            Self {
                url,
                stop,
                join: Some(join),
            }
        }
    }
    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            let _ = TcpStream::connect(self.url.trim_start_matches("http://"));
            self.join.take().unwrap().join().unwrap();
        }
    }
    fn response(v: Value) -> (u16, Vec<(String, String)>, Vec<u8>) {
        (200, vec![], v.to_string().into_bytes())
    }
    fn modes(request: &Request, lfs: bool) -> Value {
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        json!({"files": body["files"].as_array().unwrap().iter().map(|f| json!({"path": f["path"], "uploadMode": if lfs && !f["path"].as_str().unwrap().ends_with(".ptr") { "lfs" } else { "regular" }, "shouldIgnore": false})).collect::<Vec<_>>()})
    }

    /// Regression: archive upload slurped the spool, published siblings separately,
    /// or hit WouldBlock in the mock server on Darwin's inherited nonblocking socket.
    #[test]
    fn regression_hf_archive_streams_lfs_with_atomic_siblings() {
        let archive = vec![b'a'; 2 * 1024 * 1024 + 17];
        let uploaded = Arc::new(Mutex::new(Vec::new()));
        let storage_bytes = uploaded.clone();
        let storage = Server::spawn(move |request| {
            assert!(!request.headers.contains_key("authorization"));
            *storage_bytes.lock().unwrap() = request.body;
            response(json!({}))
        });
        let href = storage.url.clone();
        let commits = Arc::new(Mutex::new(Vec::new()));
        let commit_bytes = commits.clone();
        let hub = Server::spawn(move |request| {
            if request.path.contains("preupload") {
                let value: Value = serde_json::from_slice(&request.body).unwrap();
                assert_eq!(value["files"].as_array().unwrap().len(), 3);
                assert_eq!(value["files"][0]["size"], 2 * 1024 * 1024 + 17);
                assert_eq!(
                    STANDARD
                        .decode(value["files"][0]["sample"].as_str().unwrap())
                        .unwrap(),
                    vec![b'a'; 512]
                );
                // Small archives may negotiate regular; write-back explicitly uses LFS.
                response(modes(&request, false))
            } else if request.path.ends_with("batch") {
                let value: Value = serde_json::from_slice(&request.body).unwrap();
                response(
                    json!({"transfer":"basic","objects":[{"oid":value["objects"][0]["oid"],"size":value["objects"][0]["size"],"actions":{"upload":{"href":format!("{href}/archive")}}}]}),
                )
            } else {
                assert!(request.path.contains("/commit/"));
                *commit_bytes.lock().unwrap() = request.body;
                response(json!({"commitOid":"B".repeat(40)}))
            }
        });
        let repo = crate::hf::commit_test_repo(&hub.url, Some("hub-secret"));
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), &archive).unwrap();
        let result = repo
            .commit_archive(
                file.path(),
                &[
                    HfCommitFile {
                        path: "a.tar.index.sqlite",
                        content: b"index",
                    },
                    HfCommitFile {
                        path: "a.tar.index.ptr",
                        content: b"ptr",
                    },
                ],
                "main",
                false,
                &repo.commit,
            )
            .unwrap();
        assert_eq!(
            result.commit,
            "b".repeat(40),
            "commit identity must match the reader's normalization"
        );
        assert_eq!(*uploaded.lock().unwrap(), archive);
        let ops: Vec<Value> = std::str::from_utf8(&commits.lock().unwrap())
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(ops.len(), 4);
        assert_eq!(ops[0]["value"]["parentCommit"], repo.commit);
        assert_eq!(ops[1]["key"], "lfsFile");
        assert_eq!(ops[1]["value"]["oid"], hex::encode(Sha256::digest(archive)));
        assert_eq!(ops[2]["value"]["path"], "a.tar.index.sqlite");
        assert_eq!(ops[3]["value"]["path"], "a.tar.index.ptr");
    }

    /// Regression: a streamed storage PUT must not be replayed or forward credentials through redirects.
    #[test]
    fn regression_hf_archive_upload_redirect_is_not_replayed() {
        let followed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = followed.clone();
        let target = Server::spawn(move |_| {
            count.fetch_add(1, Ordering::Relaxed);
            response(json!({}))
        });
        let target_url = target.url.clone();
        let storage = Server::spawn(move |request| {
            assert!(!request.headers.contains_key("authorization"));
            (
                302,
                vec![(
                    "Location".into(),
                    format!("{target_url}/upload?secret=storage-secret"),
                )],
                vec![],
            )
        });
        let storage_url = storage.url.clone();
        let hub = Server::spawn(move |request| {
            if request.path.contains("preupload") {
                response(modes(&request, false))
            } else {
                assert!(
                    request.path.ends_with("batch"),
                    "failed upload must not commit"
                );
                let value: Value = serde_json::from_slice(&request.body).unwrap();
                response(
                    json!({"objects":[{"oid":value["objects"][0]["oid"],"size":value["objects"][0]["size"],"actions":{"upload":{"href":format!("{storage_url}/upload")}}}]}),
                )
            }
        });
        let repo = crate::hf::commit_test_repo(&hub.url, Some("hub-secret"));
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), b"archive").unwrap();
        let err = repo
            .commit_archive(file.path(), &[], "main", false, &repo.commit)
            .unwrap_err()
            .to_string();
        assert!(err.contains("LFS upload request failed"), "{err}");
        assert!(!err.contains("secret"));
        assert_eq!(followed.load(Ordering::Relaxed), 0);
    }

    /// Regression: Hub token leaked to LFS storage, or pointer was committed before the upload/verify.
    #[test]
    fn regression_hf_publish_basic_blob_before_atomic_pointer_and_no_token_leak() {
        for supplied_auth in [false, true] {
            let requests = Arc::new(Mutex::new(Vec::<Request>::new()));
            let storage_requests = requests.clone();
            let storage = Server::spawn(move |r| {
                assert_eq!(
                    r.headers.get("authorization").map(String::as_str),
                    supplied_auth.then_some("storage credential")
                );
                assert_eq!(r.headers["x-upload"], "batch-header");
                if r.method == "PUT" {
                    assert_eq!(r.body, b"SQLite format 3\0index");
                } else {
                    let v: Value = serde_json::from_slice(&r.body).unwrap();
                    assert_eq!(v["size"], 21);
                    assert!(v["oid"].is_string());
                }
                storage_requests.lock().unwrap().push(r);
                response(json!({}))
            });
            let storage_url = storage.url.clone();
            let hub_requests = requests.clone();
            let server = Server::spawn(move |r| {
                assert_eq!(r.headers["authorization"], "Bearer hub-secret");
                let result = if r.path.contains("/preupload/") {
                    assert!(r.path.ends_with("?create_pr=1"));
                    response(modes(&r, true))
                } else if r.path.ends_with("/batch") {
                    assert_eq!(r.headers["content-type"], LFS_JSON);
                    assert_eq!(r.headers["accept"], LFS_JSON);
                    let payload: Value = serde_json::from_slice(&r.body).unwrap();
                    assert_eq!(payload["operation"], "upload");
                    assert_eq!(payload["transfers"], json!(["basic", "multipart"]));
                    assert_eq!(payload["hash_algo"], "sha256");
                    assert_eq!(payload["ref"]["name"], "feature/new");
                    let mut headers = json!({"X-Upload": "batch-header"});
                    if supplied_auth {
                        headers["Authorization"] = json!("storage credential");
                    }
                    response(
                        json!({"transfer": "basic", "objects": [{"oid": payload["objects"][0]["oid"], "size": payload["objects"][0]["size"], "actions": {
                            "upload": {"href": format!("{storage_url}/blob"), "header": headers},
                            "verify": {"href": format!("{storage_url}/verify"), "header": headers}
                        }}]}),
                    )
                } else if r.path.contains("/commit/") {
                    assert_eq!(r.headers["content-type"], "application/x-ndjson");
                    assert_eq!(
                        r.path,
                        "/api/datasets/org/data/commit/feature%2Fnew?create_pr=1"
                    );
                    response(
                        json!({"commitOid": "b".repeat(40), "pullRequestUrl": "https://hub/pr/1"}),
                    )
                } else {
                    panic!("unexpected path {}", r.path)
                };
                hub_requests.lock().unwrap().push(r);
                result
            });
            let repo = crate::hf::commit_test_repo(&server.url, Some("hub-secret"));
            let blob = b"SQLite format 3\0index";
            let id = hex::encode(Sha256::digest(blob));
            let pointer = json!({"schema":"ratarmount.index.pointer.v1", "index_id":id, "etag_sha256":id, "archive_hf_commit":repo.commit}).to_string();
            let files = [
                HfCommitFile {
                    path: &format!("a.tar.index.{id}.sqlite"),
                    content: blob,
                },
                HfCommitFile {
                    path: "a.tar.index.ptr",
                    content: pointer.as_bytes(),
                },
            ];
            let result = repo.commit_files(&files, Some("feature/new"), true, Some(&repo.commit));
            assert!(result.is_ok(), "{result:?}");
            let requests = requests.lock().unwrap();
            let order: Vec<_> = requests.iter().map(|r| r.method.as_str()).collect();
            assert_eq!(order, ["POST", "POST", "PUT", "POST", "POST"]);
            let pre: Value = serde_json::from_slice(&requests[0].body).unwrap();
            assert_eq!(pre["files"][0]["sha"], id);
            assert_eq!(
                STANDARD
                    .decode(pre["files"][0]["sample"].as_str().unwrap())
                    .unwrap(),
                blob
            );
            let commit: Vec<Value> = String::from_utf8(requests.last().unwrap().body.clone())
                .unwrap()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect();
            assert_eq!(commit[0]["value"]["parentCommit"], repo.commit);
            assert_eq!(
                commit[1],
                json!({"key":"lfsFile", "value":{"path":files[0].path,"oid":id,"algo":"sha256","size":blob.len()}})
            );
            assert_eq!(commit[2]["key"], "file");
            assert_eq!(commit[2]["value"]["encoding"], "base64");
            assert_eq!(
                STANDARD
                    .decode(commit[2]["value"]["content"].as_str().unwrap())
                    .unwrap(),
                pointer.as_bytes()
            );
        }
    }

    /// Regression: a failed commit must leave both repository names unpublished.
    #[test]
    fn regression_hf_publish_commit_failure_has_no_partial_pointer() {
        let visible = Arc::new(Mutex::new(Vec::<String>::new()));
        let visible_c = visible.clone();
        let server = Server::spawn(move |r| {
            if r.path.contains("preupload") {
                response(modes(&r, false))
            } else {
                assert!(r.path.contains("/commit/"));
                assert!(visible_c.lock().unwrap().is_empty());
                (500, vec![], vec![])
            }
        });
        let repo = crate::hf::commit_test_repo(&server.url, Some("token"));
        let err = repo
            .commit_files(
                &[
                    HfCommitFile {
                        path: "a.index.sqlite",
                        content: b"index",
                    },
                    HfCommitFile {
                        path: "a.index.ptr",
                        content: b"ptr",
                    },
                ],
                Some("main"),
                false,
                None,
            )
            .unwrap_err();
        assert!(err.to_string().contains("commit HTTP 500"));
        assert!(visible.lock().unwrap().is_empty());
    }

    /// Regression: anonymous publication and insufficient token scope must fail clearly.
    #[test]
    fn regression_hf_publish_requires_write_scope() {
        let repo = crate::hf::commit_test_repo("http://127.0.0.1:1", None);
        assert!(repo
            .live_commit_branch()
            .unwrap_err()
            .to_string()
            .contains("token with write scope"));
        assert!(repo
            .commit_archive(
                Path::new("/nonexistent/archive.tar.zst"),
                &[],
                "main",
                false,
                &repo.commit
            )
            .unwrap_err()
            .to_string()
            .contains("token with write scope"));
        let file = HfCommitFile {
            path: "a.index.ptr",
            content: b"ptr",
        };
        let err = repo
            .commit_files(&[file], Some("main"), false, None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("token with write scope"), "{err}");
        for status in [401, 403] {
            let server =
                Server::spawn(move |_| (status, vec![], b"secret must not be echoed".to_vec()));
            let repo = crate::hf::commit_test_repo(&server.url, Some("token"));
            let err = repo
                .commit_files(
                    &[HfCommitFile {
                        path: "a.index.ptr",
                        content: b"ptr",
                    }],
                    Some("main"),
                    false,
                    None,
                )
                .unwrap_err()
                .to_string();
            assert!(
                err.contains(&format!("HTTP {status}")) && err.contains("write scope"),
                "{err}"
            );
            assert!(!err.contains("secret"));
        }
    }
    /// Regression: multipart completion must use returned part URLs and ETags in numeric order.
    #[test]
    fn regression_hf_publish_multipart_completion_and_upload_failure() {
        for fail in [false, true] {
            let requests = Arc::new(Mutex::new(Vec::<Request>::new()));
            let storage_requests = requests.clone();
            let storage = Server::spawn(move |r| {
                assert!(!r.headers.contains_key("authorization"));
                let result = if r.method == "PUT" {
                    if fail {
                        (500, vec![], vec![])
                    } else {
                        (
                            200,
                            vec![("ETag".into(), format!("etag{}", r.path))],
                            vec![],
                        )
                    }
                } else {
                    response(json!({}))
                };
                storage_requests.lock().unwrap().push(r);
                result
            });
            let href = storage.url.clone();
            let hub_requests = requests.clone();
            let hub = Server::spawn(move |r| {
                let result = if r.path.contains("preupload") {
                    response(modes(&r, true))
                } else if r.path.ends_with("batch") {
                    let v: Value = serde_json::from_slice(&r.body).unwrap();
                    response(
                        json!({"transfer":"multipart", "objects":[{"oid":v["objects"][0]["oid"], "size":5,
                        "actions":{"upload":{"href":format!("{href}/complete"), "header":{"chunk_size":"3", "2":format!("{href}/2"), "1":format!("{href}/1")}}}}]}),
                    )
                } else {
                    response(json!({"commitOid":"b".repeat(40)}))
                };
                hub_requests.lock().unwrap().push(r);
                result
            });
            let repo = crate::hf::commit_test_repo(&hub.url, Some("token"));
            let result = repo.commit_files(
                &[HfCommitFile {
                    path: "a.sqlite",
                    content: b"abcde",
                }],
                Some("main"),
                false,
                None,
            );
            let reqs = requests.lock().unwrap();
            if fail {
                assert!(result.is_err());
                assert_eq!(reqs.len(), 3);
                assert!(!reqs
                    .iter()
                    .any(|r| r.path.contains("commit") || r.path.contains("complete")));
            } else {
                result.unwrap();
                assert_eq!(reqs[2].path, "/1");
                assert_eq!(reqs[2].body, b"abc");
                assert_eq!(reqs[3].path, "/2");
                assert_eq!(reqs[3].body, b"de");
                let complete: Value = serde_json::from_slice(&reqs[4].body).unwrap();
                assert_eq!(
                    complete["parts"],
                    json!([{"partNumber":1,"etag":"etag/1"},{"partNumber":2,"etag":"etag/2"}])
                );
                assert_eq!(reqs[4].headers["content-type"], LFS_JSON);
            }
        }
    }

    /// Regression: tags/SHAs must not be used as writable branches by default.
    #[test]
    fn regression_hf_publish_revision_defaults_to_branch_else_main() {
        let server = Server::spawn(|r| {
            assert_eq!(r.path, "/api/datasets/org/data/refs");
            response(json!({"branches":[{"name":"dev"}],"tags":[{"name":"v1"}]}))
        });
        let mut repo = crate::hf::commit_test_repo(&server.url, Some("token"));
        for (revision, expected) in [
            ("main", "main"),
            ("dev", "dev"),
            ("v1", "main"),
            (&"a".repeat(40), "main"),
        ] {
            repo.location.revision = revision.into();
            assert_eq!(repo.publish_branch(None).unwrap(), expected);
        }
        assert_eq!(
            repo.publish_branch(Some("feature/new")).unwrap(),
            "feature/new"
        );
        assert!(repo.publish_branch(Some("../main")).is_err());
    }
    /// Regression: Xet-only or malformed upload instructions must never reach the commit endpoint.
    #[test]
    fn regression_hf_publish_xet_or_malformed_batch_fails_closed() {
        for mode in ["xet", "bad-oid", "already-present"] {
            let commits = Arc::new(Mutex::new(0));
            let count = commits.clone();
            let server = Server::spawn(move |r| {
                if r.path.contains("preupload") {
                    response(modes(&r, true))
                } else if r.path.ends_with("batch") {
                    let body: Value = serde_json::from_slice(&r.body).unwrap();
                    response(
                        json!({"transfer":if mode=="xet" {"xet"} else {"basic"},"objects":[{"oid":if mode=="bad-oid" {json!("bad")} else {body["objects"][0]["oid"].clone()},"size":5}]}),
                    )
                } else {
                    *count.lock().unwrap() += 1;
                    response(json!({"commitOid":"b".repeat(40)}))
                }
            });
            let repo = crate::hf::commit_test_repo(&server.url, Some("token"));
            let result = repo.commit_files(
                &[HfCommitFile {
                    path: "index.sqlite",
                    content: b"index",
                }],
                Some("main"),
                false,
                None,
            );
            assert_eq!(result.is_ok(), mode == "already-present");
            assert_eq!(
                *commits.lock().unwrap(),
                if mode == "already-present" { 1 } else { 0 }
            );
            if mode == "xet" {
                assert!(result.unwrap_err().to_string().contains("Xet"));
            }
        }
    }
    /// Regression: models omit the LFS URL prefix, while datasets and spaces retain it.
    #[test]
    fn regression_hf_publish_lfs_repo_type_urls() {
        let mut repo = crate::hf::commit_test_repo("https://example.org/hub", Some("token"));
        for (kind, prefix) in [
            ("models", ""),
            ("datasets", "datasets/"),
            ("spaces", "spaces/"),
        ] {
            repo.location.kind = kind.into();
            assert_eq!(
                repo.lfs_batch_url(),
                format!("https://example.org/hub/{prefix}org/data.git/info/lfs/objects/batch")
            );
        }
        assert!(repo
            .write_request("POST", "https://other.example/hub/commit")
            .is_err());
        assert!(repo
            .write_request("POST", "https://example.org/outside/commit")
            .is_err());
    }

    /// Regression: (R11-S7, #151): the staged archive was opened with a raw
    /// `File` (sampled, hashed, rewound, uploaded); its close released this
    /// process's lock on it. Basic and multipart LFS, and a failing upload.
    /// The lock is a VFS-level SHARED lock of this SQLite instance (the same
    /// per-inode bookkeeping a connection uses; the file need not be a
    /// database).
    #[cfg(unix)]
    #[test]
    fn regression_hf_archive_upload_keeps_index_lock() {
        use ratarmount_index::managed_read::{lock_probe::other_process_sees_lock, VfsLockHolder};
        for (transfer, fail) in [("basic", false), ("multipart", false), ("basic", true)] {
            let archive: Vec<u8> = (0..300_000u32).map(|i| (i % 249) as u8).collect();
            let uploaded = Arc::new(Mutex::new(Vec::<u8>::new()));
            let up = uploaded.clone();
            let storage = Server::spawn(move |r| {
                if r.method == "PUT" {
                    if fail {
                        return (500, vec![], vec![]);
                    }
                    up.lock().unwrap().extend_from_slice(&r.body);
                    return (
                        200,
                        vec![("ETag".into(), format!("etag{}", r.path))],
                        vec![],
                    );
                }
                response(json!({}))
            });
            let href = storage.url.clone();
            let size = archive.len();
            let hub = Server::spawn(move |r| {
                if r.path.contains("preupload") {
                    response(modes(&r, true))
                } else if r.path.ends_with("batch") {
                    let v: Value = serde_json::from_slice(&r.body).unwrap();
                    let oid = v["objects"][0]["oid"].clone();
                    if transfer == "basic" {
                        response(json!({"transfer":"basic","objects":[{"oid":oid,"size":size,
                            "actions":{"upload":{"href":format!("{href}/archive")}}}]}))
                    } else {
                        response(
                            json!({"transfer":"multipart","objects":[{"oid":oid,"size":size,
                            "actions":{"upload":{"href":format!("{href}/complete"),
                            "header":{"chunk_size":"200000","1":format!("{href}/1"),"2":format!("{href}/2")}}}}]}),
                        )
                    }
                } else {
                    response(json!({"commitOid":"b".repeat(40)}))
                }
            });
            let repo = crate::hf::commit_test_repo(&hub.url, Some("hub-secret"));
            let file = tempfile::NamedTempFile::new().unwrap();
            std::fs::write(file.path(), &archive).unwrap();
            let lock = VfsLockHolder::shared(file.path()).unwrap();
            assert!(other_process_sees_lock(file.path()));
            let got = repo.commit_archive(file.path(), &[], "main", false, &repo.commit);
            if fail {
                assert!(got.is_err());
            } else {
                got.unwrap();
                assert_eq!(*uploaded.lock().unwrap(), archive, "{transfer}");
            }
            assert!(
                other_process_sees_lock(file.path()),
                "{transfer}: lock kept"
            );
            drop(lock);
        }
    }
}
