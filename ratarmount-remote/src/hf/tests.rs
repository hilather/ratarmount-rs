use super::*;

#[test]
fn regression_hf_parser_revisions_and_legacy_models() {
    for (url, kind, repo, rev, path) in [
        ("hf://org/model", "models", "org/model", "main", ""),
        ("hf://gpt2", "models", "gpt2", "main", ""),
        (
            "hf://gpt2@main/config.json",
            "models",
            "gpt2",
            "main",
            "config.json",
        ),
        (
            "hf://datasets/org/data@v1/train/a.tar.zst",
            "datasets",
            "org/data",
            "v1",
            "train/a.tar.zst",
        ),
        (
            "hf://spaces/org/demo@branch/",
            "spaces",
            "org/demo",
            "branch",
            "",
        ),
        (
            "hf://org/model@refs/pr/3/config.json",
            "models",
            "org/model",
            "refs/pr/3",
            "config.json",
        ),
        (
            "hf://org/model@refs%2Fpr%2F3/config.json",
            "models",
            "org/model",
            "refs/pr/3",
            "config.json",
        ),
        (
            "hf://datasets/org/data@refs/convert/parquet/dir",
            "datasets",
            "org/data",
            "refs/convert/parquet",
            "dir",
        ),
        (
            "hf://org/model@feature%2Fnew/a%20b",
            "models",
            "org/model",
            "feature/new",
            "a b",
        ),
        (
            "hf://org/model@0123456789abcdef0123456789abcdef01234567/f",
            "models",
            "org/model",
            "0123456789abcdef0123456789abcdef01234567",
            "f",
        ),
    ] {
        assert_eq!(
            parse_hf_url(url).unwrap(),
            HfLocation {
                kind: kind.into(),
                repo: repo.into(),
                revision: rev.into(),
                path: path.into()
            },
            "{url}"
        );
    }
    for url in [
        "http://org/model",
        "hf://",
        "hf:///org/model",
        "hf://org//model",
        "hf://org/model@",
        "hf://org/model@refs/pr/no",
        "hf://org/model@refs/pr",
        "hf://org/model@bad%XY",
        "hf://org/model/../secret",
        "hf://org/model/%2e%2e/secret",
        "hf://org/model?token=x",
        "hf://org/model#x",
        "hf://org/model@rev@bad",
    ] {
        assert!(parse_hf_url(url).is_err(), "{url}");
    }
}

use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::thread::{self, JoinHandle};

const SHA: &str = "0123456789abcdef0123456789abcdef01234567";

struct Request {
    path: String,
    headers: BTreeMap<String, String>,
}
struct Response {
    status: u16,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}
impl Response {
    fn new(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            headers: vec![],
            body: body.into(),
        }
    }
    fn header(mut self, key: &str, value: impl Into<String>) -> Self {
        self.headers.push((key.into(), value.into()));
        self
    }
}
struct Server {
    url: String,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}
impl Server {
    fn new(handler: impl Fn(Request) -> Response + Send + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let requests_t = requests.clone();
        let stop_t = stop.clone();
        let thread = thread::spawn(move || {
            while !stop_t.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(e) => panic!("accept: {e}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut first = String::new();
                if reader.read_line(&mut first).unwrap_or(0) == 0 {
                    continue;
                }
                let path = first.split_whitespace().nth(1).unwrap().to_string();
                let mut headers = BTreeMap::new();
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some((key, value)) = line.split_once(':') {
                        headers.insert(key.to_ascii_lowercase(), value.trim().to_string());
                    }
                }
                requests_t.lock().unwrap().push(path.clone());
                let response = handler(Request { path, headers });
                let _ = write!(
                    stream,
                    "HTTP/1.1 {} Test\r\nContent-Length: {}\r\nConnection: close\r\n",
                    response.status,
                    response.body.len()
                );
                for (key, value) in response.headers {
                    let _ = write!(stream, "{key}: {value}\r\n");
                }
                let _ = stream.write_all(b"\r\n");
                let _ = stream.write_all(&response.body);
            }
        });
        Self {
            url,
            requests,
            stop,
            thread: Some(thread),
        }
    }
    fn count(&self, needle: &str) -> usize {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .filter(|s| s.contains(needle))
            .count()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(self.url.strip_prefix("http://").unwrap());
        if let Some(thread) = self.thread.take() {
            thread.join().unwrap();
        }
    }
}
fn config(server: &Server, cache: Option<PathBuf>) -> Config {
    Config {
        endpoint: Url::parse(&format!("{}/", server.url)).unwrap(),
        token: Some(SecretString::new("hf_test_secret".into())),
        cache,
        offline: false,
    }
}
fn range_response(req: &Request, data: &[u8]) -> Response {
    let (start, end) = req.headers["range"]
        .strip_prefix("bytes=")
        .unwrap()
        .split_once('-')
        .unwrap();
    let start: usize = start.parse().unwrap();
    let end: usize = end.parse().unwrap();
    Response::new(206, data[start..=end].to_vec()).header(
        "Content-Range",
        format!("bytes {start}-{end}/{}", data.len()),
    )
}

#[test]
fn regression_hf_three_page_tree_cached_on_remount_and_cdn_has_no_token() {
    let data = b"PAR1mock parquet dataPAR1";
    let expire = Arc::new(AtomicBool::new(false));
    let expire_cdn = expire.clone();
    let cdn = Server::new(move |req| {
        assert!(!req.headers.contains_key("authorization"));
        assert!(!req.headers.contains_key("cookie"));
        if expire_cdn.swap(false, Ordering::Relaxed) {
            return Response::new(403, "expired signed URL");
        }
        range_response(&req, data)
    });
    let cdn_url = cdn.url.clone();
    let hub = Server::new(move |req| {
        assert_eq!(
            req.headers.get("authorization").map(String::as_str),
            Some("Bearer hf_test_secret")
        );
        if req.path.contains("/revision/") {
            return Response::new(200, json!({"sha": SHA}).to_string());
        }
        if req.path.contains("/tree/") {
            assert!(req.path.contains(SHA));
            let page = if req.path.contains("cursor=2") {
                2
            } else if req.path.contains("cursor=1") {
                1
            } else {
                0
            };
            let body = match page {
                0 => json!([{"type":"directory","path":"train"}]),
                1 => {
                    json!([{"type":"file","path":"train/a.parquet","size":data.len(),"oid":"gitblob","lfs":{"oid":"sha256"},"xetHash":"xet"}])
                }
                _ => json!([{"type":"file","path":"config.json","size":2}]),
            };
            let response = Response::new(200, body.to_string());
            return if page < 2 {
                response.header(
                    "Link",
                    format!(
                        "<?recursive=true&expand=true&cursor={}>; rel=\"next\"",
                        page + 1
                    ),
                )
            } else {
                response
            };
        }
        if req.path.contains("/resolve/") {
            assert!(req.path.contains(SHA));
            return Response::new(302, "").header("Location", format!("{cdn_url}/data"));
        }
        Response::new(404, "")
    });
    let tmp = tempfile::tempdir().unwrap();
    let conf = config(&hub, Some(tmp.path().into()));
    let location = parse_hf_url("hf://datasets/org/data@v1").unwrap();
    let repo = HfRepo::with_config(location.clone(), conf.clone()).unwrap();
    let folder = repo.folder().unwrap().unwrap();
    assert_eq!(folder.list_dirents("/").unwrap().len(), 2);
    let fi = folder.lookup("/train/a.parquet", 0).unwrap();
    assert_eq!(folder.read(&fi, data.len(), 0).unwrap(), data);
    let root = folder.lookup("/", 0).unwrap();
    assert_eq!(
        folder.get_xattr(&root, "user.hf.commit").unwrap(),
        SHA.as_bytes()
    );
    assert_eq!(
        folder.get_xattr(&fi, "user.hf.commit").unwrap(),
        SHA.as_bytes()
    );
    let mut file = repo.open_file("train/a.parquet").unwrap();
    assert!(file.uses_ranges());
    let resolve_before = hub.count("/resolve/");
    for offset in [2, 6, 1] {
        file.seek(SeekFrom::Start(offset)).unwrap();
        let mut bytes = [0; 2];
        file.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, &data[offset as usize..offset as usize + 2]);
    }
    assert_eq!(
        hub.count("/resolve/"),
        resolve_before,
        "redirect target reused"
    );
    expire.store(true, Ordering::Relaxed);
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = [0; 2];
    file.read_exact(&mut bytes).unwrap();
    assert_eq!(&bytes, &data[..2]);
    assert_eq!(hub.count("/resolve/"), resolve_before + 1);
    assert_eq!(hub.count("/tree/"), 3);
    assert_eq!(hub.count("/revision/"), 1);
    drop(folder);
    drop(repo);
    let second = HfRepo::with_config(location, conf).unwrap();
    assert_eq!(
        second
            .folder()
            .unwrap()
            .unwrap()
            .list_dirents("/train")
            .unwrap()
            .len(),
        1
    );
    assert_eq!(hub.count("/tree/"), 3, "remount must not relist");
    assert_eq!(
        hub.count("/revision/"),
        2,
        "moving revision resolved once per mount"
    );
    let cached: Value =
        serde_json::from_reader(std::fs::File::open(second.tree_cache_path().unwrap()).unwrap())
            .unwrap();
    assert_eq!(cached["identity"]["commit"], SHA);
    assert_eq!(cached["entries"][1]["xetHash"], "xet");
}

#[test]
fn regression_hf_token_precedence_endpoint_and_offline_without_network() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path().join(".cache/huggingface")).unwrap();
    std::fs::write(tmp.path().join(".cache/huggingface/token"), "default\n").unwrap();
    std::fs::write(tmp.path().join("token"), "home\n").unwrap();
    std::fs::write(tmp.path().join("explicit"), "path\n").unwrap();
    let mut env = BTreeMap::from([
        ("HOME", tmp.path().to_string_lossy().into_owned()),
        ("HF_ENDPOINT", "http://127.0.0.1:1/mirror".into()),
    ]);
    let token = |env: &BTreeMap<&str, String>| {
        Config::from_values(|k| env.get(k).cloned())
            .unwrap()
            .token
            .unwrap()
            .expose_secret()
            .clone()
    };
    assert_eq!(token(&env), "default");
    env.insert("HF_HOME", tmp.path().to_string_lossy().into_owned());
    assert_eq!(token(&env), "home");
    env.insert(
        "HF_TOKEN_PATH",
        tmp.path().join("explicit").to_string_lossy().into_owned(),
    );
    assert_eq!(token(&env), "path");
    env.insert("HF_TOKEN", "env".into());
    assert_eq!(token(&env), "env");
    env.insert("HF_HUB_OFFLINE", "1".into());
    let config = Config::from_values(|k| env.get(k).cloned()).unwrap();
    assert_eq!(config.endpoint.as_str(), "http://127.0.0.1:1/mirror/");
    let err = HfRepo::with_config(parse_hf_url("hf://org/model").unwrap(), config)
        .err()
        .unwrap()
        .to_string();
    assert!(err.contains("HF_HUB_OFFLINE"), "{err}");
    for invalid in [
        "file:///tmp",
        "https://secret@host",
        "https://host/?key=secret",
    ] {
        env.insert("HF_ENDPOINT", invalid.into());
        assert!(Config::from_values(|k| env.get(k).cloned()).is_err());
    }
}

#[test]
fn regression_hf_private_repo_error_names_token_sources() {
    for status in [401, 403] {
        let hub = Server::new(move |_| Response::new(status, ""));
        let err = HfRepo::with_config(
            parse_hf_url("hf://org/private").unwrap(),
            config(&hub, None),
        )
        .err()
        .unwrap()
        .to_string();
        for expected in [
            "org/private",
            "HF_TOKEN",
            "HF_TOKEN_PATH",
            "HF_HOME/token",
            "~/.cache/huggingface/token",
        ] {
            assert!(err.contains(expected), "{err}");
        }
        assert!(!err.contains("hf_test_secret"));
    }
}

#[test]
fn regression_hf_pagination_cannot_exfiltrate_token_or_cache_partial_tree() {
    let outside = Server::new(|_| panic!("pagination must not leave Hub origin"));
    let outside_url = outside.url.clone();
    let hub = Server::new(move |req| {
        if req.path.contains("/revision/") {
            Response::new(200, json!({"sha":SHA}).to_string())
        } else {
            Response::new(200, "[]").header("Link", format!("<{outside_url}/steal>; rel=\"next\""))
        }
    });
    let tmp = tempfile::tempdir().unwrap();
    let repo = HfRepo::with_config(
        parse_hf_url("hf://org/model").unwrap(),
        config(&hub, Some(tmp.path().into())),
    )
    .unwrap();
    assert!(repo
        .folder()
        .err()
        .unwrap()
        .to_string()
        .contains("escapes HF_ENDPOINT"));
    assert!(!repo.tree_cache_path().unwrap().exists());
    assert_eq!(outside.count(""), 0);
}

#[test]
fn regression_hf_ignored_range_buffers_once_and_empty_file_opens() {
    let gets = Arc::new(AtomicUsize::new(0));
    let count = gets.clone();
    let hub = Server::new(move |req| {
        if req.path.contains("/revision/") {
            return Response::new(200, json!({"sha":SHA}).to_string());
        }
        count.fetch_add(1, Ordering::Relaxed);
        if req.path.ends_with("/empty") {
            Response::new(416, "").header("Content-Range", "bytes */0")
        } else {
            Response::new(200, "full body")
        }
    });
    let repo =
        HfRepo::with_config(parse_hf_url("hf://org/model").unwrap(), config(&hub, None)).unwrap();
    let mut file = repo.open_file("file").unwrap();
    assert!(!file.uses_ranges());
    for _ in 0..3 {
        let mut s = String::new();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.read_to_string(&mut s).unwrap();
        assert_eq!(s, "full body");
    }
    assert_eq!(gets.load(Ordering::Relaxed), 1);
    assert!(repo.open_file("empty").unwrap().is_empty());
}

#[test]
fn regression_hf_invalid_tree_and_pagination_cycle_fail_closed() {
    for value in [
        json!([{"path":"../escape","type":"file","size":1}]),
        json!([{"path":"f","type":"file","size":-1}]),
        json!([{"path":"f","type":"file","size":1},{"path":"f","type":"file","size":1}]),
    ] {
        assert!(entries(&value).is_err());
    }
    let hub = Server::new(|req| {
        if req.path.contains("/revision/") {
            Response::new(200, json!({"sha":SHA}).to_string())
        } else {
            Response::new(200, "[]").header("Link", format!("<{}>; rel=next", req.path))
        }
    });
    let repo =
        HfRepo::with_config(parse_hf_url("hf://org/model").unwrap(), config(&hub, None)).unwrap();
    assert!(repo.folder().err().unwrap().to_string().contains("cycle"));
}

#[test]
#[ignore = "public Hub network; also requires RATARMOUNT_TEST_HF_LIVE=1"]
fn hf_live_xet_concurrent_ranges() {
    if std::env::var("RATARMOUNT_TEST_HF_LIVE").as_deref() != Ok("1") {
        eprintln!("skip: set RATARMOUNT_TEST_HF_LIVE=1");
        return;
    }
    let config = Config::from_env().unwrap();
    if config.offline {
        eprintln!("skip: HF_HUB_OFFLINE is enabled");
        return;
    }
    let repo = HfRepo::with_config(
        parse_hf_url("hf://datasets/hf-internal-testing/fixtures_image_utils").unwrap(),
        config,
    )
    .unwrap();
    let tree = repo.tree().unwrap().unwrap();
    let entry = tree
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| {
            e["xetHash"].is_string()
                && e["size"]
                    .as_u64()
                    .is_some_and(|s| s > 4096 && s < 1024 * 1024)
        })
        .min_by_key(|e| e["size"].as_u64())
        .unwrap();
    let path = entry["path"].as_str().unwrap();
    let mut file = repo.open_file(path).unwrap();
    assert!(file.uses_ranges(), "Xet Range support changed");
    let source = file.source.clone();
    let chunks = thread::scope(|scope| {
        (0..4)
            .map(|i| {
                let source = source.clone();
                scope.spawn(move || {
                    let response = source
                        .request("GET", Some((i * 1024, i * 1024 + 1023)))
                        .unwrap();
                    assert_eq!(response.status(), 206);
                    http_pool::validate_content_range(&response, i * 1024, i * 1024 + 1023, None)
                        .unwrap();
                    let host = Url::parse(response.get_url())
                        .unwrap()
                        .host_str()
                        .unwrap()
                        .to_string();
                    let mut data = Vec::new();
                    response.into_reader().read_to_end(&mut data).unwrap();
                    assert_eq!(data.len(), 1024);
                    (host, data)
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    let mut full = Vec::new();
    file.read_to_end(&mut full).unwrap();
    for (i, (_, data)) in chunks.iter().enumerate() {
        assert_eq!(data, &full[i * 1024..(i + 1) * 1024]);
    }
    assert_eq!(
        hex::encode(Sha256::digest(&full)),
        entry["lfs"]["oid"].as_str().unwrap()
    );
    eprintln!("HF live: commit={} path={path} size={} xetHash={} host={} four concurrent ranges=206, matching full SHA256", repo.commit, full.len(), entry["xetHash"], chunks[0].0);
}

#[test]
fn regression_hf_subdirectory_tree_does_not_expose_outside_entries() {
    let config =
        Config::from_values(|key| (key == "HF_ENDPOINT").then(|| "http://127.0.0.1:1".into()))
            .unwrap();
    let repo = HfRepo {
        location: parse_hf_url("hf://datasets/org/data/train").unwrap(),
        commit: SHA.into(),
        config,
    };
    let listing = HfListing::new(
        repo.clone(),
        &json!([
            {"type":"file", "path":"train/sub/a.jsonl", "size":3}
        ]),
    )
    .unwrap();
    assert_eq!(listing.list("train").unwrap()[0].name, "sub");
    assert_eq!(listing.list("train/sub").unwrap()[0].name, "a.jsonl");
    assert!(HfListing::new(
        repo,
        &json!([
            {"type":"file", "path":"outside.jsonl", "size":3}
        ])
    )
    .is_err());
}

#[test]
fn regression_hf_file_rejects_wrong_repo_commit_header() {
    let hub = Server::new(|req| {
        if req.path.contains("/revision/") {
            Response::new(200, json!({"sha": SHA}).to_string())
        } else {
            range_response(&req, b"payload")
                .header("X-Repo-Commit", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        }
    });
    let repo =
        HfRepo::with_config(parse_hf_url("hf://org/model").unwrap(), config(&hub, None)).unwrap();
    assert!(repo
        .open_file("data")
        .unwrap_err()
        .to_string()
        .contains("pinned commit"));
}

#[test]
fn regression_hf_link_comma_does_not_truncate_listing() {
    let base = "https://hub.example/api/models/org/repo/tree/abc/a%2Cb";
    let header = r#"<https://hub.example/previous>; rel="prev", <a,b?cursor=two>; title="page, two"; rel="Next""#;
    assert_eq!(
        next_link(header, base).unwrap().unwrap(),
        "https://hub.example/api/models/org/repo/tree/abc/a,b?cursor=two"
    );
    assert!(next_link("<next?cursor=x; rel=next", base).is_err());
    assert!(next_link(r#"<next>; rel="next"#, base).is_err());
    assert!(next_link("", base).unwrap().is_none());
}

#[test]
fn regression_hf_compositing_tags_are_not_remote_paths() {
    let hub = Server::new(|req| {
        if req.path.contains("/revision/") {
            Response::new(200, json!({"sha": SHA}).to_string())
        } else if req.path.contains("/tree/") {
            Response::new(200, r#"[{"path":"data.parquet","type":"file","size":4}]"#)
        } else {
            assert!(req.path.ends_with("/data.parquet"), "{}", req.path);
            range_response(&req, b"PAR1")
        }
    });
    let repo =
        HfRepo::with_config(parse_hf_url("hf://org/model").unwrap(), config(&hub, None)).unwrap();
    let source = repo.folder().unwrap().unwrap();
    let mut fi = source.lookup("/data.parquet", 0).unwrap();
    fi.userdata.push(UserData::Other("automount:/".into()));
    assert_eq!(source.read(&fi, 4, 0).unwrap(), b"PAR1");
    let synthetic_root = ratarmount_core::create_root_file_info();
    assert_eq!(
        source.get_xattr(&synthetic_root, "user.hf.commit").unwrap(),
        SHA.as_bytes()
    );
}
