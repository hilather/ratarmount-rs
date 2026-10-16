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
        hub_cache: None,
        range_cache: None,
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
            assert!(!req.path.contains("expand"));
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
                    json!([{"type":"file","path":"train/a.parquet","size":data.len(),"oid":"gitblob","lfs":{"oid":"sha256","size":data.len()},"xetHash":"xet"}])
                }
                _ => json!([{"type":"file","path":"config.json","size":2}]),
            };
            let response = Response::new(200, body.to_string());
            return if page < 2 {
                response.header(
                    "Link",
                    format!("<?recursive=true&cursor={}>; rel=\"next\"", page + 1),
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
    thread::scope(|scope| {
        let opens: Vec<_> = (0..10)
            .map(|_| scope.spawn(|| assert_eq!(folder.read(&fi, data.len(), 0).unwrap(), data)))
            .collect();
        for open in opens {
            open.join().unwrap();
        }
    });
    assert_eq!(
        hub.count("/resolve/"),
        1,
        "ten opens share one resolve and probe"
    );
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
    let file = repo.open_file("file").unwrap();
    assert!(!file.uses_ranges());
    for _ in 0..3 {
        let mut file = repo.open_file("file").unwrap();
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
        files: Arc::default(),
        hashes: Arc::default(),
        metadata: Arc::default(),
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

/// Regression: Hub token paths ignored XDG, tilde expansion and legacy variables.
#[test]
fn regression_hf_environment_matches_huggingface_hub_precedence() {
    let tmp = tempfile::tempdir().unwrap();
    for (path, token) in [
        (".cache/huggingface/token", "default"),
        ("xdg/huggingface/token", "xdg"),
        ("custom/token", "home"),
        ("explicit", "path"),
    ] {
        let path = tmp.path().join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, token).unwrap();
    }
    let mut env = BTreeMap::from([("HOME", tmp.path().to_string_lossy().into_owned())]);
    let token = |env: &BTreeMap<&str, String>| {
        Config::from_values(|k| env.get(k).cloned())
            .unwrap()
            .token
            .map(|s| s.expose_secret().clone())
    };
    assert_eq!(token(&env).as_deref(), Some("default"));
    env.insert("XDG_CACHE_HOME", "~/xdg".into());
    assert_eq!(token(&env).as_deref(), Some("xdg"));
    env.insert("HF_HOME", "~/custom".into());
    assert_eq!(token(&env).as_deref(), Some("home"));
    env.insert("HF_HOME", "${HOME}/custom".into());
    assert_eq!(token(&env).as_deref(), Some("home"));
    env.insert("HF_TOKEN_PATH", "~/explicit".into());
    assert_eq!(token(&env).as_deref(), Some("path"));
    env.insert("HF_TOKEN_PATH", "$HOME/explicit".into());
    assert_eq!(token(&env).as_deref(), Some("path"));
    env.insert("HUGGING_FACE_HUB_TOKEN", " legacy\r\ntoken ".into());
    assert_eq!(token(&env).as_deref(), Some("legacytoken"));
    env.insert("HF_TOKEN", "env".into());
    assert_eq!(token(&env).as_deref(), Some("env"));
    env.insert("HF_TOKEN", "".into());
    assert_eq!(token(&env).as_deref(), Some("legacytoken"));
    env.insert("HF_TOKEN", " \r\n".into());
    assert_eq!(token(&env).as_deref(), Some("path"));
    env.insert("HF_TOKEN_PATH", "~/missing".into());
    assert!(
        token(&env).is_none(),
        "selected file overrides other locations"
    );
    assert_eq!(
        expand_env_path("$UNKNOWN/${MISSING}/$", &|_| None),
        "$UNKNOWN/${MISSING}/$"
    );

    for (hub, legacy, expected) in [
        (None, Some("1"), true),
        (Some(""), Some("YES"), true),
        (Some("0"), Some("1"), false),
        (Some("false"), Some("ON"), false),
        (Some("True"), Some("0"), true),
        (None, Some("0"), false),
        (None, None, false),
    ] {
        env.remove("HF_HUB_OFFLINE");
        env.remove("TRANSFORMERS_OFFLINE");
        if let Some(s) = hub {
            env.insert("HF_HUB_OFFLINE", s.into());
        }
        if let Some(s) = legacy {
            env.insert("TRANSFORMERS_OFFLINE", s.into());
        }
        let config = Config::from_values(|k| env.get(k).cloned()).unwrap();
        assert_eq!(config.offline, expected);
        assert_eq!(config.online().is_err(), expected);
    }
}

/// Regression: an ignored Range could buffer an arbitrary file and redownload on open.
#[test]
fn regression_hf_ignored_range_large_file_refused_once() {
    let hub = Server::new(|req| {
        if req.path.contains("/revision/") {
            Response::new(200, json!({"sha":SHA}).to_string())
        } else {
            Response::new(200, vec![0; MAX_BUFFER_BYTES as usize + 1])
        }
    });
    let repo =
        HfRepo::with_config(parse_hf_url("hf://org/model").unwrap(), config(&hub, None)).unwrap();
    for _ in 0..3 {
        let err = repo.open_file("large").err().unwrap().to_string();
        assert!(
            err.contains("ignores Range") && err.contains("64 MiB"),
            "{err}"
        );
    }
    assert_eq!(hub.count("/resolve/"), 1);
    // A missing/dishonest Content-Length must not bypass the streaming limit.
    let mut reader = io::repeat(0);
    assert!(bounded_body(&mut reader, 64).unwrap().is_none());
    assert_eq!(bounded_body(&b"abc"[..], 3).unwrap().unwrap(), b"abc");
}

/// Regression: generic 404 strings classified missing repos/revisions as files.
#[test]
fn regression_hf_error_codes_distinguish_files_revisions_and_repos() {
    for (status, code, expected) in [
        (401, None, "not found or private"),
        (404, Some("RepoNotFound"), "repository not found or private"),
        (403, Some("GatedRepo"), "gated repository"),
        (404, Some("RevisionNotFound"), "revision not found"),
        (404, Some("EntryNotFound"), "entry not found"),
        (404, None, "Hub request failed"),
    ] {
        let hub = Server::new(move |req| {
            if req.path.contains("/revision/") {
                return Response::new(200, json!({"sha":SHA}).to_string());
            }
            let response = Response::new(status, "");
            match code {
                Some(code) => response.header("X-Error-Code", code),
                None => response,
            }
        });
        let repo = HfRepo::with_config(
            parse_hf_url("hf://org/model/file").unwrap(),
            config(&hub, None),
        )
        .unwrap();
        let result = repo.tree();
        if code == Some("EntryNotFound") {
            assert!(result.unwrap().is_none());
        } else {
            let err = result.unwrap_err().to_string();
            assert!(err.contains(expected) && err.contains("org/model"), "{err}");
        }
        let err = repo.open_file("file").err().unwrap().to_string();
        assert!(err.contains(expected), "{err}");
    }
}

/// Regression: 429 failed immediately or retries were applied to file reads.
#[test]
fn regression_hf_api_retry_after_bounded_and_data_not_retried() {
    let revisions = Arc::new(AtomicUsize::new(0));
    let trees = Arc::new(AtomicUsize::new(0));
    let rev = revisions.clone();
    let tree = trees.clone();
    let hub = Server::new(move |req| {
        if req.path.contains("/revision/") && rev.fetch_add(1, Ordering::Relaxed) == 3 {
            return Response::new(200, json!({"sha":SHA}).to_string());
        }
        if req.path.contains("/tree/") && tree.fetch_add(1, Ordering::Relaxed) == 1 {
            return Response::new(200, "[]");
        }
        Response::new(429, "").header("Retry-After", "0")
    });
    let repo =
        HfRepo::with_config(parse_hf_url("hf://org/model").unwrap(), config(&hub, None)).unwrap();
    assert!(repo.tree().unwrap().is_some());
    assert_eq!(revisions.load(Ordering::Relaxed), 4);
    assert_eq!(trees.load(Ordering::Relaxed), 2);
    assert!(repo
        .open_file("file")
        .err()
        .unwrap()
        .to_string()
        .contains("429"));
    assert_eq!(hub.count("/resolve/"), 1);
    assert!(repo.fetch_bytes(&repo.resolve_url("sidecar"), 64).is_err());
    assert_eq!(hub.count("/sidecar"), 1);
    let hub = Server::new(|_| Response::new(429, "").header("Retry-After", "0"));
    assert!(
        HfRepo::with_config(parse_hf_url("hf://org/model").unwrap(), config(&hub, None)).is_err()
    );
    assert_eq!(hub.count("/revision/"), 4);
    let now = SystemTime::UNIX_EPOCH + Duration::from_secs(784111777);
    for (header, expected) in [
        (Some("0"), 0),
        (Some("2"), 2),
        (Some("999999"), 5),
        (None, 1),
        (Some("invalid"), 1),
        (Some("Sun, 06 Nov 1994 08:49:40 GMT"), 3),
        (Some("Sun, 06 Nov 1994 08:49:30 GMT"), 0),
    ] {
        assert_eq!(retry_after(header, now), Duration::from_secs(expected));
    }
}

/// Regression: an error after a successful probe suggested generic HTTP credentials.
#[test]
fn regression_hf_range_read_unauthorized_mentions_hf_token() {
    let probes = Arc::new(AtomicUsize::new(0));
    let count = probes.clone();
    let hub = Server::new(move |req| {
        if req.path.contains("/revision/") {
            return Response::new(200, json!({"sha":SHA}).to_string());
        }
        if count.fetch_add(1, Ordering::Relaxed) == 0 {
            range_response(&req, b"abc")
        } else {
            Response::new(401, "")
        }
    });
    let repo =
        HfRepo::with_config(parse_hf_url("hf://org/model").unwrap(), config(&hub, None)).unwrap();
    let mut file = repo.open_file("file").unwrap();
    let err = file.read(&mut [0; 1]).unwrap_err().to_string();
    assert!(
        err.contains("HF_TOKEN") && err.contains("not found or private"),
        "{err}"
    );
    assert!(!err.contains("RATARMOUNT_HTTP"), "{err}");
}

/// Regression: ureq transport Display exposed cached CDN signatures in read errors.
#[test]
fn regression_http_cached_redirect_transport_error_redacts_signature() {
    let cdn = Server::new(|req| range_response(&req, b"abc"));
    let target = format!("{}/data?Signature=secret-signature", cdn.url);
    let hub = Server::new(move |_| Response::new(302, "").header("Location", target.clone()));
    let source = http_pool::HttpRangeSource::new(
        HttpLocation {
            url: hub.url.clone(),
            auth: None,
            cookie: None,
        },
        HttpAuthOptions::default(),
    );
    let mut file = HttpRangeFile::from_source(Arc::new(source), 3, None);
    file.read_exact(&mut [0; 1]).unwrap();
    drop(cdn);
    let err = file.read(&mut [0; 1]).unwrap_err().to_string();
    assert!(
        !err.contains("Signature") && !err.contains("secret-signature"),
        "{err}"
    );
    // Callers that log the shared request's error directly must also be safe.
    let err = file
        .source
        .request("GET", Some((0, 0)))
        .unwrap_err()
        .to_string();
    assert!(
        !err.contains("Signature") && !err.contains("secret-signature"),
        "{err}"
    );
    assert_eq!(hub.count(""), 1, "error must come from the cached target");
    let url = "https://user:password@cdn.example/data?Signature=secret-signature#token";
    assert_eq!(http_pool::redacted_url(url), "https://cdn.example/data");
    let response = ureq::Response::new(401, "Unauthorized", "").unwrap();
    let err = crate::map_ureq_http_error(ureq::Error::Status(401, response), url).to_string();
    for secret in ["password", "secret-signature", "#token"] {
        assert!(!err.contains(secret), "{err}");
    }
}

/// Regression: authenticated plain-HTTP endpoints silently sent tokens in cleartext.
#[test]
fn regression_hf_plain_http_token_warning_once() {
    let server = Server::new(|_| Response::new(200, ""));
    let mut config = config(&server, None);
    let once = Once::new();
    config.token = None;
    assert!(!warn_plain_http(&config, &once));
    config.token = Some(SecretString::new("secret".into()));
    config.endpoint.set_scheme("https").unwrap();
    assert!(!warn_plain_http(&config, &once));
    config.endpoint.set_scheme("http").unwrap();
    assert!(warn_plain_http(&config, &once));
    assert!(!warn_plain_http(&config, &once));
}

#[test]
#[ignore = "public Hub network; also requires RATARMOUNT_TEST_HF_LIVE=1"]
fn hf_live_unexpanded_tree_page_retains_file_metadata() {
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
        parse_hf_url("hf://datasets/HuggingFaceFW/fineweb-edu").unwrap(),
        config,
    )
    .unwrap();
    let url = format!(
        "{}?recursive=true",
        repo.api_url(&format!("tree/{}", repo.commit))
    );
    let response = repo.get_api(&url).unwrap();
    assert!(next_link(&response.all("Link").join(","), &url)
        .unwrap()
        .is_some());
    let body = read_json(response.into_reader()).unwrap();
    let items = body.as_array().unwrap();
    assert!(
        items.len() > 50,
        "unexpanded tree unexpectedly uses expanded-size pages"
    );
    let mut xet_count = 0;
    for file in items.iter().filter(|e| e["type"] == "file") {
        assert!(file["path"].is_string() && file["size"].is_u64());
        if !file["lfs"].is_null() {
            assert!(file["lfs"]["oid"].is_string() && file["lfs"]["size"].is_u64());
        }
        if file["xetHash"].is_string() {
            xet_count += 1;
        }
    }
    assert!(xet_count > 0);
    eprintln!(
        "HF live unexpanded tree: commit={} entries={} xetHash entries={xet_count}",
        repo.commit,
        items.len()
    );
}

/// Regression: Hub opens bypassed the persistent byte cache despite a pinned commit.
#[test]
fn regression_hf_range_cache_second_read_zero_cdn_gets_and_commit_refetch() {
    let body = b"cached model weights";
    let cdn = Server::new(move |req| range_response(&req, body));
    let cdn_url = cdn.url.clone();
    let hub = Server::new(move |req| {
        if req.path.contains("/revision/") {
            return Response::new(200, json!({"sha":SHA}).to_string());
        }
        Response::new(302, vec![]).header("Location", format!("{cdn_url}/file"))
    });
    let temp = tempfile::tempdir().unwrap();
    let mut cfg = config(&hub, None);
    cfg.range_cache = Some(ratarmount_index::RangeCache::with_dirs(
        temp.path().join("payload-v1/range-v1"),
        temp.path().join("payload-v1"),
        1024,
        4 * 1024 * 1024,
    ));
    let repo =
        HfRepo::with_config(parse_hf_url("hf://org/model/weights.bin").unwrap(), cfg).unwrap();
    let mut first = repo.open_file("weights.bin").unwrap();
    let mut bytes = Vec::new();
    first.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, body);
    let before = cdn.count("/file");
    let mut second = repo.open_file("weights.bin").unwrap();
    bytes.clear();
    second.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, body);
    assert_eq!(cdn.count("/file"), before);
    let mut other = repo.clone();
    other.commit = "b".repeat(40);
    let mut changed = other.open_file("weights.bin").unwrap();
    bytes.clear();
    changed.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, body);
    assert!(
        cdn.count("/file") > before,
        "a different commit must have its own probe and byte identity"
    );
}

/// Regression: X-Linked-Etag on the Hub redirect was lost before completed-file verification.
#[test]
fn regression_hf_range_cache_linked_sha256_verifies_complete_file() {
    for valid in [true, false] {
        let body = b"verified weights";
        let digest = hex::encode(Sha256::digest(if valid {
            body.as_slice()
        } else {
            b"wrong weights"
        }));
        let cdn = Server::new(move |req| range_response(&req, body));
        let cdn_url = cdn.url.clone();
        let hub = Server::new(move |req| {
            if req.path.contains("/revision/") {
                return Response::new(200, json!({"sha":SHA}).to_string());
            }
            Response::new(302, vec![])
                .header("Location", format!("{cdn_url}/file"))
                .header("X-Linked-Etag", format!("\"{digest}\""))
        });
        let temp = tempfile::tempdir().unwrap();
        let mut cfg = config(&hub, None);
        cfg.range_cache = Some(ratarmount_index::RangeCache::with_dirs(
            temp.path().join("payload-v1/range-v1"),
            temp.path().join("payload-v1"),
            1024,
            4 * 1024 * 1024,
        ));
        let repo = HfRepo::with_config(parse_hf_url("hf://org/model/f").unwrap(), cfg).unwrap();
        let mut file = repo.open_file("f").unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(
            bytes, body,
            "a cache digest mismatch must not fail the network read"
        );
        assert_eq!(file.complete_file().is_some(), valid);
    }
}

/// Regression: tree API lfs.oid digests were discarded before file cache verification.
#[test]
fn regression_hf_range_cache_tree_lfs_oid_verifies_complete_file() {
    let body = b"lfs body";
    let hub = Server::new(move |req| {
        if req.path.contains("/revision/") {
            return Response::new(200, json!({"sha":SHA}).to_string());
        }
        range_response(&req, body)
    });
    let temp = tempfile::tempdir().unwrap();
    let mut cfg = config(&hub, None);
    cfg.range_cache = Some(ratarmount_index::RangeCache::with_dirs(
        temp.path().join("payload-v1/range-v1"),
        temp.path().join("payload-v1"),
        1024,
        4 * 1024 * 1024,
    ));
    let repo = HfRepo::with_config(parse_hf_url("hf://org/model").unwrap(), cfg).unwrap();
    let _listing = HfListing::new(
        repo.clone(),
        &json!([{"type":"file", "path":"f", "size":body.len(), "lfs":{"oid":"0".repeat(64)}}]),
    )
    .unwrap();
    let mut file = repo.open_file("f").unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, body);
    assert!(
        file.complete_file().is_none(),
        "the bad LFS digest must prevent completed publication"
    );
}

/// Regression: a tiny memory budget must degrade without corrupting reads.
#[test]
fn regression_memory_budget_hf_spills_ignored_range() {
    let name = std::thread::current().name().unwrap().to_string();
    if std::env::var("RATARMOUNT_BUDGET_TEST").ok().as_deref() != Some(&name) {
        assert!(std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &name, "--nocapture"])
            .env("RATARMOUNT_BUDGET_TEST", &name)
            .status()
            .unwrap()
            .success());
        return;
    }
    ratarmount_core::budget::MemoryBudget::install(64).unwrap();

    regression_hf_ignored_range_buffers_once_and_empty_file_opens();
    regression_hf_cache_buffered_and_empty_files_shared();
    let snapshot = ratarmount_core::budget::MemoryBudget::global().snapshot();
    assert_eq!(snapshot.reserved, 0);
    assert!(snapshot.pools.iter().any(|p| p.name == "hf-fallback"));
}

fn shared_cache_config(server: &Server, root: &std::path::Path) -> Config {
    let mut config = config(server, None);
    config.hub_cache = Some(crate::hf_cache::HubCache::from_values(&|key| {
        (key == "HF_HUB_CACHE").then(|| root.join("hub").to_string_lossy().into())
    }));
    config.range_cache = Some(ratarmount_index::RangeCache::with_dirs(
        root.join("payload/range-v1"),
        root.join("payload"),
        1024 * 1024,
        4,
    ));
    config
}

fn shared_cache_server(data: &'static [u8], lfs: bool) -> (Server, String) {
    let etag = if lfs {
        hex::encode(Sha256::digest(data))
    } else {
        let mut hash = sha1::Sha1::new();
        hash.update(format!("blob {}\0", data.len()).as_bytes());
        hash.update(data);
        hex::encode(hash.finalize())
    };
    let hash = etag.clone();
    let server = Server::new(move |req| {
        if req.path.contains("/revision/") {
            Response::new(200, json!({"sha": SHA}).to_string())
        } else if req.path.contains("/tree/") {
            let entry = if lfs {
                json!({"type": "file", "path": "sub/file", "size": data.len(), "lfs": {"oid": hash}})
            } else {
                json!({"type": "file", "path": "sub/file", "size": data.len(), "oid": hash})
            };
            Response::new(200, json!([entry]).to_string())
        } else {
            range_response(&req, data).header("ETag", format!("\"{hash}\""))
        }
    });
    (server, etag)
}

fn cached_file_requests(server: &Server) -> usize {
    server
        .requests
        .lock()
        .unwrap()
        .iter()
        .filter(|p| p.contains("/resolve/"))
        .count()
}

/// Regression: hf:// re-fetched files already downloaded by huggingface_hub.
#[cfg(unix)]
#[test]
fn regression_hf_cache_read_through_zero_file_requests_and_passthrough() {
    let data = b"existing Hub blob";
    let (server, etag) = shared_cache_server(data, true);
    let dir = tempfile::tempdir().unwrap();
    let config = shared_cache_config(&server, dir.path());
    let repo_dir = dir.path().join("hub/datasets--org--data");
    let snapshot = repo_dir.join("snapshots").join(SHA).join("sub");
    std::fs::create_dir_all(&snapshot).unwrap();
    std::fs::create_dir_all(repo_dir.join("blobs")).unwrap();
    std::fs::write(repo_dir.join("blobs").join(&etag), data).unwrap();
    std::os::unix::fs::symlink(format!("../../../blobs/{etag}"), snapshot.join("file")).unwrap();
    let repo =
        HfRepo::with_config(parse_hf_url("hf://datasets/org/data").unwrap(), config).unwrap();
    let source = repo.folder().unwrap().unwrap();
    let fi = source.lookup("/sub/file", 0).unwrap();
    let mut bytes = Vec::new();
    source
        .open(&fi, 0)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes, data);
    let mut extent = source.backing_extent(&fi).unwrap();
    assert_eq!(extent.offset, 0);
    let mut local = Vec::new();
    extent.file.read_to_end(&mut local).unwrap();
    assert_eq!(local, data);
    assert_eq!(cached_file_requests(&server), 0);
    // A known tree hash can reuse a blob even without a snapshot pointer.
    std::fs::remove_file(snapshot.join("file")).unwrap();
    let repo = HfRepo::with_config(
        parse_hf_url("hf://datasets/org/data").unwrap(),
        shared_cache_config(&server, dir.path()),
    )
    .unwrap();
    let source = repo.folder().unwrap().unwrap();
    let fi = source.lookup("/sub/file", 0).unwrap();
    let mut bytes = Vec::new();
    source
        .open(&fi, 0)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes, data);
    assert_eq!(cached_file_requests(&server), 0);
}

/// Regression: complete range bytes were duplicated instead of atomically shared with the Hub.
#[test]
fn regression_hf_cache_write_back_drops_range_copy_and_second_mount_no_file_requests() {
    for lfs in [false, true] {
        let data = b"new Hub bytes spread over multiple chunks";
        let (server, etag) = shared_cache_server(data, lfs);
        let dir = tempfile::tempdir().unwrap();
        let config = shared_cache_config(&server, dir.path());
        let ranges = config.range_cache.clone().unwrap();
        let location = parse_hf_url("hf://datasets/org/data@feature%2Fone").unwrap();
        let repo = HfRepo::with_config(location.clone(), config.clone()).unwrap();
        let source = repo.folder().unwrap().unwrap();
        let fi = source.lookup("/sub/file", 0).unwrap();
        let mut bytes = Vec::new();
        source
            .open(&fi, 0)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, data);
        repo.open_file("sub/file")
            .unwrap()
            .source
            .wait_for_publication();
        let blob = dir.path().join("hub/datasets--org--data/blobs").join(&etag);
        assert_eq!(std::fs::read(&blob).unwrap(), data);
        let mut range = repo.open_file("sub/file").unwrap();
        assert_eq!(range.complete_file().unwrap(), blob);
        range.seek(SeekFrom::Start(3)).unwrap();
        let mut suffix = Vec::new();
        range.read_to_end(&mut suffix).unwrap();
        assert_eq!(suffix, &data[3..]);
        let token = ContentToken::HfCommitPath {
            endpoint: config.endpoint.as_str().into(),
            repo_kind: location.kind.clone(),
            repo: location.repo.clone(),
            commit: SHA.into(),
            path: "sub/file".into(),
            size: data.len() as u64,
        };
        let token = if lfs {
            token.with_sha256(etag.clone())
        } else {
            token
        };
        assert!(ranges.complete_file(&token).is_none());
        for chunk in 0..(data.len() as u64).div_ceil(4) {
            assert!(!ranges.contains(&token, chunk));
        }
        assert_eq!(
            std::fs::read_dir(blob.parent().unwrap()).unwrap().count(),
            1
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("hub/datasets--org--data/refs/feature/one"))
                .unwrap(),
            SHA
        );
        assert!(dir
            .path()
            .join("hub/.locks/datasets--org--data")
            .join(format!("{etag}.lock"))
            .exists());
        let before = cached_file_requests(&server);
        let repo = HfRepo::with_config(location, config).unwrap();
        let source = repo.folder().unwrap().unwrap();
        let mut bytes = Vec::new();
        source
            .open(&source.lookup("/sub/file", 0).unwrap(), 0)
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, data);
        assert_eq!(cached_file_requests(&server), before);
    }
}

/// Regression: a corrupt same-size LFS blob must be refetched and repaired, never served.
#[test]
fn regression_hf_cache_lfs_mismatch_refetched() {
    let data = b"correct cached weights";
    let (server, etag) = shared_cache_server(data, true);
    let dir = tempfile::tempdir().unwrap();
    let config = shared_cache_config(&server, dir.path());
    let blobs = dir.path().join("hub/datasets--org--data/blobs");
    std::fs::create_dir_all(&blobs).unwrap();
    std::fs::write(blobs.join(&etag), vec![b'!'; data.len()]).unwrap();
    let repo =
        HfRepo::with_config(parse_hf_url("hf://datasets/org/data").unwrap(), config).unwrap();
    let source = repo.folder().unwrap().unwrap();
    let mut bytes = Vec::new();
    source
        .open(&source.lookup("/sub/file", 0).unwrap(), 0)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes, data);
    repo.open_file("sub/file")
        .unwrap()
        .source
        .wait_for_publication();
    assert!(cached_file_requests(&server) > 0);
    assert_eq!(std::fs::read(blobs.join(etag)).unwrap(), data);
}

/// Regression: non-Range responses and empty files bypassed whole-file cache sharing.
#[test]
fn regression_hf_cache_buffered_and_empty_files_shared() {
    for data in [b"buffered body".as_slice(), b"".as_slice()] {
        let hash = {
            let mut sha = sha1::Sha1::new();
            sha.update(format!("blob {}\0", data.len()).as_bytes());
            sha.update(data);
            hex::encode(sha.finalize())
        };
        let etag = hash.clone();
        let server = Server::new(move |req| {
            if req.path.contains("/revision/") {
                Response::new(200, json!({"sha": SHA}).to_string())
            } else if req.path.contains("/tree/") {
                Response::new(
                    200,
                    json!([{"type":"file", "path":"file", "size":data.len(), "oid":etag}])
                        .to_string(),
                )
            } else if data.is_empty() {
                Response::new(416, "").header("Content-Range", "bytes */0")
            } else {
                Response::new(200, data).header("ETag", format!("\"{etag}\""))
            }
        });
        let dir = tempfile::tempdir().unwrap();
        let mut config = shared_cache_config(&server, dir.path());
        config.range_cache = None;
        let location = parse_hf_url("hf://org/model").unwrap();
        let repo = HfRepo::with_config(location.clone(), config.clone()).unwrap();
        repo.folder().unwrap();
        let mut file = repo.open_file("file").unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, data);
        file.source.wait_for_publication();
        let blob = dir.path().join("hub/models--org--model/blobs").join(hash);
        assert_eq!(std::fs::read(&blob).unwrap(), data);
        assert_eq!(file.complete_file().unwrap(), blob);
        let before = cached_file_requests(&server);
        let repo = HfRepo::with_config(location, config).unwrap();
        let mut file = repo.open_file("file").unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, data);
        assert_eq!(cached_file_requests(&server), before);
    }
}

/// Regression: uppercase response ETags created noncanonical, unshared blob names.
#[test]
fn regression_hf_cache_header_etag_lowercase() {
    let data = b"header-only regular file";
    let mut sha = sha1::Sha1::new();
    sha.update(format!("blob {}\0", data.len()).as_bytes());
    sha.update(data);
    let etag = hex::encode(sha.finalize());
    let header = etag.to_ascii_uppercase();
    let server = Server::new(move |request| {
        if request.path.contains("/revision/") {
            Response::new(200, json!({"sha": SHA}).to_string())
        } else {
            range_response(&request, data).header("ETag", format!("\"{header}\""))
        }
    });
    let dir = tempfile::tempdir().unwrap();
    let repo = HfRepo::with_config(
        parse_hf_url("hf://org/model/file").unwrap(),
        shared_cache_config(&server, dir.path()),
    )
    .unwrap();
    let mut file = repo.open_file("file").unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    file.source.wait_for_publication();
    assert_eq!(bytes, data);
    let blobs = dir.path().join("hub/models--org--model/blobs");
    let names: Vec<_> = std::fs::read_dir(blobs)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    assert_eq!(names, vec![etag]);
}

/// Regression: a newer Python ref written while the revision API was in flight was replaced at mount open.
#[test]
fn regression_hf_cache_mount_open_preserves_concurrent_ref_move() {
    let dir = tempfile::tempdir().unwrap();
    let reference = dir.path().join("hub/models--org--model/refs/main");
    std::fs::create_dir_all(reference.parent().unwrap()).unwrap();
    std::fs::write(&reference, "b".repeat(40)).unwrap();
    let destination = reference.clone();
    let server = Server::new(move |_| {
        std::fs::write(&destination, "c".repeat(40)).unwrap();
        Response::new(200, json!({"sha": SHA}).to_string())
    });
    let repo = HfRepo::with_config(
        parse_hf_url("hf://org/model").unwrap(),
        shared_cache_config(&server, dir.path()),
    )
    .unwrap();
    assert_eq!(repo.commit, SHA);
    assert_eq!(std::fs::read_to_string(reference).unwrap(), "c".repeat(40));
}

/// Regression: disabling Hub sharing also disabled completed range-cache passthrough.
#[test]
fn regression_hf_cache_disabled_sharing_keeps_range_backing_fd() {
    let data = b"range cache backing without Hub sharing";
    let (server, _) = shared_cache_server(data, true);
    let dir = tempfile::tempdir().unwrap();
    let mut config = shared_cache_config(&server, dir.path());
    config.hub_cache = None;
    let repo =
        HfRepo::with_config(parse_hf_url("hf://datasets/org/data").unwrap(), config).unwrap();
    let source = repo.folder().unwrap().unwrap();
    let fi = source.lookup("/sub/file", 0).unwrap();
    let mut bytes = Vec::new();
    source
        .open(&fi, 0)
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(bytes, data);
    let mut extent = source.backing_extent(&fi).unwrap();
    let mut bytes = Vec::new();
    extent.file.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, data);
    assert!(!dir.path().join("hub").exists());
}
