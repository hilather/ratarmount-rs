use super::*;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::AtomicUsize;
use std::thread::JoinHandle;
use std::time::Duration;

fn b(s: impl AsRef<[u8]>) -> Vec<u8> {
    let s = s.as_ref();
    let mut out = format!("{}:", s.len()).into_bytes();
    out.extend(s);
    out
}
fn n(n: u64) -> Vec<u8> {
    format!("i{n}e").into_bytes()
}
fn l(values: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    let mut out = b"l".to_vec();
    for v in values {
        out.extend(v);
    }
    out.push(b'e');
    out
}
fn d(values: impl IntoIterator<Item = (&'static str, Vec<u8>)>) -> Vec<u8> {
    let values: BTreeMap<_, _> = values.into_iter().collect();
    let mut out = b"d".to_vec();
    for (key, value) in values {
        out.extend(b(key));
        out.extend(value);
    }
    out.push(b'e');
    out
}
fn envelope(info: Vec<u8>, seeds: &[String]) -> Vec<u8> {
    d([("info", info), ("url-list", l(seeds.iter().map(b)))])
}
fn v1_info(
    files: &[(&str, &[u8])],
    piece: usize,
    multi: bool,
    expected: Option<[u8; 32]>,
) -> Vec<u8> {
    let body: Vec<_> = files.iter().flat_map(|(_, b)| b.iter().copied()).collect();
    let hashes: Vec<_> = body
        .chunks(piece)
        .flat_map(|b| Sha1::digest(b).to_vec())
        .collect();
    let mut info = vec![
        ("name", b(if multi { "bundle" } else { files[0].0 })),
        ("piece length", n(piece as u64)),
        ("pieces", b(hashes)),
    ];
    if multi {
        info.push((
            "files",
            l(files.iter().map(|(path, body)| {
                d([
                    ("length", n(body.len() as u64)),
                    ("path", l(path.split('/').map(b))),
                ])
            })),
        ));
    } else {
        info.push(("length", n(body.len() as u64)));
        if let Some(hash) = expected {
            info.push(("sha256", b(hash)));
        }
    }
    d(info)
}

struct Web {
    url: String,
    count: Arc<AtomicUsize>,
    requests: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
    handle: Option<JoinHandle<()>>,
}
impl Web {
    fn new(files: BTreeMap<String, Vec<u8>>) -> Self {
        Self::with_ranges(files, true)
    }
    fn with_ranges(files: BTreeMap<String, Vec<u8>>, ranges: bool) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (c, r, s) = (count.clone(), requests.clone(), stop.clone());
        let handle = std::thread::spawn(move || {
            for stream in listener.incoming() {
                if s.load(Ordering::Relaxed) {
                    break;
                }
                let mut stream = stream.unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut first = String::new();
                if reader.read_line(&mut first).is_err() || first.is_empty() {
                    continue;
                }
                let path = first.split_whitespace().nth(1).unwrap().to_string();
                let mut range = None;
                loop {
                    let mut line = String::new();
                    if reader.read_line(&mut line).unwrap_or(0) == 0 || line == "\r\n" {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("range: bytes=") {
                        let (a, b) = value.trim().split_once('-').unwrap();
                        range = Some((a.parse::<usize>().unwrap(), b.parse::<usize>().unwrap()));
                    }
                }
                c.fetch_add(1, Ordering::Relaxed);
                r.lock().unwrap().push(path.clone());
                let Some(bytes) = files.get(&path) else {
                    let _ = write!(
                        stream,
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    continue;
                };
                if let Some((a, z)) = range.filter(|_| ranges) {
                    let z = z.min(bytes.len() - 1);
                    let _ = write!(stream, "HTTP/1.1 206 Partial Content\r\nContent-Range: bytes {a}-{z}/{}\r\nContent-Length: {}\r\nETag: \"untrusted\"\r\nConnection: close\r\n\r\n", bytes.len(), z - a + 1);
                    let _ = stream.write_all(&bytes[a..=z]);
                } else {
                    let _ = write!(
                        stream,
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        bytes.len()
                    );
                    let _ = stream.write_all(bytes);
                }
            }
        });
        Self {
            url: format!("http://{addr}/"),
            count,
            requests,
            stop,
            handle: Some(handle),
        }
    }
}
impl Drop for Web {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let url = Url::parse(&self.url).unwrap();
        let _ = TcpStream::connect(("127.0.0.1", url.port().unwrap()));
        let _ = self.handle.take().unwrap().join();
    }
}
fn options(dir: &std::path::Path) -> TorrentOptions {
    TorrentOptions {
        metadata_dir: dir.join("meta"),
        range_cache: Some(RangeCache::with_dirs(
            dir.join("range-v1"),
            dir.into(),
            8 * 1024 * 1024,
            4096,
        )),
        swarm: SwarmOptions {
            dht: false,
            trackers: false,
            lsd: false,
            initial_peers: vec![],
            // Match production: peer retry backoffs and parallel test load can exceed 8s.
            timeout: Duration::from_secs(30),
            ..Default::default()
        },
        readahead_bytes: 0,
    }
}
fn read(source: &TorrentMountSource, path: &str) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    source
        .open(&source.lookup(path, 0).unwrap(), 0)?
        .read_to_end(&mut bytes)?;
    Ok(bytes)
}

/// Regression: metadata listing fetched pieces, or a v1 boundary read used the wrong file offset.
#[test]
fn regression_lazy_tree_and_cross_file_pieces() {
    let dir = tempfile::tempdir().unwrap();
    let files: &[(&str, &[u8])] = &[("a", b"abc"), ("sub/b space", b"defghi")];
    let web = Web::new(BTreeMap::from([
        ("/bundle/a".into(), b"abc".to_vec()),
        ("/bundle/sub/b%20space".into(), b"defghi".to_vec()),
    ]));
    let bytes = envelope(
        v1_info(files, 4, true, None),
        std::slice::from_ref(&web.url),
    );
    let meta = Metainfo::parse(bytes.clone()).unwrap();
    assert_eq!(meta.spans(0), [(0, 0, 3), (1, 0, 1)]);
    assert_eq!(meta.spans(1), [(1, 1, 4)]);
    assert_eq!(meta.spans(2), [(1, 5, 1)]);
    let source = TorrentMountSource::from_bytes(bytes, options(dir.path())).unwrap();
    assert_eq!(source.list_dirents("/").unwrap().len(), 2);
    assert_eq!(source.lookup("/sub/b space", 0).unwrap().size, 6);
    assert_eq!(web.count.load(Ordering::Relaxed), 0);
    assert_eq!(read(&source, "/sub/b space").unwrap(), b"defghi");
    assert!(source.data.swarm.lock().unwrap().is_none());
    assert!(web.requests.lock().unwrap().contains(&"/bundle/a".into()));
}

/// Regression: a valid torrent piece bypassed the independent whole-file SHA-256 check.
#[test]
fn regression_whole_file_sha256_mismatch_eio() {
    let dir = tempfile::tempdir().unwrap();
    let web = Web::new(BTreeMap::from([("/file".into(), b"hello".to_vec())]));
    let bytes = envelope(
        v1_info(&[("file", b"hello")], 4, false, Some([0; 32])),
        &[format!("{}file", web.url)],
    );
    let source = TorrentMountSource::from_bytes(bytes, options(dir.path())).unwrap();
    let fi = source.lookup("/file", 0).unwrap();
    let mut reader = source.open(&fi, 0).unwrap();
    let mut buf = [0; 5];
    assert_eq!(reader.read(&mut buf).unwrap(), 4);
    let _ = reader.read(&mut buf);
    wait_until(|| source.data.verification[0].lock().unwrap().bad);
    assert_eq!(
        source
            .open(&fi, 0)
            .unwrap()
            .read(&mut buf)
            .unwrap_err()
            .raw_os_error(),
        Some(5)
    );
    assert!(source.verified_file_sha256("/file").is_none());
}

/// Regression: random reads never completed whole-file verification across handles.
#[test]
fn regression_random_reads_complete_sha256_hook() {
    let dir = tempfile::tempdir().unwrap();
    let payload = b"hello torrent";
    let web = Web::new(BTreeMap::from([("/file".into(), payload.to_vec())]));
    let bytes = envelope(
        v1_info(
            &[("file", payload)],
            4,
            false,
            Some(Sha256::digest(payload).into()),
        ),
        &[format!("{}file", web.url)],
    );
    let source = TorrentMountSource::from_bytes(bytes, options(dir.path())).unwrap();
    for pos in (0..payload.len()).rev() {
        let mut reader = source.open(&source.lookup("/file", 0).unwrap(), 0).unwrap();
        reader.seek(SeekFrom::Start(pos as u64)).unwrap();
        let mut byte = [0];
        reader.read_exact(&mut byte).unwrap();
        assert_eq!(byte[0], payload[pos]);
    }
    wait_until(|| source.verified_file_sha256("/file").is_some());
    assert_eq!(
        source.verified_file_sha256("/file"),
        Some(hex::encode(Sha256::digest(payload)))
    );
}

fn v2_info(payload: &[u8], hybrid: bool) -> (Vec<u8>, [u8; 32], Vec<u8>) {
    let piece = BLOCK * 2;
    let hashes: Vec<[u8; 32]> = payload
        .chunks(piece)
        .map(|p| {
            piece_root(
                p,
                if payload.len() > piece {
                    2
                } else {
                    payload.len().div_ceil(BLOCK).next_power_of_two()
                },
            )
        })
        .collect();
    let padding = metainfo::merkle(vec![[0; 32], [0; 32]], [0; 32]);
    let root = metainfo::merkle(hashes.clone(), padding);
    let mut info = vec![
        (
            "file tree",
            d([(
                "file",
                d([(
                    "",
                    d([
                        ("length", n(payload.len() as u64)),
                        ("pieces root", b(root)),
                    ]),
                )]),
            )]),
        ),
        ("meta version", n(2)),
        ("name", b("bundle")),
        ("piece length", n(piece as u64)),
    ];
    if hybrid {
        info.push((
            "files",
            l([d([
                ("length", n(payload.len() as u64)),
                ("path", l([b("file")])),
            ])]),
        ));
        info.push((
            "pieces",
            b(payload
                .chunks(piece)
                .flat_map(|p| Sha1::digest(p).to_vec())
                .collect::<Vec<_>>()),
        ));
    }
    (d(info), root, hashes.into_iter().flatten().collect())
}
fn v2_bytes(payload: &[u8], hybrid: bool, seed: &str) -> Vec<u8> {
    let (info, root, layers) = v2_info(payload, hybrid);
    let mut layer = b"d".to_vec();
    layer.extend(b(root));
    layer.extend(b(layers));
    layer.push(b'e');
    d([
        ("info", info),
        ("piece layers", layer),
        ("url-list", l([b(seed)])),
    ])
}

/// Regression: v2/hybrid payloads trusted an unauthenticated piece layer or padded the last block incorrectly.
#[test]
fn regression_v2_and_hybrid_merkle_verified_web_seed() {
    for hybrid in [false, true] {
        for len in [1, BLOCK - 1, BLOCK * 5 + 7] {
            let dir = tempfile::tempdir().unwrap();
            let payload: Vec<_> = (0..len).map(|n| (n % 251) as u8).collect();
            let web = Web::new(BTreeMap::from([(
                if hybrid { "/bundle/file" } else { "/file" }.into(),
                payload.clone(),
            )]));
            let bytes = v2_bytes(&payload, hybrid, &web.url);
            let source =
                TorrentMountSource::from_bytes(bytes.clone(), options(dir.path())).unwrap();
            assert_eq!(read(&source, "/file").unwrap(), payload);
            assert!(source.data.swarm.lock().unwrap().is_none());
            if len > BLOCK * 2 {
                let mut corrupt = bytes;
                let top = metainfo::parse(&corrupt).unwrap();
                let layer = top.required(b"piece layers").unwrap().raw;
                let offset = layer.as_ptr() as usize - corrupt.as_ptr() as usize + layer.len() - 2;
                corrupt[offset] ^= 1;
                assert!(Metainfo::parse(corrupt).is_err());
            }
        }
    }
}

/// Regression: malformed/ambiguous metainfo escaped the mount or panicked the parser.
#[test]
fn regression_bencode_and_unsafe_paths_fail_closed() {
    for bytes in [
        b"d1:ai01ee".as_slice(),
        b"d1:ai-0ee",
        b"d1:ai1e1:ai2ee",
        b"9999999999999999999999999:x",
        b"leextra",
    ] {
        assert!(metainfo::parse(bytes).is_err());
    }
    for path in ["..", "/absolute", "a/../b", "a\\b", "C:escape"] {
        assert!(Metainfo::parse(envelope(v1_info(&[(path, b"a")], 4, true, None), &[])).is_err());
    }
    assert!(Metainfo::parse(envelope(
        v1_info(&[("a", b"a"), ("a/b", b"b")], 4, true, None),
        &[]
    ))
    .is_err());
    let info = v1_info(&[("file", b"bytes")], 4, false, None);
    let meta = Metainfo::parse(envelope(info.clone(), &[])).unwrap();
    assert_eq!(meta.v1_hash, Some(hex::encode(Sha1::digest(info))));
}

/// Regression: resolved xs metadata was not cached by exact infohash for offline remount.
#[test]
fn regression_magnet_xs_and_offline_metadata_cache() {
    let dir = tempfile::tempdir().unwrap();
    let bytes = envelope(v1_info(&[("file", b"data")], BLOCK, false, None), &[]);
    let meta = Metainfo::parse(bytes.clone()).unwrap();
    let web = Web::new(BTreeMap::from([("/meta.torrent".into(), bytes)]));
    let mut url = Url::parse(&format!("magnet:?xt=urn:btih:{}", meta.identity())).unwrap();
    url.query_pairs_mut()
        .append_pair("xs", &format!("{}meta.torrent", web.url))
        .append_pair("ws", &web.url);
    let source = TorrentMountSource::open(url.as_str(), options(dir.path())).unwrap();
    assert_eq!(source.lookup("/file", 0).unwrap().size, 4);
    assert_eq!(web.count.load(Ordering::Relaxed), 1);
    assert!(source.data.swarm.lock().unwrap().is_none());
    drop(web);
    let offline = TorrentMountSource::open(
        &format!("magnet:?xt=urn:btih:{}", meta.identity()),
        options(dir.path()),
    )
    .unwrap();
    assert_eq!(offline.data.meta.web_seeds, source.data.meta.web_seeds);
    assert_eq!(offline.lookup("/file", 0).unwrap().size, 4);
    let repeated = TorrentMountSource::open(url.as_str(), options(dir.path())).unwrap();
    assert_eq!(repeated.data.meta.web_seeds, source.data.meta.web_seeds);
}

/// Regression: btih base32 / v2 magnets were mistaken for filesystem names.
#[test]
fn regression_magnet_v1_v2_hybrid_hash_binding() {
    let payload = vec![7; BLOCK * 3];
    let bytes = v2_bytes(&payload, true, "http://127.0.0.1:1/");
    let meta = Metainfo::parse(bytes).unwrap();
    let magnet = metadata::Magnet::parse(&format!(
        "magnet:?xt=urn:btih:{}&xt=urn:btmh:1220{}",
        meta.v1_hash.as_ref().unwrap(),
        meta.v2_hash.as_ref().unwrap()
    ))
    .unwrap();
    assert!(magnet.matches(&meta));
    assert!(
        metadata::Magnet::parse("magnet:?xt=urn:btih:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").is_ok()
    );
    assert!(metadata::Magnet::parse("magnet:?xt=urn:btmh:1220abcd").is_err());
    assert!(
        !metadata::Magnet::parse(&format!("magnet:?xt=urn:btmh:1220{}", "0".repeat(64)))
            .unwrap()
            .matches(&meta)
    );
}

struct Seed {
    runtime: Option<tokio::runtime::Runtime>,
    session: Arc<librqbit::Session>,
    addr: SocketAddr,
    _dir: tempfile::TempDir,
}
impl Seed {
    fn new(bytes: &[u8], files: &[(&str, &[u8])]) -> Self {
        let dir = tempfile::tempdir().unwrap();
        for (path, bytes) in files {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, bytes).unwrap();
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let session = runtime
            .block_on(librqbit::Session::new_with_opts(
                dir.path().into(),
                librqbit::SessionOptions {
                    dht: None,
                    disable_trackers: true,
                    disable_local_service_discovery: true,
                    listen: Some(librqbit::ListenerOptions {
                        listen_addr: "127.0.0.1:0".parse().unwrap(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ))
            .unwrap();
        runtime.block_on(async {
            let torrent = session
                .add_torrent(
                    librqbit::AddTorrent::TorrentFileBytes(bytes.to_vec().into()),
                    Some(librqbit::AddTorrentOptions {
                        overwrite: true,
                        output_folder: Some(dir.path().to_str().unwrap().into()),
                        disable_trackers: true,
                        ..Default::default()
                    }),
                )
                .await
                .unwrap()
                .into_handle()
                .unwrap();
            tokio::time::timeout(Duration::from_secs(5), torrent.wait_until_completed())
                .await
                .unwrap()
                .unwrap();
        });
        let addr = session.listen_addr().unwrap();
        assert!(addr.ip().is_loopback());
        Self {
            runtime: Some(runtime),
            session,
            addr,
            _dir: dir,
        }
    }
}
impl Drop for Seed {
    fn drop(&mut self) {
        let rt = self.runtime.take().unwrap();
        rt.block_on(self.session.stop());
        rt.shutdown_timeout(Duration::from_secs(1));
    }
}

/// Regression: corrupt web-seed bytes reached the reader/cache instead of retrying the local swarm.
#[test]
fn regression_tampered_web_seed_falls_back_to_loopback_swarm() {
    for web_seed in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let payload: Vec<_> = (0..BLOCK * 2 + 7).map(|n| (n % 251) as u8).collect();
        let web = Web::new(BTreeMap::from([("/file".into(), vec![0; payload.len()])]));
        let seeds = if web_seed {
            vec![format!("{}file", web.url)]
        } else {
            vec![]
        };
        let bytes = envelope(v1_info(&[("file", &payload)], BLOCK, false, None), &seeds);
        let seed = Seed::new(&bytes, &[("file", &payload)]);
        let mut opts = options(dir.path());
        opts.swarm.initial_peers = vec![seed.addr];
        assert!(swarm::session_options(&opts.swarm).disable_upload);
        let source = TorrentMountSource::from_bytes(bytes.clone(), opts.clone()).unwrap();
        assert_eq!(read(&source, "/file").unwrap(), payload);
        assert!(source.data.swarm.lock().unwrap().is_some());
        drop(source);
        drop(seed);
        drop(web);
        // No server or swarm remains. Only independently verified cache pieces can satisfy this.
        opts.swarm.initial_peers.clear();
        let offline = TorrentMountSource::from_bytes(bytes, opts).unwrap();
        assert_eq!(read(&offline, "/file").unwrap(), payload);
        assert!(offline.data.swarm.lock().unwrap().is_none());
    }
}

/// Regression: magnet metadata resolution started payload downloading or contacted public discovery.
#[test]
fn regression_magnet_metadata_from_loopback_peer() {
    let dir = tempfile::tempdir().unwrap();
    let payload = b"metadata only";
    let bytes = envelope(v1_info(&[("file", payload)], BLOCK, false, None), &[]);
    let meta = Metainfo::parse(bytes.clone()).unwrap();
    let seed = Seed::new(&bytes, &[("file", payload)]);
    let mut opts = options(dir.path());
    opts.swarm.initial_peers = vec![seed.addr];
    let source =
        TorrentMountSource::open(&format!("magnet:?xt=urn:btih:{}", meta.identity()), opts)
            .unwrap();
    assert_eq!(
        source.lookup("/file", 0).unwrap().size,
        payload.len() as u64
    );
    assert!(source.data.swarm.lock().unwrap().is_none());
    assert!(!dir.path().join("range-v1").exists());
}

/// Regression: Hub checksum discovery confused a moving branch or foreign host with a pinned Hub file.
#[test]
fn regression_hub_web_seed_checksum_identity() {
    let rev = "a".repeat(40);
    assert_eq!(
        hub_file(&format!(
            "https://huggingface.co/org/repo/resolve/{rev}/dir/a"
        )),
        Some((format!("hf://org/repo@{rev}"), "dir/a".into()))
    );
    assert_eq!(
        hub_file(&format!(
            "https://pirateface.co/api/ws/org/repo/{rev}/bundle/dir/a"
        )),
        Some((format!("hf://org/repo@{rev}"), "dir/a".into()))
    );
    assert!(hub_file("https://huggingface.co/org/repo/resolve/main/a").is_none());
    assert!(hub_file(&format!("http://huggingface.co/org/repo/resolve/{rev}/a")).is_none());
    assert!(hub_file(&format!(
        "https://huggingface.co:444/org/repo/resolve/{rev}/a"
    ))
    .is_none());
    assert!(hub_file(&format!("https://other.example/org/repo/resolve/{rev}/a")).is_none());
}

#[test]
#[ignore = "public network; requires explicit user approval and RATARMOUNT_TEST_MAGNET"]
fn live_pirate_face_magnet() {
    let Ok(magnet) = std::env::var("RATARMOUNT_TEST_MAGNET") else {
        eprintln!("skip: RATARMOUNT_TEST_MAGNET is unset");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let mut opts = options(dir.path());
    opts.swarm = SwarmOptions::default();
    let source = TorrentMountSource::open(&magnet, opts).unwrap();
    assert!(!source.list_dirents("/").unwrap().is_empty());
}

pub(super) fn single_file_fixture() -> Vec<u8> {
    envelope(v1_info(&[("file", b"test")], BLOCK, false, None), &[])
}

/// Regression: HTTP readahead was ignored or fetched before the demanded piece.
#[test]
fn regression_torrent_readahead_fills_verified_following_pieces() {
    let dir = tempfile::tempdir().unwrap();
    let payload: Vec<_> = (0..BLOCK * 3).map(|n| (n % 251) as u8).collect();
    let web = Web::new(BTreeMap::from([("/file".into(), payload.clone())]));
    let bytes = envelope(
        v1_info(&[("file", &payload)], BLOCK, false, None),
        &[format!("{}file", web.url)],
    );
    let mut opts = options(dir.path());
    opts.readahead_bytes = (BLOCK * 2) as u64;
    let source = TorrentMountSource::from_bytes(bytes, opts).unwrap();
    let mut reader = source.open(&source.lookup("/file", 0).unwrap(), 0).unwrap();
    let mut first = [0];
    reader.read_exact(&mut first).unwrap();
    assert_eq!(first[0], payload[0]);
    let start = std::time::Instant::now();
    while web.count.load(Ordering::Relaxed) < 3
        || source
            .data
            .cached(Piece {
                file: None,
                index: 2,
            })
            .is_none()
    {
        assert!(start.elapsed() < Duration::from_secs(5));
        std::thread::sleep(Duration::from_millis(5));
    }
    assert_eq!(web.count.load(Ordering::Relaxed), 3);
    for index in 0..3 {
        assert!(source.data.cached(Piece { file: None, index }).is_some());
    }
}

/// Regression: a corrupt first HTTP source poisoned persistent pieces instead of trying the next seed.
#[test]
fn regression_bad_web_seed_never_enters_range_cache() {
    let dir = tempfile::tempdir().unwrap();
    let payload = b"verified data";
    let bad = Web::new(BTreeMap::from([("/file".into(), vec![0; payload.len()])]));
    let good = Web::new(BTreeMap::from([("/file".into(), payload.to_vec())]));
    let bytes = envelope(
        v1_info(&[("file", payload)], BLOCK, false, None),
        &[format!("{}file", bad.url), format!("{}file", good.url)],
    );
    let source = TorrentMountSource::from_bytes(bytes, options(dir.path())).unwrap();
    assert_eq!(read(&source, "/file").unwrap(), payload);
    assert_eq!(bad.count.load(Ordering::Relaxed), 1);
    assert_eq!(good.count.load(Ordering::Relaxed), 1);
    assert_eq!(
        source
            .data
            .cached(Piece {
                file: None,
                index: 0
            })
            .unwrap(),
        payload
    );
    assert!(source.data.swarm.lock().unwrap().is_none());
}

/// Regression: empty files bypassed whole-file verification at EOF.
#[test]
fn regression_empty_file_sha256_and_seek_overflow() {
    let dir = tempfile::tempdir().unwrap();
    for valid in [true, false] {
        let digest = if valid {
            Sha256::digest([]).into()
        } else {
            [0; 32]
        };
        let bytes = envelope(v1_info(&[("file", b"")], BLOCK, false, Some(digest)), &[]);
        let source = TorrentMountSource::from_bytes(bytes, options(dir.path())).unwrap();
        let _ = read(&source, "/file");
        wait_until(|| {
            let s = source.data.verification[0].lock().unwrap();
            s.bad || s.complete
        });
        assert_eq!(read(&source, "/file").is_ok(), valid);
        let mut reader = source.open(&source.lookup("/file", 0).unwrap(), 0).unwrap();
        assert!(reader.seek(SeekFrom::Current(-1)).is_err());
        reader.seek(SeekFrom::Start(u64::MAX)).unwrap();
        assert!(reader.seek(SeekFrom::Current(1)).is_err());
    }
}

/// Regression: hybrid single-file metainfo required a nonexistent v1 path list.
#[test]
fn regression_hybrid_single_file_and_v2_direct_url() {
    let payload = b"small hybrid";
    let info = d([
        (
            "file tree",
            d([(
                "file",
                d([(
                    "",
                    d([
                        ("length", n(payload.len() as u64)),
                        ("pieces root", b(Sha256::digest(payload))),
                    ]),
                )]),
            )]),
        ),
        ("length", n(payload.len() as u64)),
        ("meta version", n(2)),
        ("name", b("file")),
        ("piece length", n(BLOCK as u64)),
        ("pieces", b(Sha1::digest(payload))),
    ]);
    let meta =
        Metainfo::parse(envelope(info, &["https://example.org/exact-object".into()])).unwrap();
    assert!(!meta.multi);
    assert_eq!(
        web_seed_url(&meta, 0, 0).unwrap(),
        "https://example.org/exact-object"
    );
    assert!(meta.files[0].v2.is_some());
}

/// Regression: an idle swarm lost its only peer or bytes where a v1 piece crossed file boundaries.
#[test]
fn regression_swarm_cross_file_piece_streams() {
    let dir = tempfile::tempdir().unwrap();
    let other = vec![b'b'; BLOCK + 9];
    let files: &[(&str, &[u8])] = &[("a", b"abc"), ("dir/b", &other)];
    let bytes = envelope(v1_info(files, BLOCK, true, None), &[]);
    let seed = Seed::new(&bytes, files);
    // Fresh sessions with no selected files exercise peer startup repeatedly.
    for _ in 0..4 {
        let mut opts = options(dir.path());
        opts.swarm.initial_peers = vec![seed.addr];
        opts.range_cache = None;
        let source = TorrentMountSource::from_bytes(bytes.clone(), opts).unwrap();
        assert_eq!(read(&source, "/dir/b").unwrap(), other);
        assert_eq!(read(&source, "/a").unwrap(), b"abc");
    }
}

/// Regression: hybrid padding shifted v2 file-relative offsets during v1 swarm fallback.
#[test]
fn regression_hybrid_padding_swarm_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let a = b"first";
    let bdata = b"second";
    let pad = vec![0; BLOCK - a.len()];
    let body = [a.as_slice(), &pad, bdata.as_slice()].concat();
    let info = d([
        (
            "file tree",
            d([
                (
                    "a",
                    d([(
                        "",
                        d([
                            ("length", n(a.len() as u64)),
                            ("pieces root", b(Sha256::digest(a))),
                        ]),
                    )]),
                ),
                (
                    "b",
                    d([(
                        "",
                        d([
                            ("length", n(bdata.len() as u64)),
                            ("pieces root", b(Sha256::digest(bdata))),
                        ]),
                    )]),
                ),
            ]),
        ),
        (
            "files",
            l([
                d([("length", n(a.len() as u64)), ("path", l([b("a")]))]),
                d([
                    ("attr", b("p")),
                    ("length", n(pad.len() as u64)),
                    ("path", l([b(".pad"), b("0")])),
                ]),
                d([("length", n(bdata.len() as u64)), ("path", l([b("b")]))]),
            ]),
        ),
        ("meta version", n(2)),
        ("name", b("bundle")),
        ("piece length", n(BLOCK as u64)),
        (
            "pieces",
            b(body
                .chunks(BLOCK)
                .flat_map(|p| Sha1::digest(p).to_vec())
                .collect::<Vec<_>>()),
        ),
    ]);
    let bytes = envelope(info, &[]);
    let seed = Seed::new(&bytes, &[("a", a), (".pad/0", &pad), ("b", bdata)]);
    let mut opts = options(dir.path());
    opts.swarm.initial_peers = vec![seed.addr];
    let source = TorrentMountSource::from_bytes(bytes, opts).unwrap();
    assert!(source.lookup("/.pad", 0).is_none());
    assert_eq!(read(&source, "/b").unwrap(), bdata);
    assert_eq!(read(&source, "/a").unwrap(), a);
}

/// Regression: rejecting a v2-only magnet started a needless discovery session.
#[test]
fn regression_v2_only_magnet_rejected_before_swarm_start() {
    let dir = tempfile::tempdir().unwrap();
    let opts = options(dir.path());
    let err = TorrentMountSource::open(
        &format!("magnet:?xt=urn:btmh:1220{}", "0".repeat(64)),
        opts.clone(),
    )
    .err()
    .unwrap();
    assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    assert!(!opts.metadata_dir.join("scratch").exists());
}

/// Regression: v2 tail blocks were hashed with byte padding instead of zero hash leaves.
#[test]
fn regression_v2_merkle_tail_vectors() {
    // Fixed vectors calculated independently with Python hashlib, not the fixture builder.
    let tail = vec![b'b'; 37];
    let body = [vec![b'a'; BLOCK], tail.clone()].concat();
    assert_eq!(
        hex::encode(piece_root(&body, 2)),
        "84691f5c6b53619463ac8b04fc5dcdcaa13b9b7070d2f8ee91f6837dac98c359"
    );
    assert_eq!(
        hex::encode(piece_root(&tail, 2)),
        "9096cbfd748c9ca797f37053c2254a1f9d8cb0b0757125a32ec34a52f53dddb0"
    );
    assert_eq!(
        hex::encode(piece_root(b"aaa", 1)),
        "9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0"
    );
}

/// Regression: hybrid magnets failed because BEP 9 metadata omits external v2 piece layers.
#[test]
fn regression_hybrid_magnet_without_piece_layers_uses_verified_v1() {
    let dir = tempfile::tempdir().unwrap();
    let payload = vec![b'h'; 3 * BLOCK + 7];
    let bytes = v2_bytes(&payload, true, "http://127.0.0.1:1/");
    let meta = Metainfo::parse(bytes.clone()).unwrap();
    let seed = Seed::new(&bytes, &[("file", &payload)]);
    let mut opts = options(dir.path());
    opts.swarm.initial_peers = vec![seed.addr];
    let source = TorrentMountSource::open(
        &format!(
            "magnet:?xt=urn:btih:{}&xt=urn:btmh:1220{}",
            meta.v1_hash.unwrap(),
            meta.v2_hash.unwrap()
        ),
        opts,
    )
    .unwrap();
    assert!(source.data.meta.files[0].v2.is_none());
    assert!(source.data.meta.v2_hash.is_some());
    assert_eq!(read(&source, "/file").unwrap(), payload);
}

fn wait_until(mut condition: impl FnMut() -> bool) {
    let start = std::time::Instant::now();
    while !condition() {
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "background work did not finish"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Regression: repeated BEP 47 .pad/<size> names collided with each other and visible files.
#[test]
fn regression_duplicate_padding_paths_are_hidden() {
    let payload = b"a\0\0b\0\0c";
    let info = d([
        ("name", b("bundle")),
        ("piece length", n(4)),
        (
            "pieces",
            b(payload
                .chunks(4)
                .flat_map(|p| Sha1::digest(p).to_vec())
                .collect::<Vec<_>>()),
        ),
        (
            "files",
            l([
                d([("length", n(1)), ("path", l([b(".pad")]))]),
                d([
                    ("length", n(2)),
                    ("path", l([b(".pad"), b("2")])),
                    ("attr", b("p")),
                ]),
                d([("length", n(1)), ("path", l([b("b")]))]),
                d([
                    ("length", n(2)),
                    ("path", l([b(".pad"), b("2")])),
                    ("attr", b("p")),
                ]),
                d([("length", n(1)), ("path", l([b("c")]))]),
            ]),
        ),
    ]);
    let dir = tempfile::tempdir().unwrap();
    let web = Web::new(BTreeMap::from([
        ("/bundle/.pad".into(), b"a".to_vec()),
        ("/bundle/b".into(), b"b".to_vec()),
        ("/bundle/c".into(), b"c".to_vec()),
    ]));
    let source = TorrentMountSource::from_bytes(
        envelope(info, std::slice::from_ref(&web.url)),
        options(dir.path()),
    )
    .unwrap();
    assert_eq!(source.list_dirents("/").unwrap().len(), 3);
    assert!(source.lookup("/.pad/2", 0).is_none());
    assert_eq!(read(&source, "/b").unwrap(), b"b");
    assert_eq!(read(&source, "/c").unwrap(), b"c");
}

/// Regression: concurrent readers fetched the same verified piece twice and thrashed one last slot.
#[test]
fn regression_piece_lru_and_single_flight() {
    let dir = tempfile::tempdir().unwrap();
    let payload = vec![7; BLOCK * 5];
    let web = Web::new(BTreeMap::from([("/file".into(), payload.clone())]));
    let mut opts = options(dir.path());
    opts.range_cache = None;
    let source = TorrentMountSource::from_bytes(
        envelope(
            v1_info(&[("file", &payload)], BLOCK, false, None),
            &[format!("{}file", web.url)],
        ),
        opts,
    )
    .unwrap();
    let barrier = std::sync::Barrier::new(8);
    std::thread::scope(|scope| {
        for _ in 0..8 {
            scope.spawn(|| {
                barrier.wait();
                assert_eq!(
                    source
                        .data
                        .piece(Piece {
                            file: None,
                            index: 0
                        })
                        .unwrap()
                        .len(),
                    BLOCK
                );
            });
        }
    });
    assert_eq!(web.count.load(Ordering::Relaxed), 1);
    for _ in 0..3 {
        for index in 0..4 {
            source.data.piece(Piece { file: None, index }).unwrap();
        }
    }
    assert_eq!(web.count.load(Ordering::Relaxed), 4);
    source
        .data
        .piece(Piece {
            file: None,
            index: 4,
        })
        .unwrap();
    source
        .data
        .piece(Piece {
            file: None,
            index: 0,
        })
        .unwrap();
    assert_eq!(web.count.load(Ordering::Relaxed), 6);
}

/// Regression: seeking one reader cancelled a different handle's readahead.
#[test]
fn regression_prefetch_generation_is_per_reader() {
    let dir = tempfile::tempdir().unwrap();
    let source =
        TorrentMountSource::from_bytes(single_file_fixture(), options(dir.path())).unwrap();
    let make = || TorrentReader {
        data: source.data.clone(),
        file: 0,
        pos: 0,
        prefetch: Arc::default(),
    };
    let mut first = make();
    let second = make();
    first.seek(SeekFrom::Start(1)).unwrap();
    assert_eq!(first.prefetch.generation.load(Ordering::Relaxed), 1);
    assert_eq!(second.prefetch.generation.load(Ordering::Relaxed), 0);
}

/// Regression: a successful web seed unnecessarily opened DHT sockets or announced to trackers.
#[test]
fn regression_swarm_policy_auto_never_always() {
    let dir = tempfile::tempdir().unwrap();
    let web = Web::new(BTreeMap::from([("/file".into(), b"test".to_vec())]));
    let bytes = envelope(
        v1_info(&[("file", b"test")], BLOCK, false, None),
        &[format!("{}file", web.url)],
    );
    for policy in [
        TorrentSwarmPolicy::Auto,
        TorrentSwarmPolicy::Never,
        TorrentSwarmPolicy::Always,
    ] {
        let mut opts = options(dir.path());
        opts.swarm.policy = policy;
        let announced = opts.swarm.announced.clone();
        let source = TorrentMountSource::from_bytes(bytes.clone(), opts).unwrap();
        assert_eq!(read(&source, "/file").unwrap(), b"test");
        assert_eq!(
            announced.load(Ordering::Relaxed),
            policy == TorrentSwarmPolicy::Always
        );
        assert_eq!(
            source.data.swarm.lock().unwrap().is_some(),
            policy == TorrentSwarmPolicy::Always
        );
    }
    let mut opts = options(dir.path());
    opts.swarm.policy = TorrentSwarmPolicy::Never;
    opts.range_cache = None;
    let source = TorrentMountSource::from_bytes(single_file_fixture(), opts.clone()).unwrap();
    assert!(read(&source, "/file")
        .unwrap_err()
        .to_string()
        .contains("--torrent-swarm never"));
    assert!(!opts.swarm.announced.load(Ordering::Relaxed));
    let error = TorrentMountSource::open(
        "magnet:?xt=urn:btih:0000000000000000000000000000000000000000",
        opts,
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("metadata unavailable"));
}

/// Regression: whole-file completion held the read mutex while re-fetching an evicted prefix.
#[test]
fn regression_whole_file_hashing_never_blocks_reader_mutex() {
    let dir = tempfile::tempdir().unwrap();
    let payload = vec![5; BLOCK * 6];
    let web = Web::new(BTreeMap::from([("/file".into(), payload.clone())]));
    let source = TorrentMountSource::from_bytes(
        envelope(
            v1_info(
                &[("file", &payload)],
                BLOCK,
                false,
                Some(Sha256::digest(&payload).into()),
            ),
            &[format!("{}file", web.url)],
        ),
        options(dir.path()),
    )
    .unwrap();
    // A stalled piece producer stands in for a very slow HTTP refetch. The
    // verification worker will wait there after the coverage event, not the caller.
    let key = Piece {
        file: None,
        index: 0,
    };
    let flight = Arc::new(pieces::Flight::new(true));
    source
        .data
        .pieces
        .lock()
        .unwrap()
        .flights
        .insert(key, flight.clone());
    source.data.after_read(0, 0, payload.len() as u64).unwrap();
    wait_until(|| flight.waiting.load(Ordering::Acquire));
    let state = source.data.verification[0]
        .try_lock()
        .expect("read-path mutex held by verifier");
    assert!(!state.complete);
    drop(state);
    let mut reader = source.open(&source.lookup("/file", 0).unwrap(), 0).unwrap();
    reader.seek(SeekFrom::Start(BLOCK as u64 * 5)).unwrap();
    let mut byte = [0];
    reader.read_exact(&mut byte).unwrap();
    assert_eq!(byte, [5]);
    // Release the simulated producer and let background verification finish.
    let bytes = Arc::new(payload[..BLOCK].to_vec());
    source.data.pieces.lock().unwrap().flights.remove(&key);
    flight.finish(&Ok(bytes));
    wait_until(|| source.verified_file_sha256("/file").is_some());
}

/// Regression: a web seed ignoring Range streamed gigabytes of prefix on a random read.
#[test]
fn regression_ignored_range_skips_seed_beyond_prefix_limit() {
    let dir = tempfile::tempdir().unwrap();
    let payload = vec![42; 2 * 1024 * 1024];
    let bad = Web::with_ranges(BTreeMap::from([("/file".into(), payload.clone())]), false);
    let good = Web::new(BTreeMap::from([("/file".into(), payload.clone())]));
    let mut opts = options(dir.path());
    opts.swarm.policy = TorrentSwarmPolicy::Never;
    let source = TorrentMountSource::from_bytes(
        envelope(
            v1_info(&[("file", &payload)], BLOCK, false, None),
            &[format!("{}file", bad.url), format!("{}file", good.url)],
        ),
        opts,
    )
    .unwrap();
    let mut reader = source.open(&source.lookup("/file", 0).unwrap(), 0).unwrap();
    reader
        .seek(SeekFrom::Start((1024 * 1024 + BLOCK) as u64))
        .unwrap();
    let mut byte = [0];
    reader.read_exact(&mut byte).unwrap();
    assert_eq!(byte, [42]);
    assert_eq!(bad.count.load(Ordering::Relaxed), 1);
    assert_eq!(good.count.load(Ordering::Relaxed), 1);
    assert!(source.data.swarm.lock().unwrap().is_none());
}

/// Regression: cached metainfo retained a previous magnet's different Hub checksum source.
#[test]
fn regression_magnet_ws_replaces_cached_source_context() {
    let dir = tempfile::tempdir().unwrap();
    let mut meta = Metainfo::parse(single_file_fixture()).unwrap();
    meta.web_seeds = vec![
        "https://huggingface.co/old/repo/resolve/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/file"
            .into(),
    ];
    meta.bytes = metadata::envelope(&meta).unwrap();
    let mut opts = options(dir.path());
    opts.swarm.policy = TorrentSwarmPolicy::Never;
    metadata::save(&meta, &opts.metadata_dir).unwrap();
    let good =
        "https://huggingface.co/new/repo/resolve/bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb/file";
    let mut magnet = Url::parse(&format!("magnet:?xt=urn:btih:{}", meta.identity())).unwrap();
    magnet.query_pairs_mut().append_pair("ws", good);
    let resolved = metadata::resolve(magnet.as_str(), &mut opts).unwrap();
    assert_eq!(resolved.web_seeds, vec![good]);
}

/// Regression: late checksum discovery was coupled to the first read and delayed payload delivery.
#[test]
fn regression_checksum_arrives_after_read_without_network_wait() {
    let dir = tempfile::tempdir().unwrap();
    let web = Web::new(BTreeMap::from([("/file".into(), b"test".to_vec())]));
    let source = TorrentMountSource::from_bytes(
        envelope(
            v1_info(&[("file", b"test")], BLOCK, false, None),
            &[format!("{}file", web.url)],
        ),
        options(dir.path()),
    )
    .unwrap();
    assert_eq!(read(&source, "/file").unwrap(), b"test");
    assert!(source.verified_file_sha256("/file").is_none());
    source
        .data
        .verify_tx
        .send(verification::Event::Hashes(checksums::Observations {
            checks: BTreeMap::from([("file".into(), Sha256::digest(b"test").into())]),
            ..Default::default()
        }))
        .unwrap();
    wait_until(|| source.verified_file_sha256("/file").is_some());
    assert_eq!(
        web.count.load(Ordering::Relaxed),
        1,
        "ordered streaming digest refetched payload"
    );
}

/// Regression: sequential completion re-read every evicted piece instead of retaining a streaming digest.
#[test]
fn regression_ordered_sha256_does_not_refetch_evicted_pieces() {
    let dir = tempfile::tempdir().unwrap();
    let payload = vec![9; BLOCK * 12];
    let web = Web::new(BTreeMap::from([("/file".into(), payload.clone())]));
    let mut opts = options(dir.path());
    opts.range_cache = None;
    let source = TorrentMountSource::from_bytes(
        envelope(
            v1_info(
                &[("file", &payload)],
                BLOCK,
                false,
                Some(Sha256::digest(&payload).into()),
            ),
            &[format!("{}file", web.url)],
        ),
        opts,
    )
    .unwrap();
    let mut reader = source.open(&source.lookup("/file", 0).unwrap(), 0).unwrap();
    let mut block = vec![0; BLOCK];
    for _ in 0..12 {
        reader.read_exact(&mut block).unwrap();
        // Deterministically let the asynchronous hasher observe this piece
        // before intentionally exceeding the four-piece working set.
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        source
            .data
            .verify_tx
            .send(verification::Event::Barrier(tx))
            .unwrap();
        rx.recv_timeout(Duration::from_secs(5)).unwrap();
    }
    wait_until(|| source.verified_file_sha256("/file").is_some());
    assert_eq!(web.count.load(Ordering::Relaxed), 12);
}

fn seed_options(dir: &std::path::Path) -> TorrentOptions {
    let mut opts = options(dir);
    opts.swarm.seed = true;
    opts.swarm.policy = TorrentSwarmPolicy::Lan;
    opts.swarm.listen_ip = std::net::Ipv4Addr::LOCALHOST.into();
    opts.swarm.listen_port = 0;
    opts
}

fn cache_payload(meta: &Metainfo, opts: &TorrentOptions, payload: &[u8]) {
    let cache = opts.range_cache.as_ref().unwrap();
    for (piece, bytes) in payload.chunks(meta.piece_len as usize).enumerate() {
        let token = ContentToken::TorrentPiece {
            infohash: meta.identity().into(),
            file: None,
            piece: piece as u64,
            size: bytes.len() as u64,
        };
        for (chunk, bytes) in bytes.chunks(cache.chunk_size() as usize).enumerate() {
            cache.put(&token, chunk as u64, bytes).unwrap();
        }
    }
}

/// Regression: LAN mode contacted trackers/DHT and used a web seed before its local peer.
#[test]
fn regression_lan_peer_precedes_web_seed_without_tracker_or_dht() {
    let dir = tempfile::tempdir().unwrap();
    let payload = vec![17; BLOCK * 3];
    let tracker = Web::new(BTreeMap::new());
    let web = Web::new(BTreeMap::from([("/file".into(), payload.clone())]));
    let info = v1_info(&[("file", &payload)], BLOCK, false, None);
    let bytes = d([
        ("announce", b(format!("{}announce", tracker.url))),
        ("info", info),
        ("url-list", l([b(format!("{}file", web.url))])),
    ]);
    let meta = Metainfo::parse(bytes.clone()).unwrap();
    let seed_opts = seed_options(&dir.path().join("seed"));
    cache_payload(&meta, &seed_opts, &payload);
    let seed = TorrentMountSource::from_bytes(bytes.clone(), seed_opts).unwrap();
    let addr = seed.data.start_seed().unwrap().listen_addr.unwrap();
    let mut opts = options(&dir.path().join("downloader"));
    opts.swarm.policy = TorrentSwarmPolicy::Lan;
    opts.swarm.dht = true;
    opts.swarm.trackers = true;
    opts.swarm.initial_peers = vec![addr]; // deterministic substitute for multicast discovery
    let config = swarm::session_options(&opts.swarm);
    assert!(config.dht.is_none());
    assert!(config.disable_trackers);
    assert!(config.disable_upload);
    let source = TorrentMountSource::from_bytes(bytes, opts).unwrap();
    assert_eq!(read(&source, "/file").unwrap(), payload);
    assert_eq!(web.count.load(Ordering::Relaxed), 0);
    assert_eq!(tracker.count.load(Ordering::Relaxed), 0);
}

fn seed_bitfield(addr: SocketAddr, hash: &[u8]) -> (TcpStream, Vec<u8>) {
    let start = std::time::Instant::now();
    loop {
        let attempt = || -> io::Result<(TcpStream, Vec<u8>)> {
            let mut stream = TcpStream::connect(addr)?;
            stream.set_read_timeout(Some(Duration::from_secs(2)))?;
            let mut handshake = vec![19];
            handshake.extend(b"BitTorrent protocol");
            handshake.extend([0; 8]);
            handshake.extend(hash);
            handshake.extend([b'R'; 20]);
            stream.write_all(&handshake)?;
            let mut reply = [0; 68];
            stream.read_exact(&mut reply)?;
            assert_eq!(&reply[28..48], hash);
            loop {
                let mut len = [0; 4];
                stream.read_exact(&mut len)?;
                let len = u32::from_be_bytes(len) as usize;
                assert!(len < 1024 * 1024);
                if len == 0 {
                    continue;
                }
                let mut msg = vec![0; len];
                stream.read_exact(&mut msg)?;
                if msg[0] == 5 {
                    return Ok((stream, msg[1..].to_vec()));
                }
            }
        };
        match attempt() {
            Ok(value) => return value,
            Err(e) => {
                assert!(
                    start.elapsed() < Duration::from_secs(10),
                    "seed handshake: {e}"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }
}

/// Regression: corrupt/missing cache pieces were advertised, or eviction uploaded zero-filled holes.
#[test]
fn regression_seed_advertises_only_verified_cache_pieces_and_refuses_eviction() {
    let dir = tempfile::tempdir().unwrap();
    let payload = vec![31; BLOCK * 3];
    let bytes = envelope(v1_info(&[("file", &payload)], BLOCK, false, None), &[]);
    let meta = Metainfo::parse(bytes.clone()).unwrap();
    let opts = seed_options(dir.path());
    let mut corrupt = payload.clone();
    corrupt[BLOCK..BLOCK * 2].fill(9);
    cache_payload(&meta, &opts, &corrupt);
    let source = TorrentMountSource::from_bytes(bytes, opts.clone()).unwrap();
    let addr = source.data.start_seed().unwrap().listen_addr.unwrap();
    let (mut stream, bitmap) = seed_bitfield(addr, &hex::decode(meta.v1_hash.unwrap()).unwrap());
    assert_eq!(bitmap[0] & 0xe0, 0xa0);
    // Evict the first piece after HAVE was advertised. A request must fail closed.
    let key = Piece {
        file: None,
        index: 0,
    };
    opts.range_cache
        .as_ref()
        .unwrap()
        .remove_file(&source.data.token(key));
    *source.data.pieces.lock().unwrap() = Default::default();
    stream.write_all(&[0, 0, 0, 1, 2]).unwrap(); // interested
    let mut request = vec![0, 0, 0, 13, 6];
    request.extend(0u32.to_be_bytes());
    request.extend(0u32.to_be_bytes());
    request.extend((BLOCK as u32).to_be_bytes());
    stream.write_all(&request).unwrap();
    loop {
        let mut len = [0; 4];
        if stream.read_exact(&mut len).is_err() {
            break;
        }
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 {
            continue;
        }
        assert!(len < BLOCK * 2);
        let mut msg = vec![0; len];
        if stream.read_exact(&mut msg).is_err() {
            break;
        }
        assert_ne!(
            msg[0], 7,
            "evicted piece must never upload unverified scratch zeros"
        );
    }
}

/// Regression: an upload cap was configured but not applied to outgoing payload bytes.
#[test]
fn regression_seed_upload_limit_and_unmount_stop_listener() {
    let dir = tempfile::tempdir().unwrap();
    let payload = vec![23; BLOCK * 20];
    let bytes = envelope(v1_info(&[("file", &payload)], BLOCK, false, None), &[]);
    let meta = Metainfo::parse(bytes.clone()).unwrap();
    let mut opts = seed_options(&dir.path().join("seed"));
    opts.swarm.upload_limit = 64 * 1024;
    cache_payload(&meta, &opts, &payload);
    let seed = TorrentMountSource::from_bytes(bytes.clone(), opts).unwrap();
    let addr = seed.data.start_seed().unwrap().listen_addr.unwrap();
    let hash = hex::decode(meta.v1_hash.as_ref().unwrap()).unwrap();
    drop(seed_bitfield(addr, &hash)); // exclude initialization from the rate window
    let mut down = options(&dir.path().join("downloader"));
    down.swarm.policy = TorrentSwarmPolicy::Lan;
    down.swarm.initial_peers = vec![addr];
    let source = TorrentMountSource::from_bytes(bytes, down).unwrap();
    let start = std::time::Instant::now();
    assert_eq!(read(&source, "/file").unwrap(), payload);
    let elapsed = start.elapsed();
    // A one-second burst is allowed; generous tolerance covers scheduling jitter.
    assert!(
        elapsed >= Duration::from_secs(2),
        "upload cap bypassed: {elapsed:?}"
    );
    drop(source);
    let retained_data = seed.data.clone(); // e.g. a background verifier still owns Data
    let (mut held_peer, _) = seed_bitfield(addr, &hash);
    drop(seed);
    wait_until(|| TcpStream::connect_timeout(&addr, Duration::from_millis(50)).is_err());
    let mut byte = [0; 1];
    loop {
        match held_peer.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => continue,
            Err(e) if e.kind() == io::ErrorKind::ConnectionReset => break,
            other => panic!("unmount did not close an existing peer: {other:?}"),
        }
    }
    drop(retained_data);
}

/// Regression: --seed ignored never, accepted an unusable sub-block cap, or enabled uploads by default.
#[test]
fn regression_seed_policy_limits_and_lsd_defaults() {
    let defaults = SwarmOptions::default();
    assert!(swarm::session_options(&defaults).disable_upload);
    assert!(!swarm::session_options(&defaults).disable_local_service_discovery);
    let mut opts = defaults.clone();
    opts.policy = TorrentSwarmPolicy::Never;
    assert!(swarm::session_options(&opts).disable_local_service_discovery);
    opts.seed = true;
    assert!(opts
        .validate()
        .unwrap_err()
        .to_string()
        .contains("conflicts"));
    opts.policy = TorrentSwarmPolicy::Lan;
    opts.upload_limit = BLOCK as u32 - 1;
    assert!(opts.validate().is_err());
    opts.upload_limit = BLOCK as u32;
    opts.initial_peers = vec!["203.0.113.1:4240".parse().unwrap()];
    assert!(opts.validate().is_err());
    opts.initial_peers.clear();
    assert!(opts.validate().is_ok());
    opts.lsd = false;
    assert!(swarm::session_options(&opts).disable_local_service_discovery);
}

/// Regression: both magnet hashes were present but the v1 cache entry discarded authenticated v2 layers.
#[test]
fn regression_hybrid_magnet_prefers_v2_metadata_and_piece_verification() {
    let dir = tempfile::tempdir().unwrap();
    let payload = vec![7; BLOCK * 5];
    let bytes = v2_bytes(&payload, true, "http://127.0.0.1:1/");
    let meta = Metainfo::parse(bytes.clone()).unwrap();
    let mut opts = options(dir.path());
    opts.swarm.policy = TorrentSwarmPolicy::Never;
    metadata::save(&meta, &opts.metadata_dir).unwrap();
    let info = metainfo::parse(&bytes)
        .unwrap()
        .required(b"info")
        .unwrap()
        .raw
        .to_vec();
    std::fs::write(
        opts.metadata_dir
            .join(format!("{}.torrent", meta.v1_hash.as_ref().unwrap())),
        d([("info", info)]),
    )
    .unwrap();
    let magnet = format!(
        "magnet:?xt=urn:btih:{}&xt=urn:btmh:1220{}",
        meta.v1_hash.unwrap(),
        meta.v2_hash.as_ref().unwrap()
    );
    let source = TorrentMountSource::open(&magnet, opts).unwrap();
    assert_eq!(source.infohash(), meta.v2_hash.unwrap());
    let (key, _) = source.data.key(0, 0);
    assert_eq!(key.file, Some(0));
    assert!(source
        .data
        .verify_piece(key, &payload[..source.data.size(key) as usize])
        .is_ok());
    let mut corrupt = payload[..source.data.size(key) as usize].to_vec();
    corrupt[0] ^= 1;
    assert!(source.data.verify_piece(key, &corrupt).is_err());
}

fn hub_cache(root: &std::path::Path) -> crate::hf_cache::HubCache {
    crate::hf_cache::HubCache::from_values(&|key| match key {
        "HF_HUB_CACHE" => Some(root.to_string_lossy().into()),
        // Torrent reuse must still hash blobs if the HF-only override disables checks.
        "RATARMOUNT_HF_CACHE_VERIFY" => Some("0".into()),
        _ => None,
    })
}

fn hub_metainfo(payload: &[u8], opts: &TorrentOptions) -> Metainfo {
    let source = format!("hf://org/model@{}", "a".repeat(40));
    let sha256 = Sha256::digest(payload).into();
    let meta = Metainfo::parse(envelope(
        v1_info(&[("file", payload)], BLOCK, false, Some(sha256)),
        &[format!(
            "https://huggingface.co/org/model/resolve/{}/file",
            "a".repeat(40)
        )],
    ))
    .unwrap();
    // A source-bound previous Hub observation keeps this offline test off public APIs.
    checksums::save(
        &meta,
        &opts.metadata_dir,
        &source,
        &BTreeMap::from([("file".into(), sha256)]),
    )
    .unwrap();
    meta
}

fn authorize_mock_hub(hub: &cache::HubFiles, payload: &[u8], git: bool) {
    let commit = "a".repeat(40);
    let oid = if git {
        let mut hash = Sha1::new();
        hash.update(format!("blob {}\0", payload.len()).as_bytes());
        hash.update(payload);
        hex::encode(hash.finalize())
    } else {
        hex::encode(Sha256::digest(payload))
    };
    let item = if git {
        serde_json::json!({"type":"file", "path":"file", "size":payload.len(), "oid":oid})
    } else {
        serde_json::json!({"type":"file", "path":"file", "size":payload.len(), "lfs":{"oid":oid}})
    };
    let web = Web::new(BTreeMap::from([
        (
            format!("/api/models/org/model/revision/{commit}"),
            serde_json::to_vec(&serde_json::json!({"sha":commit})).unwrap(),
        ),
        (
            format!("/api/models/org/model/tree/{commit}?recursive=true"),
            serde_json::to_vec(&vec![item]).unwrap(),
        ),
    ]));
    let source = format!("hf://org/model@{commit}");
    let repo = HfRepo::torrent_test_repo(&source, &web.url).unwrap();
    let hashes = repo
        .torrent_oids()
        .unwrap()
        .into_iter()
        .map(|(path, oid)| ((source.clone(), path), oid))
        .collect();
    hub.authorize(&hashes);
}

fn mock_hub_reader(
    web: &Web,
    cache: crate::hf_cache::HubCache,
    payload: &[u8],
    root: &std::path::Path,
) -> crate::HttpRangeFile {
    let sha256 = hex::encode(Sha256::digest(payload));
    let location = crate::parse_hf_url(&format!("hf://org/model@{}", "a".repeat(40))).unwrap();
    let bridge = Arc::new(crate::hf_cache::HubCacheFile::new(
        cache,
        location,
        "a".repeat(40),
        "file".into(),
        Some(sha256),
        Some(payload.len() as u64),
    ));
    bridge.initialize();
    let token = ContentToken::HfCommitPath {
        endpoint: web.url.clone(),
        repo_kind: "models".into(),
        repo: "org/model".into(),
        commit: "a".repeat(40),
        path: "file".into(),
        size: payload.len() as u64,
    };
    let source = HttpRangeSource::new(
        HttpLocation {
            url: format!("{}file", web.url),
            auth: None,
            cookie: None,
        },
        HttpAuthOptions::default(),
    )
    .with_hub_cache(bridge)
    .with_range_cache(RangeCache::with_dirs(
        root.join("hf-ranges"),
        root.into(),
        1024 * 1024,
        4096,
    ))
    .with_content_token(token);
    crate::HttpRangeFile::from_source(Arc::new(source), payload.len() as u64, None)
}

/// Regression: a completed loopback torrent stayed separate from hf://, wasting a second download.
#[test]
fn regression_verified_torrent_installs_hub_blob_and_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let payload = vec![19; BLOCK * 3 + 1];
    let mut opts = options(&dir.path().join("torrent"));
    opts.swarm.policy = TorrentSwarmPolicy::Lan;
    let meta = hub_metainfo(&payload, &opts);
    let seed = Seed::new(&meta.bytes, &[("file", &payload)]);
    opts.swarm.initial_peers = vec![seed.addr];
    let cache = hub_cache(&dir.path().join("hub"));
    let hub = cache::HubFiles::with_cache(&meta, Some(cache.clone()));
    authorize_mock_hub(&hub, &payload, false);
    let source = TorrentMountSource::with_hub(meta, opts, hub).unwrap();
    assert_eq!(read(&source, "/file").unwrap(), payload);
    let hash = hex::encode(Sha256::digest(&payload));
    let blob = dir.path().join("hub/models--org--model/blobs").join(&hash);
    wait_until(|| blob.exists());
    assert_eq!(source.verified_file_sha256("/file"), Some(hash));
    let token = source.data.token(source.data.key(0, 0).0);
    wait_until(|| {
        source
            .data
            .options
            .range_cache
            .as_ref()
            .unwrap()
            .get(&token, 0)
            .is_none()
    });
    let snapshot = dir
        .path()
        .join("hub/models--org--model/snapshots")
        .join("a".repeat(40))
        .join("file");
    wait_until(|| snapshot.exists());
    assert_eq!(std::fs::read(snapshot).unwrap(), payload);
    let web = Web::new(BTreeMap::new());
    let mut reader = mock_hub_reader(&web, cache, &payload, dir.path());
    let mut actual = Vec::new();
    reader.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, payload);
    assert_eq!(web.count.load(Ordering::Relaxed), 0);
}

/// Regression: a verified hf:// blob was downloaded again by a torrent, or a corrupt blob bypassed hashes.
#[test]
fn regression_hub_cache_serves_torrent_offline_and_refuses_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let payload = vec![29; BLOCK * 3 + 7];
    let cache = hub_cache(&dir.path().join("hub"));
    let web = Web::new(BTreeMap::from([("/file".into(), payload.clone())]));
    let mut reader = mock_hub_reader(&web, cache.clone(), &payload, dir.path());
    // The normal HF cache bridge receives verified completed HTTP ranges.
    let mut actual = Vec::new();
    reader.read_to_end(&mut actual).unwrap();
    assert_eq!(actual, payload);
    reader.source.wait_for_publication();
    let requests = web.count.load(Ordering::Relaxed);
    assert!(requests > 0);
    let mut opts = options(&dir.path().join("torrent"));
    opts.swarm.policy = TorrentSwarmPolicy::Never;
    opts.range_cache = None;
    let mut meta = hub_metainfo(&payload, &opts);
    meta.files[0].sha256 = None; // the pinned Hub observation supplies the LFS hash

    let hub = cache::HubFiles::with_cache(&meta, Some(cache.clone()));
    let torrent = TorrentMountSource::with_hub(meta.clone(), opts.clone(), hub).unwrap();
    assert_eq!(read(&torrent, "/file").unwrap(), payload);
    assert!(torrent.data.swarm.lock().unwrap().is_none());
    assert!(torrent.data.sources.lock().unwrap().is_empty());
    assert_eq!(web.count.load(Ordering::Relaxed), requests);
    // An opt-in donor can also seed straight from that HF blob with no range cache.
    let mut donor_opts = seed_options(&dir.path().join("donor"));
    donor_opts.range_cache = None;
    donor_opts.metadata_dir = opts.metadata_dir.clone();
    let hub = cache::HubFiles::with_cache(&meta, Some(cache.clone()));
    let donor = TorrentMountSource::with_hub(meta.clone(), donor_opts, hub).unwrap();
    let mut peer_opts = options(&dir.path().join("peer"));
    peer_opts.metadata_dir = opts.metadata_dir.clone();
    peer_opts.swarm.policy = TorrentSwarmPolicy::Lan;
    peer_opts.swarm.initial_peers = vec![donor.data.start_seed().unwrap().listen_addr.unwrap()];
    let peer_hub = cache::HubFiles::with_cache(&meta, None);
    let peer = TorrentMountSource::with_hub(meta.clone(), peer_opts, peer_hub).unwrap();
    assert_eq!(read(&peer, "/file").unwrap(), payload);
    assert!(peer.data.sources.lock().unwrap().is_empty());
    drop(peer);
    drop(donor);
    let blob = dir
        .path()
        .join("hub/models--org--model/blobs")
        .join(hex::encode(Sha256::digest(&payload)));
    // A same-length replacement must fail even with RATARMOUNT_HF_CACHE_VERIFY=0.
    std::fs::write(&blob, vec![0; payload.len()]).unwrap();
    let hub = cache::HubFiles::with_cache(&meta, Some(cache));
    let torrent = TorrentMountSource::with_hub(meta, opts, hub).unwrap();
    assert!(torrent
        .data
        .hub
        .piece(
            &torrent.data,
            Piece {
                file: None,
                index: 0
            }
        )
        .is_none());
}

/// Regression: real BEP 14 discovery did not find the other session without an explicit peer.
#[test]
fn regression_real_lsd_lan_transfer_env_gated() {
    if std::env::var("RATARMOUNT_TEST_LSD").as_deref() != Ok("1") {
        eprintln!("skip: real LAN multicast requires RATARMOUNT_TEST_LSD=1");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let payload = vec![13; BLOCK * 2];
    let bytes = envelope(v1_info(&[("file", &payload)], BLOCK, false, None), &[]);
    let meta = Metainfo::parse(bytes.clone()).unwrap();
    let mut down = options(&dir.path().join("downloader"));
    down.swarm.policy = TorrentSwarmPolicy::Lan;
    down.swarm.lsd = true;
    let source = TorrentMountSource::from_bytes(bytes.clone(), down).unwrap();
    let download = std::thread::spawn(move || read(&source, "/file"));
    std::thread::sleep(Duration::from_millis(500));
    let mut opts = seed_options(&dir.path().join("seed"));
    opts.swarm.lsd = true;
    opts.swarm.listen_ip = std::net::Ipv4Addr::UNSPECIFIED.into();
    cache_payload(&meta, &opts, &payload);
    let _seed = TorrentMountSource::from_bytes(bytes, opts).unwrap();
    assert_eq!(download.join().unwrap().unwrap(), payload);
}

/// Regression: auto used internet discovery before trying a reachable LAN peer after web-seed failure.
#[test]
fn regression_auto_prefers_lan_after_web_seed_failure() {
    let dir = tempfile::tempdir().unwrap();
    let payload = vec![43; BLOCK * 2];
    let bytes = envelope(v1_info(&[("file", &payload)], BLOCK, false, None), &[]);
    let seed = Seed::new(&bytes, &[("file", &payload)]);
    let mut opts = options(dir.path());
    opts.swarm.lsd = true;
    opts.swarm.initial_peers = vec![seed.addr];
    let announced = opts.swarm.announced.clone();
    let source = TorrentMountSource::from_bytes(bytes, opts).unwrap();
    assert_eq!(read(&source, "/file").unwrap(), payload);
    assert!(source.data.swarm.lock().unwrap().as_ref().unwrap().lan_only);
    assert!(
        !announced.load(Ordering::Relaxed),
        "public discovery must remain inactive"
    );
}

/// Regression: web-seed pieces verified after mount were never added to the seeding bitmap.
#[test]
fn regression_seed_refreshes_new_verified_http_pieces() {
    let dir = tempfile::tempdir().unwrap();
    let payload = vec![47; BLOCK * 2];
    let web = Web::new(BTreeMap::from([("/file".into(), payload.clone())]));
    let bytes = envelope(
        v1_info(&[("file", &payload)], BLOCK, false, None),
        &[format!("{}file", web.url)],
    );
    let mut opts = seed_options(dir.path());
    opts.swarm.policy = TorrentSwarmPolicy::Auto;
    let source = TorrentMountSource::from_bytes(bytes, opts).unwrap();
    let addr = source.data.start_seed().unwrap().listen_addr.unwrap();
    assert_eq!(read(&source, "/file").unwrap(), payload);
    let hash = hex::decode(source.data.meta.v1_hash.as_ref().unwrap()).unwrap();
    wait_until(|| {
        let (_, bitmap) = seed_bitfield(addr, &hash);
        bitmap[0] & 0xc0 == 0xc0
    });
    assert_eq!(web.count.load(Ordering::Relaxed), 2);
}

/// Regression: a metainfo SHA-256 conflicting with the pinned Hub hash was published as a valid snapshot.
#[test]
fn regression_hub_conflicting_sha256_never_publishes_or_reads() {
    let dir = tempfile::tempdir().unwrap();
    let payload = b"valid torrent piece";
    let opts = options(&dir.path().join("torrent"));
    let mut meta = hub_metainfo(payload, &opts);
    meta.files[0].sha256 = Some([0; 32]);
    let hub = cache::HubFiles::with_cache(&meta, Some(hub_cache(&dir.path().join("hub"))));
    let source = TorrentMountSource::with_hub(meta, opts, hub).unwrap();
    assert_eq!(read(&source, "/file").unwrap_err().raw_os_error(), Some(5));
    assert!(!dir.path().join("hub/models--org--model/blobs").exists());
}

/// Regression: a hybrid magnet kept layer-less v1 metadata although xs supplied authenticated v2 layers.
#[test]
fn regression_hybrid_magnet_upgrades_cached_v1_fallback_from_xs() {
    let dir = tempfile::tempdir().unwrap();
    let payload = vec![11; BLOCK * 5];
    let bytes = v2_bytes(&payload, true, "http://127.0.0.1:1/");
    let meta = Metainfo::parse(bytes.clone()).unwrap();
    let top = metainfo::parse(&bytes).unwrap();
    let fallback =
        Metainfo::parse(d([("info", top.required(b"info").unwrap().raw.to_vec())])).unwrap();
    assert!(!fallback.complete_v2());
    let mut opts = options(dir.path());
    opts.swarm.policy = TorrentSwarmPolicy::Never;
    metadata::save(&fallback, &opts.metadata_dir).unwrap();
    let web = Web::new(BTreeMap::from([("/meta.torrent".into(), bytes)]));
    let mut magnet = Url::parse(&format!(
        "magnet:?xt=urn:btih:{}&xt=urn:btmh:1220{}",
        meta.v1_hash.unwrap(),
        meta.v2_hash.unwrap()
    ))
    .unwrap();
    magnet
        .query_pairs_mut()
        .append_pair("xs", &format!("{}meta.torrent", web.url));
    let source = TorrentMountSource::open(magnet.as_str(), opts).unwrap();
    assert!(source.data.meta.complete_v2());
    assert!(source.data.key(0, 0).0.file.is_some());
    assert_eq!(web.count.load(Ordering::Relaxed), 1);
}

/// Regression: invalid seed policies fetched HTTP metadata before reporting their conflict.
#[test]
fn regression_seed_never_refused_before_metadata_network() {
    let dir = tempfile::tempdir().unwrap();
    let web = Web::new(BTreeMap::from([(
        "/meta.torrent".into(),
        single_file_fixture(),
    )]));
    let mut opts = seed_options(dir.path());
    opts.swarm.policy = TorrentSwarmPolicy::Never;
    assert!(TorrentMountSource::open(&format!("{}meta.torrent", web.url), opts).is_err());
    assert_eq!(web.count.load(Ordering::Relaxed), 0);
}

/// Regression: a magnet could not solicit an existing donor's LSD reply or reuse its metadata peer for payload.
#[test]
fn regression_real_lsd_resolves_existing_donor_magnet_env_gated() {
    if std::env::var("RATARMOUNT_TEST_LSD").as_deref() != Ok("1") {
        eprintln!("skip: real LAN multicast requires RATARMOUNT_TEST_LSD=1");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let payload = vec![53; BLOCK * 2];
    let bytes = envelope(v1_info(&[("file", &payload)], BLOCK, false, None), &[]);
    let meta = Metainfo::parse(bytes.clone()).unwrap();
    let mut opts = seed_options(&dir.path().join("donor"));
    opts.swarm.lsd = true;
    opts.swarm.listen_ip = std::net::Ipv4Addr::UNSPECIFIED.into();
    cache_payload(&meta, &opts, &payload);
    let donor = TorrentMountSource::from_bytes(bytes, opts).unwrap();
    let port = donor.data.start_seed().unwrap().listen_addr.unwrap().port();
    drop(seed_bitfield(
        ([127, 0, 0, 1], port).into(),
        &hex::decode(meta.v1_hash.as_ref().unwrap()).unwrap(),
    ));
    let mut down = options(&dir.path().join("downloader"));
    down.swarm.policy = TorrentSwarmPolicy::Lan;
    down.swarm.lsd = true;
    let source = TorrentMountSource::open(
        &format!("magnet:?xt=urn:btih:{}", meta.v1_hash.unwrap()),
        down,
    )
    .unwrap();
    assert!(!source.data.options.swarm.initial_peers.is_empty());
    assert_eq!(read(&source, "/file").unwrap(), payload);
}

/// Regression: a Python-held blob lock at completion permanently prevented torrent-to-Hub publication.
#[test]
fn regression_torrent_hub_publication_retries_busy_lock_without_more_reads() {
    let dir = tempfile::tempdir().unwrap();
    let payload = vec![59; BLOCK * 2];
    let opts = options(&dir.path().join("torrent"));
    let meta = hub_metainfo(&payload, &opts);
    cache_payload(&meta, &opts, &payload);
    let root = dir.path().join("hub");
    let hash = hex::encode(Sha256::digest(&payload));
    let locks = root.join(".locks/models--org--model");
    std::fs::create_dir_all(&locks).unwrap();
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(locks.join(format!("{hash}.lock")))
        .unwrap();
    lock.lock().unwrap();
    let hub = cache::HubFiles::with_cache(&meta, Some(hub_cache(&root)));
    authorize_mock_hub(&hub, &payload, false);
    let source = TorrentMountSource::with_hub(meta, opts, hub).unwrap();
    assert_eq!(read(&source, "/file").unwrap(), payload);
    wait_until(|| source.verified_file_sha256("/file").is_some());
    let (tx, rx) = mpsc::sync_channel(1);
    source
        .data
        .verify_tx
        .send(verification::Event::Barrier(tx))
        .unwrap();
    rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let blob = root.join("models--org--model/blobs").join(hash);
    assert!(!blob.exists());
    drop(lock);
    wait_until(|| blob.exists());
    assert_eq!(std::fs::read(blob).unwrap(), payload);
}

/// Regression: upload safety checks rejected incomplete internal downloader reads when --seed was enabled.
#[test]
fn regression_seed_download_uses_separate_protocol_scratch_then_shares_verified_pieces() {
    let dir = tempfile::tempdir().unwrap();
    let payload = vec![61; BLOCK * 3 + 7];
    let bytes = envelope(v1_info(&[("file", &payload)], BLOCK, false, None), &[]);
    let original = Seed::new(&bytes, &[("file", &payload)]);
    let mut opts = seed_options(dir.path());
    opts.swarm.initial_peers = vec![original.addr];
    let source = TorrentMountSource::from_bytes(bytes, opts).unwrap();
    let addr = source.data.start_seed().unwrap().listen_addr.unwrap();
    assert_eq!(read(&source, "/file").unwrap(), payload);
    assert!(source.data.swarm.lock().unwrap().is_some());
    assert!(source.data.seeder.lock().unwrap().is_some());
    let hash = hex::decode(source.data.meta.v1_hash.as_ref().unwrap()).unwrap();
    wait_until(|| seed_bitfield(addr, &hash).1[0] & 0xf0 == 0xf0);
}

/// Regression: a Python-style pinned snapshot needed a torrent checksum record or a Hub API call before reuse.
#[test]
fn regression_hub_snapshot_supplies_sha256_without_torrent_checksum_cache() {
    let dir = tempfile::tempdir().unwrap();
    let payload = vec![67; BLOCK + 7];
    let commit = "a".repeat(40);
    let cache = hub_cache(&dir.path().join("hub"));
    let location = crate::parse_hf_url(&format!("hf://org/model@{commit}")).unwrap();
    let hash: [u8; 32] = Sha256::digest(&payload).into();
    cache
        .install_reader(
            &location,
            &commit,
            "file",
            &hex::encode(hash),
            payload.len() as u64,
            &mut io::Cursor::new(&payload),
        )
        .unwrap();
    let meta = Metainfo::parse(envelope(
        v1_info(&[("file", &payload)], BLOCK, false, None),
        &[format!(
            "https://huggingface.co/org/model/resolve/{commit}/file"
        )],
    ))
    .unwrap();
    let mut opts = options(&dir.path().join("torrent"));
    opts.range_cache = None;
    opts.swarm.policy = TorrentSwarmPolicy::Never;
    let web = Web::new(BTreeMap::new());
    let fallback = HttpRangeSource::new(
        HttpLocation {
            url: format!("{}file", web.url),
            auth: None,
            cookie: None,
        },
        HttpAuthOptions::default(),
    )
    .without_range_cache();
    let hub = cache::HubFiles::with_cache(&meta, Some(cache));
    let (verify_tx, _verify_rx) = mpsc::channel();
    // Exercise the read/cache layer without starting checksum-discovery workers.
    // Any accidental payload fallback is confined to the empty loopback server.
    let data = Arc::new_cyclic(|weak| Data {
        meta,
        options: opts,
        self_ref: weak.clone(),
        seed_pending: Mutex::default(),
        stopped: AtomicBool::new(false),
        lan_probe_done: AtomicBool::new(false),
        lan_retry_at: Mutex::default(),
        swarm_gate: Mutex::new(()),
        hub,
        swarm: Mutex::new(None),
        seeder: Mutex::new(None),
        sources: Mutex::new(BTreeMap::from([((0, 0), Arc::new(fallback))])),
        pieces: Mutex::default(),
        verification: vec![Mutex::default()],
        verify_tx,
    });
    let mut actual = Vec::new();
    for index in 0..2 {
        actual.extend_from_slice(&data.piece(Piece { file: None, index }).unwrap());
    }
    assert_eq!(actual, payload);
    assert_eq!(data.verification[0].lock().unwrap().expected, Some(hash));
    assert_eq!(web.count.load(Ordering::Relaxed), 0);
    assert!(data.swarm.lock().unwrap().is_none());
    assert!(!data.options.metadata_dir.exists());
}

/// Regression: third-party manifests and legacy checksum caches authorized poisoned Hub snapshots.
#[test]
fn regression_manifest_hash_never_authorizes_hub_publication() {
    let dir = tempfile::tempdir().unwrap();
    let payload = b"attacker bytes";
    let opts = options(&dir.path().join("torrent"));
    let meta = hub_metainfo(payload, &opts); // populates the legacy *.sha256-v2.json cache
    cache_payload(&meta, &opts, payload);
    let root = dir.path().join("hub");
    let cache = hub_cache(&root);
    let hub = cache::HubFiles::with_cache(&meta, Some(cache));
    let source = TorrentMountSource::with_hub(meta, opts, hub).unwrap();
    source
        .data
        .verify_tx
        .send(verification::Event::Hashes(checksums::Observations {
            checks: BTreeMap::from([("file".into(), Sha256::digest(payload).into())]),
            hub: BTreeMap::new(), // gated/offline/429 Hub lookup cannot authorize
        }))
        .unwrap();
    assert_eq!(read(&source, "/file").unwrap(), payload);
    wait_until(|| source.verified_file_sha256("/file").is_some());
    let (tx, rx) = mpsc::sync_channel(1);
    source
        .data
        .verify_tx
        .send(verification::Event::Barrier(tx))
        .unwrap();
    rx.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(!root.join("models--org--model/blobs").exists());
    source
        .data
        .hub
        .publish(&source.data, 0, Sha256::digest(payload).into())
        .unwrap();
    assert!(!root.join("models--org--model/snapshots").exists());
}

/// Regression: a Hub-vouched non-LFS object was installed under a manifest SHA-256 instead of its Git oid.
#[test]
fn regression_non_lfs_torrent_publishes_only_hub_git_oid() {
    let dir = tempfile::tempdir().unwrap();
    let payload = b"small git config";
    let opts = options(&dir.path().join("torrent"));
    let mut meta = hub_metainfo(payload, &opts);
    meta.files[0].sha256 = None;
    // No independent SHA-256 is needed when the fresh Hub Git oid verifies the file.
    std::fs::remove_dir_all(&opts.metadata_dir).unwrap();
    cache_payload(&meta, &opts, payload);
    let root = dir.path().join("hub");
    let hub = cache::HubFiles::with_cache(&meta, Some(hub_cache(&root)));
    authorize_mock_hub(&hub, payload, true);
    let oid = hub.git_oid(0).unwrap();
    let source = TorrentMountSource::with_hub(meta, opts, hub).unwrap();
    assert_eq!(read(&source, "/file").unwrap(), payload);
    let blob = root.join("models--org--model/blobs").join(oid);
    wait_until(|| blob.exists());
    assert_eq!(std::fs::read(blob).unwrap(), payload);
    assert!(!root
        .join("models--org--model/blobs")
        .join(hex::encode(Sha256::digest(payload)))
        .exists());
}

/// Regression: each new seed piece rescanned old pieces and disconnected an already connected peer.
#[test]
fn regression_seed_incremental_have_keeps_peer_without_rescanning() {
    let dir = tempfile::tempdir().unwrap();
    let payload = vec![71; BLOCK * 3];
    let web = Web::new(BTreeMap::from([("/file".into(), payload.clone())]));
    let bytes = envelope(
        v1_info(&[("file", &payload)], BLOCK, false, None),
        &[format!("{}file", web.url)],
    );
    let meta = Metainfo::parse(bytes.clone()).unwrap();
    let opts = seed_options(dir.path());
    cache_payload(&meta, &opts, &payload[..BLOCK]);
    let source = TorrentMountSource::from_bytes(bytes, opts).unwrap();
    let seed = source.data.start_seed().unwrap();
    wait_until(|| seed.seed_checks.lock().unwrap().len() == 3);
    let hash = hex::decode(meta.v1_hash.unwrap()).unwrap();
    let (mut peer, bitmap) = seed_bitfield(seed.listen_addr.unwrap(), &hash);
    assert_eq!(bitmap[0] & 0xe0, 0x80);
    peer.write_all(&[0, 0, 0, 2, 5, 0]).unwrap(); // peer's empty bitfield
    peer.write_all(&[0, 0, 0, 1, 2]).unwrap(); // interested
    let mut request = vec![0, 0, 0, 13, 6];
    request.extend(0u32.to_be_bytes());
    request.extend(0u32.to_be_bytes());
    request.extend((BLOCK as u32).to_be_bytes());
    peer.write_all(&request).unwrap();
    loop {
        let mut len = [0; 4];
        peer.read_exact(&mut len).unwrap();
        let len = u32::from_be_bytes(len) as usize;
        if len == 0 {
            continue;
        }
        assert!(len < BLOCK * 2);
        let mut msg = vec![0; len];
        peer.read_exact(&mut msg).unwrap();
        if msg[0] == 7 {
            assert_eq!(&msg[9..], &payload[..BLOCK]);
            break;
        }
    }
    // Avoid the LAN-first attempt: this is the piece completion path shared with HTTP reads.
    source
        .data
        .fetch_piece(
            Piece {
                file: None,
                index: 1,
            },
            false,
        )
        .unwrap();
    loop {
        let mut len = [0; 4];
        peer.read_exact(&mut len)
            .expect("existing peer must stay connected");
        let len = u32::from_be_bytes(len) as usize;
        assert!(len < 1024 * 1024);
        if len == 0 {
            continue;
        }
        let mut msg = vec![0; len];
        peer.read_exact(&mut msg).unwrap();
        if msg[0] == 4 && msg[1..] == 1u32.to_be_bytes() {
            break;
        }
    }
    assert_eq!(*seed.seed_checks.lock().unwrap(), vec![0, 1, 2, 1]);
    std::thread::sleep(Duration::from_millis(250));
    assert_eq!(*seed.seed_checks.lock().unwrap(), vec![0, 1, 2, 1]);
}

/// Regression: absent LAN peers delayed every piece and serialized unrelated HTTP fallbacks.
#[test]
fn regression_lan_absent_peer_backoff_does_not_block_other_pieces() {
    let dir = tempfile::tempdir().unwrap();
    let payload = vec![73; BLOCK * 9];
    let web = Web::new(BTreeMap::from([("/file".into(), payload.clone())]));
    let bytes = envelope(
        v1_info(&[("file", &payload)], BLOCK, false, None),
        &[format!("{}file", web.url)],
    );
    let mut opts = options(dir.path());
    opts.swarm.policy = TorrentSwarmPolicy::Lan;
    opts.swarm.timeout = Duration::from_secs(30);
    opts.swarm.lsd = false;
    let source = TorrentMountSource::from_bytes(bytes, opts).unwrap();
    let data = source.data.clone();
    let start = std::time::Instant::now();
    let first = std::thread::spawn(move || {
        data.piece(Piece {
            file: None,
            index: 0,
        })
        .unwrap()
    });
    wait_until(|| source.data.swarm_gate.try_lock().is_err());
    let parallel = std::time::Instant::now();
    let second = source
        .data
        .piece(Piece {
            file: None,
            index: 1,
        })
        .unwrap();
    assert_eq!(&**second, &payload[..BLOCK]);
    assert!(parallel.elapsed() < Duration::from_secs(1));
    assert_eq!(&**first.join().unwrap(), &payload[..BLOCK]);
    assert!(start.elapsed() < Duration::from_secs(4));
    let after = std::time::Instant::now();
    for index in 2..8 {
        source.data.piece(Piece { file: None, index }).unwrap();
    }
    assert!(after.elapsed() < Duration::from_secs(1));
    assert!(source.data.lan_retry_at.lock().unwrap().is_some());
    // Expired negative entries permit a later discovery attempt.
    *source.data.lan_retry_at.lock().unwrap() = Some(std::time::Instant::now());
    let retry = std::time::Instant::now();
    source
        .data
        .piece(Piece {
            file: None,
            index: 8,
        })
        .unwrap();
    assert!(retry.elapsed() >= Duration::from_secs(1));
    assert!(retry.elapsed() < Duration::from_secs(4));
}
