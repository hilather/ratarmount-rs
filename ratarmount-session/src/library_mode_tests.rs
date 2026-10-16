//! Regression tests for the library-mode extent, ordering and codec APIs.

use std::collections::HashSet;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};

use crate::{
    Error, IndexPolicy, OffsetCursor, OpenRequest, ParallelizationSpec, ReadRequest, Recreate,
    Session, SourceSpec,
};

fn member<'a>(path: &'a str, bytes: &'a [u8]) -> UstarMember<'a> {
    UstarMember {
        path,
        payload: UstarPayload::File { bytes },
        mode: 0o644,
        uid: 0,
        gid: 0,
        mtime: 0,
    }
}

fn tar_bytes(members: &[UstarMember<'_>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    write_ustar_members(&mut bytes, members).unwrap();
    write_tar_eof(&mut bytes).unwrap();
    bytes
}

fn checksum(header: &mut [u8]) {
    header[148..156].fill(b' ');
    let sum: u32 = header.iter().map(|&b| u32::from(b)).sum();
    header[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
}

fn request(path: &Path) -> OpenRequest {
    OpenRequest {
        source: SourceSpec::Path(path.to_path_buf()),
        index: IndexPolicy::Sibling,
        explicit_index: None,
        extra_dirs: Vec::new(),
        password: None,
        recursive: false,
        recursion_depth: None,
        parallelization: ParallelizationSpec::default(),
        recreate: Recreate::IfInvalid,
    }
}

fn read_member(session: &Session, path: &str, size: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    session
        .read_range(ReadRequest {
            path: path.into(),
            offset: 0,
            max_len: size,
        })
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    bytes
}

fn has_offset_order_index(session: &Session) -> bool {
    let conn = rusqlite::Connection::open_with_flags(
        session.catalog_path().unwrap(),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = 'files_offsetheader')",
        [], |row| row.get(0),
    ).unwrap()
}

/// Regression: TAR header offsets must never be returned as member data offsets.
#[test]
fn member_extent_data_bytes_equal_read_range_large_and_last() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("extents.tar");
    let big: Vec<u8> = (0..1024 * 1024 + 137).map(|i| (i % 251) as u8).collect();
    let members = [
        member("first", b"first payload"),
        member("dir/big", &big),
        member("empty", b""),
        member("last", b"end of archive"),
    ];
    std::fs::write(&archive, tar_bytes(&members)).unwrap();
    // Exercise both cold and warm sidecars, and the memory-index open path.
    for policy in [
        IndexPolicy::Sibling,
        IndexPolicy::Sibling,
        IndexPolicy::Memory,
    ] {
        let mut req = request(&archive);
        req.index = policy;
        let session = Session::open(req).unwrap();
        for entry in &members {
            let extent = session
                .member_extent(entry.path)
                .unwrap()
                .expect("plain TAR extent");
            assert_eq!(extent.file, archive.canonicalize().unwrap());
            let header = session
                .lookup(entry.path)
                .unwrap()
                .unwrap()
                .archive_offset
                .unwrap();
            assert!(extent.offset >= header + 512);
            let mut file = std::fs::File::open(&extent.file).unwrap();
            file.seek(SeekFrom::Start(extent.offset)).unwrap();
            let mut bytes = vec![0; extent.len as usize];
            file.read_exact(&mut bytes).unwrap();
            assert_eq!(bytes, read_member(&session, entry.path, extent.len));
            if let UstarPayload::File { bytes: expected } = entry.payload {
                assert_eq!(bytes, expected);
            }
        }
        assert!(session.lookup("missing").unwrap().is_none());
        assert!(matches!(
            session.member_extent("missing"),
            Err(Error::NotFound)
        ));
    }
}

/// Regression: a compressed TAR's logical offsets are not local file extents.
#[test]
fn member_extent_compressed_tar_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    // Deliberately misleading extension: eligibility follows the actual probe.
    let archive = dir.path().join("compressed.tar");
    let bytes = tar_bytes(&[member("file", b"zstd payload")]);
    std::fs::write(
        &archive,
        ratarmount_compress::encode_zstd_frame(&bytes, 1).unwrap(),
    )
    .unwrap();
    let session = Session::open(request(&archive)).unwrap();
    assert_eq!(read_member(&session, "file", 100), b"zstd payload");
    assert_eq!(session.member_extent("file").unwrap(), None);
    assert!(matches!(
        session.member_extent("missing"),
        Err(Error::NotFound)
    ));
}

/// Regression: GNU sparse logical bytes do not occupy a contiguous file extent.
#[test]
fn member_extent_sparse_tar_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("sparse.tar");
    let mut bytes = tar_bytes(&[member("sparse", b"tail")]);
    let header = &mut bytes[..512];
    header[156] = b'S';
    header[257..265].copy_from_slice(b"ustar  \0");
    header[386..398].copy_from_slice(b"00000010000\0"); // data at logical 4096
    header[398..410].copy_from_slice(b"00000000004\0");
    header[483..495].copy_from_slice(b"00000010004\0"); // logical size 4100
    checksum(header);
    std::fs::write(&archive, bytes).unwrap();
    let session = Session::open(request(&archive)).unwrap();
    let bytes = read_member(&session, "sparse", 4100);
    assert_eq!(bytes.len(), 4100);
    assert!(bytes[..4096].iter().all(|&b| b == 0));
    assert_eq!(&bytes[4096..], b"tail");
    assert_eq!(session.member_extent("sparse").unwrap(), None);
}

/// Regression: flattened and AutoMount nested offsets are not outer file extents.
#[test]
fn member_extent_nested_tar_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("outer.tar");
    let inner = tar_bytes(&[member("child", b"nested payload")]);
    std::fs::write(&archive, tar_bytes(&[member("inner.tar", &inner)])).unwrap();
    for recursive in [false, true] {
        let mut req = request(&archive);
        req.recursive = recursive;
        let session = Session::open(req).unwrap();
        assert_eq!(
            read_member(&session, "inner.tar/child", 100),
            b"nested payload"
        );
        assert_eq!(session.member_extent("inner.tar/child").unwrap(), None);
    }
}

/// Regression: a joined split TAR's offsets do not address its first part.
#[test]
fn member_extent_split_tar_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("split.tar.001");
    let bytes = tar_bytes(&[member("file", b"split payload")]);
    std::fs::write(&archive, &bytes[..600]).unwrap();
    std::fs::write(dir.path().join("split.tar.002"), &bytes[600..]).unwrap();
    let mut req = request(&archive);
    req.index = IndexPolicy::Memory;
    let session = Session::open(req).unwrap();
    assert_eq!(read_member(&session, "file", 100), b"split payload");
    assert_eq!(session.member_extent("file").unwrap(), None);
}

/// Regression: overlay-modified bytes must never expose an archive data extent.
#[cfg(unix)]
#[test]
fn member_extent_overlay_modified_file_returns_none() {
    use std::io::Write;
    use std::os::fd::{FromRawFd, IntoRawFd};
    use std::sync::Arc;

    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("overlay.tar");
    std::fs::write(&archive, tar_bytes(&[member("file", b"original")])).unwrap();
    let base = crate::factory::open_path(
        &archive,
        &ratarmount_core::OpenOptions {
            index_in_memory: true,
            ..Default::default()
        },
        false,
    )
    .unwrap();
    let overlay =
        ratarmount_compositing::WriteOverlay::new(base, dir.path().join("writes")).unwrap();
    let fd = overlay.create_file("/file", 0o644).unwrap();
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(b"modified").unwrap();
    overlay.close_overlay_fd(file.into_raw_fd());
    let session = Session::from_local_source(Arc::new(overlay));
    assert_eq!(read_member(&session, "file", 100), b"modified");
    assert_eq!(session.member_extent("file").unwrap(), None);
}

/// Regression: live HTTP TAR offsets are logical stream positions, not local extents.
#[test]
fn member_extent_remote_tar_returns_none() {
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };

    struct Server {
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }
    impl Drop for Server {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            self.thread.take().unwrap().join().unwrap();
        }
    }
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let worker_stop = Arc::clone(&stop);
    let data = tar_bytes(&[member("file", b"remote payload")]);
    let _server = Server {
        stop,
        thread: Some(std::thread::spawn(move || {
            while !worker_stop.load(Ordering::Relaxed) {
                let (mut stream, _) = match listener.accept() {
                    Ok(connection) => connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("accept: {error}"),
                };
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                    .unwrap();
                let mut reader = BufReader::new(&mut stream);
                let mut first = String::new();
                reader.read_line(&mut first).unwrap();
                let mut range = None;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    let lower = line.to_ascii_lowercase();
                    if let Some(value) = lower.strip_prefix("range: bytes=") {
                        let (start, end) = value.trim().split_once('-').unwrap();
                        let start: usize = start.parse().unwrap();
                        let end = end
                            .parse::<usize>()
                            .unwrap_or(data.len() - 1)
                            .min(data.len() - 1);
                        range = Some((start, end));
                    }
                }
                drop(reader);
                if first.split_whitespace().nth(1) != Some("/archive.tar") {
                    write!(
                        stream,
                        "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    )
                    .unwrap();
                    continue;
                }
                let (start, end) = range.unwrap_or((0, data.len() - 1));
                let status = if range.is_some() {
                    "206 Partial Content"
                } else {
                    "200 OK"
                };
                write!(stream, "HTTP/1.1 {status}\r\nAccept-Ranges: bytes\r\nContent-Length: {}\r\nContent-Range: bytes {start}-{end}/{}\r\nConnection: close\r\n\r\n", end - start + 1, data.len()).unwrap();
                if !first.starts_with("HEAD ") {
                    stream.write_all(&data[start..=end]).unwrap();
                }
            }
        })),
    };
    let dir = tempfile::tempdir().unwrap();
    let mut req = request(&dir.path().join("placeholder"));
    req.source = SourceSpec::Url(format!("http://{address}/archive.tar"));
    req.index = IndexPolicy::Explicit;
    req.explicit_index = Some(dir.path().join("remote.sqlite"));
    let session = Session::open(req).unwrap();
    assert_eq!(read_member(&session, "file", 100), b"remote payload");
    assert_eq!(session.member_extent("file").unwrap(), None);
    assert!(!has_offset_order_index(&session));
    let page = session.iter_by_offset_page(OffsetCursor::Start, 1).unwrap();
    assert_eq!(page.entries[0].path, "/file");
    assert!(
        !has_offset_order_index(&session),
        "remote sources must not gain a paging index"
    );
}

/// Regression: directory and link metadata must not be treated as member payloads.
#[test]
fn member_extent_directories_and_links_return_none() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("links.tar");
    let entries = [
        member("payload", b"real bytes"),
        UstarMember {
            payload: UstarPayload::Directory,
            ..member("directory", b"")
        },
        UstarMember {
            payload: UstarPayload::Symlink { target: "payload" },
            ..member("symlink", b"")
        },
        UstarMember {
            payload: UstarPayload::Symlink { target: "payload" },
            ..member("hardlink", b"")
        },
    ];
    let mut bytes = tar_bytes(&entries);
    let last_header = bytes.len() - 1024 - 512;
    bytes[last_header + 156] = b'1';
    checksum(&mut bytes[last_header..last_header + 512]);
    std::fs::write(&archive, bytes).unwrap();
    let session = Session::open(request(&archive)).unwrap();
    for path in ["directory", "symlink", "hardlink"] {
        assert!(session.lookup(path).unwrap().is_some(), "{path}");
        assert_eq!(session.member_extent(path).unwrap(), None, "{path}");
    }
    let page = session.iter_by_offset_page(OffsetCursor::Start, 0).unwrap();
    assert_eq!(
        page.entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        ["payload"]
    );
    assert!(page.next.is_none());
}

/// Regression: absent SQL catalogs must report unsupported instead of an empty payload list.
#[test]
fn iter_by_offset_page_without_catalog_reports_unsupported() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("memory.tar");
    std::fs::write(&archive, tar_bytes(&[member("file", b"payload")])).unwrap();
    let mut req = request(&archive);
    req.index = IndexPolicy::Memory;
    let session = Session::open(req).unwrap();
    assert!(matches!(
        session.iter_by_offset_page(OffsetCursor::Start, 1),
        Err(Error::UnsupportedFormat(_))
    ));
}

/// Regression: an empty archive must end iteration without manufacturing a cursor.
#[test]
fn iter_by_offset_page_empty_archive_has_no_next() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("empty.tar");
    std::fs::write(&archive, tar_bytes(&[])).unwrap();
    let session = Session::open(request(&archive)).unwrap();
    let page = session
        .iter_by_offset_page(OffsetCursor::Start, u32::MAX)
        .unwrap();
    assert!(page.entries.is_empty());
    assert!(page.next.is_none());
}

/// Regression: Session must defer auxiliary index creation until the first writable page.
#[test]
fn iter_by_offset_page_creates_index_only_on_first_writable_page() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("lazy.tar");
    std::fs::write(&archive, tar_bytes(&[member("z", b"a"), member("a", b"b")])).unwrap();
    let session = Session::open(request(&archive)).unwrap();
    assert!(!has_offset_order_index(&session));
    session.lookup("z").unwrap();
    session
        .list_dirents_page("/", crate::DirCursor::Start, 1)
        .unwrap();
    assert!(!has_offset_order_index(&session));
    let first = session.iter_by_offset_page(OffsetCursor::Start, 1).unwrap();
    assert_eq!(first.entries[0].path, "/z");
    assert!(has_offset_order_index(&session));
    let last = session.iter_by_offset_page(first.next.unwrap(), 1).unwrap();
    assert_eq!(last.entries[0].path, "/a");
    assert!(last.next.is_none());
}

/// Regression: Recreate::Never forbids adding a paging index to a writable file.
#[test]
fn iter_by_offset_page_recreate_never_keeps_sidecar_unindexed() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("never.tar");
    std::fs::write(&archive, tar_bytes(&[member("z", b"a"), member("a", b"b")])).unwrap();
    drop(Session::open(request(&archive)).unwrap());
    let mut req = request(&archive);
    req.recreate = Recreate::Never;
    let session = Session::open(req).unwrap();
    let before = std::fs::read(session.catalog_path().unwrap()).unwrap();
    assert!(!has_offset_order_index(&session));
    let first = session.iter_by_offset_page(OffsetCursor::Start, 1).unwrap();
    assert_eq!(first.entries[0].path, "/z");
    let last = session.iter_by_offset_page(first.next.unwrap(), 1).unwrap();
    assert_eq!(last.entries[0].path, "/a");
    assert!(last.next.is_none());
    assert!(!has_offset_order_index(&session));
    assert_eq!(
        std::fs::read(session.catalog_path().unwrap()).unwrap(),
        before
    );
}

/// Regression: auxiliary DDL must not invalidate a published snapshot's SHA-256 pointer.
#[test]
fn iter_by_offset_page_published_snapshot_keeps_sha256_valid() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("published.tar");
    std::fs::write(&archive, tar_bytes(&[member("z", b"a"), member("a", b"b")])).unwrap();
    let session = Session::open(request(&archive)).unwrap();
    let index = session.catalog_path().unwrap().to_path_buf();
    drop(session);
    let pointer =
        ratarmount_index::publish_index_pointer(&archive, &index, Some(&archive)).unwrap();
    let snapshot = ratarmount_index::resolve_index_id_path(&archive, &pointer.index_id).unwrap();
    let mut explicit_paths = vec![Some(index.clone())];
    #[cfg(unix)]
    {
        let alias = dir.path().join("alias.sqlite");
        std::fs::hard_link(&snapshot, &alias).unwrap();
        explicit_paths.push(Some(alias));
    }
    explicit_paths.push(None);
    // The snapshot and its aliases must retain the published byte identity.
    for explicit in explicit_paths {
        let mut req = request(&archive);
        if let Some(path) = explicit {
            req.index = IndexPolicy::Explicit;
            req.explicit_index = Some(path);
        }
        let session = Session::open(req).unwrap();
        let page = session.iter_by_offset_page(OffsetCursor::Start, 7).unwrap();
        assert_eq!(
            page.entries
                .iter()
                .map(|entry| entry.path.as_str())
                .collect::<Vec<_>>(),
            ["/z", "/a"]
        );
        assert!(page.next.is_none());
        assert!(!has_offset_order_index(&session));
        assert_eq!(
            ratarmount_index::resolve_index_id_path(&archive, &pointer.index_id).unwrap(),
            snapshot
        );
    }
}

/// Regression: a chmod 0444 sidecar must stay unindexed even for a write-permitting open.
#[cfg(unix)]
#[test]
fn iter_by_offset_page_read_only_file_stays_unindexed() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("readonly.tar");
    std::fs::write(&archive, tar_bytes(&[member("z", b"a"), member("a", b"b")])).unwrap();
    let session = Session::open(request(&archive)).unwrap();
    std::fs::set_permissions(
        session.catalog_path().unwrap(),
        std::fs::Permissions::from_mode(0o444),
    )
    .unwrap();
    let first = session.iter_by_offset_page(OffsetCursor::Start, 1).unwrap();
    assert_eq!(first.entries[0].path, "/z");
    let last = session.iter_by_offset_page(first.next.unwrap(), 1).unwrap();
    assert_eq!(last.entries[0].path, "/a");
    assert!(last.next.is_none());
    assert!(!has_offset_order_index(&session));
}

/// Regression: offset paging must not duplicate or skip members across 10k entries.
#[test]
fn iter_by_offset_page_10000_members_no_duplicates_or_skips() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("many.tar");
    // Interleave directories and reverse name order to distinguish archive order.
    let names: Vec<String> = (0..10_000)
        .map(|i| format!("d{}/f{:05}", i % 3, 10_000 - i))
        .collect();
    let members: Vec<_> = names.iter().map(|name| member(name, b"x")).collect();
    std::fs::write(&archive, tar_bytes(&members)).unwrap();
    let session = Session::open(request(&archive)).unwrap();
    assert!(
        !has_offset_order_index(&session),
        "normal TAR builds do not create the optimization index"
    );
    let expected: Vec<_> = session
        .catalog()
        .unwrap()
        .list_visible_files_by_offset()
        .unwrap()
        .into_iter()
        .map(|entry| {
            (
                format!("{}/{}", entry.path, entry.name),
                entry.cookie.offsetheader as u64,
            )
        })
        .collect();
    assert_eq!(expected.len(), 10_000);
    for size in [1, 7, 500] {
        let mut cursor = OffsetCursor::Start;
        let mut seen = Vec::new();
        loop {
            let page = session.iter_by_offset_page(cursor, size).unwrap();
            assert!(!page.entries.is_empty());
            assert!(page.entries.len() <= size as usize);
            seen.extend(
                page.entries
                    .into_iter()
                    .map(|entry| (entry.path, entry.archive_offset.unwrap())),
            );
            match page.next {
                Some(next) => cursor = next,
                None => break,
            }
        }
        assert_eq!(seen, expected, "page size {size}");
        assert_eq!(
            seen.iter()
                .map(|(path, _)| path)
                .collect::<HashSet<_>>()
                .len(),
            10_000
        );
        assert!(seen.windows(2).all(|pair| pair[0].1 < pair[1].1));
    }
}

/// Regression: parallelization=4 must preserve bytes across zstd frame boundaries.
#[test]
fn parallelization_four_reads_multiframe_zstd_tar() {
    let dir = tempfile::tempdir().unwrap();
    let archive = dir.path().join("frames.tar.zst");
    let data: Vec<u8> = (0..1024 * 1024 + 317).map(|i| (i % 239) as u8).collect();
    let bytes = tar_bytes(&[member("big", &data), member("last", b"last frame")]);
    let mut compressed = Vec::new();
    for chunk in bytes.chunks(128 * 1024) {
        compressed.extend(ratarmount_compress::encode_zstd_frame(chunk, 1).unwrap());
    }
    std::fs::write(&archive, compressed).unwrap();
    for recreate in [Recreate::IfInvalid, Recreate::Never] {
        let mut req = request(&archive);
        req.parallelization = ParallelizationSpec::new(4);
        req.recreate = recreate;
        let session = Session::open(req).unwrap();
        assert_eq!(read_member(&session, "big", data.len() as u64), data);
        assert_eq!(read_member(&session, "last", 100), b"last frame");
        assert_eq!(session.member_extent("big").unwrap(), None);
    }
}
