//! Regression coverage for the fuser 0.18 boundary, without a kernel mount.

use super::*;

/// Regression: upgrading fuser must not change ACLs, RO defaults, or request concurrency.
#[test]
fn fuser_mount_config_preserves_access_and_serial_requests() {
    for (options, acl) in [
        ("", SessionACL::Owner),
        ("auto_unmount", SessionACL::Owner),
        ("allow_other", SessionACL::All),
        ("allow_root", SessionACL::RootAndOwner),
        ("allow_other,allow_root", SessionACL::RootAndOwner),
        ("allow_root,allow_other", SessionACL::RootAndOwner),
    ] {
        let config = mount_config(false, options);
        assert_eq!(config.acl, acl, "{options}");
        assert_eq!(config.n_threads, Some(1));
        assert!(!config.clone_fd);
        assert!(config.mount_options.contains(&MountOption::RO));
    }
    let config = mount_config(false, "auto_unmount");
    assert!(!config.mount_options.contains(&MountOption::AutoUnmount));
    for option in ["auto_unmount", "allow_other"] {
        assert!(config
            .mount_options
            .contains(&MountOption::CUSTOM(option.into())));
    }
    let config = mount_config(false, "auto_unmount,allow_root");
    assert_eq!(config.acl, SessionACL::RootAndOwner);
    assert!(config.mount_options.contains(&MountOption::AutoUnmount));
}

/// Regression: Session::new's new conflict check must not reject ordered libfuse flags.
#[test]
fn fuser_mount_config_preserves_option_precedence() {
    let config = mount_config(
        true,
        " ro,rw,dev,nodev,suid,nosuid,exec,noexec,atime,noatime,sync,async,fsname=custom,subtype=tar,max_read=65536, ",
    );
    assert_eq!(
        config.mount_options,
        vec![
            MountOption::RW,
            MountOption::NoDev,
            MountOption::NoSuid,
            MountOption::NoExec,
            MountOption::NoAtime,
            MountOption::Async,
            MountOption::FSName("custom".into()),
            MountOption::Subtype("tar".into()),
            MountOption::CUSTOM("max_read=65536".into()),
        ]
    );
    for (first, last) in [
        ("ro", "rw"),
        ("dev", "nodev"),
        ("suid", "nosuid"),
        ("exec", "noexec"),
        ("atime", "noatime"),
        ("sync", "async"),
    ] {
        for (first, last) in [(first, last), (last, first)] {
            let config = mount_config(true, &format!("{first},{last}"));
            assert!(!config.mount_options.contains(&mount_option_from_str(first)));
            assert!(config.mount_options.contains(&mount_option_from_str(last)));
        }
    }
    assert!(!mount_config(false, "rw")
        .mount_options
        .contains(&MountOption::RW));
    assert!(!mount_config(true, "")
        .mount_options
        .contains(&MountOption::RO));
}

// These packets use Linux's FUSE layout; macFUSE has additional attr fields.
#[cfg(target_os = "linux")]
mod protocol {
    use super::*;
    use fuser::{InitFlags, Session};
    use ratarmount_core::{ArchiveRead, ListResult, S_IFREG};
    use std::io::{self, Read, Write};
    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixStream;
    use std::thread::{self, JoinHandle};

    struct Source;

    impl MountSource for Source {
        fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
            (path == "/").then(|| {
                vec![CheapDirent {
                    name: "f".into(),
                    mode: S_IFREG | 0o644,
                    size: 7,
                }]
            })
        }

        fn list(&self, path: &str) -> Option<ListResult> {
            (path == "/")
                .then(|| ListResult::Infos([("f".into(), self.lookup("/f", 0).unwrap())].into()))
        }

        fn lookup(&self, path: &str, _version: i32) -> Option<FileInfo> {
            match path {
                "/" => Some(ratarmount_core::create_root_file_info()),
                "/f" => Some(FileInfo {
                    size: 7,
                    mtime: 123.0,
                    mode: S_IFREG | 0o644,
                    linkname: String::new(),
                    uid: 1000,
                    gid: 1000,
                    userdata: vec![],
                }),
                _ => None,
            }
        }

        fn open(&self, _info: &FileInfo, _buffering: i32) -> io::Result<Box<dyn ArchiveRead>> {
            Ok(Box::new(io::Cursor::new(b"payload")))
        }

        fn is_immutable(&self) -> bool {
            true
        }

        fn get_xattr(&self, _info: &FileInfo, name: &str) -> Option<Vec<u8>> {
            (name == "user.test").then(|| b"value".to_vec())
        }

        fn list_xattr(&self, _info: &FileInfo) -> Vec<String> {
            vec!["user.test".into()]
        }
    }

    fn u32_at(bytes: &[u8], at: usize) -> u32 {
        u32::from_ne_bytes(bytes[at..at + 4].try_into().unwrap())
    }

    fn u64_at(bytes: &[u8], at: usize) -> u64 {
        u64::from_ne_bytes(bytes[at..at + 8].try_into().unwrap())
    }

    fn words(values: &[u32]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_ne_bytes()).collect()
    }

    fn request(opcode: u32, ino: u64, uid: u32, body: &[u8]) -> Vec<u8> {
        let mut bytes = words(&[(40 + body.len()) as u32, opcode]);
        bytes.extend(1u64.to_ne_bytes()); // unique
        bytes.extend(ino.to_ne_bytes());
        bytes.extend(words(&[uid, 0, 0, 0])); // uid, gid, pid, padding
        bytes.extend(body);
        bytes
    }

    fn receive(peer: &mut UnixStream) -> Vec<u8> {
        let mut bytes = vec![0; 8192];
        let n = peer.read(&mut bytes).unwrap();
        bytes.truncate(n);
        assert_eq!(u32_at(&bytes, 0) as usize, n);
        bytes
    }

    struct Harness {
        peer: UnixStream,
        worker: JoinHandle<io::Result<()>>,
        init: Vec<u8>,
        notifier: fuser::Notifier,
    }

    impl Harness {
        fn new(config: Config, readahead: u32) -> Self {
            let fs = RatarmountFs::with_readahead(Arc::new(Source), None, 1024).with_passthrough(
                PassthroughOptions {
                    mode: PassthroughMode::Off,
                    ..Default::default()
                },
            );
            Self::with_fs(config, readahead, fs)
        }

        fn with_fs(config: Config, readahead: u32, fs: RatarmountFs) -> Self {
            Self::with_capabilities(config, readahead, fs, InitFlags::all())
        }

        fn with_capabilities(
            config: Config,
            readahead: u32,
            fs: RatarmountFs,
            capabilities: InitFlags,
        ) -> Self {
            // SOCK_SEQPACKET preserves the one-request-per-read /dev/fuse contract.
            let mut fds = [-1; 2];
            assert_eq!(
                unsafe {
                    libc::socketpair(
                        libc::AF_UNIX,
                        libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                        0,
                        fds.as_mut_ptr(),
                    )
                },
                0
            );
            let fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
            let mut peer = unsafe { UnixStream::from_raw_fd(fds[1]) };
            peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
            let flags = capabilities.bits();
            let mut init = words(&[7, 40, readahead, flags as u32, (flags >> 32) as u32]);
            init.resize(64, 0);
            peer.write_all(&request(26, 0, unsafe { libc::geteuid() }, &init))
                .unwrap();
            let session = Session::from_fd(fs, fd, config.acl, config).unwrap();
            let notifier = session.notifier();
            let init = receive(&mut peer);
            assert_eq!(u32_at(&init, 4), 0);
            let worker = thread::spawn(move || fuse_session_result(session.run()));
            Self {
                peer,
                worker,
                init,
                notifier,
            }
        }

        fn call_as(&mut self, opcode: u32, ino: u64, uid: u32, body: &[u8]) -> Vec<u8> {
            self.peer
                .write_all(&request(opcode, ino, uid, body))
                .unwrap();
            receive(&mut self.peer)
        }

        fn call(&mut self, opcode: u32, ino: u64, body: &[u8]) -> Vec<u8> {
            let reply = self.call_as(opcode, ino, unsafe { libc::geteuid() }, body);
            assert_eq!(u32_at(&reply, 4), 0, "opcode {opcode}");
            reply[16..].to_vec()
        }

        fn finish(mut self) {
            assert!(self.call(38, 0, &[]).is_empty()); // DESTROY
            self.worker.join().unwrap().unwrap();
        }
    }

    fn read_args(fh: u64, offset: u64, size: u32) -> Vec<u8> {
        let mut body = fh.to_ne_bytes().to_vec();
        body.extend(offset.to_ne_bytes());
        body.extend(words(&[size, 0, 0, 0, 0, 0]));
        body
    }

    /// Regression: forced passthrough on an unsupported kernel must fail INIT clearly.
    #[test]
    fn fuser_passthrough_on_unavailable_fails_mount() {
        let mut fds = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    fds.as_mut_ptr(),
                )
            },
            0
        );
        let fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let mut peer = unsafe { UnixStream::from_raw_fd(fds[1]) };
        peer.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let mut init = words(&[7, 40, 4096, 0, 0]);
        init.resize(64, 0);
        peer.write_all(&request(26, 0, unsafe { libc::geteuid() }, &init))
            .unwrap();
        let fs = RatarmountFs::new(Arc::new(Source), None).with_passthrough(PassthroughOptions {
            mode: PassthroughMode::On,
            ..Default::default()
        });
        let config = mount_config(false, "");
        let error = Session::from_fd(fs, fd, config.acl, config)
            .err()
            .expect("INIT must fail");
        assert!(
            error.to_string().contains("--passthrough on requires"),
            "{error}"
        );
    }

    /// Regression: auto negotiates only offered passthrough; forced off never does.
    #[test]
    fn fuser_passthrough_negotiation_and_registration_failure_falls_back() {
        use ratarmount_compositing::FolderMountSource;
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("file"), b"payload").unwrap();
        for (mode, offered, privileged, eligible, expected) in [
            (PassthroughMode::Auto, true, true, true, true),
            (PassthroughMode::Auto, true, false, true, false),
            (PassthroughMode::Auto, true, true, false, false),
            (PassthroughMode::Auto, false, true, true, false),
            (PassthroughMode::Off, true, true, true, false),
            (PassthroughMode::On, true, false, true, true),
        ] {
            let source = Arc::new(FolderMountSource::new(dir.path()).unwrap());
            let mut fs = RatarmountFs::new(source, None).with_passthrough(PassthroughOptions {
                mode,
                ..Default::default()
            });
            fs.passthrough_auto_privilege = Some(privileged);
            fs.passthrough_readonly_mount = eligible;
            let caps = if offered {
                InitFlags::all()
            } else {
                InitFlags::all() & !InitFlags::FUSE_PASSTHROUGH
            };
            let mut harness = Harness::with_capabilities(mount_config(false, ""), 4096, fs, caps);
            let init = &harness.init[16..];
            let flags = u32_at(init, 12) as u64 | ((u32_at(init, 32) as u64) << 32);
            assert_eq!(
                InitFlags::from_bits_retain(flags).contains(InitFlags::FUSE_PASSTHROUGH),
                expected
            );
            assert_eq!(u32_at(init, 36), u32::from(expected));
            let lookup = harness.call(1, 1, b"file\0");
            let ino = u64_at(&lookup, 0);
            // A socket cannot register a backing fd (ENOTTY). The real open
            // handler must preserve KEEP_CACHE and serve identical daemon bytes.
            let opened = harness.call(14, ino, &words(&[0, 0]));
            let fh = u64_at(&opened, 0);
            assert_eq!(u32_at(&opened, 8), FopenFlags::FOPEN_KEEP_CACHE.bits());
            assert_eq!(harness.call(15, ino, &read_args(fh, 0, 7)), b"payload");
            let mut release = fh.to_ne_bytes().to_vec();
            release.extend(words(&[0, 0, 0, 0]));
            harness.call(18, ino, &release);
            harness.finish();
        }
    }

    /// Regression: a privileged compressed/virtual-only mount must not consume stacking depth.
    #[test]
    fn fuser_passthrough_auto_without_backing_sources_keeps_stack_depth_zero() {
        let mut fs = RatarmountFs::new(Arc::new(Source), None);
        fs.passthrough_auto_privilege = Some(true);
        let harness = Harness::with_fs(mount_config(false, ""), 4096, fs);
        let init = &harness.init[16..];
        let flags = u32_at(init, 12) as u64 | ((u32_at(init, 32) as u64) << 32);
        assert!(!InitFlags::from_bits_retain(flags).contains(InitFlags::FUSE_PASSTHROUGH));
        assert_eq!(u32_at(init, 36), 0);
        harness.finish();
    }

    /// Regression: large sequential I/O requires MAX_PAGES; old kernels keep
    /// 32 pages, and neither path changes passthrough or background queues.
    #[test]
    fn fuser_init_preserves_io_limits_without_passthrough() {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u32 };
        for supported in [false, true] {
            let pages = if supported { 256 } else { 32 };
            let max_io = page_size * pages;
            for readahead in [0, 4096, max_io, max_io * 2] {
                let caps = if supported {
                    InitFlags::all()
                } else {
                    InitFlags::all() & !InitFlags::FUSE_MAX_PAGES
                };
                let harness = Harness::with_capabilities(
                    mount_config(false, ""),
                    readahead,
                    RatarmountFs::new(Arc::new(Source), None),
                    caps,
                );
                let init = &harness.init[16..];
                assert_eq!(u32_at(init, 0), 7);
                assert!(u32_at(init, 4) >= 40);
                assert_eq!(u32_at(init, 8), readahead.min(max_io));
                let flags = u32_at(init, 12) as u64 | ((u32_at(init, 32) as u64) << 32);
                let mut expected = InitFlags::FUSE_ASYNC_READ
                    | InitFlags::FUSE_BIG_WRITES
                    | InitFlags::FUSE_INIT_EXT;
                if supported {
                    expected |= InitFlags::FUSE_MAX_PAGES;
                }
                assert_eq!(InitFlags::from_bits_retain(flags), expected);
                assert_eq!(u32_at(init, 16), 12 | (9 << 16));
                assert_eq!(u32_at(init, 20), max_io);
                assert_eq!(u32_at(init, 28) & 0xffff, pages);
                assert_eq!(u32_at(init, 36), 0); // max_stack_depth
                harness.finish();
            }
        }
    }

    /// Regression: auto_unmount's kernel allow_other must not grant other UIDs userspace access.
    #[test]
    fn fuser_auto_unmount_keeps_owner_acl_on_requests() {
        let owner = unsafe { libc::geteuid() };
        let stranger = owner.wrapping_add(1).max(1);
        for (options, denied) in [
            ("auto_unmount", true),
            ("allow_root", true),
            ("allow_other", false),
        ] {
            let mut harness = Harness::new(mount_config(false, options), 4096);
            let reply = harness.call_as(1, 1, stranger, b"f\0");
            assert_eq!(u32_at(&reply, 4) as i32, if denied { -EACCES } else { 0 });
            assert!(!harness.call(1, 1, b"f\0").is_empty());
            harness.finish();
        }
    }

    /// Regression: typed inode/handle/offset/errno replies must retain bytes, KEEP_CACHE, and xattrs.
    #[test]
    fn fuser_read_and_xattr_replies_keep_bytes_and_errno() {
        let mut harness = Harness::new(mount_config(false, ""), 4096);
        let entry = harness.call(1, 1, b"f\0");
        let ino = u64_at(&entry, 0);
        assert!(ino > 1);
        assert_eq!(u64_at(&entry, 16), 60); // entry_valid
        assert_eq!(u64_at(&entry, 48), 7); // attr.size
        let open = harness.call(14, ino, &words(&[0, 0]));
        let fh = u64_at(&open, 0);
        assert_ne!(fh, 0);
        assert_eq!(u32_at(&open, 8), 2); // FOPEN_KEEP_CACHE
        assert_eq!(harness.call(15, ino, &read_args(fh, 2, 3)), b"ylo");
        assert_eq!(harness.call(15, ino, &read_args(fh, 5, 8)), b"ad");
        let xattr = |size, name: &[u8]| [words(&[size, 0]), name.to_vec()].concat();
        assert_eq!(
            u32_at(&harness.call(22, ino, &xattr(0, b"user.test\0")), 0),
            5
        );
        assert_eq!(harness.call(22, ino, &xattr(5, b"user.test\0")), b"value");
        assert_eq!(harness.call(23, ino, &words(&[10, 0])), b"user.test\0");
        for (size, name, errno) in [
            (1, b"user.test\0".as_slice(), libc::ERANGE),
            (5, b"missing\0", libc::ENODATA),
        ] {
            let reply = harness.call_as(22, ino, unsafe { libc::geteuid() }, &xattr(size, name));
            assert_eq!(u32_at(&reply, 4) as i32, -errno);
        }
        let mut release = fh.to_ne_bytes().to_vec();
        release.extend(words(&[0, 0, 0, 0]));
        assert!(harness.call(18, ino, &release).is_empty());
        harness.finish();
    }

    /// Regression: readdirplus resumes at its unsigned cookie with the same sizes and TTLs.
    #[test]
    fn fuser_readdirplus_preserves_cookies_and_attrs() {
        let mut harness = Harness::new(mount_config(false, ""), 4096);
        let dir = harness.call(44, 1, &read_args(0, 2, 4096));
        let ino = u64_at(&dir, 0);
        assert!(ino > 1);
        assert_eq!(u64_at(&dir, 16), 60);
        assert_eq!(u64_at(&dir, 48), 7);
        assert_eq!(u64_at(&dir, 128), ino); // dirent.ino
        assert_eq!(u64_at(&dir, 136), 3); // dirent.off
        assert_eq!(dir[152], b'f');
        assert!(harness.call(44, 1, &read_args(0, 3, 4096)).is_empty());
        let dir = harness.call(28, 1, &read_args(0, 2, 4096));
        assert_eq!(u64_at(&dir, 0), ino);
        assert_eq!(u64_at(&dir, 8), 3);
        assert_eq!(dir[24], b'f');
        harness.finish();
    }

    /// Regression: typed notifier inode numbers must still invalidate the whole inode and name.
    #[test]
    fn fuser_notifier_preserves_invalidation_packets() {
        let mut harness = Harness::new(mount_config(false, ""), 4096);
        InvalSink::inval_inode(&harness.notifier, 123).unwrap();
        let packet = receive(&mut harness.peer);
        assert_eq!(u32_at(&packet, 4), 2); // FUSE_NOTIFY_INVAL_INODE
        assert_eq!(u64_at(&packet, 16), 123);
        assert_eq!(u64_at(&packet, 24), 0);
        assert_eq!(u64_at(&packet, 32) as i64, -1);
        InvalSink::inval_entry(&harness.notifier, 456, OsStr::new("child")).unwrap();
        let packet = receive(&mut harness.peer);
        assert_eq!(u32_at(&packet, 4), 3); // FUSE_NOTIFY_INVAL_ENTRY
        assert_eq!(u64_at(&packet, 16), 456);
        assert_eq!(u32_at(&packet, 24), 5);
        assert_eq!(&packet[32..], b"child\0");
        harness.finish();
    }

    /// Regression: malformed protocol input must not be mistaken for a clean unmount.
    #[test]
    fn fuser_malformed_request_is_not_clean_unmount() {
        let mut harness = Harness::new(mount_config(false, ""), 4096);
        harness.peer.write_all(&[0]).unwrap();
        let error = harness.worker.join().unwrap().unwrap_err();
        assert_eq!(error.kind(), ErrorKind::InvalidData);
    }

    /// Regression: typed create/write/rename/unlink/FORGET must retain detached bytes and lifetimes.
    #[test]
    fn fuser_detached_inode_survives_until_final_forget() {
        let dir = tempfile::tempdir().unwrap();
        let ov = Arc::new(WriteOverlay::new(Arc::new(Source), dir.path()).unwrap());
        let fs = RatarmountFs::new(ov.clone(), Some(ov));
        let mut harness = Harness::with_fs(mount_config(true, ""), 4096, fs);
        let create = [
            words(&[libc::O_RDWR as u32, 0o644, 0, 0]),
            b"new\0".to_vec(),
        ]
        .concat();
        let entry = harness.call(35, 1, &create);
        let ino = u64_at(&entry, 0);
        let fh = u64_at(&entry, 128);
        assert_eq!(u64_at(&entry, 16), 0); // zero entry TTL
        assert_eq!(u32_at(&entry, 136), 0); // no create cache flags
        assert_eq!(u64_at(&harness.call(1, 1, b"new\0"), 0), ino);
        let write = [read_args(fh, 0, 4), b"body".to_vec()].concat();
        assert_eq!(u32_at(&harness.call(16, ino, &write), 0), 4);
        let rename = [
            1u64.to_ne_bytes().to_vec(),
            words(&[0, 0]),
            b"new\0renamed\0".to_vec(),
        ]
        .concat();
        assert!(harness.call(45, 1, &rename).is_empty());
        assert!(harness.call(10, 1, b"renamed\0").is_empty());
        assert_eq!(harness.call(15, ino, &read_args(fh, 0, 4)), b"body");
        let attr = harness.call(3, ino, &[0; 16]);
        assert_eq!(u64_at(&attr, 0), 0); // zero attr TTL
        assert_eq!(u32_at(&attr, 80), 0); // nlink
                                          // One ordinary FORGET leaves the second reference from lookup alive.
        harness
            .peer
            .write_all(&request(2, ino, 0, &1u64.to_ne_bytes()))
            .unwrap();
        assert!(!harness.call(3, ino, &[0; 16]).is_empty());
        // BATCH_FORGET was unavailable with abi-7-12; its default dispatch
        // must reach the same forget helper, including for kernel UID 0.
        let batch = [
            words(&[1, 0]),
            ino.to_ne_bytes().to_vec(),
            1u64.to_ne_bytes().to_vec(),
        ]
        .concat();
        harness.peer.write_all(&request(42, 0, 0, &batch)).unwrap();
        let reply = harness.call_as(3, ino, unsafe { libc::geteuid() }, &[0; 16]);
        assert_eq!(u32_at(&reply, 4) as i32, -ENOENT);
        assert_eq!(harness.call(15, ino, &read_args(fh, 0, 4)), b"body");
        let release = [fh.to_ne_bytes().to_vec(), words(&[0, 0, 0, 0])].concat();
        assert!(harness.call(18, ino, &release).is_empty());
        harness.finish();
    }
}
