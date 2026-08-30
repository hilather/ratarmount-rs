//! Bounded member reader for [`crate::ReadRequest`].

use std::io::{self, Read, Seek, SeekFrom};

use ratarmount_core::{query_normpath, read_exact_or_short, ArchiveRead};

use crate::types::ReadRequest;
use crate::{Error, Session};

/// Seek + capped `Read + Send`. Never holds the member as `Vec<u8>`.
pub struct RangeReader {
    inner: Box<dyn ArchiveRead>,
    remaining: u64,
}

impl RangeReader {
    fn empty() -> Self {
        Self {
            inner: Box::new(io::Cursor::new(&b""[..])),
            remaining: 0,
        }
    }
}

impl Read for RangeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let cap = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        let n = read_exact_or_short(&mut self.inner, &mut buf[..cap])?;
        self.remaining -= n as u64;
        Ok(n)
    }
}

impl Session {
    /// Seek + bounded reader. Never returns the member as `Vec<u8>`.
    ///
    /// `max_len == 0` yields an empty reader after a successful lookup.
    pub fn read_range(&self, req: ReadRequest) -> Result<RangeReader, Error> {
        let path = query_normpath(&req.path);
        let fi = self
            .mount_source()
            .lookup(&path, 0)
            .ok_or(Error::NotFound)?;
        if req.max_len == 0 {
            return Ok(RangeReader::empty());
        }
        let mut inner = self.mount_source().open(&fi, 0).map_err(map_member_io)?;
        inner
            .seek(SeekFrom::Start(req.offset))
            .map_err(map_member_io)?;
        Ok(RangeReader {
            inner,
            remaining: req.max_len,
        })
    }
}

/// `PermissionDenied` + "password" → [`Error::BadPassword`] (encrypted member open).
pub(crate) fn map_member_io(e: io::Error) -> Error {
    match e.kind() {
        io::ErrorKind::NotFound => Error::NotFound,
        io::ErrorKind::PermissionDenied => {
            let msg = e.to_string();
            if msg.to_ascii_lowercase().contains("password") {
                Error::BadPassword
            } else {
                Error::Internal(format!("permission denied: {e}"))
            }
        }
        _ => Error::Internal(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{IndexPolicy, OpenRequest, Recreate, SourceSpec};
    use ratarmount_core::{FileInfo, MountSource, UserData, S_IFREG};
    use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};
    use std::io::Write;
    use std::path::Path;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::Arc;

    fn member_file<'a>(path: &'a str, bytes: &'a [u8]) -> UstarMember<'a> {
        UstarMember {
            path,
            payload: UstarPayload::File { bytes },
            mode: 0o644,
            uid: 0,
            gid: 0,
            mtime: 0,
        }
    }

    fn write_tar(path: &Path, members: &[UstarMember<'_>]) {
        let mut f = std::fs::File::create(path).unwrap();
        write_ustar_members(&mut f, members).unwrap();
        write_tar_eof(&mut f).unwrap();
        f.flush().unwrap();
    }

    fn open_tar(dir: &Path, name: &str, members: &[UstarMember<'_>]) -> Session {
        let tar = dir.join(name);
        write_tar(&tar, members);
        let idx = dir.join(format!("{name}.index.sqlite"));
        Session::open(OpenRequest {
            source: SourceSpec::Path(tar),
            index: IndexPolicy::Explicit,
            explicit_index: Some(idx),
            extra_dirs: Vec::new(),
            password: None,
            recursive: false,
            recursion_depth: None,
            recreate: Recreate::IfInvalid,
        })
        .expect("Session::open")
    }

    fn assert_send<T: Send>(_: &T) {}

    /// Regression: 4 KiB from a 100 MiB member must not slurp the member.
    #[test]
    fn read_range_capped() {
        const BIG: u64 = 100 * 1024 * 1024;
        const CAP: usize = 4096;
        let dir = tempfile::tempdir().unwrap();
        let payload = dir.path().join("big.bin");
        {
            let f = std::fs::File::create(&payload).unwrap();
            f.set_len(BIG).unwrap();
        }
        let tar = dir.path().join("big.tar");
        {
            let mut f = std::fs::File::create(&tar).unwrap();
            write_ustar_members(
                &mut f,
                &[UstarMember {
                    path: "big.bin",
                    payload: UstarPayload::FileOnDisk {
                        path: &payload,
                        size: BIG,
                    },
                    mode: 0o644,
                    uid: 0,
                    gid: 0,
                    mtime: 0,
                }],
            )
            .unwrap();
            write_tar_eof(&mut f).unwrap();
            f.flush().unwrap();
        }
        let idx = dir.path().join("big.tar.index.sqlite");
        let session = Session::open(OpenRequest {
            source: SourceSpec::Path(tar),
            index: IndexPolicy::Explicit,
            explicit_index: Some(idx),
            extra_dirs: Vec::new(),
            password: None,
            recursive: false,
            recursion_depth: None,
            recreate: Recreate::IfInvalid,
        })
        .expect("open 100 MiB member tar");

        let mut reader = session
            .read_range(ReadRequest {
                path: "/big.bin".into(),
                offset: 0,
                max_len: CAP as u64,
            })
            .expect("read_range");
        assert_send(&reader);
        let mut got = Vec::new();
        reader.read_to_end(&mut got).expect("read capped");
        assert_eq!(
            got.len(),
            CAP,
            "must stop at max_len, not slurp {BIG} bytes"
        );
        assert!(got.iter().all(|&b| b == 0));

        let mut empty = session
            .read_range(ReadRequest {
                path: "/big.bin".into(),
                offset: 0,
                max_len: 0,
            })
            .expect("max_len 0");
        let mut z = Vec::new();
        empty.read_to_end(&mut z).unwrap();
        assert!(z.is_empty());

        // Spy: MountSource::read would slurp; inner bytes must stay at max_len.
        struct CountedZero {
            pos: u64,
            len: u64,
            inner_bytes: Arc<AtomicU64>,
        }
        impl Read for CountedZero {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                let left = self.len.saturating_sub(self.pos);
                let n = usize::try_from(left).unwrap_or(usize::MAX).min(buf.len());
                buf[..n].fill(0);
                self.pos += n as u64;
                self.inner_bytes.fetch_add(n as u64, Ordering::SeqCst);
                Ok(n)
            }
        }
        impl Seek for CountedZero {
            fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
                let next = match from {
                    SeekFrom::Start(o) => o,
                    SeekFrom::Current(d) => (self.pos as i64).saturating_add(d) as u64,
                    SeekFrom::End(d) => (self.len as i64).saturating_add(d) as u64,
                };
                self.pos = next.min(self.len);
                Ok(self.pos)
            }
        }
        struct SpySrc {
            len: u64,
            inner_bytes: Arc<AtomicU64>,
        }
        impl MountSource for SpySrc {
            fn list(&self, _path: &str) -> Option<ratarmount_core::ListResult> {
                None
            }
            fn lookup(&self, path: &str, _file_version: i32) -> Option<FileInfo> {
                if path != "/big.bin" {
                    return None;
                }
                Some(FileInfo {
                    size: self.len,
                    mtime: 0.0,
                    mode: S_IFREG | 0o644,
                    linkname: String::new(),
                    uid: 0,
                    gid: 0,
                    userdata: vec![UserData::Other("spy".into())],
                })
            }
            fn open(
                &self,
                _file_info: &FileInfo,
                _buffering: i32,
            ) -> io::Result<Box<dyn ArchiveRead>> {
                Ok(Box::new(CountedZero {
                    pos: 0,
                    len: self.len,
                    inner_bytes: Arc::clone(&self.inner_bytes),
                }))
            }
            fn read(
                &self,
                _file_info: &FileInfo,
                _size: usize,
                _offset: u64,
            ) -> io::Result<Vec<u8>> {
                panic!("read_range must not call MountSource::read");
            }
            fn is_immutable(&self) -> bool {
                true
            }
        }
        let inner_bytes = Arc::new(AtomicU64::new(0));
        let spy = Session::from_local_source(Arc::new(SpySrc {
            len: BIG,
            inner_bytes: Arc::clone(&inner_bytes),
        }));
        let mut r = spy
            .read_range(ReadRequest {
                path: "/big.bin".into(),
                offset: 0,
                max_len: CAP as u64,
            })
            .unwrap();
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf.len(), CAP);
        assert_eq!(inner_bytes.load(Ordering::SeqCst), CAP as u64);
    }

    /// Short inner `Read::read` is not EOF; fill-loop assembles the cap.
    #[test]
    fn read_range_fill_loop() {
        struct OneByte(io::Cursor<Vec<u8>>);
        impl Read for OneByte {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                if buf.is_empty() {
                    return Ok(0);
                }
                self.0.read(&mut buf[..1])
            }
        }
        impl Seek for OneByte {
            fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
                self.0.seek(pos)
            }
        }

        struct ShortSrc {
            data: Vec<u8>,
            opens: Arc<AtomicUsize>,
        }
        impl MountSource for ShortSrc {
            fn list(&self, _path: &str) -> Option<ratarmount_core::ListResult> {
                None
            }
            fn lookup(&self, path: &str, _file_version: i32) -> Option<FileInfo> {
                if path != "/short.bin" {
                    return None;
                }
                Some(FileInfo {
                    size: self.data.len() as u64,
                    mtime: 0.0,
                    mode: S_IFREG | 0o644,
                    linkname: String::new(),
                    uid: 0,
                    gid: 0,
                    userdata: vec![UserData::Other("short".into())],
                })
            }
            fn open(
                &self,
                _file_info: &FileInfo,
                _buffering: i32,
            ) -> io::Result<Box<dyn ArchiveRead>> {
                self.opens.fetch_add(1, Ordering::SeqCst);
                Ok(Box::new(OneByte(io::Cursor::new(self.data.clone()))))
            }
            fn read(
                &self,
                _file_info: &FileInfo,
                _size: usize,
                _offset: u64,
            ) -> io::Result<Vec<u8>> {
                panic!("read_range must not call MountSource::read");
            }
            fn is_immutable(&self) -> bool {
                true
            }
        }

        let data: Vec<u8> = (0u8..100).collect();
        let opens = Arc::new(AtomicUsize::new(0));
        let session = Session::from_local_source(Arc::new(ShortSrc {
            data: data.clone(),
            opens: Arc::clone(&opens),
        }));
        let mut reader = session
            .read_range(ReadRequest {
                path: "/short.bin".into(),
                offset: 10,
                max_len: 20,
            })
            .unwrap();
        let mut got = Vec::new();
        reader.read_to_end(&mut got).unwrap();
        assert_eq!(got, data[10..30]);
        assert_eq!(opens.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn read_range_missing_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let session = open_tar(dir.path(), "tiny.tar", &[member_file("a.txt", b"hi")]);
        let err = match session.read_range(ReadRequest {
            path: "/nope.txt".into(),
            offset: 0,
            max_len: 4,
        }) {
            Err(e) => e,
            Ok(_) => panic!("expected NotFound"),
        };
        assert!(matches!(err, Error::NotFound));
    }

    #[test]
    fn read_range_query_normpath() {
        let dir = tempfile::tempdir().unwrap();
        let session = open_tar(dir.path(), "n.tar", &[member_file("a.txt", b"hi")]);
        let mut r = session
            .read_range(ReadRequest {
                path: "a.txt".into(),
                offset: 0,
                max_len: 2,
            })
            .expect("unnormalized path");
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"hi");
    }

    #[test]
    fn map_member_io_password_is_bad_password() {
        let e = io::Error::new(
            io::ErrorKind::PermissionDenied,
            "password required to open encrypted 7z member; pass --password / --password-file",
        );
        assert!(matches!(map_member_io(e), Error::BadPassword));
        let other = io::Error::new(io::ErrorKind::PermissionDenied, "chmod 000");
        assert!(matches!(map_member_io(other), Error::Internal(_)));
    }

    #[test]
    fn read_range_encrypted_7z_is_bad_password() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("encrypted-hello.7z");
        std::fs::write(
            &archive,
            include_bytes!("../../ratarmount-formats-sevenzip/testdata/encrypted-hello.7z"),
        )
        .unwrap();
        let idx = dir.path().join("encrypted-hello.7z.index.sqlite");
        let session = Session::open(OpenRequest {
            source: SourceSpec::Path(archive),
            index: IndexPolicy::Explicit,
            explicit_index: Some(idx),
            extra_dirs: Vec::new(),
            password: None,
            recursive: false,
            recursion_depth: None,
            recreate: Recreate::IfInvalid,
        })
        .expect("metadata-only 7z open");
        let hit = session.lookup("/secret.txt").unwrap().expect("listed");
        assert!(hit.size > 0);
        let err = match session.read_range(ReadRequest {
            path: "/secret.txt".into(),
            offset: 0,
            max_len: 16,
        }) {
            Err(e) => e,
            Ok(_) => panic!("encrypted member must not open without password"),
        };
        assert!(
            matches!(err, Error::BadPassword),
            "expected BadPassword, got {err:?}"
        );
    }
}
