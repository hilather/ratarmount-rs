//! Bounded member reader for [`crate::ReadRequest`].

use std::io::{self, Read, Seek, SeekFrom};

use ratarmount_core::ArchiveRead;

use crate::types::ReadRequest;
use crate::{Error, Session};

/// Seek + capped `Read + Send`. Never holds the member as `Vec<u8>`.
///
/// There is no `read_all`. Not `Sync`.
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

/// Fill `buf` from `r`. A short `Read::read` is not EOF.
pub(crate) fn fill_read(r: &mut dyn Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

impl Read for RangeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 || buf.is_empty() {
            return Ok(0);
        }
        let cap = usize::try_from(self.remaining)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        let n = fill_read(&mut self.inner, &mut buf[..cap])?;
        self.remaining -= n as u64;
        Ok(n)
    }
}

impl Session {
    /// Seek + bounded reader. Never returns the member as `Vec<u8>`.
    ///
    /// Does not call [`ratarmount_core::MountSource::read`] (that allocates a
    /// `Vec`). `max_len == 0` yields an empty reader after a successful lookup.
    pub fn read_range(&self, req: ReadRequest) -> Result<RangeReader, Error> {
        let fi = self
            .mount_source()
            .lookup(&req.path, 0)
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

fn map_member_io(e: io::Error) -> Error {
    match e.kind() {
        io::ErrorKind::NotFound => Error::NotFound,
        io::ErrorKind::PermissionDenied => Error::Internal(format!("permission denied: {e}")),
        _ => Error::Internal(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{IndexPolicy, OpenRequest, Recreate, SourceSpec};
    use ratarmount_formats_tar::{write_tar_eof, write_ustar_members, UstarMember, UstarPayload};
    use std::io::Write;
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
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
    }

    /// Short inner `Read::read` is not EOF; fill-loop assembles the cap.
    #[test]
    fn read_range_fill_loop() {
        use ratarmount_core::{FileInfo, MountSource, UserData, S_IFREG};

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
}
