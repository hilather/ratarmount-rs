//! Compact 9P2000.L wire codec (no `rs9p`; keeps MSRV 1.74 and skips a lockfile bump).

use std::io::{self, Read, Write};

/// Protocol version string Linux v9fs sends with `version=9p2000.L`.
pub const VERSION: &str = "9P2000.L";
/// `~0` fid meaning “no fid” (`P9_NOFID`).
pub const NOFID: u32 = u32::MAX;
/// `~0` tag used by `Tversion` (`P9_NOTAG`).
#[allow(dead_code)]
pub const NOTAG: u16 = u16::MAX;
/// Cap on `msize` (and inbound frames) so a bad client cannot force a huge alloc.
pub const MAX_MSIZE: u32 = 1024 * 1024;
/// Default if the client asks for more than we want to pin.
pub const DEFAULT_MSIZE: u32 = 64 * 1024;

pub const TSTATFS: u8 = 8;
pub const RSTATFS: u8 = 9;
pub const TLOPEN: u8 = 12;
pub const RLOPEN: u8 = 13;
pub const TLCREATE: u8 = 14;
pub const RLCREATE: u8 = 15;
pub const TSYMLINK: u8 = 16;
pub const RSYMLINK: u8 = 17;
pub const TREADLINK: u8 = 22;
pub const RREADLINK: u8 = 23;
pub const TGETATTR: u8 = 24;
pub const RGETATTR: u8 = 25;
pub const TSETATTR: u8 = 26;
pub const RSETATTR: u8 = 27;
pub const TREADDIR: u8 = 40;
pub const RREADDIR: u8 = 41;
pub const TMKDIR: u8 = 72;
pub const RMKDIR: u8 = 73;
pub const TRENAMEAT: u8 = 74;
pub const RRENAMEAT: u8 = 75;
pub const TUNLINKAT: u8 = 76;
pub const RUNLINKAT: u8 = 77;
pub const TVERSION: u8 = 100;
pub const RVERSION: u8 = 101;
pub const TAUTH: u8 = 102;
pub const TATTACH: u8 = 104;
pub const RATTACH: u8 = 105;
pub const TFLUSH: u8 = 108;
pub const RFLUSH: u8 = 109;
pub const TWALK: u8 = 110;
pub const RWALK: u8 = 111;
pub const TREAD: u8 = 116;
pub const RREAD: u8 = 117;
pub const TWRITE: u8 = 118;
pub const RWRITE: u8 = 119;
pub const TCLUNK: u8 = 120;
pub const RCLUNK: u8 = 121;
pub const TREMOVE: u8 = 122;
pub const RREMOVE: u8 = 123;
pub const RLERROR: u8 = 7;

pub const QTDIR: u8 = 0x80;
pub const QTSYMLINK: u8 = 0x02;
pub const QTFILE: u8 = 0x00;

pub const DT_DIR: u8 = 4;
pub const DT_REG: u8 = 8;
pub const DT_LNK: u8 = 10;

/// `P9_GETATTR_BASIC` — fields up through `BLOCKS`.
pub const GETATTR_BASIC: u64 = 0x0000_07ff;
/// `P9_SETATTR_SIZE`.
pub const SETATTR_SIZE: u32 = 0x0000_0008;
/// Linux `AT_REMOVEDIR`.
pub const AT_REMOVEDIR: u32 = 0x200;

/// 13-byte 9P qid.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Qid {
    pub typ: u8,
    pub version: u32,
    pub path: u64,
}

/// Outbound 9P encoder. Header size is patched in [`Self::finish`].
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    pub fn reply(typ: u8, tag: u16) -> Self {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&[0, 0, 0, 0, typ]);
        buf.extend_from_slice(&tag.to_le_bytes());
        Self { buf }
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn str(&mut self, s: &str) {
        let bytes = s.as_bytes();
        let n = u16::try_from(bytes.len()).unwrap_or(u16::MAX);
        self.u16(n);
        self.buf.extend_from_slice(&bytes[..n as usize]);
    }

    pub fn qid(&mut self, q: Qid) {
        self.u8(q.typ);
        self.u32(q.version);
        self.u64(q.path);
    }

    pub fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }

    pub fn finish(mut self) -> Vec<u8> {
        let n = u32::try_from(self.buf.len()).unwrap_or(u32::MAX);
        self.buf[0..4].copy_from_slice(&n.to_le_bytes());
        self.buf
    }
}

/// Inbound 9P decoder over the payload after `size[4] type[1] tag[2]`.
pub struct Decoder<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn need(&self, n: usize) -> io::Result<()> {
        if self.pos.saturating_add(n) > self.data.len() {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated 9P field",
            ))
        } else {
            Ok(())
        }
    }

    #[allow(dead_code)]
    pub fn u8(&mut self) -> io::Result<u8> {
        self.need(1)?;
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn u16(&mut self) -> io::Result<u16> {
        self.need(2)?;
        let v = u16::from_le_bytes(self.data[self.pos..self.pos + 2].try_into().unwrap());
        self.pos += 2;
        Ok(v)
    }

    pub fn u32(&mut self) -> io::Result<u32> {
        self.need(4)?;
        let v = u32::from_le_bytes(self.data[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    pub fn u64(&mut self) -> io::Result<u64> {
        self.need(8)?;
        let v = u64::from_le_bytes(self.data[self.pos..self.pos + 8].try_into().unwrap());
        self.pos += 8;
        Ok(v)
    }

    pub fn str(&mut self) -> io::Result<String> {
        let n = self.u16()? as usize;
        self.need(n)?;
        let s = String::from_utf8_lossy(&self.data[self.pos..self.pos + n]).into_owned();
        self.pos += n;
        Ok(s)
    }

    #[allow(dead_code)]
    pub fn qid(&mut self) -> io::Result<Qid> {
        Ok(Qid {
            typ: self.u8()?,
            version: self.u32()?,
            path: self.u64()?,
        })
    }

    #[allow(dead_code)]
    pub fn rest(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    pub fn take(&mut self, n: usize) -> io::Result<&'a [u8]> {
        self.need(n)?;
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

/// Split a complete 9P frame into `(type, tag, payload)`.
pub fn split_frame(buf: &[u8]) -> io::Result<(u8, u16, &[u8])> {
    if buf.len() < 7 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "9P header too short",
        ));
    }
    let size = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
    if size != buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "9P size mismatch",
        ));
    }
    let typ = buf[4];
    let tag = u16::from_le_bytes(buf[5..7].try_into().unwrap());
    Ok((typ, tag, &buf[7..]))
}

/// Read one length-prefixed 9P message (including the size header).
#[allow(dead_code)]
pub fn read_message(r: &mut impl Read, max: u32) -> io::Result<Vec<u8>> {
    read_message_abort(r, max, || false)
}

/// Like [`read_message`], but `abort()` can stop a mid-frame wait (export stop).
pub fn read_message_abort(
    r: &mut impl Read,
    max: u32,
    abort: impl Fn() -> bool,
) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    read_exact_retry(r, &mut hdr, &abort)?;
    let size = u32::from_le_bytes(hdr);
    if size < 7 || size > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid 9P msize {size}"),
        ));
    }
    let mut buf = vec![0u8; size as usize];
    buf[0..4].copy_from_slice(&hdr);
    read_exact_retry(r, &mut buf[4..], &abort)?;
    Ok(buf)
}

fn read_exact_retry(
    r: &mut impl Read,
    mut buf: &mut [u8],
    abort: &impl Fn() -> bool,
) -> io::Result<()> {
    while !buf.is_empty() {
        if abort() {
            return Err(io::Error::new(io::ErrorKind::TimedOut, "9P stop"));
        }
        match r.read(buf) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "9P connection closed",
                ))
            }
            Ok(n) => buf = &mut buf[n..],
            Err(e)
                if e.kind() == io::ErrorKind::Interrupted
                    || e.kind() == io::ErrorKind::TimedOut
                    || e.kind() == io::ErrorKind::WouldBlock =>
            {
                continue;
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

pub fn write_message(w: &mut impl Write, msg: &[u8]) -> io::Result<()> {
    w.write_all(msg)?;
    w.flush()
}

pub fn rlerror(tag: u16, ecode: i32) -> Vec<u8> {
    let mut e = Encoder::reply(RLERROR, tag);
    e.u32(ecode as u32);
    e.finish()
}

pub fn empty_reply(typ: u8, tag: u16) -> Vec<u8> {
    Encoder::reply(typ, tag).finish()
}

pub fn rversion(tag: u16, msize: u32, version: &str) -> Vec<u8> {
    let mut e = Encoder::reply(RVERSION, tag);
    e.u32(msize);
    e.str(version);
    e.finish()
}

pub fn rattach(tag: u16, qid: Qid) -> Vec<u8> {
    let mut e = Encoder::reply(RATTACH, tag);
    e.qid(qid);
    e.finish()
}

pub fn rwalk(tag: u16, qids: &[Qid]) -> Vec<u8> {
    let mut e = Encoder::reply(RWALK, tag);
    e.u16(u16::try_from(qids.len()).unwrap_or(u16::MAX));
    for q in qids {
        e.qid(*q);
    }
    e.finish()
}

pub fn rread(tag: u16, data: &[u8]) -> Vec<u8> {
    let mut e = Encoder::reply(RREAD, tag);
    e.u32(data.len() as u32);
    e.bytes(data);
    e.finish()
}

pub fn rwrite(tag: u16, count: u32) -> Vec<u8> {
    let mut e = Encoder::reply(RWRITE, tag);
    e.u32(count);
    e.finish()
}

pub fn rreaddir(tag: u16, data: &[u8]) -> Vec<u8> {
    let mut e = Encoder::reply(RREADDIR, tag);
    e.u32(data.len() as u32);
    e.bytes(data);
    e.finish()
}

pub fn rlopen(tag: u16, qid: Qid, iounit: u32) -> Vec<u8> {
    let mut e = Encoder::reply(RLOPEN, tag);
    e.qid(qid);
    e.u32(iounit);
    e.finish()
}

pub fn rlcreate(tag: u16, qid: Qid, iounit: u32) -> Vec<u8> {
    let mut e = Encoder::reply(RLCREATE, tag);
    e.qid(qid);
    e.u32(iounit);
    e.finish()
}

pub fn rmkdir(tag: u16, qid: Qid) -> Vec<u8> {
    let mut e = Encoder::reply(RMKDIR, tag);
    e.qid(qid);
    e.finish()
}

pub fn rsymlink(tag: u16, qid: Qid) -> Vec<u8> {
    let mut e = Encoder::reply(RSYMLINK, tag);
    e.qid(qid);
    e.finish()
}

pub fn rreadlink(tag: u16, target: &str) -> Vec<u8> {
    let mut e = Encoder::reply(RREADLINK, tag);
    e.str(target);
    e.finish()
}

#[allow(clippy::too_many_arguments)]
pub fn rgetattr(
    tag: u16,
    valid: u64,
    qid: Qid,
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u64,
    rdev: u64,
    size: u64,
    blksize: u64,
    blocks: u64,
    atime_sec: u64,
    atime_nsec: u64,
    mtime_sec: u64,
    mtime_nsec: u64,
    ctime_sec: u64,
    ctime_nsec: u64,
) -> Vec<u8> {
    let mut e = Encoder::reply(RGETATTR, tag);
    e.u64(valid);
    e.qid(qid);
    e.u32(mode);
    e.u32(uid);
    e.u32(gid);
    e.u64(nlink);
    e.u64(rdev);
    e.u64(size);
    e.u64(blksize);
    e.u64(blocks);
    e.u64(atime_sec);
    e.u64(atime_nsec);
    e.u64(mtime_sec);
    e.u64(mtime_nsec);
    e.u64(ctime_sec);
    e.u64(ctime_nsec);
    e.u64(0); // btime_sec
    e.u64(0); // btime_nsec
    e.u64(0); // gen
    e.u64(0); // data_version
    e.finish()
}

#[allow(clippy::too_many_arguments)]
pub fn rstatfs(
    tag: u16,
    typ: u32,
    bsize: u32,
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    fsid: u64,
    namelen: u32,
) -> Vec<u8> {
    let mut e = Encoder::reply(RSTATFS, tag);
    e.u32(typ);
    e.u32(bsize);
    e.u64(blocks);
    e.u64(bfree);
    e.u64(bavail);
    e.u64(files);
    e.u64(ffree);
    e.u64(fsid);
    e.u32(namelen);
    e.finish()
}

/// Encode one `Treaddir` dirent: `qid[13] offset[8] type[1] name[s]`.
pub fn encode_dirent(qid: Qid, offset: u64, typ: u8, name: &str) -> Vec<u8> {
    let mut e = Encoder {
        buf: Vec::with_capacity(13 + 8 + 1 + 2 + name.len()),
    };
    e.qid(qid);
    e.u64(offset);
    e.u8(typ);
    e.str(name);
    e.buf
}

/// Parse packed readdir data (test client).
#[allow(dead_code)]
pub fn decode_dirents(mut data: &[u8]) -> io::Result<Vec<(Qid, u64, u8, String)>> {
    let mut out = Vec::new();
    while !data.is_empty() {
        if data.len() < 13 + 8 + 1 + 2 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated dirent",
            ));
        }
        let mut d = Decoder::new(data);
        let qid = d.qid()?;
        let offset = d.u64()?;
        let typ = d.u8()?;
        let name = d.str()?;
        let used = data.len() - d.rest().len();
        out.push((qid, offset, typ, name));
        data = &data[used..];
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rlerror_roundtrip() {
        let msg = rlerror(7, libc::EROFS);
        let (typ, tag, payload) = split_frame(&msg).unwrap();
        assert_eq!(typ, RLERROR);
        assert_eq!(tag, 7);
        let mut d = Decoder::new(payload);
        assert_eq!(d.u32().unwrap(), libc::EROFS as u32);
    }

    #[test]
    fn version_roundtrip() {
        let msg = rversion(NOTAG, 8192, VERSION);
        let (typ, tag, payload) = split_frame(&msg).unwrap();
        assert_eq!(typ, RVERSION);
        assert_eq!(tag, NOTAG);
        let mut d = Decoder::new(payload);
        assert_eq!(d.u32().unwrap(), 8192);
        assert_eq!(d.str().unwrap(), VERSION);
    }

    #[test]
    fn dirent_roundtrip() {
        let q = Qid {
            typ: QTFILE,
            version: 0,
            path: 3,
        };
        let raw = encode_dirent(q, 1, DT_REG, "hello.txt");
        let ents = decode_dirents(&raw).unwrap();
        assert_eq!(ents.len(), 1);
        assert_eq!(ents[0].3, "hello.txt");
        assert_eq!(ents[0].0.path, 3);
    }
}
