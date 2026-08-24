//! Bind / serve / stop. Blocking `TcpListener` (no tokio in this crate).

use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use ratarmount_compositing::WriteOverlay;
use ratarmount_core::MountSource;
use ratarmount_export_core::{
    default_export_bind, parse_export_bind, BindError, ExportServerHandle, ExportStop,
    DEFAULT_NINEP_PORT, DEFAULT_READER_SLOTS, STOP_POLL_INTERVAL,
};

use crate::proto::{
    empty_reply, rattach, rgetattr, rlcreate, rlerror, rlopen, rmkdir, rread, rreaddir, rreadlink,
    rstatfs, rsymlink, rversion, rwalk, rwrite, split_frame, write_message, Decoder, Qid,
    DEFAULT_MSIZE, GETATTR_BASIC, MAX_MSIZE, NOFID, RCLUNK, RFLUSH, RREMOVE, RRENAMEAT, RSETATTR,
    RUNLINKAT, TATTACH, TAUTH, TCLUNK, TFLUSH, TGETATTR, TLCREATE, TLOPEN, TMKDIR, TREAD, TREADDIR,
    TREADLINK, TREMOVE, TRENAMEAT, TSETATTR, TSTATFS, TSYMLINK, TUNLINKAT, TVERSION, TWALK, TWRITE,
    VERSION,
};
use crate::vfs::{root_id, Ratarmount9p};

/// `127.0.0.1:20493` — empty-string result of [`parse_ninep_bind`].
pub const DEFAULT_NINEP_BIND: SocketAddr = SocketAddr::V4(std::net::SocketAddrV4::new(
    std::net::Ipv4Addr::LOCALHOST,
    DEFAULT_NINEP_PORT,
));

/// Listen / export options for [`serve_blocking`] / [`spawn_ninep_thread`].
#[derive(Clone)]
pub struct NinepOptions {
    pub bind: SocketAddr,
    pub stop: Option<ExportStop>,
    /// When set, `Tlcreate`/`Twrite`/`Tmkdir`/`Tunlinkat`/`Trenameat`/`Tsymlink`
    /// go to this overlay. Without it those ops return `EROFS`.
    pub overlay: Option<Arc<WriteOverlay>>,
    pub readahead_bytes: usize,
    pub reader_slots: usize,
}

impl Default for NinepOptions {
    fn default() -> Self {
        Self {
            bind: default_export_bind(DEFAULT_NINEP_PORT),
            stop: None,
            overlay: None,
            readahead_bytes: 0,
            reader_slots: DEFAULT_READER_SLOTS,
        }
    }
}

impl std::fmt::Debug for NinepOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NinepOptions")
            .field("bind", &self.bind)
            .field("stop", &self.stop.as_ref().map(|_| "ExportStop"))
            .field("overlay", &self.overlay.is_some())
            .field("readahead_bytes", &self.readahead_bytes)
            .field("reader_slots", &self.reader_slots)
            .finish()
    }
}

/// Parse `[host:]port` into an IPv4 listen address (default port 20493).
pub fn parse_ninep_bind(s: &str) -> Result<SocketAddr, BindError> {
    parse_export_bind(s, DEFAULT_NINEP_PORT)
}

fn access_label(opts: &NinepOptions) -> &'static str {
    if opts.overlay.is_some() {
        "rw overlay"
    } else {
        "ro"
    }
}

fn fs_from_opts(source: Arc<dyn MountSource>, opts: &NinepOptions) -> Arc<Ratarmount9p> {
    Arc::new(Ratarmount9p::with_overlay(
        source,
        opts.readahead_bytes,
        opts.reader_slots,
        opts.overlay.clone(),
    ))
}

/// Bind + accept until [`ExportStop`] (200 ms poll).
pub fn serve_blocking(source: Arc<dyn MountSource>, opts: NinepOptions) -> io::Result<()> {
    let listener = TcpListener::bind(opts.bind)?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    let port = addr.port();
    let ip = match addr.ip() {
        std::net::IpAddr::V4(v) => v.to_string(),
        std::net::IpAddr::V6(_) => {
            return Err(io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "9P bind is IPv4-only",
            ))
        }
    };
    let access = access_label(&opts);
    log::info!(
        "9P2000.L listening on {ip}:{port} ({access}). mount: mount -t 9p -o trans=tcp,port={port},version=9p2000.L {ip} <dir>"
    );
    serve_listener(listener, source, opts)
}

fn serve_listener(
    listener: TcpListener,
    source: Arc<dyn MountSource>,
    opts: NinepOptions,
) -> io::Result<()> {
    let fs = fs_from_opts(source, &opts);
    let stop = opts.stop.clone();
    loop {
        if stop.as_ref().is_some_and(|s| s.is_stopped()) {
            return Ok(());
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let fs = Arc::clone(&fs);
                let stop = stop.clone();
                let _ = thread::Builder::new()
                    .name("ratarmount-9p-conn".into())
                    .spawn(move || handle_conn(stream, fs, stop));
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted => {
                thread::sleep(STOP_POLL_INTERVAL);
            }
            Err(e) => return Err(e),
        }
    }
}

/// Dedicated thread owns bind + accept. Returns after bind.
pub fn spawn_ninep_thread(
    source: Arc<dyn MountSource>,
    opts: NinepOptions,
) -> io::Result<ExportServerHandle> {
    let (tx, rx) = std::sync::mpsc::channel();
    let join = thread::Builder::new()
        .name("ratarmount-9p".into())
        .spawn(move || {
            let listener = match TcpListener::bind(opts.bind) {
                Ok(l) => l,
                Err(e) => {
                    let _ = tx.send(Err(io::Error::new(e.kind(), e.to_string())));
                    return Err(e);
                }
            };
            if let Err(e) = listener.set_nonblocking(true) {
                let _ = tx.send(Err(io::Error::new(e.kind(), e.to_string())));
                return Err(e);
            }
            let addr = match listener.local_addr() {
                Ok(a) => a,
                Err(e) => {
                    let _ = tx.send(Err(io::Error::new(e.kind(), e.to_string())));
                    return Err(e);
                }
            };
            let port = addr.port();
            let ip = match addr.ip() {
                std::net::IpAddr::V4(v) => v.to_string(),
                std::net::IpAddr::V6(_) => {
                    let e = io::Error::new(io::ErrorKind::AddrNotAvailable, "9P bind is IPv4-only");
                    let _ = tx.send(Err(io::Error::new(e.kind(), e.to_string())));
                    return Err(e);
                }
            };
            let access = access_label(&opts);
            log::info!(
                "9P2000.L listening on {ip}:{port} ({access}). mount: mount -t 9p -o trans=tcp,port={port},version=9p2000.L {ip} <dir>"
            );
            let _ = tx.send(Ok(port));
            serve_listener(listener, source, opts)
        })?;
    let port = rx
        .recv()
        .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "9P thread exited before bind"))??;
    Ok(ExportServerHandle::from_join(port, join))
}

struct Fid {
    id: u64,
}

struct Session {
    fs: Arc<Ratarmount9p>,
    fids: HashMap<u32, Fid>,
    msize: u32,
}

fn handle_conn(stream: TcpStream, fs: Arc<Ratarmount9p>, stop: Option<ExportStop>) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(STOP_POLL_INTERVAL));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let mut session = Session {
        fs,
        fids: HashMap::new(),
        msize: DEFAULT_MSIZE,
    };
    let mut r = stream;
    loop {
        if stop.as_ref().is_some_and(|s| s.is_stopped()) {
            return;
        }
        let stopped = || stop.as_ref().is_some_and(|s| s.is_stopped());
        let frame =
            match crate::proto::read_message_abort(&mut r, session.msize.max(MAX_MSIZE), stopped) {
                Ok(f) => f,
                Err(e) if e.kind() == ErrorKind::TimedOut => return,
                Err(_) => return,
            };
        let reply = match session.dispatch(&frame) {
            Ok(m) => m,
            Err(e) => {
                let tag = if frame.len() >= 7 {
                    u16::from_le_bytes(frame[5..7].try_into().unwrap_or([0, 0]))
                } else {
                    0
                };
                rlerror(tag, io_kind_to_errno(&e))
            }
        };
        if write_message(&mut r, &reply).is_err() {
            return;
        }
    }
}

fn io_kind_to_errno(e: &io::Error) -> i32 {
    match e.kind() {
        ErrorKind::UnexpectedEof | ErrorKind::InvalidData | ErrorKind::InvalidInput => libc::EINVAL,
        _ => libc::EIO,
    }
}

impl Session {
    fn dispatch(&mut self, frame: &[u8]) -> io::Result<Vec<u8>> {
        let (typ, tag, payload) = split_frame(frame)?;
        let mut d = Decoder::new(payload);
        match typ {
            TVERSION => {
                let msize = d.u32()?;
                let _ver = d.str()?;
                self.fids.clear();
                self.msize = msize.clamp(128u32, MAX_MSIZE);
                Ok(rversion(tag, self.msize, VERSION))
            }
            TAUTH => Ok(rlerror(tag, libc::EOPNOTSUPP)),
            TFLUSH => Ok(empty_reply(RFLUSH, tag)),
            TATTACH => {
                let fid = d.u32()?;
                let _afid = d.u32()?;
                let _uname = d.str()?;
                let _aname = d.str()?;
                let _n_uname = d.u32().unwrap_or(NOFID);
                if fid == NOFID {
                    return Ok(rlerror(tag, libc::EINVAL));
                }
                self.fids.insert(fid, Fid { id: root_id() });
                match self.fs.qid_for_id(root_id()) {
                    Ok(q) => Ok(rattach(tag, q)),
                    Err(e) => Ok(rlerror(tag, e)),
                }
            }
            TWALK => {
                let fid = d.u32()?;
                let newfid = d.u32()?;
                let nwname = d.u16()? as usize;
                let mut names = Vec::with_capacity(nwname);
                for _ in 0..nwname {
                    names.push(d.str()?);
                }
                let start = match self.fids.get(&fid) {
                    Some(f) => f.id,
                    None => return Ok(rlerror(tag, libc::EBADF)),
                };
                if newfid != fid && self.fids.contains_key(&newfid) {
                    return Ok(rlerror(tag, libc::EBADF));
                }
                match self.fs.walk_names(start, &names) {
                    Ok(steps) => {
                        if names.is_empty() {
                            self.fids.insert(newfid, Fid { id: start });
                            Ok(rwalk(tag, &[]))
                        } else if steps.len() == names.len() {
                            let last = steps.last().map(|s| s.0).unwrap_or(start);
                            self.fids.insert(newfid, Fid { id: last });
                            let qids: Vec<Qid> = steps.into_iter().map(|s| s.1).collect();
                            Ok(rwalk(tag, &qids))
                        } else {
                            // Incomplete walk does not install newfid.
                            let qids: Vec<Qid> = steps.into_iter().map(|s| s.1).collect();
                            Ok(rwalk(tag, &qids))
                        }
                    }
                    Err(e) => Ok(rlerror(tag, e)),
                }
            }
            TGETATTR => {
                let fid = d.u32()?;
                let _mask = d.u64()?;
                let id = match self.fid_id(fid) {
                    Ok(id) => id,
                    Err(e) => return Ok(rlerror(tag, e)),
                };
                match self.fs.getattr(id) {
                    Ok(a) => Ok(rgetattr(
                        tag,
                        GETATTR_BASIC,
                        a.qid,
                        a.mode,
                        a.uid,
                        a.gid,
                        a.nlink,
                        a.rdev,
                        a.size,
                        a.blksize,
                        a.blocks,
                        a.atime_sec,
                        a.atime_nsec,
                        a.mtime_sec,
                        a.mtime_nsec,
                        a.ctime_sec,
                        a.ctime_nsec,
                    )),
                    Err(e) => Ok(rlerror(tag, e)),
                }
            }
            TSETATTR => {
                let fid = d.u32()?;
                let valid = d.u32()?;
                let _mode = d.u32()?;
                let _uid = d.u32()?;
                let _gid = d.u32()?;
                let size = d.u64()?;
                let id = match self.fid_id(fid) {
                    Ok(id) => id,
                    Err(e) => return Ok(rlerror(tag, e)),
                };
                match self.fs.setattr_size(id, valid, size) {
                    Ok(()) => Ok(empty_reply(RSETATTR, tag)),
                    Err(e) => Ok(rlerror(tag, e)),
                }
            }
            TSTATFS => {
                let _fid = d.u32()?;
                let s = self.fs.statfs();
                Ok(rstatfs(
                    tag, s.typ, s.bsize, s.blocks, s.bfree, s.bavail, s.files, s.ffree, s.fsid,
                    s.namelen,
                ))
            }
            TLOPEN => {
                let fid = d.u32()?;
                let flags = d.u32()?;
                if let Err(e) = self.fs.require_write_open(flags) {
                    return Ok(rlerror(tag, e));
                }
                let id = match self.fid_id(fid) {
                    Ok(id) => id,
                    Err(e) => return Ok(rlerror(tag, e)),
                };
                match self.fs.qid_for_id(id) {
                    Ok(q) => Ok(rlopen(tag, q, 0)),
                    Err(e) => Ok(rlerror(tag, e)),
                }
            }
            TREAD => {
                let fid = d.u32()?;
                let offset = d.u64()?;
                let count = d.u32()?;
                let id = match self.fid_id(fid) {
                    Ok(id) => id,
                    Err(e) => return Ok(rlerror(tag, e)),
                };
                match self.fs.read(id, offset, count) {
                    Ok(buf) => Ok(rread(tag, &buf)),
                    Err(e) => Ok(rlerror(tag, e)),
                }
            }
            TWRITE => {
                let fid = d.u32()?;
                let offset = d.u64()?;
                let count = d.u32()? as usize;
                let data = d.take(count)?;
                let id = match self.fid_id(fid) {
                    Ok(id) => id,
                    Err(e) => return Ok(rlerror(tag, e)),
                };
                match self.fs.write(id, offset, data) {
                    Ok(n) => Ok(rwrite(tag, n)),
                    Err(e) => Ok(rlerror(tag, e)),
                }
            }
            TREADDIR => {
                let fid = d.u32()?;
                let offset = d.u64()?;
                let count = d.u32()?;
                let id = match self.fid_id(fid) {
                    Ok(id) => id,
                    Err(e) => return Ok(rlerror(tag, e)),
                };
                match self.fs.readdir(id, offset, count) {
                    Ok(buf) => Ok(rreaddir(tag, &buf)),
                    Err(e) => Ok(rlerror(tag, e)),
                }
            }
            TCLUNK => {
                let fid = d.u32()?;
                self.fids.remove(&fid);
                Ok(empty_reply(RCLUNK, tag))
            }
            TLCREATE => {
                let fid = d.u32()?;
                let name = d.str()?;
                let _flags = d.u32()?;
                let mode = d.u32()?;
                let _gid = d.u32()?;
                let dir_id = match self.fid_id(fid) {
                    Ok(id) => id,
                    Err(e) => return Ok(rlerror(tag, e)),
                };
                match self.fs.lcreate(dir_id, &name, mode) {
                    Ok((id, q)) => {
                        self.fids.insert(fid, Fid { id });
                        Ok(rlcreate(tag, q, 0))
                    }
                    Err(e) => Ok(rlerror(tag, e)),
                }
            }
            TMKDIR => {
                let fid = d.u32()?;
                let name = d.str()?;
                let mode = d.u32()?;
                let _gid = d.u32()?;
                let dir_id = match self.fid_id(fid) {
                    Ok(id) => id,
                    Err(e) => return Ok(rlerror(tag, e)),
                };
                match self.fs.mkdir(dir_id, &name, mode) {
                    Ok((_id, q)) => Ok(rmkdir(tag, q)),
                    Err(e) => Ok(rlerror(tag, e)),
                }
            }
            TUNLINKAT => {
                let fid = d.u32()?;
                let name = d.str()?;
                let flags = d.u32()?;
                let dir_id = match self.fid_id(fid) {
                    Ok(id) => id,
                    Err(e) => return Ok(rlerror(tag, e)),
                };
                match self.fs.unlinkat(dir_id, &name, flags) {
                    Ok(()) => Ok(empty_reply(RUNLINKAT, tag)),
                    Err(e) => Ok(rlerror(tag, e)),
                }
            }
            TRENAMEAT => {
                let olddir = d.u32()?;
                let oldname = d.str()?;
                let newdir = d.u32()?;
                let newname = d.str()?;
                let old_id = match self.fid_id(olddir) {
                    Ok(id) => id,
                    Err(e) => return Ok(rlerror(tag, e)),
                };
                let new_id = match self.fid_id(newdir) {
                    Ok(id) => id,
                    Err(e) => return Ok(rlerror(tag, e)),
                };
                match self.fs.renameat(old_id, &oldname, new_id, &newname) {
                    Ok(()) => Ok(empty_reply(RRENAMEAT, tag)),
                    Err(e) => Ok(rlerror(tag, e)),
                }
            }
            TSYMLINK => {
                let fid = d.u32()?;
                let name = d.str()?;
                let target = d.str()?;
                let _gid = d.u32()?;
                let dir_id = match self.fid_id(fid) {
                    Ok(id) => id,
                    Err(e) => return Ok(rlerror(tag, e)),
                };
                match self.fs.symlink(dir_id, &name, &target) {
                    Ok((_id, q)) => Ok(rsymlink(tag, q)),
                    Err(e) => Ok(rlerror(tag, e)),
                }
            }
            TREADLINK => {
                let fid = d.u32()?;
                let id = match self.fid_id(fid) {
                    Ok(id) => id,
                    Err(e) => return Ok(rlerror(tag, e)),
                };
                match self.fs.readlink(id) {
                    Ok(t) => Ok(rreadlink(tag, &t)),
                    Err(e) => Ok(rlerror(tag, e)),
                }
            }
            TREMOVE => {
                let fid = d.u32()?;
                let id = match self.fid_id(fid) {
                    Ok(id) => id,
                    Err(e) => return Ok(rlerror(tag, e)),
                };
                match self.fs.remove_path(id) {
                    Ok(()) => {
                        self.fids.remove(&fid);
                        Ok(empty_reply(RREMOVE, tag))
                    }
                    Err(e) => Ok(rlerror(tag, e)),
                }
            }
            _ => Ok(rlerror(tag, libc::EOPNOTSUPP)),
        }
    }

    fn fid_id(&self, fid: u32) -> Result<u64, i32> {
        self.fids.get(&fid).map(|f| f.id).ok_or(libc::EBADF)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read, Seek, SeekFrom};
    use std::sync::mpsc;
    use std::time::Duration;

    use ratarmount_core::{
        create_root_file_info, ArchiveRead, FileInfo, ListResult, OpenOptions, S_IFREG,
    };
    use ratarmount_export_core::fill_read;
    use ratarmount_formats_tar::{
        write_tar_eof, write_ustar_members, SqliteIndexedTar, UstarMember, UstarPayload,
    };

    use crate::proto::{
        decode_dirents, read_message, Encoder, RLERROR, RREAD, RREADDIR, RWALK, TLCREATE, TMKDIR,
        TRENAMEAT, TSYMLINK, TUNLINKAT, TWRITE,
    };

    struct NinepClient {
        stream: TcpStream,
        tag: u16,
        msize: u32,
    }

    impl NinepClient {
        fn connect(addr: SocketAddr) -> Self {
            let stream =
                TcpStream::connect_timeout(&addr, Duration::from_secs(2)).expect("connect");
            stream.set_nodelay(true).ok();
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let mut c = Self {
                stream,
                tag: 1,
                msize: DEFAULT_MSIZE,
            };
            c.version();
            c
        }

        fn rpc(&mut self, req: Vec<u8>) -> Vec<u8> {
            write_message(&mut self.stream, &req).expect("write");
            read_message(&mut self.stream, self.msize.max(MAX_MSIZE)).expect("read")
        }

        fn next_tag(&mut self) -> u16 {
            let t = self.tag;
            self.tag = self.tag.wrapping_add(1).max(1);
            t
        }

        fn version(&mut self) {
            let tag = crate::proto::NOTAG;
            let mut e = Encoder::reply(TVERSION, tag);
            e.u32(DEFAULT_MSIZE);
            e.str(VERSION);
            let reply = self.rpc(e.finish());
            let (typ, _, payload) = split_frame(&reply).unwrap();
            assert_ne!(typ, RLERROR, "Tversion failed");
            let mut d = Decoder::new(payload);
            self.msize = d.u32().unwrap();
        }

        fn attach(&mut self, fid: u32) -> Qid {
            let tag = self.next_tag();
            let mut e = Encoder::reply(TATTACH, tag);
            e.u32(fid);
            e.u32(NOFID);
            e.str("root");
            e.str("");
            e.u32(NOFID);
            let reply = self.rpc(e.finish());
            let (typ, _, payload) = split_frame(&reply).unwrap();
            assert_ne!(typ, RLERROR, "Tattach Rlerror");
            Decoder::new(payload).qid().unwrap()
        }

        fn walk(&mut self, fid: u32, newfid: u32, names: &[&str]) -> Result<Vec<Qid>, u32> {
            let tag = self.next_tag();
            let mut e = Encoder::reply(TWALK, tag);
            e.u32(fid);
            e.u32(newfid);
            e.u16(names.len() as u16);
            for n in names {
                e.str(n);
            }
            let reply = self.rpc(e.finish());
            let (typ, _, payload) = split_frame(&reply).unwrap();
            if typ == RLERROR {
                return Err(Decoder::new(payload).u32().unwrap());
            }
            assert_eq!(typ, RWALK);
            let mut d = Decoder::new(payload);
            let n = d.u16().unwrap() as usize;
            let mut qids = Vec::with_capacity(n);
            for _ in 0..n {
                qids.push(d.qid().unwrap());
            }
            Ok(qids)
        }

        fn lopen(&mut self, fid: u32, flags: u32) -> Result<Qid, u32> {
            let tag = self.next_tag();
            let mut e = Encoder::reply(TLOPEN, tag);
            e.u32(fid);
            e.u32(flags);
            let reply = self.rpc(e.finish());
            let (typ, _, payload) = split_frame(&reply).unwrap();
            if typ == RLERROR {
                return Err(Decoder::new(payload).u32().unwrap());
            }
            Ok(Decoder::new(payload).qid().unwrap())
        }

        fn read(&mut self, fid: u32, offset: u64, count: u32) -> Result<Vec<u8>, u32> {
            let tag = self.next_tag();
            let mut e = Encoder::reply(TREAD, tag);
            e.u32(fid);
            e.u64(offset);
            e.u32(count);
            let reply = self.rpc(e.finish());
            let (typ, _, payload) = split_frame(&reply).unwrap();
            if typ == RLERROR {
                return Err(Decoder::new(payload).u32().unwrap());
            }
            assert_eq!(typ, RREAD);
            let mut d = Decoder::new(payload);
            let n = d.u32().unwrap() as usize;
            Ok(d.take(n).unwrap().to_vec())
        }

        fn readdir(&mut self, fid: u32, offset: u64, count: u32) -> Result<Vec<u8>, u32> {
            let tag = self.next_tag();
            let mut e = Encoder::reply(TREADDIR, tag);
            e.u32(fid);
            e.u64(offset);
            e.u32(count);
            let reply = self.rpc(e.finish());
            let (typ, _, payload) = split_frame(&reply).unwrap();
            if typ == RLERROR {
                return Err(Decoder::new(payload).u32().unwrap());
            }
            assert_eq!(typ, RREADDIR);
            let mut d = Decoder::new(payload);
            let n = d.u32().unwrap() as usize;
            Ok(d.take(n).unwrap().to_vec())
        }

        fn getattr_size(&mut self, fid: u32) -> u64 {
            let tag = self.next_tag();
            let mut e = Encoder::reply(TGETATTR, tag);
            e.u32(fid);
            e.u64(GETATTR_BASIC);
            let reply = self.rpc(e.finish());
            let (typ, _, payload) = split_frame(&reply).unwrap();
            assert_ne!(typ, RLERROR);
            let mut d = Decoder::new(payload);
            let _valid = d.u64().unwrap();
            let _qid = d.qid().unwrap();
            let _mode = d.u32().unwrap();
            let _uid = d.u32().unwrap();
            let _gid = d.u32().unwrap();
            let _nlink = d.u64().unwrap();
            let _rdev = d.u64().unwrap();
            d.u64().unwrap()
        }

        fn mkdir_err(&mut self, fid: u32, name: &str) -> u32 {
            let tag = self.next_tag();
            let mut e = Encoder::reply(TMKDIR, tag);
            e.u32(fid);
            e.str(name);
            e.u32(0o755);
            e.u32(0);
            self.ecode(e.finish())
        }

        fn lcreate_err(&mut self, fid: u32, name: &str) -> u32 {
            let tag = self.next_tag();
            let mut e = Encoder::reply(TLCREATE, tag);
            e.u32(fid);
            e.str(name);
            e.u32(libc::O_WRONLY as u32);
            e.u32(0o644);
            e.u32(0);
            self.ecode(e.finish())
        }

        fn write_err(&mut self, fid: u32) -> u32 {
            let tag = self.next_tag();
            let mut e = Encoder::reply(TWRITE, tag);
            e.u32(fid);
            e.u64(0);
            e.u32(1);
            e.bytes(b"x");
            self.ecode(e.finish())
        }

        fn unlinkat_err(&mut self, fid: u32, name: &str) -> u32 {
            let tag = self.next_tag();
            let mut e = Encoder::reply(TUNLINKAT, tag);
            e.u32(fid);
            e.str(name);
            e.u32(0);
            self.ecode(e.finish())
        }

        fn renameat_err(&mut self, fid: u32, old: &str, new: &str) -> u32 {
            let tag = self.next_tag();
            let mut e = Encoder::reply(TRENAMEAT, tag);
            e.u32(fid);
            e.str(old);
            e.u32(fid);
            e.str(new);
            self.ecode(e.finish())
        }

        fn symlink_err(&mut self, fid: u32, name: &str, target: &str) -> u32 {
            let tag = self.next_tag();
            let mut e = Encoder::reply(TSYMLINK, tag);
            e.u32(fid);
            e.str(name);
            e.str(target);
            e.u32(0);
            self.ecode(e.finish())
        }

        fn ecode(&mut self, req: Vec<u8>) -> u32 {
            let reply = self.rpc(req);
            let (typ, _, payload) = split_frame(&reply).unwrap();
            assert_eq!(typ, RLERROR, "expected Rlerror");
            Decoder::new(payload).u32().unwrap()
        }
    }

    fn spawn_src(source: Arc<dyn MountSource>) -> (ExportServerHandle, SocketAddr, ExportStop) {
        let stop = ExportStop::new();
        let opts = NinepOptions {
            bind: "127.0.0.1:0".parse().unwrap(),
            stop: Some(stop.clone()),
            ..NinepOptions::default()
        };
        let handle = spawn_ninep_thread(source, opts).expect("spawn 9p");
        let addr = SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, handle.port));
        (handle, addr, stop)
    }

    fn tar_source() -> Arc<dyn MountSource> {
        let mut buf = Vec::new();
        write_ustar_members(
            &mut buf,
            &[UstarMember {
                path: "hello.txt",
                payload: UstarPayload::File {
                    bytes: b"hello 9p\n",
                },
                mode: 0o644,
                uid: 0,
                gid: 0,
                mtime: 0,
            }],
        )
        .unwrap();
        write_tar_eof(&mut buf).unwrap();
        let opts = OpenOptions {
            index_in_memory: true,
            write_index: false,
            ..OpenOptions::default()
        };
        let tar = SqliteIndexedTar::open_from_reader(
            Cursor::new(buf),
            std::path::Path::new("memory://ninep-fixture.tar"),
            None,
            &opts,
            "test",
        )
        .expect("index tar");
        Arc::new(tar)
    }

    struct ShortRead(Cursor<Vec<u8>>);
    impl Read for ShortRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            self.0.read(&mut buf[..1])
        }
    }
    impl Seek for ShortRead {
        fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
            self.0.seek(pos)
        }
    }

    struct ShortFs {
        data: Vec<u8>,
    }
    impl MountSource for ShortFs {
        fn list(&self, path: &str) -> Option<ListResult> {
            if path == "/" {
                Some(ListResult::Names(vec!["blob".into()]))
            } else {
                None
            }
        }
        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            if path == "/" {
                Some(create_root_file_info())
            } else if path == "/blob" {
                Some(FileInfo {
                    size: self.data.len() as u64,
                    mtime: 1.0,
                    mode: S_IFREG | 0o644,
                    linkname: String::new(),
                    uid: 0,
                    gid: 0,
                    userdata: vec![],
                })
            } else {
                None
            }
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ArchiveRead>> {
            Ok(Box::new(ShortRead(Cursor::new(self.data.clone()))))
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }

    struct EmptyFs;
    impl MountSource for EmptyFs {
        fn list(&self, path: &str) -> Option<ListResult> {
            if path == "/" {
                Some(ListResult::Names(Vec::new()))
            } else {
                None
            }
        }
        fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
            if path == "/" {
                Some(create_root_file_info())
            } else {
                None
            }
        }
        fn open(&self, _: &FileInfo, _: i32) -> io::Result<Box<dyn ArchiveRead>> {
            Ok(Box::new(Cursor::new(Vec::<u8>::new())))
        }
        fn is_immutable(&self) -> bool {
            true
        }
    }

    fn join_stop(handle: ExportServerHandle, stop: ExportStop) {
        stop.request_stop();
        let (tx, rx) = mpsc::channel();
        thread::spawn(move || {
            let _ = tx.send(handle.join());
        });
        rx.recv_timeout(Duration::from_secs(2))
            .expect("9P serve stop timed out")
            .expect("join");
    }

    #[test]
    fn parse_ninep_bind_defaults_to_20493() {
        let a = parse_ninep_bind("").unwrap();
        assert_eq!(a.port(), 20493);
        assert_eq!(a, DEFAULT_NINEP_BIND);
        assert_ne!(a.port(), 20490);
    }

    #[test]
    fn attach_walk_read_tar_fixture() {
        let (handle, addr, stop) = spawn_src(tar_source());
        let mut c = NinepClient::connect(addr);
        c.attach(0);
        let qids = c.walk(0, 1, &["hello.txt"]).expect("walk");
        assert_eq!(qids.len(), 1);
        c.lopen(1, libc::O_RDONLY as u32).expect("lopen");
        let size = c.getattr_size(1);
        let body = c.read(1, 0, 64).expect("read");
        assert_eq!(body, b"hello 9p\n");
        assert_eq!(size, body.len() as u64);

        c.walk(0, 2, &[]).expect("clone root");
        c.lopen(2, libc::O_RDONLY as u32).expect("lopen dir");
        let raw = c.readdir(2, 0, 8192).expect("readdir");
        let ents = decode_dirents(&raw).unwrap();
        let names: Vec<_> = ents.iter().map(|e| e.3.as_str()).collect();
        assert!(names.contains(&"hello.txt"), "{names:?}");
        join_stop(handle, stop);
    }

    /// Regression: 9P Tread of a short `Read::read` is not truncated (gzip windows).
    #[test]
    fn fill_read_ninep_tread_not_truncated() {
        let payload = b"hello!".to_vec();
        let src: Arc<dyn MountSource> = Arc::new(ShortFs {
            data: payload.clone(),
        });
        let (handle, addr, stop) = spawn_src(src);
        let mut c = NinepClient::connect(addr);
        c.attach(0);
        c.walk(0, 1, &["blob"]).expect("walk");
        c.lopen(1, 0).expect("lopen");
        let body = c.read(1, 0, 6).expect("tread");
        assert_eq!(body, b"hello!");
        join_stop(handle, stop);
    }

    /// Lowest-layer fill_read loop (same contract as the 9P Tread path).
    #[test]
    fn fill_read_loops_until_full() {
        let mut r = ShortRead(Cursor::new(b"abcdef".to_vec()));
        let mut buf = [0u8; 6];
        let n = fill_read(&mut r, &mut buf).unwrap();
        assert_eq!(n, 6);
        assert_eq!(&buf, b"abcdef");
    }

    /// Regression: writes without `-w` / overlay are EROFS.
    #[test]
    fn writers_erofs_without_overlay() {
        let (handle, addr, stop) = spawn_src(Arc::new(EmptyFs));
        let mut c = NinepClient::connect(addr);
        c.attach(0);
        assert_eq!(c.mkdir_err(0, "d"), libc::EROFS as u32);
        assert_eq!(c.lcreate_err(0, "x"), libc::EROFS as u32);
        assert_eq!(c.write_err(0), libc::EROFS as u32);
        assert_eq!(c.unlinkat_err(0, "x"), libc::EROFS as u32);
        assert_eq!(c.renameat_err(0, "a", "b"), libc::EROFS as u32);
        assert_eq!(c.symlink_err(0, "l", "t"), libc::EROFS as u32);
        join_stop(handle, stop);
    }

    #[test]
    fn serve_stop_exits() {
        let stop = ExportStop::new();
        let opts = NinepOptions {
            bind: "127.0.0.1:0".parse().unwrap(),
            stop: Some(stop.clone()),
            ..NinepOptions::default()
        };
        let handle = spawn_ninep_thread(Arc::new(EmptyFs), opts).expect("spawn");
        thread::sleep(Duration::from_millis(50));
        join_stop(handle, stop);
    }
}
