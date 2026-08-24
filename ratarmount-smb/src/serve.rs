//! Bind / serve / stop. Blocking `TcpListener` (no tokio in this crate).

use std::collections::HashMap;
use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use ratarmount_compositing::WriteOverlay;
use ratarmount_core::{is_dir_mode, MountSource};
use ratarmount_export_core::{
    default_export_bind, parse_export_bind, BindError, ExportServerHandle, ExportStop,
    DEFAULT_READER_SLOTS, DEFAULT_SMB_PORT, STOP_POLL_INTERVAL,
};

use crate::smb2::{self, CreateReq, FileMeta, Smb2Header};
use crate::vfs::RatarmountSmb;

/// `127.0.0.1:20445` — empty-string result of [`parse_smb_bind`].
pub const DEFAULT_SMB_BIND: SocketAddr = SocketAddr::V4(std::net::SocketAddrV4::new(
    std::net::Ipv4Addr::LOCALHOST,
    DEFAULT_SMB_PORT,
));

/// Default TREE_CONNECT share (`--smb-share`).
pub const DEFAULT_SMB_SHARE: &str = "ratarmount";

/// Listen / export options for [`serve_blocking`] / [`spawn_smb_thread`].
#[derive(Clone)]
pub struct SmbOptions {
    pub bind: SocketAddr,
    pub stop: Option<ExportStop>,
    /// When set, CREATE/WRITE/SET_INFO/DELETE go to this overlay.
    pub overlay: Option<Arc<WriteOverlay>>,
    pub readahead_bytes: usize,
    pub reader_slots: usize,
    pub share_name: String,
    /// Required SESSION_SETUP user (`RATARMOUNT_SMB_USER`). `None` = any user.
    pub username: Option<String>,
    /// When set (`RATARMOUNT_SMB_PASSWORD`), NTLMv2 proof is required and SMB 2.0.2
    /// signing is required. When unset, guest (username match only; unsigned OK).
    pub password: Option<String>,
}

impl Default for SmbOptions {
    fn default() -> Self {
        Self {
            bind: default_export_bind(DEFAULT_SMB_PORT),
            stop: None,
            overlay: None,
            readahead_bytes: 0,
            reader_slots: DEFAULT_READER_SLOTS,
            share_name: DEFAULT_SMB_SHARE.into(),
            username: None,
            password: None,
        }
    }
}

impl std::fmt::Debug for SmbOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmbOptions")
            .field("bind", &self.bind)
            .field("stop", &self.stop.as_ref().map(|_| "ExportStop"))
            .field("overlay", &self.overlay.is_some())
            .field("readahead_bytes", &self.readahead_bytes)
            .field("reader_slots", &self.reader_slots)
            .field("share_name", &self.share_name)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "***"))
            .finish()
    }
}

/// `RATARMOUNT_SMB_USER` / `RATARMOUNT_SMB_PASSWORD` (password never logged).
pub fn smb_credentials_from_env() -> (Option<String>, Option<String>) {
    let user = std::env::var("RATARMOUNT_SMB_USER")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let pass = std::env::var("RATARMOUNT_SMB_PASSWORD")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    (user, pass)
}

/// Parse `[host:]port` into an IPv4 listen address (default port 20445).
pub fn parse_smb_bind(s: &str) -> Result<SocketAddr, BindError> {
    parse_export_bind(s, DEFAULT_SMB_PORT)
}

fn access_label(opts: &SmbOptions) -> &'static str {
    if opts.overlay.is_some() {
        "rw overlay"
    } else {
        "ro"
    }
}

fn password_configured(opts: &SmbOptions) -> bool {
    opts.password.as_deref().is_some_and(|s| !s.is_empty())
}

fn warn_non_loopback(addr: SocketAddr, opts: &SmbOptions) {
    if !addr.ip().is_loopback() {
        if password_configured(opts) {
            log::warn!(
                "SMB bind {addr} is not loopback; SMB encryption / 3.1.1 are residual (localhost is the security boundary)"
            );
        } else {
            log::warn!(
                "SMB bind {addr} is not loopback; guest SMB is unsigned (localhost is the security boundary)"
            );
        }
    }
}

fn fs_from_opts(source: Arc<dyn MountSource>, opts: &SmbOptions) -> Arc<RatarmountSmb> {
    Arc::new(RatarmountSmb::with_overlay(
        source,
        opts.readahead_bytes,
        opts.reader_slots,
        opts.overlay.clone(),
    ))
}

fn bind_smb(opts: &SmbOptions) -> io::Result<TcpListener> {
    if opts.bind.is_ipv6() {
        return Err(io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            BindError::Ipv6Unsupported.to_string(),
        ));
    }
    warn_non_loopback(opts.bind, opts);
    TcpListener::bind(opts.bind)
}

fn log_listen(addr: SocketAddr, opts: &SmbOptions) {
    let access = access_label(opts);
    let ip = addr.ip();
    let port = addr.port();
    let share = &opts.share_name;
    let guest = if password_configured(opts) { "" } else { " -N" };
    log::info!(
        "SMB2 listening on {ip}:{port} ({access}). smbclient: smbclient //{ip}/{share} -p {port}{guest}"
    );
}

/// SMB-only: this thread owns the listener (bind then serve).
pub fn serve_blocking(source: Arc<dyn MountSource>, opts: SmbOptions) -> io::Result<()> {
    let listener = bind_smb(&opts)?;
    listener.set_nonblocking(true)?;
    let addr = listener.local_addr()?;
    log_listen(addr, &opts);
    serve_listener(listener, source, opts)
}

fn serve_listener(
    listener: TcpListener,
    source: Arc<dyn MountSource>,
    opts: SmbOptions,
) -> io::Result<()> {
    let fs = fs_from_opts(source, &opts);
    let stop = opts.stop.clone();
    let cfg = Arc::new(opts);
    loop {
        if stop.as_ref().is_some_and(|s| s.is_stopped()) {
            return Ok(());
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let fs = Arc::clone(&fs);
                let stop = stop.clone();
                let cfg = Arc::clone(&cfg);
                let _ = thread::Builder::new()
                    .name("ratarmount-smb-conn".into())
                    .spawn(move || handle_conn(stream, fs, cfg, stop));
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::Interrupted => {
                thread::sleep(STOP_POLL_INTERVAL);
            }
            Err(e) => return Err(e),
        }
    }
}

/// Dedicated thread owns bind + accept. Returns after bind.
pub fn spawn_smb_thread(
    source: Arc<dyn MountSource>,
    opts: SmbOptions,
) -> io::Result<ExportServerHandle> {
    let (tx, rx) = std::sync::mpsc::channel();
    let join =
        thread::Builder::new()
            .name("ratarmount-smb".into())
            .spawn(move || match bind_smb(&opts) {
                Ok(listener) => {
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
                    log_listen(addr, &opts);
                    let _ = tx.send(Ok(addr.port()));
                    serve_listener(listener, source, opts)
                }
                Err(e) => {
                    let _ = tx.send(Err(io::Error::new(e.kind(), e.to_string())));
                    Err(e)
                }
            })?;
    let port = rx.recv().map_err(|_| {
        io::Error::new(io::ErrorKind::BrokenPipe, "SMB thread exited before bind")
    })??;
    Ok(ExportServerHandle::from_join(port, join))
}

struct OpenFile {
    inode: u64,
    delete_on_close: bool,
    is_dir: bool,
    dir_snapshot: Option<Vec<smb2::DirEntry>>,
    dir_pos: usize,
}

struct Tree {
    is_ipc: bool,
}

struct Session {
    fs: Arc<RatarmountSmb>,
    cfg: Arc<SmbOptions>,
    session_id: u64,
    authed: bool,
    ntlm_started: bool,
    ntlm_challenge: Option<[u8; 8]>,
    session_key: Option<[u8; 16]>,
    trees: HashMap<u32, Tree>,
    next_tree: u32,
    opens: HashMap<u64, OpenFile>,
    next_fid: AtomicU64,
    last_compound_fid: Option<[u8; 16]>,
}

fn handle_conn(
    mut stream: TcpStream,
    fs: Arc<RatarmountSmb>,
    cfg: Arc<SmbOptions>,
    stop: Option<ExportStop>,
) {
    let _ = stream.set_nodelay(true);
    let _ = stream.set_read_timeout(Some(STOP_POLL_INTERVAL));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(30)));
    let mut session = Session {
        fs,
        cfg,
        session_id: 0,
        authed: false,
        ntlm_started: false,
        ntlm_challenge: None,
        session_key: None,
        trees: HashMap::new(),
        next_tree: 1,
        opens: HashMap::new(),
        next_fid: AtomicU64::new(1),
        last_compound_fid: None,
    };
    loop {
        if stop.as_ref().is_some_and(|s| s.is_stopped()) {
            return;
        }
        let frame = match read_frame(&mut stream) {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::WouldBlock => {
                continue;
            }
            Err(_) => return,
        };
        let reply = match session.dispatch_frame(&frame) {
            Ok(m) => m,
            Err(e) => {
                log::debug!("SMB frame: {e}");
                return;
            }
        };
        if stream.write_all(&smb2::encode_nbss(&reply)).is_err() {
            return;
        }
    }
}

fn read_frame(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr)?;
    let n = smb2::decode_nbss_len(hdr)?;
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

impl Session {
    fn dispatch_frame(&mut self, frame: &[u8]) -> io::Result<Vec<u8>> {
        if smb2::is_smb1(frame) {
            return self.dispatch_smb1(frame);
        }
        let parts = smb2::split_compound(frame)?;
        self.last_compound_fid = None;
        let mut replies = Vec::with_capacity(parts.len());
        let mut sign_key = self.session_key;
        for part in parts {
            let hdr = smb2::parse_smb2_header(part)?;
            let skip_verify = hdr.command == smb2::SMB2_SESSION_SETUP && !self.authed;
            if self.signing_required() && !skip_verify {
                let ok = sign_key
                    .as_ref()
                    .is_some_and(|k| smb2::smb2_verify_packet(part, k));
                if !ok {
                    let credits = hdr.credits.clamp(1, 64);
                    let mut rh = smb2::reply_header(&hdr, 0, credits);
                    rh.status = smb2::STATUS_ACCESS_DENIED;
                    if rh.session_id == 0 {
                        rh.session_id = self.session_id;
                    }
                    replies.push(smb2::encode_packet(&rh, &smb2::error_body()));
                    continue;
                }
            }
            let (status, mut rh, body) = self.dispatch_one(&hdr, part);
            rh.status = status;
            if rh.session_id == 0 {
                rh.session_id = self.session_id;
            }
            replies.push(smb2::encode_packet(&rh, &body));
            if self.session_key.is_some() {
                sign_key = self.session_key;
            }
        }
        let mut out = smb2::stitch_compound(&replies);
        if let Some(key) = sign_key {
            smb2::smb2_sign_compound(&mut out, &key);
        }
        Ok(out)
    }

    fn signing_required(&self) -> bool {
        password_configured(&self.cfg) && self.authed
    }

    fn negotiate_security_mode(&self) -> u16 {
        if password_configured(&self.cfg) {
            smb2::NEGOTIATE_SIGNING_ENABLED | smb2::NEGOTIATE_SIGNING_REQUIRED
        } else {
            smb2::NEGOTIATE_SIGNING_ENABLED
        }
    }

    fn dispatch_smb1(&mut self, frame: &[u8]) -> io::Result<Vec<u8>> {
        if !smb2::smb1_has_smb2_dialect(frame) {
            return Err(io::Error::new(
                ErrorKind::InvalidData,
                "SMB1 without SMB2 dialect",
            ));
        }
        let fake = Smb2Header {
            credit_charge: 1,
            status: 0,
            command: smb2::SMB2_NEGOTIATE,
            credits: 1,
            flags: 0,
            next_command: 0,
            message_id: 0,
            process_id: 0xfeff,
            tree_id: 0,
            session_id: 0,
        };
        let sec = smb2::spnego_neg_token_init();
        let body = smb2::encode_negotiate_response(
            smb2::DIALECT_202,
            &sec,
            self.negotiate_security_mode(),
        );
        let mut rh = smb2::reply_header(&fake, smb2::STATUS_SUCCESS, 1);
        rh.credits = 1;
        Ok(smb2::encode_packet(&rh, &body))
    }

    fn dispatch_one(&mut self, hdr: &Smb2Header, cmd: &[u8]) -> (u32, Smb2Header, Vec<u8>) {
        let credits = hdr.credits.clamp(1, 64);
        let mut rh = smb2::reply_header(hdr, 0, credits);
        match hdr.command {
            smb2::SMB2_NEGOTIATE => self.cmd_negotiate(hdr, cmd, &mut rh),
            smb2::SMB2_SESSION_SETUP => self.cmd_session_setup(hdr, cmd, &mut rh),
            smb2::SMB2_LOGOFF => {
                self.authed = false;
                self.session_key = None;
                self.ntlm_started = false;
                self.ntlm_challenge = None;
                self.trees.clear();
                self.opens.clear();
                (smb2::STATUS_SUCCESS, rh, smb2::encode_empty_sized(4, 4))
            }
            smb2::SMB2_TREE_CONNECT => self.cmd_tree_connect(hdr, cmd, &mut rh),
            smb2::SMB2_TREE_DISCONNECT => {
                self.trees.remove(&hdr.tree_id);
                (smb2::STATUS_SUCCESS, rh, smb2::encode_empty_sized(4, 4))
            }
            smb2::SMB2_CREATE => self.cmd_create(hdr, cmd, rh),
            smb2::SMB2_CLOSE => self.cmd_close(hdr, cmd, rh),
            smb2::SMB2_FLUSH => {
                if let Err(s) = self.require_tree(hdr.tree_id) {
                    return err(rh, s);
                }
                (smb2::STATUS_SUCCESS, rh, smb2::encode_empty_sized(4, 4))
            }
            smb2::SMB2_READ => self.cmd_read(hdr, cmd, rh),
            smb2::SMB2_WRITE => self.cmd_write(hdr, cmd, rh),
            smb2::SMB2_LOCK => (smb2::STATUS_SUCCESS, rh, smb2::encode_empty_sized(4, 4)),
            smb2::SMB2_IOCTL => err(rh, smb2::STATUS_NOT_SUPPORTED),
            smb2::SMB2_CANCEL => (smb2::STATUS_SUCCESS, rh, smb2::error_body()),
            smb2::SMB2_ECHO => (smb2::STATUS_SUCCESS, rh, smb2::encode_empty_sized(4, 4)),
            smb2::SMB2_QUERY_DIRECTORY => self.cmd_query_directory(hdr, cmd, rh),
            smb2::SMB2_CHANGE_NOTIFY => err(rh, smb2::STATUS_NOT_SUPPORTED),
            smb2::SMB2_QUERY_INFO => self.cmd_query_info(hdr, cmd, rh),
            smb2::SMB2_SET_INFO => self.cmd_set_info(hdr, cmd, rh),
            _ => err(rh, smb2::STATUS_NOT_IMPLEMENTED),
        }
    }

    fn cmd_negotiate(
        &mut self,
        _hdr: &Smb2Header,
        cmd: &[u8],
        rh: &mut Smb2Header,
    ) -> (u32, Smb2Header, Vec<u8>) {
        let dialects = match smb2::parse_negotiate_dialects(cmd) {
            Ok(d) => d,
            Err(_) => return err(rh.clone(), smb2::STATUS_INVALID_PARAMETER),
        };
        let Some(d) = smb2::pick_dialect(&dialects) else {
            return err(rh.clone(), smb2::STATUS_NOT_SUPPORTED);
        };
        let sec = smb2::spnego_neg_token_init();
        rh.credits = 1;
        (
            smb2::STATUS_SUCCESS,
            rh.clone(),
            smb2::encode_negotiate_response(d, &sec, self.negotiate_security_mode()),
        )
    }

    fn cmd_session_setup(
        &mut self,
        _hdr: &Smb2Header,
        cmd: &[u8],
        rh: &mut Smb2Header,
    ) -> (u32, Smb2Header, Vec<u8>) {
        if self.session_id == 0 {
            self.session_id = 1;
        }
        rh.session_id = self.session_id;
        let sec = match smb2::parse_session_setup_sec(cmd) {
            Ok(s) => s,
            Err(_) => return err(rh.clone(), smb2::STATUS_INVALID_PARAMETER),
        };
        let typ = smb2::ntlm_type(&sec).unwrap_or(0);
        let wrap = smb2::looks_like_spnego(&sec);
        if typ == 1 || (typ != 3 && !self.ntlm_started) {
            self.ntlm_started = true;
            let challenge = smb2::challenge8();
            self.ntlm_challenge = Some(challenge);
            let t2 = smb2::ntlm_type2(challenge, "RATARMOUNT");
            let buf = if wrap {
                smb2::spnego_challenge(&t2)
            } else {
                t2
            };
            return (
                smb2::STATUS_MORE_PROCESSING_REQUIRED,
                rh.clone(),
                smb2::encode_session_setup_response(0, &buf),
            );
        }
        if typ == 3 {
            let Some(t3) = smb2::parse_ntlm_type3(&sec) else {
                return err(rh.clone(), smb2::STATUS_LOGON_FAILURE);
            };
            let flags =
                if let Some(password) = self.cfg.password.as_deref().filter(|s| !s.is_empty()) {
                    let Some(challenge) = self.ntlm_challenge else {
                        return err(rh.clone(), smb2::STATUS_LOGON_FAILURE);
                    };
                    match smb2::ntlm_verify_type3(
                        &t3,
                        password,
                        self.cfg.username.as_deref(),
                        challenge,
                    ) {
                        Ok(key) => self.session_key = Some(key),
                        Err(st) => return err(rh.clone(), st),
                    }
                    0
                } else {
                    if !auth_ok(self.cfg.username.as_deref(), &t3.user) {
                        return err(rh.clone(), smb2::STATUS_LOGON_FAILURE);
                    }
                    if self.cfg.username.is_none() {
                        smb2::SESSION_FLAG_IS_GUEST
                    } else {
                        0
                    }
                };
            self.authed = true;
            let buf = if wrap {
                smb2::spnego_accept()
            } else {
                Vec::new()
            };
            return (
                smb2::STATUS_SUCCESS,
                rh.clone(),
                smb2::encode_session_setup_response(flags, &buf),
            );
        }
        err(rh.clone(), smb2::STATUS_LOGON_FAILURE)
    }

    fn cmd_tree_connect(
        &mut self,
        _hdr: &Smb2Header,
        cmd: &[u8],
        rh: &mut Smb2Header,
    ) -> (u32, Smb2Header, Vec<u8>) {
        if !self.authed {
            return err(rh.clone(), smb2::STATUS_USER_SESSION_DELETED);
        }
        let path = match smb2::parse_tree_connect_path(cmd) {
            Ok(p) => p,
            Err(_) => return err(rh.clone(), smb2::STATUS_INVALID_PARAMETER),
        };
        let Some(share) = smb2::share_name_from_unc(&path) else {
            return err(rh.clone(), smb2::STATUS_BAD_NETWORK_NAME);
        };
        let ipc = share.eq_ignore_ascii_case("IPC$");
        if !ipc && !share.eq_ignore_ascii_case(&self.cfg.share_name) {
            return err(rh.clone(), smb2::STATUS_BAD_NETWORK_NAME);
        }
        let tid = self.next_tree;
        self.next_tree = self.next_tree.saturating_add(1);
        self.trees.insert(tid, Tree { is_ipc: ipc });
        rh.tree_id = tid;
        let stype = if ipc {
            smb2::SHARE_TYPE_PIPE
        } else {
            smb2::SHARE_TYPE_DISK
        };
        let access = if self.fs.writable() {
            0x001F_01FF
        } else {
            0x0012_0089
        };
        (
            smb2::STATUS_SUCCESS,
            rh.clone(),
            smb2::encode_tree_connect_response(stype, access),
        )
    }

    fn cmd_create(
        &mut self,
        hdr: &Smb2Header,
        cmd: &[u8],
        rh: Smb2Header,
    ) -> (u32, Smb2Header, Vec<u8>) {
        let is_ipc = match self.tree_is_ipc(hdr.tree_id) {
            Ok(v) => v,
            Err(s) => return err(rh, s),
        };
        if is_ipc {
            return err(rh, smb2::STATUS_ACCESS_DENIED);
        }
        let req = match smb2::parse_create(cmd) {
            Ok(r) => r,
            Err(_) => return err(rh, smb2::STATUS_INVALID_PARAMETER),
        };
        match self.do_create(&req) {
            Ok((fid, action, meta)) => {
                let file_id = smb2::file_id_from_u64(fid);
                self.last_compound_fid = Some(file_id);
                let times = smb2::unix_float_to_filetime(meta.mtime);
                let attrs = attrs_of(&meta);
                let body = smb2::encode_create_response(action, times, meta.size, attrs, file_id);
                (smb2::STATUS_SUCCESS, rh, body)
            }
            Err(s) => err(rh, s),
        }
    }

    fn do_create(&mut self, req: &CreateReq) -> Result<(u64, u32, FileMeta), u32> {
        let unix = smb2::smb_path_to_unix(&req.name);
        let dir_opt = req.create_options & smb2::FILE_DIRECTORY_FILE != 0;
        let file_opt = req.create_options & smb2::FILE_NON_DIRECTORY_FILE != 0;
        let disp = req.create_disposition;
        let write_disp = matches!(
            disp,
            smb2::FILE_CREATE
                | smb2::FILE_OPEN_IF
                | smb2::FILE_OVERWRITE
                | smb2::FILE_OVERWRITE_IF
                | smb2::FILE_SUPERSEDE
        );
        let existing = self.fs.lookup_path(&unix).ok();

        if let Some((id, fi)) = existing {
            if dir_opt && !is_dir_mode(fi.mode) {
                return Err(smb2::STATUS_NOT_A_DIRECTORY);
            }
            if file_opt && is_dir_mode(fi.mode) {
                return Err(smb2::STATUS_FILE_IS_A_DIRECTORY);
            }
            match disp {
                smb2::FILE_CREATE => return Err(smb2::STATUS_OBJECT_NAME_COLLISION),
                smb2::FILE_OPEN | smb2::FILE_OPEN_IF => {
                    if smb2::wants_write(req.desired_access) && !self.fs.writable() {
                        return Err(smb2::STATUS_ACCESS_DENIED);
                    }
                    let meta = self.fs.meta_for(id)?;
                    let fid = self.alloc_fid(OpenFile {
                        inode: id,
                        delete_on_close: req.create_options & smb2::FILE_DELETE_ON_CLOSE != 0,
                        is_dir: is_dir_mode(fi.mode),
                        dir_snapshot: None,
                        dir_pos: 0,
                    });
                    return Ok((fid, smb2::FILE_OPENED, meta));
                }
                smb2::FILE_OVERWRITE | smb2::FILE_OVERWRITE_IF | smb2::FILE_SUPERSEDE => {
                    self.fs.truncate(id, 0)?;
                    let meta = self.fs.meta_for(id)?;
                    let fid = self.alloc_fid(OpenFile {
                        inode: id,
                        delete_on_close: req.create_options & smb2::FILE_DELETE_ON_CLOSE != 0,
                        is_dir: false,
                        dir_snapshot: None,
                        dir_pos: 0,
                    });
                    return Ok((fid, smb2::FILE_OVERWRITTEN, meta));
                }
                _ => return Err(smb2::STATUS_INVALID_PARAMETER),
            }
        }

        // Missing
        if disp == smb2::FILE_OPEN {
            return Err(path_missing_status(&unix));
        }
        if !write_disp {
            return Err(path_missing_status(&unix));
        }
        if !self.fs.writable() {
            return Err(smb2::STATUS_ACCESS_DENIED);
        }
        let (id, fi) = if dir_opt {
            self.fs.mkdir(&unix, 0o755)?
        } else {
            self.fs.create_file(&unix, 0o644)?
        };
        let meta = FileMeta {
            inode: id,
            size: fi.size,
            mtime: fi.mtime,
            is_dir: is_dir_mode(fi.mode),
            is_lnk: false,
            name: unix,
            readonly: false,
        };
        let fid = self.alloc_fid(OpenFile {
            inode: id,
            delete_on_close: req.create_options & smb2::FILE_DELETE_ON_CLOSE != 0,
            is_dir: meta.is_dir,
            dir_snapshot: None,
            dir_pos: 0,
        });
        Ok((fid, smb2::FILE_CREATED, meta))
    }

    fn cmd_close(
        &mut self,
        hdr: &Smb2Header,
        cmd: &[u8],
        rh: Smb2Header,
    ) -> (u32, Smb2Header, Vec<u8>) {
        if let Err(s) = self.require_tree(hdr.tree_id) {
            return err(rh, s);
        }
        let fid_raw = match smb2::parse_close_file_id(cmd) {
            Ok(id) => self.resolve_fid(hdr, id),
            Err(_) => return err(rh, smb2::STATUS_INVALID_PARAMETER),
        };
        let key = smb2::file_id_to_u64(&fid_raw);
        match self.opens.remove(&key) {
            Some(open) => {
                if open.delete_on_close {
                    let _ = self.fs.unlink(open.inode);
                }
                (smb2::STATUS_SUCCESS, rh, smb2::encode_close_response())
            }
            None => err(rh, smb2::STATUS_FILE_CLOSED),
        }
    }

    fn cmd_read(
        &mut self,
        hdr: &Smb2Header,
        cmd: &[u8],
        rh: Smb2Header,
    ) -> (u32, Smb2Header, Vec<u8>) {
        if let Err(s) = self.require_tree(hdr.tree_id) {
            return err(rh, s);
        }
        let req = match smb2::parse_read(cmd) {
            Ok(r) => r,
            Err(_) => return err(rh, smb2::STATUS_INVALID_PARAMETER),
        };
        let fid = self.resolve_fid(hdr, req.file_id);
        let (is_dir, inode) = match self.opens.get(&smb2::file_id_to_u64(&fid)) {
            Some(open) => (open.is_dir, open.inode),
            None => return err(rh, smb2::STATUS_FILE_CLOSED),
        };
        if is_dir {
            return err(rh, smb2::STATUS_FILE_IS_A_DIRECTORY);
        }
        match self.fs.read(inode, req.offset, req.length) {
            Ok(data) => (smb2::STATUS_SUCCESS, rh, smb2::encode_read_response(&data)),
            Err(s) => err(rh, s),
        }
    }

    fn cmd_write(
        &mut self,
        hdr: &Smb2Header,
        cmd: &[u8],
        rh: Smb2Header,
    ) -> (u32, Smb2Header, Vec<u8>) {
        if let Err(s) = self.require_tree(hdr.tree_id) {
            return err(rh, s);
        }
        if !self.fs.writable() {
            return err(rh, smb2::STATUS_ACCESS_DENIED);
        }
        let req = match smb2::parse_write(cmd) {
            Ok(r) => r,
            Err(_) => return err(rh, smb2::STATUS_INVALID_PARAMETER),
        };
        let fid = self.resolve_fid(hdr, req.file_id);
        let inode = match self.opens.get(&smb2::file_id_to_u64(&fid)) {
            Some(open) => open.inode,
            None => return err(rh, smb2::STATUS_FILE_CLOSED),
        };
        match self.fs.write(inode, req.offset, &req.data) {
            Ok(n) => (smb2::STATUS_SUCCESS, rh, smb2::encode_write_response(n)),
            Err(s) => err(rh, s),
        }
    }

    fn cmd_query_directory(
        &mut self,
        hdr: &Smb2Header,
        cmd: &[u8],
        rh: Smb2Header,
    ) -> (u32, Smb2Header, Vec<u8>) {
        if let Err(s) = self.require_tree(hdr.tree_id) {
            return err(rh, s);
        }
        let req = match smb2::parse_query_directory(cmd) {
            Ok(r) => r,
            Err(_) => return err(rh, smb2::STATUS_INVALID_PARAMETER),
        };
        let fid = self.resolve_fid(hdr, req.file_id);
        let key = smb2::file_id_to_u64(&fid);
        let restart = req.flags & (smb2::SMB2_RESTART_SCANS | smb2::SMB2_REOPEN) != 0;
        let (is_dir, inode, need_list) = match self.opens.get(&key) {
            Some(o) => (o.is_dir, o.inode, restart || o.dir_snapshot.is_none()),
            None => return err(rh, smb2::STATUS_FILE_CLOSED),
        };
        if !is_dir {
            return err(rh, smb2::STATUS_NOT_A_DIRECTORY);
        }
        if need_list {
            match self.fs.list_dir(inode, &req.pattern) {
                Ok(ents) => {
                    if let Some(open) = self.opens.get_mut(&key) {
                        open.dir_snapshot = Some(ents);
                        open.dir_pos = 0;
                    }
                }
                Err(s) => return err(rh, s),
            }
        }
        let open = match self.opens.get_mut(&key) {
            Some(o) => o,
            None => return err(rh, smb2::STATUS_FILE_CLOSED),
        };
        let snap = open.dir_snapshot.clone().unwrap_or_default();
        if snap.is_empty() && open.dir_pos == 0 {
            return err(rh, smb2::STATUS_NO_SUCH_FILE);
        }
        if open.dir_pos >= snap.len() {
            return err(rh, smb2::STATUS_NO_MORE_FILES);
        }
        let max = req.output_len.min(smb2::MAX_TRANSACT) as usize;
        let remaining = &snap[open.dir_pos..];
        let buf = smb2::encode_dir_entries(req.info_class, remaining, max);
        if buf.is_empty() {
            return err(rh, smb2::STATUS_NO_MORE_FILES);
        }
        let n = count_dirents(&buf);
        open.dir_pos = open.dir_pos.saturating_add(n.max(1));
        (
            smb2::STATUS_SUCCESS,
            rh,
            smb2::encode_query_directory_response(&buf),
        )
    }

    fn cmd_query_info(
        &mut self,
        hdr: &Smb2Header,
        cmd: &[u8],
        rh: Smb2Header,
    ) -> (u32, Smb2Header, Vec<u8>) {
        if let Err(s) = self.require_tree(hdr.tree_id) {
            return err(rh, s);
        }
        let req = match smb2::parse_query_info(cmd) {
            Ok(r) => r,
            Err(_) => return err(rh, smb2::STATUS_INVALID_PARAMETER),
        };
        let fid = self.resolve_fid(hdr, req.file_id);
        let inode = match self.opens.get(&smb2::file_id_to_u64(&fid)) {
            Some(open) => open.inode,
            None => return err(rh, smb2::STATUS_FILE_CLOSED),
        };
        let buf = match req.info_type {
            smb2::SMB2_0_INFO_FILESYSTEM => {
                match smb2::encode_fs_info(req.file_info_class, !self.fs.writable(), "ratarmount") {
                    Some(b) => b,
                    None => return err(rh, smb2::STATUS_INVALID_INFO_CLASS),
                }
            }
            smb2::SMB2_0_INFO_FILE => {
                let meta = match self.fs.meta_for(inode) {
                    Ok(m) => m,
                    Err(s) => return err(rh, s),
                };
                match smb2::encode_file_info(req.file_info_class, &meta) {
                    Some(b) => b,
                    None => return err(rh, smb2::STATUS_INVALID_INFO_CLASS),
                }
            }
            _ => return err(rh, smb2::STATUS_INVALID_INFO_CLASS),
        };
        if buf.len() as u32 > req.output_len && req.output_len > 0 {
            let n = req.output_len as usize;
            let slice = buf[..n.min(buf.len())].to_vec();
            return (
                smb2::STATUS_BUFFER_OVERFLOW,
                rh,
                smb2::encode_query_info_response(&slice),
            );
        }
        (
            smb2::STATUS_SUCCESS,
            rh,
            smb2::encode_query_info_response(&buf),
        )
    }

    fn cmd_set_info(
        &mut self,
        hdr: &Smb2Header,
        cmd: &[u8],
        rh: Smb2Header,
    ) -> (u32, Smb2Header, Vec<u8>) {
        if let Err(s) = self.require_tree(hdr.tree_id) {
            return err(rh, s);
        }
        if !self.fs.writable() {
            return err(rh, smb2::STATUS_ACCESS_DENIED);
        }
        let req = match smb2::parse_set_info(cmd) {
            Ok(r) => r,
            Err(_) => return err(rh, smb2::STATUS_INVALID_PARAMETER),
        };
        let fid = self.resolve_fid(hdr, req.file_id);
        let key = smb2::file_id_to_u64(&fid);
        let inode = match self.opens.get(&key) {
            Some(open) => open.inode,
            None => return err(rh, smb2::STATUS_FILE_CLOSED),
        };
        if req.info_type != smb2::SMB2_0_INFO_FILE {
            return err(rh, smb2::STATUS_INVALID_INFO_CLASS);
        }
        match req.file_info_class {
            smb2::FILE_END_OF_FILE_INFORMATION => {
                if req.buffer.len() < 8 {
                    return err(rh, smb2::STATUS_INFO_LENGTH_MISMATCH);
                }
                let size = u64::from_le_bytes(req.buffer[..8].try_into().unwrap_or([0; 8]));
                if let Err(s) = self.fs.truncate(inode, size) {
                    return err(rh, s);
                }
            }
            smb2::FILE_DISPOSITION_INFORMATION => {
                let del = req.buffer.first().copied().unwrap_or(0) != 0;
                if let Some(open) = self.opens.get_mut(&key) {
                    open.delete_on_close = del;
                }
            }
            smb2::FILE_RENAME_INFORMATION => {
                if req.buffer.len() < 20 {
                    return err(rh, smb2::STATUS_INFO_LENGTH_MISMATCH);
                }
                let name_len =
                    u32::from_le_bytes(req.buffer[16..20].try_into().unwrap_or([0; 4])) as usize;
                if 20 + name_len > req.buffer.len() {
                    return err(rh, smb2::STATUS_INFO_LENGTH_MISMATCH);
                }
                let new_name = smb2::decode_utf16le(&req.buffer[20..20 + name_len]);
                let unix = smb2::smb_path_to_unix(&new_name);
                if let Err(s) = self.fs.rename(inode, &unix) {
                    return err(rh, s);
                }
            }
            _ => return err(rh, smb2::STATUS_INVALID_INFO_CLASS),
        }
        (smb2::STATUS_SUCCESS, rh, smb2::encode_set_info_response())
    }

    fn require_tree(&self, tid: u32) -> Result<(), u32> {
        self.tree_is_ipc(tid).map(|_| ())
    }

    fn tree_is_ipc(&self, tid: u32) -> Result<bool, u32> {
        if !self.authed {
            return Err(smb2::STATUS_USER_SESSION_DELETED);
        }
        self.trees
            .get(&tid)
            .map(|t| t.is_ipc)
            .ok_or(smb2::STATUS_NETWORK_NAME_DELETED)
    }

    fn resolve_fid(&mut self, hdr: &Smb2Header, fid: [u8; 16]) -> [u8; 16] {
        if hdr.related() && fid == smb2::RELATED_FILE_ID {
            self.last_compound_fid.unwrap_or(fid)
        } else {
            self.last_compound_fid = Some(fid);
            fid
        }
    }

    fn alloc_fid(&mut self, open: OpenFile) -> u64 {
        let id = self.next_fid.fetch_add(1, Ordering::Relaxed);
        self.opens.insert(id, open);
        id
    }
}

fn err(rh: Smb2Header, status: u32) -> (u32, Smb2Header, Vec<u8>) {
    (status, rh, smb2::error_body())
}

fn auth_ok(required: Option<&str>, user: &str) -> bool {
    match required {
        None => true,
        Some(want) => user.eq_ignore_ascii_case(want),
    }
}

fn attrs_of(m: &FileMeta) -> u32 {
    let mut a = if m.is_dir {
        smb2::FILE_ATTRIBUTE_DIRECTORY
    } else {
        smb2::FILE_ATTRIBUTE_ARCHIVE
    };
    if m.is_lnk {
        a |= smb2::FILE_ATTRIBUTE_REPARSE_POINT;
    }
    if m.readonly {
        a |= smb2::FILE_ATTRIBUTE_READONLY;
    }
    a
}

fn path_missing_status(unix: &str) -> u32 {
    let parent = unix
        .rsplit_once('/')
        .map(|(p, _)| if p.is_empty() { "/" } else { p });
    match parent {
        Some("/") | None => smb2::STATUS_OBJECT_NAME_NOT_FOUND,
        Some(_) => smb2::STATUS_OBJECT_PATH_NOT_FOUND,
    }
}

fn count_dirents(buf: &[u8]) -> usize {
    let mut n = 0usize;
    let mut off = 0usize;
    while off + 4 <= buf.len() {
        n += 1;
        let next = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap_or([0; 4])) as usize;
        if next == 0 {
            break;
        }
        off = off.saturating_add(next);
        if off >= buf.len() {
            break;
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_smb_bind_defaults_to_20445() {
        let a = parse_smb_bind("").unwrap();
        assert_eq!(a.port(), 20445);
        assert_eq!(a, DEFAULT_SMB_BIND);
        assert_ne!(a.port(), 20490);
        assert_eq!(DEFAULT_SMB_SHARE, "ratarmount");
    }

    #[test]
    fn options_debug_redacts_password() {
        let opts = SmbOptions {
            password: Some("s3cret".into()),
            username: Some("alice".into()),
            ..SmbOptions::default()
        };
        let s = format!("{opts:?}");
        assert!(!s.contains("s3cret"), "{s}");
        assert!(s.contains("***"), "{s}");
        assert!(s.contains("alice"), "{s}");
    }

    #[test]
    fn auth_guest_accepts_any_user() {
        assert!(auth_ok(None, ""));
        assert!(auth_ok(None, "bob"));
        assert!(auth_ok(Some("Alice"), "alice"));
        assert!(!auth_ok(Some("Alice"), "bob"));
    }
}
