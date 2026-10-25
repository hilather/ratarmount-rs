//! russh SSH-2 server + russh-sftp v3 subsystem (`sftp-russh` feature).

use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use russh::keys::{Algorithm, PrivateKey, PublicKey};
use russh::server::{Auth, Msg, Server as _, Session};
use russh::{Channel, ChannelId};
use russh_sftp::protocol::{
    Attrs, Data, File, FileAttributes, Handle, Name, OpenFlags, Status, StatusCode, Version,
};
use russh_sftp::server::{Handler, StatusReply};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;

use ratarmount_core::{is_dir_mode, is_lnk_mode, FileInfo, MountSource};
use ratarmount_export_core::{ExportServerHandle, ExportStop, STOP_POLL_INTERVAL};

use crate::auth::{load_authorized_keys, sftp_password_from_env, AuthorizedKeysSource};
use crate::serve::{fs_from_opts, log_listen, resolved_host_key, SftpOptions};
use crate::vfs::{sftp_permissions, unix_mtime_u32, OpenMode, RatarmountSftp, SftpHandle};

pub fn serve_russh_blocking(
    source: Arc<dyn MountSource>,
    opts: SftpOptions,
    keys_src: AuthorizedKeysSource,
) -> io::Result<()> {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("ratarmount-sftp-worker")
        .build()?;
    rt.block_on(serve_russh(source, opts, keys_src, None))
}

pub fn spawn_russh_thread(
    source: Arc<dyn MountSource>,
    opts: SftpOptions,
    keys_src: AuthorizedKeysSource,
) -> io::Result<ExportServerHandle> {
    let (tx, rx) = std::sync::mpsc::channel();
    let join = std::thread::Builder::new()
        .name("ratarmount-sftp".into())
        .spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_name("ratarmount-sftp-worker")
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = tx.send(Err(io::Error::new(e.kind(), e.to_string())));
                    return Err(e);
                }
            };
            rt.block_on(serve_russh(source, opts, keys_src, Some(tx)))
        })?;
    let port = rx
        .recv()
        .map_err(|_| io::Error::new(ErrorKind::BrokenPipe, "SFTP thread exited before bind"))??;
    Ok(ExportServerHandle::from_join(port, join))
}

async fn serve_russh(
    source: Arc<dyn MountSource>,
    opts: SftpOptions,
    keys_src: AuthorizedKeysSource,
    port_tx: Option<std::sync::mpsc::Sender<io::Result<u16>>>,
) -> io::Result<()> {
    let host_key = load_or_ephemeral_host_key(resolved_host_key(&opts).as_deref())?;
    let allowed = parse_pubkeys(&load_authorized_keys(&keys_src)?)?;
    let password = Arc::new(sftp_password_from_env());
    let fs = fs_from_opts(source, &opts);
    let listener = tokio::net::TcpListener::bind(opts.bind).await?;
    let addr = listener.local_addr()?;
    log_listen(addr, &opts);
    if let Some(tx) = port_tx {
        let _ = tx.send(Ok(addr.port()));
    }

    let config = russh::server::Config {
        auth_rejection_time: Duration::from_millis(50),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: vec![host_key],
        ..Default::default()
    };

    let mut server = SftpServer {
        fs,
        allowed: Arc::new(allowed),
        password,
    };
    let stop = opts.stop.clone();
    let run = server.run_on_socket(Arc::new(config), &listener);
    match stop {
        None => run.await,
        Some(s) => {
            tokio::select! {
                r = run => r,
                _ = wait_stop(s) => Ok(()),
            }
        }
    }
}

async fn wait_stop(stop: ExportStop) {
    while !stop.is_stopped() {
        tokio::time::sleep(STOP_POLL_INTERVAL).await;
    }
}

fn parse_pubkeys(lines: &[String]) -> io::Result<Vec<PublicKey>> {
    let mut out = Vec::new();
    for line in lines {
        match PublicKey::from_openssh(line) {
            Ok(k) => out.push(k),
            Err(e) => log::debug!("SFTP skip authorized_keys line: {e}"),
        }
    }
    Ok(out)
}

fn load_or_ephemeral_host_key(path: Option<&Path>) -> io::Result<PrivateKey> {
    if let Some(p) = path {
        match PrivateKey::read_openssh_file(p) {
            Ok(k) => return Ok(k),
            Err(e) => {
                if !p.exists() {
                    let key = generate_ed25519()?;
                    if let Err(w) = write_host_key(p, &key) {
                        return Err(io::Error::other(format!(
                            "RATARMOUNT_SFTP_HOST_KEY {}: generate ok, write failed: {w}",
                            p.display()
                        )));
                    }
                    log::info!("SFTP wrote host key {}", p.display());
                    return Ok(key);
                }
                return Err(io::Error::other(format!(
                    "RATARMOUNT_SFTP_HOST_KEY {}: {e}",
                    p.display()
                )));
            }
        }
    }
    log::warn!(
        "SFTP host key: generating ephemeral ed25519 (set RATARMOUNT_SFTP_HOST_KEY to persist)"
    );
    generate_ed25519()
}

fn generate_ed25519() -> io::Result<PrivateKey> {
    let mut rng = rand::rng();
    PrivateKey::random(&mut rng, Algorithm::Ed25519).map_err(|e| io::Error::other(e.to_string()))
}

fn write_host_key(path: &Path, key: &PrivateKey) -> io::Result<()> {
    if let Some(dir) = path.parent() {
        if !dir.as_os_str().is_empty() {
            #[cfg_attr(
                internal_read_inventory,
                expect(
                    clippy::disallowed_methods,
                    reason = r###"internal-read:v1 {"id":"IR-E0100-M01","item":"ratarmount_sftp::handler::write_host_key","disposition":"output-owner","category":"sftp-host-key-directory","reason":"Create the configured SFTP host key parent before writing a generated host key.","creation":{"policy":"recursive-directory","basis":"This reviewed site creates only the parent tree with current defaults; host-key content writing is separately inventoried."}}"###
                )
            )]
            std::fs::create_dir_all(dir)?;
        }
    }
    let encoded = key
        .to_openssh(russh::keys::ssh_key::LineEnding::LF)
        .map_err(|e| io::Error::other(e.to_string()))?;
    {
        #[cfg_attr(
            internal_read_inventory,
            expect(
                clippy::disallowed_methods,
                reason = r###"internal-read:v1 {"id":"IR-B0543-M01","item":"ratarmount_sftp::handler::write_host_key","disposition":"output-owner","mode_policy":"unchanged-from-e6ca64e","category":"output-owner","reason":"Preserve this reviewed output acquisition and its existing permissions.","creation":{"policy":"unchanged-from-e6ca64e","basis":"Retain the individually reviewed baseline creation and permission policy at this site."}}"###
            )
        )]
        let __inventory_value_0 = std::fs::write(path, encoded.as_bytes());
        __inventory_value_0
    }
}

#[derive(Clone)]
struct SftpServer {
    fs: Arc<RatarmountSftp>,
    allowed: Arc<Vec<PublicKey>>,
    password: Arc<(Option<String>, Option<String>)>,
}

impl russh::server::Server for SftpServer {
    type Handler = SshSession;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        SshSession {
            fs: Arc::clone(&self.fs),
            allowed: Arc::clone(&self.allowed),
            password: Arc::clone(&self.password),
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

struct SshSession {
    fs: Arc<RatarmountSftp>,
    allowed: Arc<Vec<PublicKey>>,
    password: Arc<(Option<String>, Option<String>)>,
    clients: Arc<Mutex<HashMap<ChannelId, Channel<Msg>>>>,
}

impl russh::server::Handler for SshSession {
    type Error = russh::Error;

    async fn auth_none(&mut self, _user: &str) -> Result<Auth, Self::Error> {
        Ok(reject())
    }

    async fn auth_password(&mut self, user: &str, password: &str) -> Result<Auth, Self::Error> {
        if crate::auth::password_ok(user, password, self.password.as_ref()) {
            Ok(Auth::Accept)
        } else {
            Ok(reject())
        }
    }

    async fn auth_publickey(
        &mut self,
        _user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        if self.allowed.iter().any(|k| k == public_key) {
            Ok(Auth::Accept)
        } else {
            Ok(reject())
        }
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        opened: russh::ChannelOpenHandleInner<Msg>,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        opened.accept().await;
        self.clients.lock().await.insert(channel.id(), channel);
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        channel: ChannelId,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        session.close(channel)?;
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel_id: ChannelId,
        name: &str,
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        if name == "sftp" {
            let channel = {
                let mut g = self.clients.lock().await;
                g.remove(&channel_id)
            };
            let Some(channel) = channel else {
                session.channel_failure(channel_id)?;
                return Ok(());
            };
            session.channel_success(channel_id)?;
            let sftp = SftpSession::new(Arc::clone(&self.fs));
            russh_sftp::server::run(channel.into_stream(), sftp).await;
        } else {
            session.channel_failure(channel_id)?;
        }
        Ok(())
    }
}

fn reject() -> Auth {
    Auth::Reject {
        proceed_with_methods: None,
        partial_success: false,
    }
}

pub(crate) struct SftpSession {
    fs: Arc<RatarmountSftp>,
    handles: HashMap<String, SftpHandle>,
    next: u64,
}

impl SftpSession {
    pub(crate) fn new(fs: Arc<RatarmountSftp>) -> Self {
        Self {
            fs,
            handles: HashMap::new(),
            next: 1,
        }
    }

    fn alloc_handle(&mut self, h: SftpHandle) -> String {
        let name = format!("{}", self.next);
        self.next = self.next.saturating_add(1);
        self.handles.insert(name.clone(), h);
        name
    }

    fn ok(id: u32) -> Status {
        Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".into(),
            language_tag: "en-US".into(),
        }
    }
}

fn map_err(e: i32) -> StatusReply {
    if e == libc::EDQUOT || e == libc::ENOSPC {
        // SFTP v3 has no dedicated capacity statuses. Preserve the cause in
        // the SSH_FXP_STATUS message, including errors from OPEN/COW.
        return StatusCode::Failure.with_message(io::Error::from_raw_os_error(e).to_string());
    }
    let code = match e {
        libc::ENOENT | libc::ESTALE => StatusCode::NoSuchFile,
        libc::EACCES | libc::EPERM | libc::EROFS => StatusCode::PermissionDenied,
        libc::ENOSYS | libc::EOPNOTSUPP => StatusCode::OpUnsupported,
        libc::EINVAL => StatusCode::BadMessage,
        _ => StatusCode::Failure,
    };
    code.into()
}

fn attrs_from_fi(fi: &FileInfo, mapping: ratarmount_core::AttributeMapping) -> FileAttributes {
    let mut a = FileAttributes {
        size: Some(fi.size),
        uid: Some(mapping.uid(fi.uid)),
        gid: Some(mapping.gid(fi.gid)),
        permissions: Some(mapping.mode(sftp_permissions(fi))),
        atime: Some(unix_mtime_u32(ratarmount_compositing::overlay_atime(fi))),
        mtime: Some(unix_mtime_u32(fi.mtime)),
        ..FileAttributes::default()
    };
    if is_dir_mode(fi.mode) {
        a.set_dir(true);
    } else if is_lnk_mode(fi.mode) {
        a.set_symlink(true);
    } else {
        a.set_regular(true);
    }
    a
}

fn flags_to_mode(pflags: OpenFlags) -> OpenMode {
    OpenMode {
        read: pflags.contains(OpenFlags::READ) || !pflags.contains(OpenFlags::WRITE),
        write: pflags.contains(OpenFlags::WRITE) || pflags.contains(OpenFlags::APPEND),
        create: pflags.contains(OpenFlags::CREATE),
        truncate: pflags.contains(OpenFlags::TRUNCATE),
        exclusive: pflags.contains(OpenFlags::EXCLUDE),
        permissions: None,
    }
}

impl Handler for SftpSession {
    type Error = StatusReply;

    fn unimplemented(&self) -> Self::Error {
        StatusCode::OpUnsupported.into()
    }

    async fn init(
        &mut self,
        _version: u32,
        _extensions: HashMap<String, String>,
    ) -> Result<Version, Self::Error> {
        Ok(Version::new())
    }

    async fn realpath(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let p = self.fs.realpath(&path);
        Ok(Name {
            id,
            files: vec![File::dummy(p)],
        })
    }

    async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        let fi = self.fs.file_info_at(&path).map_err(map_err)?;
        Ok(Attrs {
            id,
            attrs: attrs_from_fi(&fi, self.fs.attribute_mapping()),
        })
    }

    async fn lstat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
        self.stat(id, path).await
    }

    async fn fstat(&mut self, id: u32, handle: String) -> Result<Attrs, Self::Error> {
        let h = self.handles.get(&handle).ok_or(StatusCode::Failure)?;
        let fi = match h {
            SftpHandle::File { id: fid, .. } => self.fs.file_info(*fid).map_err(map_err)?,
            SftpHandle::Dir { path, .. } => self.fs.file_info_at(path).map_err(map_err)?,
        };
        Ok(Attrs {
            id,
            attrs: attrs_from_fi(&fi, self.fs.attribute_mapping()),
        })
    }

    async fn opendir(&mut self, id: u32, path: String) -> Result<Handle, Self::Error> {
        let path = self.fs.realpath(&path);
        let fi = self.fs.file_info_at(&path).map_err(map_err)?;
        if !is_dir_mode(fi.mode) {
            return Err(StatusCode::NoSuchFile.into());
        }
        let handle = self.alloc_handle(SftpHandle::Dir {
            path,
            exhausted: false,
        });
        Ok(Handle { id, handle })
    }

    async fn readdir(&mut self, id: u32, handle: String) -> Result<Name, Self::Error> {
        let h = self.handles.get_mut(&handle).ok_or(StatusCode::Failure)?;
        let (path, exhausted) = match h {
            SftpHandle::Dir { path, exhausted } => (path.clone(), *exhausted),
            SftpHandle::File { .. } => return Err(StatusCode::Failure.into()),
        };
        if exhausted {
            return Err(StatusCode::Eof.into());
        }
        if let SftpHandle::Dir { exhausted, .. } = self.handles.get_mut(&handle).unwrap() {
            *exhausted = true;
        }
        let ents = self.fs.readdir(&path).map_err(map_err)?;
        let files = ents
            .into_iter()
            .map(|(name, fi)| File::new(name, attrs_from_fi(&fi, self.fs.attribute_mapping())))
            .collect();
        Ok(Name { id, files })
    }

    async fn open(
        &mut self,
        id: u32,
        filename: String,
        pflags: OpenFlags,
        attrs: FileAttributes,
    ) -> Result<Handle, Self::Error> {
        let mut mode = flags_to_mode(pflags);
        mode.permissions = attrs.permissions;
        let fid = self.fs.open_path(&filename, mode).map_err(map_err)?;
        let handle = self.alloc_handle(SftpHandle::File {
            id: fid,
            write: mode.write,
        });
        Ok(Handle { id, handle })
    }

    async fn read(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        len: u32,
    ) -> Result<Data, Self::Error> {
        let h = self.handles.get(&handle).ok_or(StatusCode::Failure)?;
        let fid = match h {
            SftpHandle::File { id, .. } => *id,
            SftpHandle::Dir { .. } => return Err(StatusCode::Failure.into()),
        };
        let data = self.fs.read(fid, offset, len).map_err(map_err)?;
        if data.is_empty() && len > 0 {
            return Err(StatusCode::Eof.into());
        }
        Ok(Data { id, data })
    }

    async fn write(
        &mut self,
        id: u32,
        handle: String,
        offset: u64,
        data: Vec<u8>,
    ) -> Result<Status, Self::Error> {
        let h = self.handles.get(&handle).ok_or(StatusCode::Failure)?;
        let fid = match h {
            SftpHandle::File { id, write } => {
                if !*write {
                    return Err(StatusCode::PermissionDenied.into());
                }
                *id
            }
            SftpHandle::Dir { .. } => return Err(StatusCode::Failure.into()),
        };
        self.fs.write(fid, offset, &data).map_err(map_err)?;
        Ok(Self::ok(id))
    }

    async fn close(&mut self, id: u32, handle: String) -> Result<Status, Self::Error> {
        self.handles.remove(&handle);
        Ok(Self::ok(id))
    }

    async fn mkdir(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let perm = attrs.permissions.unwrap_or(0o755);
        self.fs.mkdir(&path, perm).map_err(map_err)?;
        Ok(Self::ok(id))
    }

    async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
        self.fs.remove(&filename).map_err(map_err)?;
        Ok(Self::ok(id))
    }

    async fn rmdir(&mut self, id: u32, path: String) -> Result<Status, Self::Error> {
        self.fs.rmdir(&path).map_err(map_err)?;
        Ok(Self::ok(id))
    }

    async fn rename(
        &mut self,
        id: u32,
        oldpath: String,
        newpath: String,
    ) -> Result<Status, Self::Error> {
        self.fs.rename(&oldpath, &newpath).map_err(map_err)?;
        Ok(Self::ok(id))
    }

    async fn setstat(
        &mut self,
        id: u32,
        path: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let metadata = ratarmount_compositing::OverlayMetadata {
            mode: attrs.permissions,
            uid: attrs.uid,
            gid: attrs.gid,
            atime: attrs.atime.map(f64::from),
            mtime: attrs.mtime.map(f64::from),
        };
        self.fs
            .setstat(&path, attrs.size, &metadata)
            .map_err(map_err)?;
        Ok(Self::ok(id))
    }

    async fn fsetstat(
        &mut self,
        id: u32,
        handle: String,
        attrs: FileAttributes,
    ) -> Result<Status, Self::Error> {
        let path = match self.handles.get(&handle).ok_or(StatusCode::Failure)? {
            SftpHandle::File { id: fid, .. } => self.fs.path_for_id(*fid).map_err(map_err)?,
            SftpHandle::Dir { path, .. } => path.clone(),
        };
        self.setstat(id, path, attrs).await
    }

    async fn readlink(&mut self, id: u32, path: String) -> Result<Name, Self::Error> {
        let target = self.fs.readlink(&path).map_err(map_err)?;
        Ok(Name {
            id,
            files: vec![File::dummy(target)],
        })
    }

    async fn symlink(
        &mut self,
        id: u32,
        linkpath: String,
        targetpath: String,
    ) -> Result<Status, Self::Error> {
        self.fs.symlink(&linkpath, &targetpath).map_err(map_err)?;
        Ok(Self::ok(id))
    }
}

/// stdin + stdout as one `AsyncRead + AsyncWrite` for `russh_sftp::server::run`.
struct StdioDuplex {
    stdin: tokio::io::Stdin,
    stdout: tokio::io::Stdout,
    /// Signalled when the duplex is dropped (`run` returns on stdin EOF).
    done: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for StdioDuplex {
    fn drop(&mut self) {
        if let Some(tx) = self.done.take() {
            let _ = tx.send(());
        }
    }
}

impl AsyncRead for StdioDuplex {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdin).poll_read(cx, buf)
    }
}

impl AsyncWrite for StdioDuplex {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stdout).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdout).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdout).poll_shutdown(cx)
    }
}

/// SFTP v3 on stdin/stdout. No SSH auth, bind, or keys.
pub fn serve_stdio_russh(source: Arc<dyn MountSource>, opts: SftpOptions) -> io::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(async {
        let fs = fs_from_opts(source, &opts);
        let sftp = SftpSession::new(fs);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let duplex = StdioDuplex {
            stdin: tokio::io::stdin(),
            stdout: tokio::io::stdout(),
            done: Some(done_tx),
        };
        // `run` spawns a worker and returns; wait until stdin EOF drops the duplex.
        russh_sftp::server::run(duplex, sftp).await;
        let _ = done_rx.await;
        Ok(())
    })
}

#[cfg(test)]
mod policy_status_tests {
    use super::*;

    /// Regression: v3 capacity errors retain a useful message instead of bare Failure.
    #[test]
    fn regression_overlay_policy_sftp_status_messages() {
        assert_eq!(
            map_err(libc::EROFS).status_code,
            StatusCode::PermissionDenied
        );
        for errno in [libc::EDQUOT, libc::ENOSPC] {
            let reply = map_err(errno);
            assert_eq!(reply.status_code, StatusCode::Failure);
            assert_eq!(
                reply.error_message.as_deref(),
                Some(io::Error::from_raw_os_error(errno).to_string().as_str())
            );
        }
    }
}

#[cfg(test)]
mod sandbox_attr_tests {
    use super::*;
    use ratarmount_core::AttributeMapping;

    /// Regression: SFTP STAT/FSTAT/READDIR must report the same mapped Unix attributes.
    #[test]
    fn regression_mapped_attrs_include_unset() {
        for mode in [0o100777, 0o040777, 0o120777] {
            let mut fi = ratarmount_core::create_root_file_info();
            fi.mode = mode;
            fi.uid = 42;
            fi.gid = 43;
            let attr = attrs_from_fi(
                &fi,
                AttributeMapping::parse("uid=12345,gid=23456,umask=027").unwrap(),
            );
            assert_eq!((attr.uid, attr.gid), (Some(12345), Some(23456)));
            assert_eq!(attr.permissions.unwrap() & 0o777, 0o750);
            let attr = attrs_from_fi(&fi, AttributeMapping::default());
            assert_eq!((attr.uid, attr.gid), (Some(42), Some(43)));
            assert_eq!(attr.permissions.unwrap() & 0o777, 0o777);
        }
    }
}
