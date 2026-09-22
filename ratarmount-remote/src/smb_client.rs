//! Synchronous SMB 2.0.2 client (`Read` + `Seek` of one file).
//!
//! Direct TCP to `host:port` (default 445). Dialect offered is only `0x0202`.
//! Session setup is two legs: NTLM Type1, then Type3 (guest or NTLMv2). No
//! WRITE and no QUERY_DIRECTORY. Credentials are URL userinfo, else
//! [`crate::SMB_CLIENT_USER_ENV`] / [`crate::SMB_CLIENT_PASSWORD_ENV`] /
//! [`crate::SMB_CLIENT_DOMAIN_ENV`]. This module does not read
//! `RATARMOUNT_SMB_PASSWORD` or `RATARMOUNT_SMB_USER`.
//!
//! A short non-zero READ (`STATUS_SUCCESS` with `DataLength` < requested) is
//! not EOF. The fill loop stops when the caller's buffer is full, `offset >=
//! size`, status is `STATUS_END_OF_FILE` (`0xC0000011`), or status is
//! `STATUS_SUCCESS` with `DataLength == 0`. `0x80000002`
//! (`STATUS_DATATYPE_MISALIGNMENT`) is a hard error, not EOF.
//!
//! Packet layouts and NTLMv2 / HMAC-SHA256 signing follow `ratarmount-smb`'s
//! SMB 2.0.2 codec. Those helpers are `pub(crate)` there; this crate must not
//! depend on the server crate, so the pieces used here are copied.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use log::{debug, info};
use md4::Digest;
use md4::Md4;
use md5::Md5;
use sha2::Sha256;

use crate::smb::{
    env_nonempty, parse_smb_url, SmbLocation, SMB_CLIENT_DOMAIN_ENV, SMB_CLIENT_PASSWORD_ENV,
    SMB_CLIENT_USER_ENV,
};
use crate::{RemoteError, Result};

const SMB2_NEGOTIATE: u16 = 0x0000;
const SMB2_SESSION_SETUP: u16 = 0x0001;
const SMB2_TREE_CONNECT: u16 = 0x0003;
const SMB2_CREATE: u16 = 0x0005;
const SMB2_CLOSE: u16 = 0x0006;
const SMB2_READ: u16 = 0x0008;
const SMB2_QUERY_INFO: u16 = 0x0010;

const SMB2_HEADER_LEN: usize = 64;
const SMB2_FLAGS_SIGNED: u32 = 0x0000_0008;
const DIALECT_202: u16 = 0x0202;
const NEGOTIATE_SIGNING_ENABLED: u16 = 0x0001;
const NEGOTIATE_SIGNING_REQUIRED: u16 = 0x0002;
/// SMB 3.x global capability. A 2.0.2 negotiate that sets it fails closed.
const SMB2_GLOBAL_CAP_ENCRYPTION: u32 = 0x0000_0040;

const STATUS_SUCCESS: u32 = 0;
const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
const STATUS_END_OF_FILE: u32 = 0xC000_0011;
/// Not EOF. Samba and Windows use [`STATUS_END_OF_FILE`] at end of file.
const STATUS_DATATYPE_MISALIGNMENT: u32 = 0x8000_0002;

const MAX_FRAME: usize = 8 * 1024 * 1024;
const MAX_READ_CAP: u32 = 1024 * 1024;
/// Read-only desired access (no bits from the server crate's write mask).
const FILE_READ_ACCESS: u32 = 0x0012_0089;
const TYPE3_FLAGS: u32 = 0x2088_8201;
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;
const IO_TIMEOUT: Duration = Duration::from_secs(15);
/// Drop must not wait out [`IO_TIMEOUT`] when the server is already dead.
const CLOSE_TIMEOUT: Duration = Duration::from_millis(200);

type HmacSha256 = Hmac<Sha256>;
type HmacMd5 = Hmac<Md5>;

struct Smb2Header {
    credit_charge: u16,
    status: u32,
    command: u16,
    credits: u16,
    flags: u32,
    next_command: u32,
    message_id: u64,
    process_id: u32,
    tree_id: u32,
    session_id: u64,
}

struct ClientCreds {
    user: String,
    password: Option<String>,
    domain: String,
}

struct NegotiateInfo {
    security_mode: u16,
    dialect: u16,
    capabilities: u32,
    max_read: u32,
}

enum ReadStop {
    /// Keep filling. `DataLength` was non-zero.
    Continue,
    /// EOF status, or `STATUS_SUCCESS` with an empty buffer.
    Stop,
}

/// Seekable SMB 2.0.2 file. One TCP session; a dead socket is an `io::Error`
/// (no reconnect). [`SmbRangeFile::uses_ranges`] is true after QUERY_INFO
/// returned a size.
pub struct SmbRangeFile {
    conn: SmbConn,
    file_id: [u8; 16],
    size: u64,
    pos: u64,
    sized: bool,
}

struct SmbConn {
    stream: TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    session_key: Option<[u8; 16]>,
    sign: bool,
    signing_required: bool,
    max_read: u32,
    closed: bool,
}

impl std::fmt::Debug for SmbRangeFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmbRangeFile")
            .field("size", &self.size)
            .field("pos", &self.pos)
            .field("uses_ranges", &self.uses_ranges())
            .finish()
    }
}

impl SmbRangeFile {
    pub fn len(&self) -> u64 {
        self.size
    }

    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// True when QUERY_INFO returned a file size (including zero).
    pub fn uses_ranges(&self) -> bool {
        self.sized
    }

    /// Fill `buf` from `offset`. Short non-zero READ replies are not EOF.
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || offset >= self.size {
            return Ok(0);
        }
        let mut filled = 0usize;
        let mut off = offset;
        while filled < buf.len() {
            if off >= self.size {
                break;
            }
            let remain = self.size - off;
            let want = (buf.len() - filled)
                .min(self.conn.max_read as usize)
                .min(remain.min(usize::MAX as u64) as usize);
            if want == 0 {
                break;
            }
            let want_u32 = u32::try_from(want).unwrap_or(self.conn.max_read);
            let (status, data) = self
                .conn
                .read_file(self.file_id, off, want_u32)
                .map_err(|e| io::Error::other(e.to_string()))?;
            match read_stop(status, data.len()).map_err(|e| io::Error::other(e.to_string()))? {
                ReadStop::Stop => break,
                ReadStop::Continue => {
                    let n = data.len().min(want).min(buf.len() - filled);
                    if n == 0 {
                        break;
                    }
                    buf[filled..filled + n].copy_from_slice(&data[..n]);
                    filled += n;
                    off = off.saturating_add(n as u64);
                }
            }
        }
        Ok(filled)
    }
}

impl Read for SmbRangeFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.read_at(self.pos, buf)?;
        self.pos = self.pos.saturating_add(n as u64);
        Ok(n)
    }
}

impl Seek for SmbRangeFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let new = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::End(o) => self.size as i64 + o,
            SeekFrom::Current(o) => self.pos as i64 + o,
        };
        if new < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.pos = new as u64;
        Ok(self.pos)
    }
}

impl Drop for SmbRangeFile {
    fn drop(&mut self) {
        self.conn.close_file(self.file_id);
    }
}

/// Open `smb://[domain;]user[:pass]@host[:port]/share/path` and read one file.
///
/// Share root (no path) is not a file. Dispatch into the mount factory is a
/// later change; this function only speaks SMB.
pub fn open_smb_range(url_str: &str) -> Result<SmbRangeFile> {
    let loc = parse_smb_url(url_str)?;
    if loc.path.is_empty() {
        return Err(RemoteError::Smb(
            "smb URL must include a file path under the share (smb://host/share/path/to/file)"
                .into(),
        ));
    }
    let creds = client_creds(&loc);
    let mut conn = SmbConn::connect(&loc)?;
    conn.negotiate()?;
    if conn.signing_required && creds.password.is_none() {
        // A named user with no password is still unsigned, but it is not guest.
        if creds.user.is_empty() {
            info!("SMB signing required and client is guest");
            return Err(RemoteError::Smb(
                "SMB server requires signing; guest sessions are unsigned".into(),
            ));
        }
        info!("SMB signing required and no client password is set");
        return Err(RemoteError::Smb(
            "SMB server requires signing and no client password is set".into(),
        ));
    }
    conn.session_setup(&creds)?;
    conn.tree_connect(&loc)?;
    let file_id = conn.create(&loc.path)?;
    let size = conn.query_standard_size(file_id)?;
    debug!(
        "SMB 2.0.2 open //{}/{} {} ({} bytes, ranges)",
        loc.host, loc.share, loc.path, size
    );
    Ok(SmbRangeFile {
        conn,
        file_id,
        size,
        pos: 0,
        sized: true,
    })
}

fn client_creds(loc: &SmbLocation) -> ClientCreds {
    let (mut user, password, domain) =
        if loc.user.is_some() || loc.password.is_some() || loc.domain.is_some() {
            (
                loc.user.clone().unwrap_or_default(),
                loc.password.clone().filter(|s| !s.is_empty()),
                loc.domain.clone().unwrap_or_default(),
            )
        } else {
            (
                env_nonempty(SMB_CLIENT_USER_ENV).unwrap_or_default(),
                env_nonempty(SMB_CLIENT_PASSWORD_ENV),
                env_nonempty(SMB_CLIENT_DOMAIN_ENV).unwrap_or_default(),
            )
        };
    // Password with no username is the same `guest` smbclient puts in `-U`.
    // A URL user, when present, is already in `user` and wins.
    if password.is_some() && user.is_empty() {
        user = "guest".to_string();
    }
    ClientCreds {
        user,
        password,
        domain,
    }
}

fn read_stop(status: u32, data_len: usize) -> Result<ReadStop> {
    if status == STATUS_END_OF_FILE {
        return Ok(ReadStop::Stop);
    }
    if status == STATUS_SUCCESS {
        return Ok(if data_len == 0 {
            ReadStop::Stop
        } else {
            ReadStop::Continue
        });
    }
    if status == STATUS_DATATYPE_MISALIGNMENT {
        return Err(RemoteError::Smb(
            "SMB status 0x80000002 (STATUS_DATATYPE_MISALIGNMENT) is not EOF".into(),
        ));
    }
    Err(RemoteError::Smb(format!("SMB status {status:#010x}")))
}

impl SmbConn {
    fn connect(loc: &SmbLocation) -> Result<Self> {
        let addrs = (loc.host.as_str(), loc.port)
            .to_socket_addrs()
            .map_err(|e| RemoteError::Smb(format!("SMB resolve {}:{}: {e}", loc.host, loc.port)))?;
        let mut last = None;
        let mut stream = None;
        for addr in addrs {
            match TcpStream::connect_timeout(&addr, Duration::from_secs(10)) {
                Ok(s) => {
                    stream = Some(s);
                    break;
                }
                Err(e) => last = Some(e),
            }
        }
        let stream = match stream {
            Some(s) => s,
            None => {
                return Err(RemoteError::Smb(format!(
                    "SMB connect {}:{}: {}",
                    loc.host,
                    loc.port,
                    last.map(|e| e.to_string())
                        .unwrap_or_else(|| "no addresses".into())
                )));
            }
        };
        let _ = stream.set_nodelay(true);
        let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
        let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
        Ok(Self {
            stream,
            message_id: 0,
            session_id: 0,
            tree_id: 0,
            session_key: None,
            sign: false,
            signing_required: false,
            max_read: 64 * 1024,
            closed: false,
        })
    }

    fn negotiate(&mut self) -> Result<()> {
        let resp = self.transact(SMB2_NEGOTIATE, &negotiate_body())?;
        let status = header_status(&resp)?;
        if status != STATUS_SUCCESS {
            return Err(RemoteError::Smb(format!(
                "SMB NEGOTIATE status {status:#010x}"
            )));
        }
        let info = parse_negotiate(&resp)?;
        if info.dialect != DIALECT_202 {
            info!(
                "SMB negotiate dialect mismatch: server {:#06x}; SMB client v1 speaks SMB 2.0.2 only",
                info.dialect
            );
            return Err(RemoteError::Smb(
                "SMB client v1 speaks SMB 2.0.2 only".into(),
            ));
        }
        if info.capabilities & SMB2_GLOBAL_CAP_ENCRYPTION != 0 {
            info!("SMB negotiate requires encryption; client v1 does not implement it");
            return Err(RemoteError::Smb("SMB encryption is not implemented".into()));
        }
        let max_read = info.max_read.min(MAX_READ_CAP);
        if max_read == 0 {
            return Err(RemoteError::Smb("SMB MaxReadSize is 0".into()));
        }
        self.max_read = max_read;
        self.signing_required = info.security_mode & NEGOTIATE_SIGNING_REQUIRED != 0;
        Ok(())
    }

    fn session_setup(&mut self, creds: &ClientCreds) -> Result<()> {
        let t1 = ntlm_type1();
        let resp1 = self.transact(SMB2_SESSION_SETUP, &session_setup_body(&t1))?;
        let st1 = header_status(&resp1)?;
        if st1 != STATUS_MORE_PROCESSING_REQUIRED {
            return Err(RemoteError::Smb(format!(
                "SMB SESSION_SETUP expected STATUS_MORE_PROCESSING_REQUIRED, got {st1:#010x}"
            )));
        }
        let (_flags, sec) = parse_session_security(&resp1)?;
        if sec.is_empty() {
            return Err(RemoteError::Smb("empty SMB security buffer".into()));
        }
        let (challenge, av) = ntlm_type2_parts(sec)?;
        let password = creds.password.as_deref().unwrap_or("");
        let (t3, key) = ntlm_type3_v2(&creds.user, &creds.domain, password, challenge, &av);
        // The Type3 request stays unsigned. The key is known so a signed
        // Type3 response can be checked. An unsigned failure (wrong password)
        // is returned as its NT status; STATUS_SUCCESS still requires a signature.
        if creds.password.is_some() || self.signing_required {
            self.session_key = Some(key);
        }
        let resp2 = self.transact(SMB2_SESSION_SETUP, &session_setup_body(&t3))?;
        let st2 = header_status(&resp2)?;
        if st2 != STATUS_SUCCESS {
            return Err(RemoteError::Smb(format!(
                "SMB SESSION_SETUP Type3 status {st2:#010x}"
            )));
        }
        self.sign = self.session_key.is_some();
        Ok(())
    }

    fn tree_connect(&mut self, loc: &SmbLocation) -> Result<()> {
        let unc = format!(r"\\{}\{}", loc.host, loc.share);
        let path = encode_utf16le(&unc);
        let mut body = vec![0u8; 8];
        body[0..2].copy_from_slice(&9u16.to_le_bytes());
        let off = (SMB2_HEADER_LEN + 8) as u16;
        body[4..6].copy_from_slice(&off.to_le_bytes());
        body[6..8].copy_from_slice(&(path.len() as u16).to_le_bytes());
        body.extend_from_slice(&path);
        let resp = self.transact(SMB2_TREE_CONNECT, &body)?;
        let st = header_status(&resp)?;
        if st != STATUS_SUCCESS {
            return Err(RemoteError::Smb(format!(
                "SMB TREE_CONNECT status {st:#010x}"
            )));
        }
        Ok(())
    }

    fn create(&mut self, path: &str) -> Result<[u8; 16]> {
        let name = encode_utf16le(&path.replace('/', "\\"));
        let mut body = vec![0u8; 56];
        body[0..2].copy_from_slice(&57u16.to_le_bytes());
        body[4..8].copy_from_slice(&2u32.to_le_bytes());
        body[24..28].copy_from_slice(&FILE_READ_ACCESS.to_le_bytes());
        body[28..32].copy_from_slice(&0x80u32.to_le_bytes());
        body[32..36].copy_from_slice(&0x7u32.to_le_bytes());
        body[36..40].copy_from_slice(&1u32.to_le_bytes());
        body[40..44].copy_from_slice(&0x40u32.to_le_bytes());
        let off = (SMB2_HEADER_LEN + 56) as u16;
        body[44..46].copy_from_slice(&off.to_le_bytes());
        body[46..48].copy_from_slice(&(name.len() as u16).to_le_bytes());
        body.extend_from_slice(&name);
        let resp = self.transact(SMB2_CREATE, &body)?;
        let st = header_status(&resp)?;
        if st != STATUS_SUCCESS {
            return Err(RemoteError::Smb(format!("SMB CREATE status {st:#010x}")));
        }
        copy_at(&resp, SMB2_HEADER_LEN + 64)
    }

    fn query_standard_size(&mut self, fid: [u8; 16]) -> Result<u64> {
        let mut body = vec![0u8; 40];
        body[0..2].copy_from_slice(&41u16.to_le_bytes());
        body[2] = 1;
        body[3] = 5;
        body[4..8].copy_from_slice(&65536u32.to_le_bytes());
        body[24..40].copy_from_slice(&fid);
        let resp = self.transact(SMB2_QUERY_INFO, &body)?;
        let st = header_status(&resp)?;
        if st != STATUS_SUCCESS {
            return Err(RemoteError::Smb(format!(
                "SMB QUERY_INFO status {st:#010x}"
            )));
        }
        let info = query_output(&resp)?;
        if info.len() < 16 {
            return Err(RemoteError::Smb("SMB QUERY_INFO short file size".into()));
        }
        let mut raw = [0u8; 8];
        raw.copy_from_slice(&info[8..16]);
        Ok(u64::from_le_bytes(raw))
    }

    fn read_file(&mut self, fid: [u8; 16], offset: u64, length: u32) -> Result<(u32, Vec<u8>)> {
        let mut body = vec![0u8; 48];
        body[0..2].copy_from_slice(&49u16.to_le_bytes());
        // MinimumCount stays 0: a short DataLength is success, not an error.
        body[4..8].copy_from_slice(&length.to_le_bytes());
        body[8..16].copy_from_slice(&offset.to_le_bytes());
        body[16..32].copy_from_slice(&fid);
        let resp = self.transact(SMB2_READ, &body)?;
        let st = header_status(&resp)?;
        if st != STATUS_SUCCESS {
            return Ok((st, Vec::new()));
        }
        Ok((st, read_data(&resp)?))
    }

    fn close_file(&mut self, fid: [u8; 16]) {
        if self.closed {
            return;
        }
        self.closed = true;
        // READ keeps [`IO_TIMEOUT`]. CLOSE is best-effort and must not stall Drop.
        let _ = self.stream.set_read_timeout(Some(CLOSE_TIMEOUT));
        let _ = self.stream.set_write_timeout(Some(CLOSE_TIMEOUT));
        let mut body = vec![0u8; 24];
        body[0..2].copy_from_slice(&24u16.to_le_bytes());
        body[8..24].copy_from_slice(&fid);
        let _ = self.transact(SMB2_CLOSE, &body);
    }

    fn transact(&mut self, command: u16, body: &[u8]) -> Result<Vec<u8>> {
        let message_id = self.message_id;
        let hdr = Smb2Header {
            credit_charge: 1,
            status: 0,
            command,
            credits: 1,
            flags: 0,
            next_command: 0,
            message_id,
            process_id: 0xfeff,
            tree_id: self.tree_id,
            session_id: self.session_id,
        };
        self.message_id = self.message_id.saturating_add(1);
        let mut pkt = encode_packet(&hdr, body);
        if self.sign {
            let key = self
                .session_key
                .ok_or_else(|| RemoteError::Smb("SMB signing key missing".into()))?;
            smb2_sign_packet(&mut pkt, &key);
        }
        write_frame(&mut self.stream, &pkt)?;
        let resp = read_frame(&mut self.stream)?;
        let rh = parse_smb2_header(&resp)?;
        if let Some(key) = self.session_key {
            // SESSION_SETUP may be unsigned when the server rejects the logon
            // before it has a key. STATUS_SUCCESS and every later command still
            // require a valid HMAC. A set FLAGS_SIGNED is always verified.
            let signed = rh.flags & SMB2_FLAGS_SIGNED != 0;
            let allow_unsigned =
                command == SMB2_SESSION_SETUP && !signed && rh.status != STATUS_SUCCESS;
            if !allow_unsigned && !smb2_verify_packet(&resp, &key) {
                return Err(RemoteError::Smb("SMB response signature mismatch".into()));
            }
        }
        if rh.command != command || rh.message_id != message_id {
            return Err(RemoteError::Smb(
                "SMB response command or message id does not match the request".into(),
            ));
        }
        if command == SMB2_SESSION_SETUP && rh.session_id != 0 {
            self.session_id = rh.session_id;
        }
        if command == SMB2_TREE_CONNECT && rh.status == STATUS_SUCCESS {
            self.tree_id = rh.tree_id;
        }
        Ok(resp)
    }
}

fn negotiate_body() -> Vec<u8> {
    let mut body = vec![0u8; 36];
    body[0..2].copy_from_slice(&36u16.to_le_bytes());
    body[2..4].copy_from_slice(&1u16.to_le_bytes());
    body[4..6].copy_from_slice(&NEGOTIATE_SIGNING_ENABLED.to_le_bytes());
    body.extend_from_slice(&DIALECT_202.to_le_bytes());
    body
}

fn session_setup_body(sec: &[u8]) -> Vec<u8> {
    let mut body = vec![0u8; 24];
    body[0..2].copy_from_slice(&25u16.to_le_bytes());
    body[3] = 1;
    let off = (SMB2_HEADER_LEN + 24) as u16;
    body[12..14].copy_from_slice(&off.to_le_bytes());
    body[14..16].copy_from_slice(&(sec.len() as u16).to_le_bytes());
    body.extend_from_slice(sec);
    body
}

fn encode_packet(header: &Smb2Header, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SMB2_HEADER_LEN + body.len());
    out.extend_from_slice(&encode_smb2_header(header));
    out.extend_from_slice(body);
    out
}

fn encode_smb2_header(h: &Smb2Header) -> [u8; SMB2_HEADER_LEN] {
    let mut b = [0u8; SMB2_HEADER_LEN];
    b[0] = 0xfe;
    b[1..4].copy_from_slice(b"SMB");
    b[4..6].copy_from_slice(&64u16.to_le_bytes());
    b[6..8].copy_from_slice(&h.credit_charge.to_le_bytes());
    b[8..12].copy_from_slice(&h.status.to_le_bytes());
    b[12..14].copy_from_slice(&h.command.to_le_bytes());
    b[14..16].copy_from_slice(&h.credits.to_le_bytes());
    b[16..20].copy_from_slice(&h.flags.to_le_bytes());
    b[20..24].copy_from_slice(&h.next_command.to_le_bytes());
    b[24..32].copy_from_slice(&h.message_id.to_le_bytes());
    b[32..36].copy_from_slice(&h.process_id.to_le_bytes());
    b[36..40].copy_from_slice(&h.tree_id.to_le_bytes());
    b[40..48].copy_from_slice(&h.session_id.to_le_bytes());
    b
}

fn parse_smb2_header(buf: &[u8]) -> Result<Smb2Header> {
    if buf.len() < SMB2_HEADER_LEN {
        return Err(RemoteError::Smb("truncated SMB2 header".into()));
    }
    if buf[0] != 0xfe || &buf[1..4] != b"SMB" {
        return Err(RemoteError::Smb("not SMB2".into()));
    }
    if u16_at(buf, 4)? != 64 {
        return Err(RemoteError::Smb("SMB2 StructureSize".into()));
    }
    Ok(Smb2Header {
        credit_charge: u16_at(buf, 6)?,
        status: u32_at(buf, 8)?,
        command: u16_at(buf, 12)?,
        credits: u16_at(buf, 14)?,
        flags: u32_at(buf, 16)?,
        next_command: u32_at(buf, 20)?,
        message_id: u64_at(buf, 24)?,
        process_id: u32_at(buf, 32)?,
        tree_id: u32_at(buf, 36)?,
        session_id: u64_at(buf, 40)?,
    })
}

fn header_status(pkt: &[u8]) -> Result<u32> {
    Ok(parse_smb2_header(pkt)?.status)
}

fn parse_negotiate(pkt: &[u8]) -> Result<NegotiateInfo> {
    let body = pkt
        .get(SMB2_HEADER_LEN..)
        .ok_or_else(|| RemoteError::Smb("short NEGOTIATE response".into()))?;
    if body.len() < 40 {
        return Err(RemoteError::Smb("short NEGOTIATE response".into()));
    }
    Ok(NegotiateInfo {
        security_mode: u16_at(body, 2)?,
        dialect: u16_at(body, 4)?,
        capabilities: u32_at(body, 24)?,
        max_read: u32_at(body, 32)?,
    })
}

fn parse_session_security(pkt: &[u8]) -> Result<(u16, &[u8])> {
    let body = pkt
        .get(SMB2_HEADER_LEN..)
        .ok_or_else(|| RemoteError::Smb("short SESSION_SETUP response".into()))?;
    if body.len() < 8 {
        return Err(RemoteError::Smb("short SESSION_SETUP response".into()));
    }
    let flags = u16_at(body, 2)?;
    let off = u16_at(body, 4)? as usize;
    let len = u16_at(body, 6)? as usize;
    if len == 0 {
        return Ok((flags, &[]));
    }
    let sec = pkt
        .get(off..off + len)
        .ok_or_else(|| RemoteError::Smb("SESSION_SETUP security buffer truncated".into()))?;
    Ok((flags, sec))
}

fn query_output(pkt: &[u8]) -> Result<&[u8]> {
    let body = pkt
        .get(SMB2_HEADER_LEN..)
        .ok_or_else(|| RemoteError::Smb("short QUERY_INFO response".into()))?;
    if body.len() < 8 {
        return Err(RemoteError::Smb("short QUERY_INFO response".into()));
    }
    let off = u16_at(body, 2)? as usize;
    let len = u32_at(body, 4)? as usize;
    if len == 0 {
        return Ok(&[]);
    }
    pkt.get(off..off + len)
        .ok_or_else(|| RemoteError::Smb("QUERY_INFO output truncated".into()))
}

fn read_data(pkt: &[u8]) -> Result<Vec<u8>> {
    let body = pkt
        .get(SMB2_HEADER_LEN..)
        .ok_or_else(|| RemoteError::Smb("short READ response".into()))?;
    if body.len() < 8 {
        return Err(RemoteError::Smb("short READ response".into()));
    }
    let off = body[2] as usize;
    let len = u32_at(body, 4)? as usize;
    if len == 0 {
        return Ok(Vec::new());
    }
    pkt.get(off..off + len)
        .map(|s| s.to_vec())
        .ok_or_else(|| RemoteError::Smb("READ data truncated".into()))
}

/// FLAGS_SIGNED at offset 16, signature bytes 48..64 zeroed, then HMAC-SHA256.
/// The first 16 MAC bytes are written back to 48..64.
fn smb2_sign_packet(msg: &mut [u8], session_key: &[u8; 16]) {
    if msg.len() < SMB2_HEADER_LEN {
        return;
    }
    let mut flags = u32::from_le_bytes(msg[16..20].try_into().unwrap_or([0; 4]));
    flags |= SMB2_FLAGS_SIGNED;
    msg[16..20].copy_from_slice(&flags.to_le_bytes());
    msg[48..64].fill(0);
    let mut mac = HmacSha256::new_from_slice(session_key).expect("HMAC-SHA256 key");
    mac.update(msg);
    let sig = mac.finalize().into_bytes();
    msg[48..64].copy_from_slice(&sig[..16]);
}

/// HMAC-SHA256 over the packet with signature bytes 48..64 forced to zero.
fn smb2_verify_packet(msg: &[u8], session_key: &[u8; 16]) -> bool {
    if msg.len() < SMB2_HEADER_LEN {
        return false;
    }
    let Ok(flags) = u32_at(msg, 16) else {
        return false;
    };
    if flags & SMB2_FLAGS_SIGNED == 0 {
        return false;
    }
    let got = &msg[48..64];
    let mut mac = HmacSha256::new_from_slice(session_key).expect("HMAC-SHA256 key");
    mac.update(&msg[..48]);
    mac.update(&[0u8; 16]);
    if msg.len() > SMB2_HEADER_LEN {
        mac.update(&msg[SMB2_HEADER_LEN..]);
    }
    let computed = mac.finalize().into_bytes();
    ct_eq(&computed[..16], got)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut d = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        d |= x ^ y;
    }
    d == 0
}

fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<()> {
    let n = payload.len();
    if n > MAX_FRAME {
        return Err(RemoteError::Smb("SMB frame too large".into()));
    }
    let mut hdr = [0u8; 4];
    hdr[1] = ((n >> 16) & 0xff) as u8;
    hdr[2] = ((n >> 8) & 0xff) as u8;
    hdr[3] = (n & 0xff) as u8;
    stream.write_all(&hdr)?;
    stream.write_all(payload)?;
    Ok(())
}

fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr)?;
    if hdr[0] != 0 {
        return Err(RemoteError::Smb("SMB Direct TCP type must be 0".into()));
    }
    let n = ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | (hdr[3] as usize);
    if n == 0 || n > MAX_FRAME {
        return Err(RemoteError::Smb("SMB frame length".into()));
    }
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

fn u16_at(b: &[u8], o: usize) -> Result<u16> {
    let s = b
        .get(o..o + 2)
        .ok_or_else(|| RemoteError::Smb("truncated SMB field".into()))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], o: usize) -> Result<u32> {
    let s = b
        .get(o..o + 4)
        .ok_or_else(|| RemoteError::Smb("truncated SMB field".into()))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64_at(b: &[u8], o: usize) -> Result<u64> {
    let s = b
        .get(o..o + 8)
        .ok_or_else(|| RemoteError::Smb("truncated SMB field".into()))?;
    let mut raw = [0u8; 8];
    raw.copy_from_slice(s);
    Ok(u64::from_le_bytes(raw))
}

fn copy_at<const N: usize>(buf: &[u8], off: usize) -> Result<[u8; N]> {
    let s = buf
        .get(off..off + N)
        .ok_or_else(|| RemoteError::Smb("truncated SMB field".into()))?;
    let mut a = [0u8; N];
    a.copy_from_slice(s);
    Ok(a)
}

fn encode_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

fn extract_ntlm(buf: &[u8]) -> Option<&[u8]> {
    buf.windows(8)
        .position(|w| w == b"NTLMSSP\0")
        .map(|i| &buf[i..])
}

fn ntlm_message_type(buf: &[u8]) -> Option<u32> {
    let n = extract_ntlm(buf)?;
    if n.len() < 12 {
        return None;
    }
    u32_at(n, 8).ok()
}

fn ntlm_type1() -> Vec<u8> {
    let mut b = Vec::from(&b"NTLMSSP\0"[..]);
    b.extend_from_slice(&1u32.to_le_bytes());
    let flags: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0004 | 0x0000_0200 | 0x0008_0000;
    b.extend_from_slice(&flags.to_le_bytes());
    for _ in 0..4 {
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
    }
    b
}

fn ntlm_type2_parts(buf: &[u8]) -> Result<([u8; 8], Vec<u8>)> {
    let n =
        extract_ntlm(buf).ok_or_else(|| RemoteError::Smb("SMB Type2 missing NTLMSSP".into()))?;
    if ntlm_message_type(n) != Some(2) || n.len() < 48 {
        return Err(RemoteError::Smb("SMB Type2 challenge missing".into()));
    }
    let mut challenge = [0u8; 8];
    challenge.copy_from_slice(&n[24..32]);
    let av_len = u16_at(n, 40)? as usize;
    let av_off = u32_at(n, 44)? as usize;
    let av = if av_len == 0 {
        Vec::new()
    } else {
        n.get(av_off..av_off + av_len)
            .ok_or_else(|| RemoteError::Smb("SMB Type2 target info truncated".into()))?
            .to_vec()
    };
    Ok((challenge, av))
}

fn ntlm_type3_v2(
    user: &str,
    domain: &str,
    password: &str,
    challenge: [u8; 8],
    av: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    let temp = ntlmv2_temp(client_challenge8(), now_filetime(), av);
    let rk = ntlmv2_response_key_nt(password, user, domain);
    let proof = ntlmv2_nt_proof(&rk, challenge, &temp);
    let key = ntlmv2_session_base_key(&rk, &proof);
    let mut nt = Vec::with_capacity(16 + temp.len());
    nt.extend_from_slice(&proof);
    nt.extend_from_slice(&temp);
    (
        ntlm_type3_authenticate(user, domain, &nt, TYPE3_FLAGS, 0),
        key,
    )
}

fn ntlmv2_temp(client_challenge: [u8; 8], timestamp: u64, av: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(28 + av.len() + 4);
    t.push(0x01);
    t.push(0x01);
    t.extend_from_slice(&0u16.to_le_bytes());
    t.extend_from_slice(&0u32.to_le_bytes());
    t.extend_from_slice(&timestamp.to_le_bytes());
    t.extend_from_slice(&client_challenge);
    t.extend_from_slice(&0u32.to_le_bytes());
    if av.is_empty() {
        t.extend_from_slice(&0u16.to_le_bytes());
        t.extend_from_slice(&0u16.to_le_bytes());
    } else {
        t.extend_from_slice(av);
    }
    t
}

fn ntlm_type3_authenticate(
    user: &str,
    domain: &str,
    nt_response: &[u8],
    flags: u32,
    session_key_len: u16,
) -> Vec<u8> {
    let user_raw = encode_utf16le(user);
    let domain_raw = encode_utf16le(domain);
    let nt_off = 64u32;
    let domain_off = nt_off + nt_response.len() as u32;
    let user_off = domain_off + domain_raw.len() as u32;
    let end_off = user_off + user_raw.len() as u32;
    let mut b = Vec::from(&b"NTLMSSP\0"[..]);
    b.extend_from_slice(&3u32.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&nt_off.to_le_bytes());
    b.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
    b.extend_from_slice(&(nt_response.len() as u16).to_le_bytes());
    b.extend_from_slice(&nt_off.to_le_bytes());
    b.extend_from_slice(&(domain_raw.len() as u16).to_le_bytes());
    b.extend_from_slice(&(domain_raw.len() as u16).to_le_bytes());
    b.extend_from_slice(&domain_off.to_le_bytes());
    b.extend_from_slice(&(user_raw.len() as u16).to_le_bytes());
    b.extend_from_slice(&(user_raw.len() as u16).to_le_bytes());
    b.extend_from_slice(&user_off.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&0u16.to_le_bytes());
    b.extend_from_slice(&end_off.to_le_bytes());
    b.extend_from_slice(&session_key_len.to_le_bytes());
    b.extend_from_slice(&session_key_len.to_le_bytes());
    b.extend_from_slice(&end_off.to_le_bytes());
    b.extend_from_slice(&flags.to_le_bytes());
    debug_assert_eq!(b.len(), 64);
    b.extend_from_slice(nt_response);
    b.extend_from_slice(&domain_raw);
    b.extend_from_slice(&user_raw);
    b
}

fn ntlmv2_response_key_nt(password: &str, user: &str, domain: &str) -> [u8; 16] {
    let mut material = user.to_uppercase();
    material.push_str(domain);
    hmac_md5(&ntowfv1(password), &encode_utf16le(&material))
}

fn ntlmv2_nt_proof(response_key_nt: &[u8; 16], server_challenge: [u8; 8], temp: &[u8]) -> [u8; 16] {
    let mut data = Vec::with_capacity(8 + temp.len());
    data.extend_from_slice(&server_challenge);
    data.extend_from_slice(temp);
    hmac_md5(response_key_nt, &data)
}

fn ntlmv2_session_base_key(response_key_nt: &[u8; 16], nt_proof: &[u8]) -> [u8; 16] {
    hmac_md5(response_key_nt, nt_proof)
}

fn ntowfv1(password: &str) -> [u8; 16] {
    let mut h = Md4::new();
    h.update(encode_utf16le(password));
    copy16(h.finalize())
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = HmacMd5::new_from_slice(key).expect("HMAC-MD5 key");
    mac.update(data);
    copy16(mac.finalize().into_bytes())
}

fn copy16(bytes: impl AsRef<[u8]>) -> [u8; 16] {
    let b = bytes.as_ref();
    let mut out = [0u8; 16];
    out.copy_from_slice(&b[..16]);
    out
}

fn now_filetime() -> u64 {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    FILETIME_UNIX_EPOCH + d.as_secs().saturating_mul(10_000_000) + u64::from(d.subsec_nanos() / 100)
}

fn client_challenge8() -> [u8; 8] {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mix =
        t.as_nanos() as u64 ^ u64::from(std::process::id()).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    mix.to_le_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::Mac;
    use std::io::Read;
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};
    use std::thread;
    use std::time::Duration;

    const ACCESS_DENIED: u32 = 0xC000_0022;
    const LOGON_FAILURE: u32 = 0xC000_006D;
    const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
    const CHALLENGE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];
    const EXPORT_PW: &str = "EXPORT_SERVER_PW_7f3c9a";
    const EXPORT_USER: &str = "EXPORT_SERVER_USER_7f3c9a";

    #[derive(Clone, Copy)]
    enum EofStyle {
        EndOfFile,
        EmptySuccess,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum ReadTamper {
        None,
        FlipPayload,
        ClearSignature,
    }

    struct Script {
        dialect: u16,
        security_mode: u16,
        capabilities: u32,
        max_read: u32,
        file: Vec<u8>,
        size_claim: u64,
        chunk: usize,
        stop_after: u64,
        eof: EofStyle,
        hard_status: Option<u32>,
        empty_type2: bool,
        password: Option<String>,
        challenge: [u8; 8],
        max_reads: u32,
        read_tamper: ReadTamper,
    }

    fn script_file(file: &[u8]) -> Script {
        Script {
            dialect: DIALECT_202,
            security_mode: NEGOTIATE_SIGNING_ENABLED,
            capabilities: 0,
            max_read: 65_536,
            file: file.to_vec(),
            size_claim: file.len() as u64,
            chunk: usize::MAX,
            stop_after: file.len() as u64,
            eof: EofStyle::EndOfFile,
            hard_status: None,
            empty_type2: false,
            password: None,
            challenge: CHALLENGE,
            max_reads: 128,
            read_tamper: ReadTamper::None,
        }
    }

    #[derive(Clone)]
    struct Seen {
        command: u16,
        raw: Vec<u8>,
        sec: Vec<u8>,
        dialects: Vec<u16>,
        desired_access: u32,
        response_status: u32,
    }

    struct Server {
        script: Script,
        session_id: u64,
        tree_id: u32,
        authed: bool,
        session_key: Option<[u8; 16]>,
        saw_type1: bool,
        file_id: [u8; 16],
        reads: u32,
    }

    impl Server {
        fn new(script: Script) -> Self {
            Self {
                script,
                session_id: 0,
                tree_id: 0,
                authed: false,
                session_key: None,
                saw_type1: false,
                file_id: [0x11; 16],
                reads: 0,
            }
        }

        fn handle(
            &mut self,
            pkt: &[u8],
            seen: &Mutex<Vec<Seen>>,
        ) -> std::result::Result<Vec<u8>, ()> {
            let hdr = parse_smb2_header(pkt).map_err(|_| ())?;
            let meta = Seen {
                command: hdr.command,
                raw: pkt.to_vec(),
                sec: if hdr.command == SMB2_SESSION_SETUP {
                    request_security(pkt)
                } else {
                    Vec::new()
                },
                dialects: if hdr.command == SMB2_NEGOTIATE {
                    parse_dialects(pkt)
                } else {
                    Vec::new()
                },
                desired_access: if hdr.command == SMB2_CREATE {
                    desired_access(pkt)
                } else {
                    0
                },
                response_status: 0,
            };
            if self.authed && self.script.password.is_some() && !sig_ok(pkt, &self.session_key) {
                return Ok(self.finish(&hdr, ACCESS_DENIED, error_body(), meta, seen));
            }
            let (status, body) = self.dispatch(&hdr, pkt)?;
            Ok(self.finish(&hdr, status, body, meta, seen))
        }

        fn finish(
            &self,
            hdr: &Smb2Header,
            status: u32,
            body: Vec<u8>,
            mut meta: Seen,
            seen: &Mutex<Vec<Seen>>,
        ) -> Vec<u8> {
            let mut rh = reply_header(hdr, status);
            if hdr.command == SMB2_SESSION_SETUP {
                rh.session_id = self.session_id;
            }
            if hdr.command == SMB2_TREE_CONNECT && status == STATUS_SUCCESS {
                rh.tree_id = self.tree_id;
            }
            meta.response_status = status;
            seen.lock().unwrap_or_else(|e| e.into_inner()).push(meta);
            let mut pkt = encode_packet(&rh, &body);
            if let Some(key) = self.session_key {
                smb2_sign_packet(&mut pkt, &key);
            }
            if hdr.command == SMB2_READ {
                match self.script.read_tamper {
                    ReadTamper::FlipPayload => {
                        if pkt.len() > 80 {
                            pkt[80] ^= 0xff;
                        }
                    }
                    ReadTamper::ClearSignature => {
                        if pkt.len() >= SMB2_HEADER_LEN {
                            pkt[48..64].fill(0);
                        }
                    }
                    ReadTamper::None => {}
                }
            }
            pkt
        }

        fn dispatch(
            &mut self,
            hdr: &Smb2Header,
            pkt: &[u8],
        ) -> std::result::Result<(u32, Vec<u8>), ()> {
            match hdr.command {
                SMB2_NEGOTIATE => Ok((
                    STATUS_SUCCESS,
                    encode_negotiate_response(
                        self.script.dialect,
                        self.script.security_mode,
                        self.script.capabilities,
                        self.script.max_read,
                    ),
                )),
                SMB2_SESSION_SETUP => self.dispatch_session(pkt),
                SMB2_TREE_CONNECT => {
                    if !self.authed {
                        return Ok((0xC000_0203, error_body()));
                    }
                    self.tree_id = 7;
                    Ok((STATUS_SUCCESS, encode_tree_connect_response()))
                }
                SMB2_CREATE => Ok((
                    STATUS_SUCCESS,
                    encode_create_response(self.file_id, self.script.size_claim),
                )),
                SMB2_QUERY_INFO => Ok((
                    STATUS_SUCCESS,
                    encode_query_info_response(&file_standard(self.script.size_claim)),
                )),
                SMB2_READ => self.dispatch_read(pkt),
                SMB2_CLOSE => Ok((STATUS_SUCCESS, encode_close_response())),
                0x0009 | 0x000E => Ok((ACCESS_DENIED, error_body())),
                _ => Ok((0xC000_0002, error_body())),
            }
        }

        fn dispatch_session(&mut self, pkt: &[u8]) -> std::result::Result<(u32, Vec<u8>), ()> {
            let sec = request_security(pkt);
            if !self.saw_type1 {
                self.saw_type1 = true;
                self.session_id = 0x42;
                if self.script.empty_type2 || sec.is_empty() {
                    return Ok((
                        STATUS_MORE_PROCESSING_REQUIRED,
                        encode_session_setup_response(0, &[]),
                    ));
                }
                let t2 = ntlm_type2(self.script.challenge, "RATARMOUNT");
                return Ok((
                    STATUS_MORE_PROCESSING_REQUIRED,
                    encode_session_setup_response(0, &t2),
                ));
            }
            if sec.is_empty() || ntlm_message_type(&sec) != Some(3) {
                return Ok((LOGON_FAILURE, error_body()));
            }
            if let Some(pw) = self.script.password.clone() {
                let Some(t3) = parse_type3(&sec) else {
                    return Ok((LOGON_FAILURE, error_body()));
                };
                if t3.nt_response.len() < 16 || t3.nt_response.len() == 24 {
                    return Ok((LOGON_FAILURE, error_body()));
                }
                let rk = ntlmv2_response_key_nt(&pw, &t3.user, &t3.domain);
                let expect = ntlmv2_nt_proof(&rk, self.script.challenge, &t3.nt_response[16..]);
                if t3.nt_response[..16] != expect {
                    return Ok((LOGON_FAILURE, error_body()));
                }
                self.session_key = Some(ntlmv2_session_base_key(&rk, &expect));
            }
            self.authed = true;
            let flags = if self.script.password.is_none() {
                0x0001
            } else {
                0
            };
            Ok((STATUS_SUCCESS, encode_session_setup_response(flags, &[])))
        }

        fn dispatch_read(&mut self, pkt: &[u8]) -> std::result::Result<(u32, Vec<u8>), ()> {
            self.reads = self.reads.saturating_add(1);
            if self.reads > self.script.max_reads {
                return Ok((STATUS_INVALID_PARAMETER, error_body()));
            }
            if let Some(st) = self.script.hard_status.take() {
                return Ok((st, error_body()));
            }
            let body = pkt.get(SMB2_HEADER_LEN..).ok_or(())?;
            if body.len() < 16 {
                return Ok((STATUS_INVALID_PARAMETER, error_body()));
            }
            let length = u32::from_le_bytes([body[4], body[5], body[6], body[7]]) as usize;
            let mut raw = [0u8; 8];
            raw.copy_from_slice(&body[8..16]);
            let offset = u64::from_le_bytes(raw);
            if offset >= self.script.stop_after {
                return Ok(self.eof_reply());
            }
            let start = offset as usize;
            let room = (self.script.stop_after as usize).saturating_sub(start);
            let n = self.script.chunk.min(length).min(room);
            let end = start.saturating_add(n).min(self.script.file.len());
            let data = if start < self.script.file.len() && end > start {
                self.script.file[start..end].to_vec()
            } else {
                Vec::new()
            };
            if data.is_empty() {
                return Ok(self.eof_reply());
            }
            Ok((STATUS_SUCCESS, encode_read_response(&data)))
        }

        fn eof_reply(&self) -> (u32, Vec<u8>) {
            match self.script.eof {
                EofStyle::EndOfFile => (STATUS_END_OF_FILE, error_body()),
                EofStyle::EmptySuccess => (STATUS_SUCCESS, encode_read_response(&[])),
            }
        }
    }

    struct Running {
        addr: std::net::SocketAddr,
        seen: Arc<Mutex<Vec<Seen>>>,
        join: Option<thread::JoinHandle<()>>,
    }

    impl Drop for Running {
        fn drop(&mut self) {
            if let Some(j) = self.join.take() {
                let _ = j.join();
            }
        }
    }

    fn serve(script: Script) -> Running {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let seen = Arc::new(Mutex::new(Vec::new()));
        let seen2 = Arc::clone(&seen);
        let join = thread::spawn(move || serve_one(listener, script, seen2));
        Running {
            addr,
            seen,
            join: Some(join),
        }
    }

    fn serve_one(listener: TcpListener, script: Script, seen: Arc<Mutex<Vec<Seen>>>) {
        let Ok((mut stream, _)) = listener.accept() else {
            return;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_nodelay(true);
        let mut srv = Server::new(script);
        loop {
            let frame = match read_frame(&mut stream) {
                Ok(f) => f,
                Err(_) => return,
            };
            let reply = match srv.handle(&frame, &seen) {
                Ok(p) => p,
                Err(_) => return,
            };
            if write_frame(&mut stream, &reply).is_err() {
                return;
            }
        }
    }

    fn reply_header(req: &Smb2Header, status: u32) -> Smb2Header {
        Smb2Header {
            credit_charge: req.credit_charge.max(1),
            status,
            command: req.command,
            credits: 1,
            flags: 0x0000_0001,
            next_command: 0,
            message_id: req.message_id,
            process_id: req.process_id,
            tree_id: req.tree_id,
            session_id: req.session_id,
        }
    }

    fn encode_negotiate_response(dialect: u16, mode: u16, caps: u32, max_read: u32) -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b[0..2].copy_from_slice(&65u16.to_le_bytes());
        b[2..4].copy_from_slice(&mode.to_le_bytes());
        b[4..6].copy_from_slice(&dialect.to_le_bytes());
        b[24..28].copy_from_slice(&caps.to_le_bytes());
        b[28..32].copy_from_slice(&max_read.to_le_bytes());
        b[32..36].copy_from_slice(&max_read.to_le_bytes());
        b[36..40].copy_from_slice(&max_read.to_le_bytes());
        b
    }

    fn encode_session_setup_response(flags: u16, sec: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 8];
        b[0..2].copy_from_slice(&9u16.to_le_bytes());
        b[2..4].copy_from_slice(&flags.to_le_bytes());
        let off = (SMB2_HEADER_LEN + 8) as u16;
        b[4..6].copy_from_slice(&off.to_le_bytes());
        b[6..8].copy_from_slice(&(sec.len() as u16).to_le_bytes());
        b.extend_from_slice(sec);
        b
    }

    fn encode_tree_connect_response() -> Vec<u8> {
        let mut b = vec![0u8; 16];
        b[0..2].copy_from_slice(&16u16.to_le_bytes());
        b[2] = 1;
        b
    }

    fn encode_create_response(fid: [u8; 16], size: u64) -> Vec<u8> {
        let mut b = vec![0u8; 88];
        b[0..2].copy_from_slice(&89u16.to_le_bytes());
        b[4..8].copy_from_slice(&1u32.to_le_bytes());
        b[48..56].copy_from_slice(&size.to_le_bytes());
        b[64..80].copy_from_slice(&fid);
        b
    }

    fn encode_query_info_response(info: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 8];
        b[0..2].copy_from_slice(&9u16.to_le_bytes());
        let off = (SMB2_HEADER_LEN + 8) as u16;
        b[2..4].copy_from_slice(&off.to_le_bytes());
        b[4..8].copy_from_slice(&(info.len() as u32).to_le_bytes());
        b.extend_from_slice(info);
        b
    }

    fn file_standard(size: u64) -> Vec<u8> {
        let mut b = vec![0u8; 24];
        b[8..16].copy_from_slice(&size.to_le_bytes());
        b[16..20].copy_from_slice(&1u32.to_le_bytes());
        b
    }

    fn encode_read_response(data: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; 16];
        b[0..2].copy_from_slice(&17u16.to_le_bytes());
        b[2] = (SMB2_HEADER_LEN + 16) as u8;
        b[4..8].copy_from_slice(&(data.len() as u32).to_le_bytes());
        b.extend_from_slice(data);
        b
    }

    fn encode_close_response() -> Vec<u8> {
        let mut b = vec![0u8; 60];
        b[0..2].copy_from_slice(&60u16.to_le_bytes());
        b
    }

    fn error_body() -> Vec<u8> {
        let mut b = vec![0u8; 8];
        b[0..2].copy_from_slice(&9u16.to_le_bytes());
        b
    }

    fn ntlm_type2(challenge: [u8; 8], target: &str) -> Vec<u8> {
        let name = encode_utf16le(target);
        let mut av = Vec::new();
        for id in [1u16, 2u16] {
            av.extend_from_slice(&id.to_le_bytes());
            av.extend_from_slice(&(name.len() as u16).to_le_bytes());
            av.extend_from_slice(&name);
        }
        av.extend_from_slice(&0u16.to_le_bytes());
        av.extend_from_slice(&0u16.to_le_bytes());
        const FLAGS: u32 = 0x0000_0001
            | 0x0000_0004
            | 0x0000_0200
            | 0x0000_8000
            | 0x0002_0000
            | 0x0008_0000
            | 0x0080_0000
            | 0x2000_0000;
        let mut b = Vec::from(&b"NTLMSSP\0"[..]);
        b.extend_from_slice(&2u32.to_le_bytes());
        let name_off = 48u32;
        b.extend_from_slice(&(name.len() as u16).to_le_bytes());
        b.extend_from_slice(&(name.len() as u16).to_le_bytes());
        b.extend_from_slice(&name_off.to_le_bytes());
        b.extend_from_slice(&FLAGS.to_le_bytes());
        b.extend_from_slice(&challenge);
        b.extend_from_slice(&[0u8; 8]);
        let av_off = name_off + name.len() as u32;
        b.extend_from_slice(&(av.len() as u16).to_le_bytes());
        b.extend_from_slice(&(av.len() as u16).to_le_bytes());
        b.extend_from_slice(&av_off.to_le_bytes());
        debug_assert_eq!(b.len(), 48);
        b.extend_from_slice(&name);
        b.extend_from_slice(&av);
        b
    }

    struct Type3 {
        user: String,
        domain: String,
        nt_response: Vec<u8>,
        flags: u32,
    }

    fn parse_type3(buf: &[u8]) -> Option<Type3> {
        let n = extract_ntlm(buf)?;
        if n.len() < 64 || u32_at(n, 8).ok()? != 3 {
            return None;
        }
        let flags = u32_at(n, 60).ok()?;
        let nt = sec_buf(n, 20, 24)?;
        let domain = decode_utf16(sec_buf(n, 28, 32)?);
        let user = decode_utf16(sec_buf(n, 36, 40)?);
        Some(Type3 {
            user,
            domain,
            nt_response: nt.to_vec(),
            flags,
        })
    }

    fn sec_buf(n: &[u8], len_off: usize, off_off: usize) -> Option<&[u8]> {
        let len = u16_at(n, len_off).ok()? as usize;
        let off = u32_at(n, off_off).ok()? as usize;
        n.get(off..off + len)
    }

    fn decode_utf16(raw: &[u8]) -> String {
        let mut units = Vec::with_capacity(raw.len() / 2);
        let mut i = 0;
        while i + 1 < raw.len() {
            units.push(u16::from_le_bytes([raw[i], raw[i + 1]]));
            i += 2;
        }
        String::from_utf16_lossy(&units)
    }

    fn request_security(pkt: &[u8]) -> Vec<u8> {
        let Some(body) = pkt.get(SMB2_HEADER_LEN..) else {
            return Vec::new();
        };
        if body.len() < 16 {
            return Vec::new();
        }
        let off = u16::from_le_bytes([body[12], body[13]]) as usize;
        let len = u16::from_le_bytes([body[14], body[15]]) as usize;
        if len == 0 || off.saturating_add(len) > pkt.len() {
            return Vec::new();
        }
        pkt[off..off + len].to_vec()
    }

    fn parse_dialects(pkt: &[u8]) -> Vec<u16> {
        let Some(body) = pkt.get(SMB2_HEADER_LEN..) else {
            return Vec::new();
        };
        if body.len() < 36 {
            return Vec::new();
        }
        let count = u16::from_le_bytes([body[2], body[3]]) as usize;
        let mut out = Vec::new();
        let mut o = 36usize;
        for _ in 0..count {
            if o + 2 > body.len() {
                break;
            }
            out.push(u16::from_le_bytes([body[o], body[o + 1]]));
            o += 2;
        }
        out
    }

    fn desired_access(pkt: &[u8]) -> u32 {
        let Some(body) = pkt.get(SMB2_HEADER_LEN..) else {
            return 0;
        };
        if body.len() < 28 {
            return 0;
        }
        u32::from_le_bytes([body[24], body[25], body[26], body[27]])
    }

    fn sig_ok(pkt: &[u8], key: &Option<[u8; 16]>) -> bool {
        let Some(key) = key else {
            return false;
        };
        if pkt.len() < SMB2_HEADER_LEN {
            return false;
        }
        let flags = u32::from_le_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
        if flags & SMB2_FLAGS_SIGNED == 0 {
            return false;
        }
        let got = pkt[48..64].to_vec();
        let mut tmp = pkt.to_vec();
        tmp[48..64].fill(0);
        let mut mac = HmacSha256::new_from_slice(key).expect("hmac");
        mac.update(&tmp);
        let out = mac.finalize().into_bytes();
        out[..16] == got[..]
    }

    fn url_for(running: &Running) -> String {
        format!("smb://127.0.0.1:{}/share/dir/file.bin", running.addr.port())
    }

    fn bytes_contain(hay: &[u8], needle: &str) -> bool {
        let ascii = needle.as_bytes();
        if hay.windows(ascii.len()).any(|w| w == ascii) {
            return true;
        }
        let wide = encode_utf16le(needle);
        hay.windows(wide.len()).any(|w| w == wide.as_slice())
    }

    fn snapshot(running: &Running) -> Vec<Seen> {
        running
            .seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    struct EnvGuard {
        saved: Vec<(&'static str, Option<String>)>,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl EnvGuard {
        fn acquire(keys: &[&'static str]) -> Self {
            let lock = crate::SMB_CLIENT_ENV_LOCK
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            let mut saved = Vec::new();
            for &k in keys {
                saved.push((k, std::env::var(k).ok()));
                std::env::remove_var(k);
            }
            Self { saved, _lock: lock }
        }
        fn set(&self, key: &str, val: &str) {
            std::env::set_var(key, val);
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in self.saved.drain(..) {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    const ENV_KEYS: &[&str] = &[
        "RATARMOUNT_SMB_PASSWORD",
        "RATARMOUNT_SMB_USER",
        SMB_CLIENT_PASSWORD_ENV,
        SMB_CLIENT_USER_ENV,
        SMB_CLIENT_DOMAIN_ENV,
    ];

    /// Regression: 1 byte per READ, then `0xC0000011`; `read_exact` matches.
    #[test]
    fn smb_read_fills_short_data_length() {
        let data = b"short-read-payload!";
        let mut script = script_file(data);
        script.chunk = 1;
        script.stop_after = data.len() as u64;
        script.size_claim = data.len() as u64 + 8;
        script.eof = EofStyle::EndOfFile;
        let running = serve(script);
        let mut f = open_smb_range(&url_for(&running)).expect("open");
        assert!(f.uses_ranges());
        assert_eq!(f.len(), data.len() as u64 + 8);
        let mut buf = vec![0u8; data.len()];
        f.read_exact(&mut buf).expect("read_exact");
        assert_eq!(buf, data);
        let n = f.read(&mut [0u8; 8]).expect("eof status is a stop");
        assert_eq!(n, 0);
        drop(f);
        let seen = snapshot(&running);
        let reads = seen.iter().filter(|s| s.command == SMB2_READ).count();
        assert!(
            reads > 1,
            "short DataLength must not satisfy the buffer in one READ ({reads})"
        );
    }

    /// In-tree server EOF: `STATUS_SUCCESS` and `DataLength == 0` while offset < size.
    #[test]
    fn smb_read_fills_empty_status_success() {
        let data = b"abcdefghijklmnop";
        let mut script = script_file(data);
        script.chunk = 1;
        script.stop_after = 4;
        script.size_claim = 100;
        script.eof = EofStyle::EmptySuccess;
        script.max_reads = 32;
        let running = serve(script);
        let mut f = open_smb_range(&url_for(&running)).expect("open");
        let mut buf = [0u8; 32];
        let n = f.read(&mut buf).expect("empty success stops");
        assert_eq!(n, 4);
        assert_eq!(&buf[..4], b"abcd");
        drop(f);
        let seen = snapshot(&running);
        let reads = seen.iter().filter(|s| s.command == SMB2_READ).count();
        assert!(
            reads <= 8,
            "empty STATUS_SUCCESS must not spin ({reads} READs)"
        );
    }

    /// `0x80000002` is `STATUS_DATATYPE_MISALIGNMENT`, not an EOF status.
    #[test]
    fn smb_read_fills_misalignment_is_not_eof() {
        let mut script = script_file(b"0123456789");
        script.hard_status = Some(STATUS_DATATYPE_MISALIGNMENT);
        script.size_claim = 10;
        let running = serve(script);
        let mut f = open_smb_range(&url_for(&running)).expect("open");
        let err = f.read(&mut [0u8; 8]).expect_err("misalignment is an error");
        let msg = err.to_string();
        assert!(msg.contains("80000002"), "{msg}");
        assert!(msg.contains("not EOF"), "{msg}");
    }

    #[test]
    fn smb_two_leg_session_setup() {
        let running = serve(script_file(b"two-leg"));
        let f = open_smb_range(&url_for(&running)).expect("open");
        drop(f);
        let seen = snapshot(&running);
        let setups: Vec<_> = seen
            .iter()
            .filter(|s| s.command == SMB2_SESSION_SETUP)
            .collect();
        assert_eq!(setups.len(), 2, "session setup is two legs");
        assert_eq!(ntlm_message_type(&setups[0].sec), Some(1));
        assert!(!setups[0].sec.is_empty());
        assert_eq!(setups[0].response_status, STATUS_MORE_PROCESSING_REQUIRED);
        assert_eq!(ntlm_message_type(&setups[1].sec), Some(3));
        assert!(!setups[1].sec.is_empty());
        assert_eq!(setups[1].response_status, STATUS_SUCCESS);

        let mut script = script_file(b"empty-sec");
        script.empty_type2 = true;
        let running = serve(script);
        let err = open_smb_range(&url_for(&running)).expect_err("empty security buffer");
        assert!(
            err.to_string().to_ascii_lowercase().contains("empty"),
            "{err}"
        );
    }

    #[test]
    fn smb_negotiate_rejects_dialect_other_than_202() {
        let mut script = script_file(b"dialect");
        script.dialect = 0x0210;
        let running = serve(script);
        let err = open_smb_range(&url_for(&running)).expect_err("dialect");
        assert!(err.to_string().contains("SMB 2.0.2 only"), "{err}");
        let seen = snapshot(&running);
        let neg = seen
            .iter()
            .find(|s| s.command == SMB2_NEGOTIATE)
            .expect("negotiate");
        assert_eq!(neg.dialects, vec![DIALECT_202]);
    }

    /// Regression: `RATARMOUNT_SMB_PASSWORD` set, client env unset, Type3 does
    /// not contain that secret.
    #[test]
    fn smb_guest_does_not_send_server_password() {
        let env = EnvGuard::acquire(ENV_KEYS);
        env.set("RATARMOUNT_SMB_PASSWORD", EXPORT_PW);
        env.set("RATARMOUNT_SMB_USER", EXPORT_USER);
        let running = serve(script_file(b"guest-bytes"));
        let f = open_smb_range(&url_for(&running)).expect("guest open");
        drop(f);
        let seen = snapshot(&running);
        for s in &seen {
            assert!(
                !bytes_contain(&s.raw, EXPORT_PW),
                "export password bytes were sent (cmd {:#06x})",
                s.command
            );
            assert!(
                !bytes_contain(&s.raw, EXPORT_USER),
                "export user bytes were sent (cmd {:#06x})",
                s.command
            );
        }
        let setups: Vec<_> = seen
            .iter()
            .filter(|s| s.command == SMB2_SESSION_SETUP)
            .collect();
        assert_eq!(ntlm_message_type(&setups[1].sec), Some(3));
        let t3 = parse_type3(&setups[1].sec).expect("type3");
        assert!(
            t3.nt_response.len() > 16,
            "guest Type3 must carry an NTLMv2 response, not an empty NT blob"
        );
        let rk = ntlmv2_response_key_nt(EXPORT_PW, &t3.user, &t3.domain);
        let expect = ntlmv2_nt_proof(&rk, CHALLENGE, &t3.nt_response[16..]);
        assert_ne!(
            &t3.nt_response[..16],
            &expect[..],
            "Type3 proves the export-server password"
        );
    }

    #[test]
    fn smb_ntlmv2_signs_when_password_set() {
        let mut garbage = vec![0u8; 80];
        garbage[0] = 0xfe;
        garbage[1..4].copy_from_slice(b"SMB");
        garbage[4..6].copy_from_slice(&64u16.to_le_bytes());
        garbage[48..64].fill(0x5a);
        let unit_key = [7u8; 16];
        smb2_sign_packet(&mut garbage, &unit_key);
        assert!(
            smb2_verify_packet(&garbage, &unit_key),
            "signature must be HMAC-SHA256 over the packet with bytes 48..64 zeroed"
        );
        assert_ne!(&garbage[48..64], &[0x5a; 16]);
        garbage[70] ^= 0xff;
        assert!(!smb2_verify_packet(&garbage, &unit_key));

        let env = EnvGuard::acquire(ENV_KEYS);
        env.set(SMB_CLIENT_USER_ENV, "alice");
        env.set(SMB_CLIENT_PASSWORD_ENV, "client-pw");
        env.set(SMB_CLIENT_DOMAIN_ENV, "CORP");
        env.set("RATARMOUNT_SMB_PASSWORD", EXPORT_PW);
        let mut script = script_file(b"signed-payload");
        script.password = Some("client-pw".into());
        script.challenge = CHALLENGE;
        let running = serve(script);
        let mut f = open_smb_range(&url_for(&running)).expect("signed open");
        let mut buf = vec![0u8; b"signed-payload".len()];
        f.read_exact(&mut buf).expect("signed read");
        assert_eq!(buf, b"signed-payload");
        drop(f);
        let seen = snapshot(&running);
        let setups: Vec<_> = seen
            .iter()
            .filter(|s| s.command == SMB2_SESSION_SETUP)
            .collect();
        let t3 = parse_type3(&setups[1].sec).expect("type3");
        assert_eq!(t3.user, "alice");
        assert_eq!(t3.domain, "CORP");
        assert_eq!(t3.flags & 0x4000_0000, 0, "no KEY_EXCH");
        let rk = ntlmv2_response_key_nt("client-pw", &t3.user, &t3.domain);
        let proof = ntlmv2_nt_proof(&rk, CHALLENGE, &t3.nt_response[16..]);
        assert_eq!(&t3.nt_response[..16], &proof[..]);
        let key = ntlmv2_session_base_key(&rk, &proof);
        let reads: Vec<_> = seen.iter().filter(|s| s.command == SMB2_READ).collect();
        assert!(!reads.is_empty());
        for rd in &reads {
            assert!(
                sig_ok(&rd.raw, &Some(key)),
                "READ signature was not HMAC-SHA256 with bytes 48..64 zeroed"
            );
            let mut mac = HmacSha256::new_from_slice(&key).expect("hmac");
            mac.update(&rd.raw);
            let wrong = mac.finalize().into_bytes();
            assert_ne!(&wrong[..16], &rd.raw[48..64]);
        }
        assert!(seen.iter().all(|s| !bytes_contain(&s.raw, EXPORT_PW)));

        let mut unsigned = reads[0].raw.clone();
        unsigned[48..64].fill(0);
        let flags = u32::from_le_bytes(unsigned[16..20].try_into().unwrap()) & !SMB2_FLAGS_SIGNED;
        unsigned[16..20].copy_from_slice(&flags.to_le_bytes());
        let mut srv = Server::new({
            let mut s = script_file(b"x");
            s.password = Some("client-pw".into());
            s
        });
        srv.authed = true;
        srv.session_key = Some(key);
        let seen_u = Mutex::new(Vec::new());
        let reply = srv.handle(&unsigned, &seen_u).expect("reply");
        assert_eq!(
            header_status(&reply).unwrap(),
            ACCESS_DENIED,
            "unsigned READ must fail"
        );

        // A flipped READ payload or a cleared signature must fail read_at.
        for tamper in [ReadTamper::FlipPayload, ReadTamper::ClearSignature] {
            let mut script = script_file(b"signed-payload");
            script.password = Some("client-pw".into());
            script.challenge = CHALLENGE;
            script.read_tamper = tamper;
            let running = serve(script);
            let mut f = open_smb_range(&url_for(&running)).expect("open before tampered read");
            let mut buf = vec![0u8; b"signed-payload".len()];
            let err = f.read_at(0, &mut buf).expect_err("tampered READ");
            assert!(
                err.to_string().contains("signature"),
                "tamper {tamper:?}: {err}"
            );
            assert!(
                buf.iter().all(|b| *b == 0),
                "read_at returned tampered bytes ({tamper:?}): {buf:?}"
            );
        }
    }

    /// Regression: wrong password, unsigned Type3 failure is `0xC000006D`, not a signature error.
    #[test]
    fn smb_ntlmv2_unsigned_logon_failure_is_nt_status() {
        let env = EnvGuard::acquire(ENV_KEYS);
        env.set(SMB_CLIENT_USER_ENV, "alice");
        env.set(SMB_CLIENT_PASSWORD_ENV, "client-pw");
        env.set(SMB_CLIENT_DOMAIN_ENV, "CORP");
        let mut script = script_file(b"nope");
        script.password = Some("server-does-not-match".into());
        script.challenge = CHALLENGE;
        let running = serve(script);
        let err = open_smb_range(&url_for(&running)).expect_err("wrong password");
        let msg = err.to_string();
        assert!(msg.to_ascii_lowercase().contains("c000006d"), "{msg}");
        assert!(!msg.to_ascii_lowercase().contains("signature"), "{msg}");
    }

    /// Regression: a client password with no username is NTLMv2 user `guest`.
    #[test]
    fn smb_guest_password_without_username() {
        let pw = "only-client-pw";
        let env = EnvGuard::acquire(ENV_KEYS);
        env.set(SMB_CLIENT_PASSWORD_ENV, pw);
        env.set("RATARMOUNT_SMB_PASSWORD", EXPORT_PW);
        env.set("RATARMOUNT_SMB_USER", EXPORT_USER);
        let loc = crate::SmbLocation {
            host: "h".into(),
            port: 445,
            share: "pub".into(),
            path: "a.tar".into(),
            user: None,
            password: None,
            domain: None,
        };
        let args = crate::smbclient_download_args(&loc, std::path::Path::new("/tmp/x"));
        let joined = args.join("\n");
        assert!(
            args.contains(&format!("guest%{pw}")),
            "smbclient argv: {args:?}"
        );
        assert!(!joined.contains(EXPORT_PW), "{args:?}");
        assert!(!joined.contains(EXPORT_USER), "{args:?}");
        let url_user = crate::SmbLocation {
            user: Some("alice".into()),
            password: Some(pw.into()),
            ..loc
        };
        let args = crate::smbclient_download_args(&url_user, std::path::Path::new("/tmp/x"));
        assert!(args.contains(&format!("alice%{pw}")), "{args:?}");
        assert!(
            !args.iter().any(|a| a.starts_with("guest%")),
            "URL user must win: {args:?}"
        );

        let mut script = script_file(b"guest-user");
        script.password = Some(pw.into());
        let running = serve(script);
        let f = open_smb_range(&url_for(&running)).expect("guest-named password open");
        drop(f);
        let seen = snapshot(&running);
        assert!(seen.iter().all(|s| !bytes_contain(&s.raw, EXPORT_PW)));
        assert!(seen.iter().all(|s| !bytes_contain(&s.raw, EXPORT_USER)));
        let setups: Vec<_> = seen
            .iter()
            .filter(|s| s.command == SMB2_SESSION_SETUP)
            .collect();
        let t3 = parse_type3(&setups[1].sec).expect("type3");
        assert_eq!(t3.user, "guest");
        let rk = ntlmv2_response_key_nt(pw, "guest", &t3.domain);
        let proof = ntlmv2_nt_proof(&rk, CHALLENGE, &t3.nt_response[16..]);
        assert_eq!(&t3.nt_response[..16], &proof[..]);
    }

    #[test]
    fn smb_client_does_not_encode_write() {
        let running = serve(script_file(b"abc"));
        let mut f = open_smb_range(&url_for(&running)).expect("open");
        let mut buf = [0u8; 3];
        f.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"abc");
        drop(f);
        let seen = snapshot(&running);
        const ALLOWED: &[u16] = &[
            SMB2_NEGOTIATE,
            SMB2_SESSION_SETUP,
            SMB2_TREE_CONNECT,
            SMB2_CREATE,
            SMB2_CLOSE,
            SMB2_READ,
            SMB2_QUERY_INFO,
        ];
        for s in &seen {
            assert!(
                ALLOWED.contains(&s.command),
                "unexpected SMB command {:#06x}",
                s.command
            );
        }
        let create = seen
            .iter()
            .find(|s| s.command == SMB2_CREATE)
            .expect("create");
        const WRITE_MASK: u32 = 0x0000_0002
            | 0x0000_0004
            | 0x0000_0010
            | 0x0000_0100
            | 0x0000_0040
            | 0x0001_0000
            | 0x4000_0000
            | 0x1000_0000;
        assert_eq!(create.desired_access & WRITE_MASK, 0);
        assert_ne!(create.desired_access, 0);
        assert!(seen.iter().any(|s| s.command == SMB2_READ));
    }
}
