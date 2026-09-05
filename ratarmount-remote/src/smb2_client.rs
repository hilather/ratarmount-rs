//! Blocking SMB 2.0.2 Direct-TCP client packet codec.
//!
//! In-tree `TcpStream` dialect: crates.io `smb` 0.11.x declares rust-version
//! 1.85–1.89 (workspace MSRV is 1.74). Crate-disjoint from `ratarmount-smb`
//! (server) — helpers are duplicated on purpose.
//!
//! Commands: NEGOTIATE, SESSION_SETUP (guest + NTLMv2), TREE_CONNECT, CREATE,
//! READ at offset, QUERY_DIRECTORY, QUERY_INFO, CLOSE. Live Range is
//! [`crate::SmbRangeFile`]; share listing is [`crate::SmbListing`].

use std::io::{self, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use hmac::{Hmac, Mac};
use md4::{Digest, Md4};
use md5::Md5;
use sha2::Sha256;

use crate::{RemoteError, Result};

pub const SMB2_NEGOTIATE: u16 = 0x0000;
pub const SMB2_SESSION_SETUP: u16 = 0x0001;
pub const SMB2_TREE_CONNECT: u16 = 0x0003;
pub const SMB2_CREATE: u16 = 0x0005;
pub const SMB2_CLOSE: u16 = 0x0006;
pub const SMB2_READ: u16 = 0x0008;
pub const SMB2_QUERY_DIRECTORY: u16 = 0x000E;
pub const SMB2_QUERY_INFO: u16 = 0x0010;

pub const SMB2_HEADER_LEN: usize = 64;
pub const SMB2_FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;
pub const SMB2_FLAGS_SIGNED: u32 = 0x0000_0008;

pub const DIALECT_202: u16 = 0x0202;
pub const DIALECT_210: u16 = 0x0210;

pub const NEGOTIATE_SIGNING_ENABLED: u16 = 0x0001;
pub const NEGOTIATE_SIGNING_REQUIRED: u16 = 0x0002;

pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
pub const FILE_OPEN: u32 = 1;
pub const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
/// FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
pub const FILE_GENERIC_READ: u32 = 0x0012_0089;
pub const FILE_SHARE_ALL: u32 = 0x7;

pub const SMB2_RESTART_SCANS: u8 = 0x01;
pub const FILE_DIRECTORY_INFORMATION: u8 = 1;
pub const SMB2_0_INFO_FILE: u8 = 1;
pub const FILE_BASIC_INFORMATION: u8 = 4;

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
pub const STATUS_NO_SUCH_FILE: u32 = 0xC000_000F;
pub const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
pub const STATUS_END_OF_FILE: u32 = 0xC000_0011;
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
pub const STATUS_FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
pub const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
pub const STATUS_LOGON_FAILURE: u32 = 0xC000_006D;
pub const STATUS_BAD_NETWORK_NAME: u32 = 0xC000_00CC;
pub const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;

pub const MAX_FRAME: usize = 8 * 1024 * 1024;
pub const MAX_READ: u32 = 1024 * 1024;
/// QUERY_DIRECTORY OutputBufferLength (not an unbounded slurp).
pub const QUERY_DIR_OUTPUT: u32 = 64 * 1024;
/// Max UTF-16 code units in a QUERY_DIRECTORY FileName (fail-closed).
pub const QUERY_DIR_NAME_MAX: usize = 255;
/// Max dirents across QUERY_DIRECTORY pages (not a silent truncate).
pub const QUERY_DIR_ENTRY_CAP: usize = 100_000;
/// Max QUERY_DIRECTORY round-trips per listing.
pub const QUERY_DIR_PAGE_CAP: usize = 10_000;

type HmacSha256 = Hmac<Sha256>;
type HmacMd5 = Hmac<Md5>;

/// CREATE success: persistent FileId plus advertised size / attributes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Smb2Open {
    pub file_id: [u8; 16],
    pub end_of_file: u64,
    pub file_attributes: u32,
}

impl Smb2Open {
    pub fn is_dir(&self) -> bool {
        self.file_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
    }
}

/// Depth-1 QUERY_DIRECTORY row (`FileDirectoryInformation`).
#[derive(Clone, Debug, PartialEq)]
pub struct Smb2Dirent {
    pub name: String,
    pub size: u64,
    pub is_dir: bool,
    pub mtime: f64,
}

#[derive(Clone, Debug)]
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

/// Blocking SMB 2.0.2 client over any `Read + Write` (usually [`TcpStream`]).
pub struct Smb2Client<S> {
    stream: S,
    mid: u64,
    session_id: u64,
    tree_id: u32,
    process_id: u32,
    dialect: u16,
    security_mode: u16,
    max_read_size: u32,
    /// SessionBaseKey after NTLMv2; `None` for unsigned guest.
    session_key: Option<[u8; 16]>,
}

impl<S> std::fmt::Debug for Smb2Client<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Smb2Client")
            .field("dialect", &self.dialect)
            .field("session_id", &self.session_id)
            .field("tree_id", &self.tree_id)
            .field("security_mode", &self.security_mode)
            .field("max_read_size", &self.max_read_size)
            .field("signed", &self.session_key.is_some())
            .finish_non_exhaustive()
    }
}

impl Smb2Client<TcpStream> {
    /// Connect to `addr` (Direct TCP, typically port 445). Handshake is separate.
    pub fn connect(addr: SocketAddr) -> Result<Self> {
        Self::connect_timeout(addr, Duration::from_secs(15))
    }

    pub fn connect_timeout(addr: SocketAddr, timeout: Duration) -> Result<Self> {
        let stream = TcpStream::connect_timeout(&addr, timeout)
            .map_err(|e| RemoteError::Smb(format!("SMB connect {addr} failed: {e}")))?;
        stream.set_nodelay(true).ok();
        stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(30))).ok();
        Ok(Self::new(stream))
    }

    /// Best-effort CLOSE then TCP shutdown. Short I/O timeout so Drop cannot stall 30s.
    pub fn close_and_shutdown(&mut self, file_id: [u8; 16]) {
        const DROP_IO: Duration = Duration::from_millis(250);
        let _ = self.stream.set_read_timeout(Some(DROP_IO));
        let _ = self.stream.set_write_timeout(Some(DROP_IO));
        let _ = self.close(file_id);
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
    }
}

impl<S: Read + Write> Smb2Client<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            mid: 0,
            session_id: 0,
            tree_id: 0,
            process_id: 0xfeff,
            dialect: 0,
            security_mode: 0,
            max_read_size: MAX_READ,
            session_key: None,
        }
    }

    pub fn dialect(&self) -> u16 {
        self.dialect
    }

    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    pub fn tree_id(&self) -> u32 {
        self.tree_id
    }

    pub fn max_read_size(&self) -> u32 {
        self.max_read_size
    }

    pub fn signing_required(&self) -> bool {
        self.security_mode & NEGOTIATE_SIGNING_REQUIRED != 0
    }

    /// NEGOTIATE dialects 2.0.2 and 2.1. Returns the selected dialect.
    pub fn negotiate(&mut self) -> Result<u16> {
        let mut body = vec![0u8; 36];
        body[0..2].copy_from_slice(&36u16.to_le_bytes());
        body[2..4].copy_from_slice(&2u16.to_le_bytes());
        body[4..6].copy_from_slice(&NEGOTIATE_SIGNING_ENABLED.to_le_bytes());
        body.extend_from_slice(&DIALECT_202.to_le_bytes());
        body.extend_from_slice(&DIALECT_210.to_le_bytes());
        let (h, body) = self.roundtrip(SMB2_NEGOTIATE, &body)?;
        if h.status == STATUS_NOT_SUPPORTED {
            return Err(status_err(
                h.status,
                "NEGOTIATE: server dialect not SMB 2.0.2/2.1",
            ));
        }
        check_status(h.status, "NEGOTIATE")?;
        if body.len() < 36 {
            return Err(RemoteError::Smb("NEGOTIATE response truncated".into()));
        }
        let security_mode = u16_at(&body, 2)?;
        let dialect = u16_at(&body, 4)?;
        if dialect != DIALECT_202 && dialect != DIALECT_210 {
            return Err(RemoteError::Smb(format!(
                "NEGOTIATE: unsupported dialect {dialect:#06x} (need 2.0.2/2.1)"
            )));
        }
        let max_read_size = u32_at(&body, 32)?;
        if max_read_size == 0 {
            return Err(RemoteError::Smb("NEGOTIATE MaxReadSize is 0".into()));
        }
        self.dialect = dialect;
        self.security_mode = security_mode;
        self.max_read_size = max_read_size.min(MAX_READ);
        Ok(dialect)
    }

    /// Two-leg SESSION_SETUP with empty user (guest). Unsigned after success.
    pub fn session_setup_guest(&mut self) -> Result<()> {
        if self.signing_required() {
            return Err(RemoteError::Smb(
                "NEGOTIATE SIGNING_REQUIRED; guest session is unsigned — use NTLMv2".into(),
            ));
        }
        let t1 = ntlm_type1();
        let (h, _) = self.session_setup_sec(&t1)?;
        if h.status != STATUS_MORE_PROCESSING_REQUIRED {
            return Err(status_err(h.status, "SESSION_SETUP Type1 (guest)"));
        }
        self.session_id = h.session_id;
        let t3 = ntlm_type3_guest();
        let (h, _) = self.session_setup_sec(&t3)?;
        check_status(h.status, "SESSION_SETUP Type3 (guest)")?;
        self.session_id = h.session_id;
        self.session_key = None;
        Ok(())
    }

    /// Two-leg SESSION_SETUP with NTLMv2 NT proof. Subsequent PDUs are signed.
    pub fn session_setup_ntlmv2(
        &mut self,
        user: &str,
        domain: &str,
        password: &str,
    ) -> Result<[u8; 16]> {
        let t1 = ntlm_type1();
        let (h, body) = self.session_setup_sec(&t1)?;
        if h.status != STATUS_MORE_PROCESSING_REQUIRED {
            return Err(status_err(h.status, "SESSION_SETUP Type1 (NTLMv2)"));
        }
        self.session_id = h.session_id;
        let sec = session_setup_sec_buf(&body)?;
        let challenge = ntlm_type2_challenge(&sec).ok_or_else(|| {
            RemoteError::Smb("SESSION_SETUP Type2 missing ServerChallenge".into())
        })?;
        let target_info = ntlm_type2_target_info(&sec).unwrap_or_default();
        let (t3, key) = ntlm_type3_v2(user, domain, password, challenge, &target_info);
        // Type3 request is unsigned (session key not installed yet).
        let (h, _, raw) = self.exchange(SMB2_SESSION_SETUP, &encode_session_setup_body(&t3))?;
        if h.status != STATUS_SUCCESS {
            self.session_key = None;
            return Err(status_err(h.status, "SESSION_SETUP Type3 (NTLMv2)"));
        }
        // Verify Type3 SUCCESS against the just-computed SessionBaseKey before install.
        if !smb2_verify_packet(&raw, &key) {
            return Err(RemoteError::Smb(
                "SESSION_SETUP Type3 SUCCESS unsigned or signature mismatch".into(),
            ));
        }
        self.session_id = h.session_id;
        self.session_key = Some(key);
        Ok(key)
    }

    /// TREE_CONNECT `\\host\share`.
    pub fn tree_connect(&mut self, host: &str, share: &str) -> Result<u32> {
        let unc = format!(r"\\{host}\{share}");
        let path = encode_utf16le(&unc);
        let mut body = vec![0u8; 8];
        body[0..2].copy_from_slice(&9u16.to_le_bytes());
        let off = (SMB2_HEADER_LEN + 8) as u16;
        body[4..6].copy_from_slice(&off.to_le_bytes());
        body[6..8].copy_from_slice(&(path.len() as u16).to_le_bytes());
        body.extend_from_slice(&path);
        let (h, _) = self.roundtrip(SMB2_TREE_CONNECT, &body)?;
        check_status(h.status, "TREE_CONNECT")?;
        self.tree_id = h.tree_id;
        Ok(h.tree_id)
    }

    /// CREATE/OPEN a file (FILE_OPEN, non-directory, generic read).
    pub fn create(&mut self, name: &str) -> Result<Smb2Open> {
        self.create_with(name, FILE_NON_DIRECTORY_FILE, FILE_ATTRIBUTE_NORMAL)
    }

    /// CREATE/OPEN a directory (FILE_DIRECTORY_FILE). Empty `name` is the share root.
    pub fn create_dir(&mut self, name: &str) -> Result<Smb2Open> {
        self.create_with(name, FILE_DIRECTORY_FILE, FILE_ATTRIBUTE_DIRECTORY)
    }

    fn create_with(
        &mut self,
        name: &str,
        create_options: u32,
        attributes: u32,
    ) -> Result<Smb2Open> {
        let raw = encode_utf16le(name);
        let mut body = vec![0u8; 56];
        body[0..2].copy_from_slice(&57u16.to_le_bytes());
        body[4..8].copy_from_slice(&2u32.to_le_bytes()); // Impersonation
        body[24..28].copy_from_slice(&FILE_GENERIC_READ.to_le_bytes());
        body[28..32].copy_from_slice(&attributes.to_le_bytes());
        body[32..36].copy_from_slice(&FILE_SHARE_ALL.to_le_bytes());
        body[36..40].copy_from_slice(&FILE_OPEN.to_le_bytes());
        body[40..44].copy_from_slice(&create_options.to_le_bytes());
        let off = (SMB2_HEADER_LEN + 56) as u16;
        body[44..46].copy_from_slice(&off.to_le_bytes());
        body[46..48].copy_from_slice(&(raw.len() as u16).to_le_bytes());
        body.extend_from_slice(&raw);
        let (h, b) = self.roundtrip(SMB2_CREATE, &body)?;
        check_status(h.status, "CREATE")?;
        if b.len() < 80 {
            return Err(RemoteError::Smb("CREATE response truncated".into()));
        }
        let end_of_file = u64_at(&b, 48)?;
        let file_attributes = u32_at(&b, 56)?;
        let mut file_id = [0u8; 16];
        file_id.copy_from_slice(&b[64..80]);
        Ok(Smb2Open {
            file_id,
            end_of_file,
            file_attributes,
        })
    }

    /// One QUERY_DIRECTORY page. Empty Vec is end-of-listing, not a dialect miss.
    pub fn query_directory(&mut self, file_id: [u8; 16], restart: bool) -> Result<Vec<Smb2Dirent>> {
        let pattern = encode_utf16le("*");
        let mut body = vec![0u8; 32];
        body[0..2].copy_from_slice(&33u16.to_le_bytes());
        body[2] = FILE_DIRECTORY_INFORMATION;
        body[3] = if restart { SMB2_RESTART_SCANS } else { 0 };
        body[8..24].copy_from_slice(&file_id);
        let off = (SMB2_HEADER_LEN + 32) as u16;
        body[24..26].copy_from_slice(&off.to_le_bytes());
        body[26..28].copy_from_slice(&(pattern.len() as u16).to_le_bytes());
        body[28..32].copy_from_slice(&QUERY_DIR_OUTPUT.to_le_bytes());
        body.extend_from_slice(&pattern);
        let (h, b) = self.roundtrip(SMB2_QUERY_DIRECTORY, &body)?;
        if h.status == STATUS_NO_MORE_FILES || h.status == STATUS_NO_SUCH_FILE {
            return Ok(Vec::new());
        }
        check_status(h.status, "QUERY_DIRECTORY")?;
        parse_query_directory_output(&b)
    }

    /// Loop QUERY_DIRECTORY until NO_MORE_FILES. Caps entries/pages; never silent-truncate.
    pub fn query_directory_all(&mut self, file_id: [u8; 16]) -> Result<Vec<Smb2Dirent>> {
        let mut out = Vec::new();
        let mut restart = true;
        for _ in 0..QUERY_DIR_PAGE_CAP {
            let page = self.query_directory(file_id, restart)?;
            restart = false;
            if page.is_empty() {
                return Ok(out);
            }
            if out.len().saturating_add(page.len()) > QUERY_DIR_ENTRY_CAP {
                return Err(RemoteError::Smb(format!(
                    "QUERY_DIRECTORY too large (>{QUERY_DIR_ENTRY_CAP} entries); \
                     listing is not silently truncated"
                )));
            }
            out.extend(page);
        }
        Err(RemoteError::Smb(format!(
            "QUERY_DIRECTORY exceeded {QUERY_DIR_PAGE_CAP} pages; listing is not silently truncated"
        )))
    }

    /// CREATE directory + QUERY_DIRECTORY pages + CLOSE.
    pub fn list_directory(&mut self, name: &str) -> Result<Vec<Smb2Dirent>> {
        let open = self.create_dir(name)?;
        let listed = self.query_directory_all(open.file_id);
        let _ = self.close(open.file_id);
        listed
    }

    /// QUERY_INFO FileBasicInformation (attributes).
    pub fn query_info_basic(&mut self, file_id: [u8; 16]) -> Result<u32> {
        let mut body = vec![0u8; 40];
        body[0..2].copy_from_slice(&41u16.to_le_bytes());
        body[2] = SMB2_0_INFO_FILE;
        body[3] = FILE_BASIC_INFORMATION;
        body[4..8].copy_from_slice(&40u32.to_le_bytes());
        body[24..40].copy_from_slice(&file_id);
        let (h, b) = self.roundtrip(SMB2_QUERY_INFO, &body)?;
        check_status(h.status, "QUERY_INFO")?;
        if b.len() < 8 {
            return Err(RemoteError::Smb("QUERY_INFO response truncated".into()));
        }
        let off = u16_at(&b, 2)? as usize;
        let len = u32_at(&b, 4)? as usize;
        if len < 40 {
            return Err(RemoteError::Smb(
                "QUERY_INFO FileBasicInformation truncated".into(),
            ));
        }
        let start = off.saturating_sub(SMB2_HEADER_LEN);
        let buf = b
            .get(start..start + len)
            .ok_or_else(|| RemoteError::Smb("QUERY_INFO OutputBuffer out of range".into()))?;
        u32_at(buf, 32)
    }

    /// SMB2 READ at `offset`. Short SUCCESS is not EOF; [`STATUS_END_OF_FILE`] is.
    ///
    /// `Length` is capped to the negotiated `MaxReadSize` (and [`MAX_READ`]).
    /// SUCCESS with `DataLength == 0` while a positive length was requested is a
    /// protocol error — only `STATUS_END_OF_FILE` is EOF.
    pub fn read_at(&mut self, file_id: [u8; 16], offset: u64, length: u32) -> Result<Vec<u8>> {
        if length == 0 {
            return Ok(Vec::new());
        }
        let cap = if self.max_read_size == 0 {
            MAX_READ
        } else {
            self.max_read_size.min(MAX_READ)
        };
        let length = length.min(cap);
        let mut body = vec![0u8; 48];
        body[0..2].copy_from_slice(&49u16.to_le_bytes());
        body[4..8].copy_from_slice(&length.to_le_bytes());
        body[8..16].copy_from_slice(&offset.to_le_bytes());
        body[16..32].copy_from_slice(&file_id);
        let (h, b) = self.roundtrip(SMB2_READ, &body)?;
        if h.status == STATUS_END_OF_FILE {
            return Ok(Vec::new());
        }
        check_status(h.status, "READ")?;
        if b.len() < 8 {
            return Err(RemoteError::Smb("READ response truncated".into()));
        }
        let data_off = b[2] as usize;
        let data_len = u32_at(&b, 4)? as usize;
        if data_len == 0 {
            return Err(RemoteError::Smb(
                "READ SUCCESS DataLength 0 is not EOF (need STATUS_END_OF_FILE)".into(),
            ));
        }
        let start = data_off.saturating_sub(SMB2_HEADER_LEN);
        b.get(start..start + data_len)
            .map(|s| s.to_vec())
            .ok_or_else(|| RemoteError::Smb("READ DataOffset/Length out of range".into()))
    }

    pub fn close(&mut self, file_id: [u8; 16]) -> Result<()> {
        let mut body = vec![0u8; 24];
        body[0..2].copy_from_slice(&24u16.to_le_bytes());
        body[8..24].copy_from_slice(&file_id);
        let (h, _) = self.roundtrip(SMB2_CLOSE, &body)?;
        check_status(h.status, "CLOSE")?;
        Ok(())
    }

    fn session_setup_sec(&mut self, sec: &[u8]) -> Result<(Smb2Header, Vec<u8>)> {
        self.roundtrip(SMB2_SESSION_SETUP, &encode_session_setup_body(sec))
    }

    fn roundtrip(&mut self, command: u16, body: &[u8]) -> Result<(Smb2Header, Vec<u8>)> {
        let (h, body, raw) = self.exchange(command, body)?;
        if let Some(key) = self.session_key {
            if !smb2_verify_packet(&raw, &key) {
                return Err(RemoteError::Smb(
                    "SMB2 response unsigned or signature mismatch".into(),
                ));
            }
        }
        Ok((h, body))
    }

    fn exchange(&mut self, command: u16, body: &[u8]) -> Result<(Smb2Header, Vec<u8>, Vec<u8>)> {
        let h = self.next_header(command);
        let mut pkt = encode_packet(&h, body);
        if let Some(key) = self.session_key {
            smb2_sign_packet(&mut pkt, &key);
        }
        self.stream
            .write_all(&encode_nbss(&pkt))
            .map_err(|e| RemoteError::Smb(format!("SMB write: {e}")))?;
        self.stream
            .flush()
            .map_err(|e| RemoteError::Smb(format!("SMB flush: {e}")))?;
        let raw = read_smb2_frame(&mut self.stream)?;
        let rh = parse_smb2_header(&raw)?;
        if rh.flags & SMB2_FLAGS_SERVER_TO_REDIR == 0 {
            return Err(RemoteError::Smb(
                "SMB2 response missing SERVER_TO_REDIR flag".into(),
            ));
        }
        let body = if raw.len() > SMB2_HEADER_LEN {
            raw[SMB2_HEADER_LEN..].to_vec()
        } else {
            Vec::new()
        };
        Ok((rh, body, raw))
    }

    fn next_header(&mut self, command: u16) -> Smb2Header {
        let h = Smb2Header {
            credit_charge: 1,
            status: 0,
            command,
            credits: 1,
            flags: 0,
            next_command: 0,
            message_id: self.mid,
            process_id: self.process_id,
            tree_id: self.tree_id,
            session_id: self.session_id,
        };
        self.mid += 1;
        h
    }
}

fn encode_session_setup_body(sec: &[u8]) -> Vec<u8> {
    let mut body = vec![0u8; 24];
    body[0..2].copy_from_slice(&25u16.to_le_bytes());
    body[3] = NEGOTIATE_SIGNING_ENABLED as u8;
    let off = (SMB2_HEADER_LEN + 24) as u16;
    body[12..14].copy_from_slice(&off.to_le_bytes());
    body[14..16].copy_from_slice(&(sec.len() as u16).to_le_bytes());
    body.extend_from_slice(sec);
    body
}

fn session_setup_sec_buf(body: &[u8]) -> Result<Vec<u8>> {
    if body.len() < 8 {
        return Err(RemoteError::Smb("SESSION_SETUP response truncated".into()));
    }
    let off = u16_at(body, 4)? as usize;
    let len = u16_at(body, 6)? as usize;
    if len == 0 {
        return Ok(Vec::new());
    }
    let start = off.saturating_sub(SMB2_HEADER_LEN);
    body.get(start..start + len)
        .map(|s| s.to_vec())
        .ok_or_else(|| RemoteError::Smb("SESSION_SETUP SecurityBuffer out of range".into()))
}

fn check_status(status: u32, op: &str) -> Result<()> {
    if status == STATUS_SUCCESS {
        Ok(())
    } else {
        Err(status_err(status, op))
    }
}

fn nt_status_name(status: u32) -> Option<&'static str> {
    Some(match status {
        STATUS_SUCCESS => "SUCCESS",
        STATUS_NO_MORE_FILES => "NO_MORE_FILES",
        STATUS_NO_SUCH_FILE => "NO_SUCH_FILE",
        STATUS_MORE_PROCESSING_REQUIRED => "MORE_PROCESSING_REQUIRED",
        STATUS_END_OF_FILE => "END_OF_FILE",
        STATUS_ACCESS_DENIED => "ACCESS_DENIED",
        STATUS_OBJECT_NAME_NOT_FOUND => "OBJECT_NAME_NOT_FOUND",
        STATUS_FILE_IS_A_DIRECTORY => "FILE_IS_A_DIRECTORY",
        STATUS_NOT_SUPPORTED => "NOT_SUPPORTED",
        STATUS_LOGON_FAILURE => "LOGON_FAILURE",
        STATUS_BAD_NETWORK_NAME => "BAD_NETWORK_NAME",
        STATUS_NOT_A_DIRECTORY => "NOT_A_DIRECTORY",
        _ => return None,
    })
}

fn status_err(status: u32, op: &str) -> RemoteError {
    match nt_status_name(status) {
        Some(name) => RemoteError::Smb(format!("{op} NTSTATUS {status:#010x} ({name})")),
        None => RemoteError::Smb(format!("{op} NTSTATUS {status:#010x}")),
    }
}

fn encode_nbss(payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut out = Vec::with_capacity(4 + n);
    out.push(0);
    out.push(((n >> 16) & 0xff) as u8);
    out.push(((n >> 8) & 0xff) as u8);
    out.push((n & 0xff) as u8);
    out.extend_from_slice(payload);
    out
}

fn decode_nbss_len(hdr: [u8; 4]) -> io::Result<usize> {
    if hdr[0] != 0 {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "SMB Direct TCP type must be 0",
        ));
    }
    let n = ((hdr[1] as usize) << 16) | ((hdr[2] as usize) << 8) | (hdr[3] as usize);
    if n == 0 || n > MAX_FRAME {
        return Err(io::Error::new(ErrorKind::InvalidData, "SMB frame length"));
    }
    Ok(n)
}

fn read_smb2_frame<R: Read>(r: &mut R) -> Result<Vec<u8>> {
    let mut nb = [0u8; 4];
    r.read_exact(&mut nb)
        .map_err(|e| RemoteError::Smb(format!("SMB NBSS header: {e}")))?;
    let n = decode_nbss_len(nb).map_err(|e| RemoteError::Smb(e.to_string()))?;
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)
        .map_err(|e| RemoteError::Smb(format!("SMB frame body: {e}")))?;
    Ok(buf)
}

fn parse_smb2_header(buf: &[u8]) -> Result<Smb2Header> {
    if buf.len() < SMB2_HEADER_LEN {
        return Err(RemoteError::Smb("SMB2 header truncated".into()));
    }
    if buf[0] != 0xfe || &buf[1..4] != b"SMB" {
        return Err(RemoteError::Smb("not SMB2".into()));
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

fn encode_packet(header: &Smb2Header, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SMB2_HEADER_LEN + body.len());
    out.extend_from_slice(&encode_smb2_header(header));
    out.extend_from_slice(body);
    out
}

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

fn smb2_verify_packet(msg: &[u8], session_key: &[u8; 16]) -> bool {
    if msg.len() < SMB2_HEADER_LEN {
        return false;
    }
    let Ok(flags) = u32_le(msg, 16) else {
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

fn u16_at(b: &[u8], o: usize) -> Result<u16> {
    let s = b
        .get(o..o + 2)
        .ok_or_else(|| RemoteError::Smb("truncated u16".into()))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

fn u32_at(b: &[u8], o: usize) -> Result<u32> {
    let s = b
        .get(o..o + 4)
        .ok_or_else(|| RemoteError::Smb("truncated u32".into()))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

fn u64_at(b: &[u8], o: usize) -> Result<u64> {
    let s = b
        .get(o..o + 8)
        .ok_or_else(|| RemoteError::Smb("truncated u64".into()))?;
    Ok(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

fn u32_le(b: &[u8], o: usize) -> std::result::Result<u32, ()> {
    b.get(o..o + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
        .ok_or(())
}

fn encode_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

fn decode_utf16le(bytes: &[u8]) -> String {
    let even = bytes.len() & !1;
    let u: Vec<u16> = bytes[..even]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u)
}

/// FILETIME (100-ns since 1601) → unix seconds. Zero / pre-epoch → 0.0.
fn filetime_to_unix_float(ft: u64) -> f64 {
    const EPOCH_DIFF: u64 = 116444736000000000;
    if ft < EPOCH_DIFF {
        return 0.0;
    }
    (ft - EPOCH_DIFF) as f64 / 10_000_000.0
}

fn parse_query_directory_output(body: &[u8]) -> Result<Vec<Smb2Dirent>> {
    if body.len() < 8 {
        return Err(RemoteError::Smb(
            "QUERY_DIRECTORY response truncated".into(),
        ));
    }
    let off = u16_at(body, 2)? as usize;
    let len = u32_at(body, 4)? as usize;
    if len > QUERY_DIR_OUTPUT as usize {
        return Err(RemoteError::Smb(format!(
            "QUERY_DIRECTORY OutputBufferLength {len} exceeds {QUERY_DIR_OUTPUT}"
        )));
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    let start = off.saturating_sub(SMB2_HEADER_LEN);
    let buf = body
        .get(start..start + len)
        .ok_or_else(|| RemoteError::Smb("QUERY_DIRECTORY OutputBuffer out of range".into()))?;
    parse_file_directory_information(buf)
}

fn parse_file_directory_information(buf: &[u8]) -> Result<Vec<Smb2Dirent>> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut steps = 0usize;
    while pos < buf.len() {
        steps += 1;
        if steps > QUERY_DIR_ENTRY_CAP {
            return Err(RemoteError::Smb(format!(
                "QUERY_DIRECTORY too large (>{QUERY_DIR_ENTRY_CAP} entries); \
                 listing is not silently truncated"
            )));
        }
        if buf.len() - pos < 64 {
            return Err(RemoteError::Smb(
                "QUERY_DIRECTORY FileDirectoryInformation truncated".into(),
            ));
        }
        let next = u32_at(buf, pos)? as usize;
        let name_len = u32_at(buf, pos + 60)? as usize;
        if name_len > QUERY_DIR_NAME_MAX.saturating_mul(2) {
            return Err(RemoteError::Smb(format!(
                "QUERY_DIRECTORY FileNameLength {name_len} exceeds {} bytes",
                QUERY_DIR_NAME_MAX * 2
            )));
        }
        let name_start = pos + 64;
        let name_end = name_start.saturating_add(name_len);
        if name_end > buf.len() {
            return Err(RemoteError::Smb(
                "QUERY_DIRECTORY FileName out of range".into(),
            ));
        }
        let size = u64_at(buf, pos + 40)?;
        let attrs = u32_at(buf, pos + 56)?;
        let mtime = filetime_to_unix_float(u64_at(buf, pos + 24)?);
        let name = decode_utf16le(&buf[name_start..name_end]);
        if name != "." && name != ".." && !name.is_empty() {
            if out.len() >= QUERY_DIR_ENTRY_CAP {
                return Err(RemoteError::Smb(format!(
                    "QUERY_DIRECTORY too large (>{QUERY_DIR_ENTRY_CAP} entries); \
                     listing is not silently truncated"
                )));
            }
            out.push(Smb2Dirent {
                name,
                size,
                is_dir: attrs & FILE_ATTRIBUTE_DIRECTORY != 0,
                mtime,
            });
        }
        if next == 0 {
            break;
        }
        if next < 64 {
            return Err(RemoteError::Smb(
                "QUERY_DIRECTORY NextEntryOffset too small".into(),
            ));
        }
        let new_pos = pos.saturating_add(next);
        if new_pos <= pos || new_pos > buf.len() {
            return Err(RemoteError::Smb(
                "QUERY_DIRECTORY NextEntryOffset out of range".into(),
            ));
        }
        pos = new_pos;
    }
    Ok(out)
}

fn extract_ntlm(buf: &[u8]) -> Option<&[u8]> {
    buf.windows(8)
        .position(|w| w == b"NTLMSSP\0")
        .map(|i| &buf[i..])
}

fn ntlm_type(buf: &[u8]) -> Option<u32> {
    let n = extract_ntlm(buf)?;
    if n.len() < 12 {
        return None;
    }
    u32_at(n, 8).ok()
}

fn ntlm_type2_challenge(buf: &[u8]) -> Option<[u8; 8]> {
    let n = extract_ntlm(buf)?;
    if ntlm_type(n) != Some(2) || n.len() < 32 {
        return None;
    }
    let mut c = [0u8; 8];
    c.copy_from_slice(&n[24..32]);
    Some(c)
}

fn ntlm_type2_target_info(buf: &[u8]) -> Option<Vec<u8>> {
    let n = extract_ntlm(buf)?;
    if ntlm_type(n) != Some(2) || n.len() < 48 {
        return None;
    }
    let len = u16_at(n, 40).ok()? as usize;
    let off = u32_at(n, 44).ok()? as usize;
    n.get(off..off + len).map(|s| s.to_vec())
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

fn ntlm_type3_guest() -> Vec<u8> {
    ntlm_type3_authenticate("", "", &[], 0x0000_0001 | 0x0000_0200, 0)
}

fn ntlm_type3_authenticate(
    user: &str,
    domain: &str,
    nt_response: &[u8],
    flags: u32,
    session_key_len: u16,
) -> Vec<u8> {
    let unicode = flags & 1 != 0;
    let user_raw = if unicode {
        encode_utf16le(user)
    } else {
        user.as_bytes().to_vec()
    };
    let domain_raw = if unicode {
        encode_utf16le(domain)
    } else {
        domain.as_bytes().to_vec()
    };
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
    b.extend_from_slice(nt_response);
    b.extend_from_slice(&domain_raw);
    b.extend_from_slice(&user_raw);
    if session_key_len != 0 {
        b.resize(b.len() + session_key_len as usize, 0);
    }
    b
}

fn copy16(bytes: impl AsRef<[u8]>) -> [u8; 16] {
    let b = bytes.as_ref();
    let mut out = [0u8; 16];
    out.copy_from_slice(&b[..16]);
    out
}

fn hmac_md5(key: &[u8], data: &[u8]) -> [u8; 16] {
    let mut mac = HmacMd5::new_from_slice(key).expect("HMAC-MD5 key");
    mac.update(data);
    copy16(mac.finalize().into_bytes())
}

fn ntowfv1(password: &str) -> [u8; 16] {
    let mut h = Md4::new();
    h.update(encode_utf16le(password));
    copy16(h.finalize())
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

/// MS-NLMP 2.2.2.7 `NTLMv2_CLIENT_CHALLENGE` header (28 bytes). AvPairs follow.
/// ClientChallenge is at offset 16; Reserved3 occupies [24..28].
const NTLMV2_CLIENT_CHALLENGE_HDR: [u8; 28] = [
    0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x00, 0x00, 0x00, 0x00,
];

fn ntlm_type3_v2(
    user: &str,
    domain: &str,
    password: &str,
    challenge: [u8; 8],
    target_info: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    const FLAGS: u32 = 0x2088_8201;
    let mut temp = NTLMV2_CLIENT_CHALLENGE_HDR.to_vec();
    temp.extend_from_slice(target_info);
    let rk = ntlmv2_response_key_nt(password, user, domain);
    let proof = ntlmv2_nt_proof(&rk, challenge, &temp);
    let skey = ntlmv2_session_base_key(&rk, &proof);
    let mut nt = Vec::with_capacity(16 + temp.len());
    nt.extend_from_slice(&proof);
    nt.extend_from_slice(&temp);
    (ntlm_type3_authenticate(user, domain, &nt, FLAGS, 0), skey)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::io::ErrorKind;
    use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    pub(crate) const OFFSET_1MIB: u64 = 1024 * 1024;
    pub(crate) const TAIL: &[u8] = b"smb2-range-tail!";
    pub(crate) const HEAD: &[u8] = b"smb2head";
    pub(crate) const FILE_NAME: &str = "payload.bin";
    pub(crate) const SHARE: &str = "data";
    pub(crate) const DIR_FILE_A: &str = "a.tar";
    pub(crate) const DIR_FILE_A_BODY: &[u8] = b"hello-world";
    pub(crate) const DIR_SUB: &str = "sub";
    const CHALLENGE: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    const NTLMSSP_NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;

    struct NtlmType3 {
        user: String,
        domain: String,
        nt_response: Vec<u8>,
        flags: u32,
        session_key_len: u16,
    }

    fn ntlm_sec_buf(n: &[u8], len_off: usize, off_off: usize) -> Option<&[u8]> {
        let len = u16_at(n, len_off).ok()? as usize;
        let off = u32_at(n, off_off).ok()? as usize;
        n.get(off..off + len)
    }

    fn parse_ntlm_type3(buf: &[u8]) -> Option<NtlmType3> {
        let n = extract_ntlm(buf)?;
        if n.len() < 64 {
            return None;
        }
        if u32_at(n, 8).ok()? != 3 {
            return None;
        }
        let flags = u32_at(n, 60).ok()?;
        let unicode = flags & 1 != 0;
        let nt_response = ntlm_sec_buf(n, 20, 24)?.to_vec();
        let domain_raw = ntlm_sec_buf(n, 28, 32)?;
        let user_raw = ntlm_sec_buf(n, 36, 40)?;
        let domain = if unicode {
            decode_utf16le(domain_raw)
        } else {
            String::from_utf8_lossy(domain_raw).into_owned()
        };
        let user = if unicode {
            decode_utf16le(user_raw)
        } else {
            String::from_utf8_lossy(user_raw).into_owned()
        };
        let session_key_len = u16_at(n, 52).ok()?;
        Some(NtlmType3 {
            user,
            domain,
            nt_response,
            flags,
            session_key_len,
        })
    }

    fn ntlm_verify_type3(
        t3: &NtlmType3,
        password: &str,
        required_user: Option<&str>,
        server_challenge: [u8; 8],
    ) -> std::result::Result<[u8; 16], u32> {
        if t3.flags & NTLMSSP_NEGOTIATE_KEY_EXCH != 0 || t3.session_key_len != 0 {
            return Err(STATUS_LOGON_FAILURE);
        }
        if t3.nt_response.len() < 16 || t3.nt_response.len() == 24 {
            return Err(STATUS_LOGON_FAILURE);
        }
        if let Some(want) = required_user {
            if !t3.user.eq_ignore_ascii_case(want) {
                return Err(STATUS_LOGON_FAILURE);
            }
        }
        let rk = ntlmv2_response_key_nt(password, &t3.user, &t3.domain);
        let nt_proof = &t3.nt_response[..16];
        let temp = &t3.nt_response[16..];
        let computed = ntlmv2_nt_proof(&rk, server_challenge, temp);
        if !ct_eq(&computed, nt_proof) {
            return Err(STATUS_LOGON_FAILURE);
        }
        Ok(ntlmv2_session_base_key(&rk, nt_proof))
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
        b.extend_from_slice(&name);
        b.extend_from_slice(&av);
        b
    }

    #[derive(Clone, Debug, Default)]
    pub(crate) struct FakeStats {
        pub(crate) reads: Vec<(u64, u32)>,
        creates: Vec<String>,
        pub(crate) query_dirs: usize,
    }

    #[derive(Clone)]
    pub(crate) enum AuthMode {
        Guest,
        Password {
            user: String,
            domain: String,
            password: String,
        },
        RejectDialect,
    }

    #[derive(Clone)]
    pub(crate) struct FakeOpts {
        pub(crate) auth: AuthMode,
        unsigned_read: bool,
        pub(crate) read_data_cap: Option<u32>,
        max_read_size: u32,
        signing_required: bool,
        pub(crate) reject_query_directory: bool,
    }

    impl FakeOpts {
        pub(crate) fn guest() -> Self {
            Self {
                auth: AuthMode::Guest,
                unsigned_read: false,
                read_data_cap: None,
                max_read_size: MAX_READ,
                signing_required: false,
                reject_query_directory: false,
            }
        }

        fn password(user: &str, domain: &str, password: &str) -> Self {
            Self {
                auth: AuthMode::Password {
                    user: user.into(),
                    domain: domain.into(),
                    password: password.into(),
                },
                unsigned_read: false,
                read_data_cap: None,
                max_read_size: MAX_READ,
                signing_required: true,
                reject_query_directory: false,
            }
        }
    }

    pub(crate) struct FakeSmb {
        pub(crate) addr: SocketAddr,
        stats: Arc<Mutex<FakeStats>>,
        stop: Arc<AtomicBool>,
        handle: Option<JoinHandle<()>>,
    }

    impl FakeSmb {
        pub(crate) fn spawn(mode: AuthMode) -> Self {
            match mode {
                AuthMode::Guest => Self::spawn_with(FakeOpts::guest()),
                AuthMode::Password {
                    user,
                    domain,
                    password,
                } => Self::spawn_with(FakeOpts::password(&user, &domain, &password)),
                AuthMode::RejectDialect => Self::spawn_with(FakeOpts {
                    auth: AuthMode::RejectDialect,
                    unsigned_read: false,
                    read_data_cap: None,
                    max_read_size: MAX_READ,
                    signing_required: false,
                    reject_query_directory: false,
                }),
            }
        }

        pub(crate) fn spawn_with(opts: FakeOpts) -> Self {
            let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind fake SMB");
            listener.set_nonblocking(true).ok();
            let addr = listener.local_addr().expect("local addr");
            let stats = Arc::new(Mutex::new(FakeStats::default()));
            let stats2 = Arc::clone(&stats);
            let stop = Arc::new(AtomicBool::new(false));
            let stop2 = Arc::clone(&stop);
            let handle = thread::spawn(move || {
                while !stop2.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let _ = stream.set_nonblocking(false);
                            let _ = handle_conn(stream, opts.clone(), Arc::clone(&stats2));
                        }
                        Err(e)
                            if e.kind() == ErrorKind::WouldBlock
                                || e.kind() == ErrorKind::Interrupted =>
                        {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                addr,
                stats,
                stop,
                handle: Some(handle),
            }
        }

        pub(crate) fn stats(&self) -> FakeStats {
            self.stats.lock().expect("stats").clone()
        }
    }

    impl Drop for FakeSmb {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect_timeout(&self.addr, Duration::from_millis(80));
            if let Some(h) = self.handle.take() {
                let _ = h.join();
            }
        }
    }

    fn payload() -> Vec<u8> {
        let mut v = vec![0u8; OFFSET_1MIB as usize + TAIL.len()];
        v[..HEAD.len()].copy_from_slice(HEAD);
        v[OFFSET_1MIB as usize..].copy_from_slice(TAIL);
        v
    }

    enum OpenObj {
        File(Vec<u8>),
        Dir { path: String, pos: usize },
    }

    struct ConnState {
        session_id: u64,
        tree_id: u32,
        authed: bool,
        ntlm_started: bool,
        require_password: bool,
        user: String,
        domain: String,
        password: String,
        session_key: Option<[u8; 16]>,
        files: HashMap<[u8; 16], OpenObj>,
        next_fid: u64,
        unsigned_read: bool,
        read_data_cap: Option<u32>,
        max_read_size: u32,
        signing_required: bool,
        reject_query_directory: bool,
    }

    fn normalize_name(name: &str) -> String {
        name.replace('\\', "/").trim_matches('/').to_string()
    }

    fn is_dir_path(path: &str) -> bool {
        path.is_empty() || path == DIR_SUB
    }

    fn file_payload(path: &str) -> Option<Vec<u8>> {
        match path {
            FILE_NAME => Some(payload()),
            DIR_FILE_A => Some(DIR_FILE_A_BODY.to_vec()),
            "sub/nested.bin" => Some(b"nest".to_vec()),
            _ => None,
        }
    }

    fn dir_children(path: &str) -> Vec<(String, bool, u64)> {
        match path {
            "" => vec![
                (FILE_NAME.into(), false, OFFSET_1MIB + TAIL.len() as u64),
                (DIR_FILE_A.into(), false, DIR_FILE_A_BODY.len() as u64),
                (DIR_SUB.into(), true, 0),
            ],
            DIR_SUB => vec![("nested.bin".into(), false, 4)],
            _ => Vec::new(),
        }
    }

    fn encode_file_directory_information(
        entries: &[(String, bool, u64)],
        max: usize,
    ) -> (Vec<u8>, usize) {
        let mut rows: Vec<Vec<u8>> = Vec::new();
        let mut out = Vec::new();
        for (name, is_dir, size) in entries {
            let raw = encode_utf16le(name);
            let mut b = Vec::new();
            b.extend_from_slice(&0u32.to_le_bytes());
            b.extend_from_slice(&0u32.to_le_bytes());
            for _ in 0..4 {
                b.extend_from_slice(&0u64.to_le_bytes());
            }
            b.extend_from_slice(&size.to_le_bytes());
            b.extend_from_slice(&size.to_le_bytes());
            let attrs = if *is_dir {
                FILE_ATTRIBUTE_DIRECTORY
            } else {
                FILE_ATTRIBUTE_NORMAL
            };
            b.extend_from_slice(&attrs.to_le_bytes());
            b.extend_from_slice(&(raw.len() as u32).to_le_bytes());
            b.extend_from_slice(&raw);
            let pad = (8 - (b.len() % 8)) % 8;
            b.resize(b.len() + pad, 0);
            if !rows.is_empty() && out.len().saturating_add(b.len()) > max {
                break;
            }
            if rows.is_empty() && b.len() > max {
                break;
            }
            out.extend_from_slice(&b);
            rows.push(b);
        }
        if rows.len() >= 2 {
            let mut pos = 0usize;
            for row in rows.iter().take(rows.len() - 1) {
                let n = row.len() as u32;
                out[pos..pos + 4].copy_from_slice(&n.to_le_bytes());
                pos += row.len();
            }
        }
        (out, rows.len())
    }

    fn handle_conn(
        mut stream: TcpStream,
        opts: FakeOpts,
        stats: Arc<Mutex<FakeStats>>,
    ) -> io::Result<()> {
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
        if matches!(opts.auth, AuthMode::RejectDialect) {
            if let Ok(raw) = read_smb2_frame(&mut stream) {
                if let Ok(h) = parse_smb2_header(&raw) {
                    write_frame(
                        &mut stream,
                        &error_packet_unsigned(&h, STATUS_NOT_SUPPORTED),
                    )?;
                }
            }
            return Ok(());
        }
        let (require_password, user, domain, password) = match opts.auth {
            AuthMode::Guest => (false, String::new(), String::new(), String::new()),
            AuthMode::Password {
                user,
                domain,
                password,
            } => (true, user, domain, password),
            AuthMode::RejectDialect => unreachable!(),
        };
        let mut st = ConnState {
            session_id: 0,
            tree_id: 0,
            authed: false,
            ntlm_started: false,
            require_password,
            user,
            domain,
            password,
            session_key: None,
            files: HashMap::new(),
            next_fid: 1,
            unsigned_read: opts.unsigned_read,
            read_data_cap: opts.read_data_cap,
            max_read_size: opts.max_read_size,
            signing_required: opts.signing_required,
            reject_query_directory: opts.reject_query_directory,
        };
        loop {
            let raw = match read_smb2_frame(&mut stream) {
                Ok(r) => r,
                Err(RemoteError::Smb(msg))
                    if msg.contains("NBSS") || msg.contains("frame body") =>
                {
                    break;
                }
                Err(_) => break,
            };
            let h = match parse_smb2_header(&raw) {
                Ok(h) => h,
                Err(_) => break,
            };
            if let Some(key) = st.session_key {
                if h.command != SMB2_SESSION_SETUP && !smb2_verify_packet(&raw, &key) {
                    write_frame(&mut stream, &error_packet(&h, STATUS_ACCESS_DENIED, &st))?;
                    continue;
                }
            }
            let cmd = h.command;
            let pkt = match cmd {
                SMB2_NEGOTIATE => cmd_negotiate(&h, &st),
                SMB2_SESSION_SETUP => cmd_session_setup(&h, &raw, &mut st),
                SMB2_TREE_CONNECT => cmd_tree_connect(&h, &raw, &mut st),
                SMB2_CREATE => cmd_create(&h, &raw, &mut st, &stats),
                SMB2_READ => cmd_read(&h, &raw, &st, &stats),
                SMB2_QUERY_DIRECTORY => cmd_query_directory(&h, &raw, &mut st, &stats),
                SMB2_QUERY_INFO => cmd_query_info(&h, &raw, &st),
                SMB2_CLOSE => cmd_close(&h, &raw, &mut st),
                _ => error_packet(&h, STATUS_NOT_SUPPORTED, &st),
            };
            write_frame(&mut stream, &pkt)?;
        }
        Ok(())
    }

    fn write_frame(stream: &mut TcpStream, pkt: &[u8]) -> io::Result<()> {
        stream.write_all(&encode_nbss(pkt))?;
        stream.flush()
    }

    fn reply_header(req: &Smb2Header, status: u32, session_id: u64, tree_id: u32) -> Smb2Header {
        Smb2Header {
            credit_charge: req.credit_charge.max(1),
            status,
            command: req.command,
            credits: 1,
            flags: SMB2_FLAGS_SERVER_TO_REDIR,
            next_command: 0,
            message_id: req.message_id,
            process_id: req.process_id,
            tree_id,
            session_id,
        }
    }

    fn error_body() -> Vec<u8> {
        let mut b = vec![0u8; 8];
        b[0..2].copy_from_slice(&9u16.to_le_bytes());
        b
    }

    fn maybe_sign(st: &ConnState, mut pkt: Vec<u8>) -> Vec<u8> {
        if let Some(key) = st.session_key {
            smb2_sign_packet(&mut pkt, &key);
        }
        pkt
    }

    fn error_packet_unsigned(req: &Smb2Header, status: u32) -> Vec<u8> {
        let h = reply_header(req, status, req.session_id, req.tree_id);
        encode_packet(&h, &error_body())
    }

    fn error_packet(req: &Smb2Header, status: u32, st: &ConnState) -> Vec<u8> {
        let h = reply_header(req, status, st.session_id, st.tree_id);
        maybe_sign(st, encode_packet(&h, &error_body()))
    }

    fn cmd_negotiate(req: &Smb2Header, st: &ConnState) -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b[0..2].copy_from_slice(&65u16.to_le_bytes());
        let mode = if st.signing_required {
            NEGOTIATE_SIGNING_ENABLED | NEGOTIATE_SIGNING_REQUIRED
        } else {
            NEGOTIATE_SIGNING_ENABLED
        };
        b[2..4].copy_from_slice(&mode.to_le_bytes());
        b[4..6].copy_from_slice(&DIALECT_202.to_le_bytes());
        b[8..24].copy_from_slice(b"ratarmnt-cli\0\0\0\x02");
        b[28..32].copy_from_slice(&st.max_read_size.to_le_bytes());
        b[32..36].copy_from_slice(&st.max_read_size.to_le_bytes());
        b[36..40].copy_from_slice(&st.max_read_size.to_le_bytes());
        let h = reply_header(req, STATUS_SUCCESS, 0, 0);
        encode_packet(&h, &b)
    }

    fn cmd_session_setup(req: &Smb2Header, raw: &[u8], st: &mut ConnState) -> Vec<u8> {
        let body = &raw[SMB2_HEADER_LEN..];
        if body.len() < 24 {
            return error_packet(req, STATUS_LOGON_FAILURE, st);
        }
        let off = u16::from_le_bytes(body[12..14].try_into().unwrap()) as usize;
        let len = u16::from_le_bytes(body[14..16].try_into().unwrap()) as usize;
        let sec = raw.get(off..off + len).unwrap_or(&[]);
        let typ = ntlm_type(sec).unwrap_or(0);
        if typ == 1 || (typ != 3 && !st.ntlm_started) {
            st.ntlm_started = true;
            st.session_id = 1;
            let t2 = ntlm_type2(CHALLENGE, "RATARMOUNT");
            let mut b = vec![0u8; 8];
            b[0..2].copy_from_slice(&9u16.to_le_bytes());
            let soff = (SMB2_HEADER_LEN + 8) as u16;
            b[4..6].copy_from_slice(&soff.to_le_bytes());
            b[6..8].copy_from_slice(&(t2.len() as u16).to_le_bytes());
            b.extend_from_slice(&t2);
            let h = reply_header(req, STATUS_MORE_PROCESSING_REQUIRED, st.session_id, 0);
            return encode_packet(&h, &b);
        }
        let Some(t3) = parse_ntlm_type3(sec) else {
            return error_packet(req, STATUS_LOGON_FAILURE, st);
        };
        if st.require_password {
            match ntlm_verify_type3(&t3, &st.password, Some(&st.user), CHALLENGE) {
                Ok(key) => {
                    if !t3.domain.eq_ignore_ascii_case(&st.domain) && !st.domain.is_empty() {
                        return error_packet(req, STATUS_LOGON_FAILURE, st);
                    }
                    st.session_key = Some(key);
                    st.authed = true;
                }
                Err(stt) => return error_packet(req, stt, st),
            }
        } else if t3.nt_response.is_empty() {
            st.authed = true;
            st.session_key = None;
        } else {
            return error_packet(req, STATUS_LOGON_FAILURE, st);
        }
        let mut b = vec![0u8; 8];
        b[0..2].copy_from_slice(&9u16.to_le_bytes());
        if !st.require_password {
            b[2..4].copy_from_slice(&1u16.to_le_bytes()); // SESSION_FLAG_IS_GUEST
        }
        let h = reply_header(req, STATUS_SUCCESS, st.session_id, 0);
        let pkt = encode_packet(&h, &b);
        maybe_sign(st, pkt)
    }

    fn cmd_tree_connect(req: &Smb2Header, raw: &[u8], st: &mut ConnState) -> Vec<u8> {
        if !st.authed {
            return error_packet(req, STATUS_ACCESS_DENIED, st);
        }
        let body = &raw[SMB2_HEADER_LEN..];
        if body.len() < 8 {
            return error_packet(req, STATUS_BAD_NETWORK_NAME, st);
        }
        let off = u16::from_le_bytes(body[4..6].try_into().unwrap()) as usize;
        let len = u16::from_le_bytes(body[6..8].try_into().unwrap()) as usize;
        let path = decode_utf16le(raw.get(off..off + len).unwrap_or(&[]));
        let share = path
            .replace('/', "\\")
            .trim_start_matches('\\')
            .split('\\')
            .filter(|s| !s.is_empty())
            .nth(1)
            .unwrap_or("")
            .to_string();
        if !share.eq_ignore_ascii_case(SHARE) {
            return error_packet(req, STATUS_BAD_NETWORK_NAME, st);
        }
        st.tree_id = 1;
        let mut b = vec![0u8; 16];
        b[0..2].copy_from_slice(&16u16.to_le_bytes());
        b[2] = 0x01; // disk
        let h = reply_header(req, STATUS_SUCCESS, st.session_id, st.tree_id);
        maybe_sign(st, encode_packet(&h, &b))
    }

    fn cmd_create(
        req: &Smb2Header,
        raw: &[u8],
        st: &mut ConnState,
        stats: &Arc<Mutex<FakeStats>>,
    ) -> Vec<u8> {
        if !st.authed || st.tree_id == 0 {
            return error_packet(req, STATUS_ACCESS_DENIED, st);
        }
        let body = &raw[SMB2_HEADER_LEN..];
        if body.len() < 56 {
            return error_packet(req, STATUS_OBJECT_NAME_NOT_FOUND, st);
        }
        let name_off = u16::from_le_bytes(body[44..46].try_into().unwrap()) as usize;
        let name_len = u16::from_le_bytes(body[46..48].try_into().unwrap()) as usize;
        let name = decode_utf16le(raw.get(name_off..name_off + name_len).unwrap_or(&[]));
        stats.lock().expect("stats").creates.push(name.clone());
        let n = normalize_name(&name);
        let create_options = u32::from_le_bytes(body[40..44].try_into().unwrap());
        let want_dir = create_options & FILE_DIRECTORY_FILE != 0;
        let want_file = create_options & FILE_NON_DIRECTORY_FILE != 0;
        let (obj, size, attrs) = if is_dir_path(&n) {
            if want_file {
                return error_packet(req, STATUS_FILE_IS_A_DIRECTORY, st);
            }
            (
                OpenObj::Dir { path: n, pos: 0 },
                0u64,
                FILE_ATTRIBUTE_DIRECTORY,
            )
        } else if let Some(data) = file_payload(&n) {
            if want_dir {
                return error_packet(req, STATUS_NOT_A_DIRECTORY, st);
            }
            let size = data.len() as u64;
            (OpenObj::File(data), size, FILE_ATTRIBUTE_NORMAL)
        } else {
            return error_packet(req, STATUS_OBJECT_NAME_NOT_FOUND, st);
        };
        let mut fid = [0u8; 16];
        fid[..8].copy_from_slice(&st.next_fid.to_le_bytes());
        st.next_fid += 1;
        st.files.insert(fid, obj);
        let mut b = vec![0u8; 88];
        b[0..2].copy_from_slice(&89u16.to_le_bytes());
        b[4..8].copy_from_slice(&1u32.to_le_bytes()); // FILE_OPENED
        b[40..48].copy_from_slice(&size.to_le_bytes());
        b[48..56].copy_from_slice(&size.to_le_bytes());
        b[56..60].copy_from_slice(&attrs.to_le_bytes());
        b[64..80].copy_from_slice(&fid);
        let h = reply_header(req, STATUS_SUCCESS, st.session_id, st.tree_id);
        maybe_sign(st, encode_packet(&h, &b))
    }

    fn cmd_read(
        req: &Smb2Header,
        raw: &[u8],
        st: &ConnState,
        stats: &Arc<Mutex<FakeStats>>,
    ) -> Vec<u8> {
        let body = &raw[SMB2_HEADER_LEN..];
        if body.len() < 48 {
            return error_packet(req, STATUS_ACCESS_DENIED, st);
        }
        let length = u32::from_le_bytes(body[4..8].try_into().unwrap());
        let offset = u64::from_le_bytes(body[8..16].try_into().unwrap());
        let mut fid = [0u8; 16];
        fid.copy_from_slice(&body[16..32]);
        stats.lock().expect("stats").reads.push((offset, length));
        let Some(OpenObj::File(data)) = st.files.get(&fid) else {
            return error_packet(req, STATUS_OBJECT_NAME_NOT_FOUND, st);
        };
        if offset >= data.len() as u64 {
            return error_packet(req, STATUS_END_OF_FILE, st);
        }
        let start = offset as usize;
        let mut end = (start + length as usize).min(data.len());
        if let Some(cap) = st.read_data_cap {
            end = start.saturating_add(cap as usize).min(end);
        }
        let slice = &data[start..end];
        let mut b = vec![0u8; 16];
        b[0..2].copy_from_slice(&17u16.to_le_bytes());
        b[2] = (SMB2_HEADER_LEN + 16) as u8;
        b[4..8].copy_from_slice(&(slice.len() as u32).to_le_bytes());
        b.extend_from_slice(slice);
        let h = reply_header(req, STATUS_SUCCESS, st.session_id, st.tree_id);
        let pkt = encode_packet(&h, &b);
        if st.unsigned_read {
            pkt
        } else {
            maybe_sign(st, pkt)
        }
    }

    fn cmd_close(req: &Smb2Header, raw: &[u8], st: &mut ConnState) -> Vec<u8> {
        let body = &raw[SMB2_HEADER_LEN..];
        if body.len() >= 24 {
            let mut fid = [0u8; 16];
            fid.copy_from_slice(&body[8..24]);
            st.files.remove(&fid);
        }
        let mut b = vec![0u8; 60];
        b[0..2].copy_from_slice(&60u16.to_le_bytes());
        let h = reply_header(req, STATUS_SUCCESS, st.session_id, st.tree_id);
        maybe_sign(st, encode_packet(&h, &b))
    }

    fn cmd_query_directory(
        req: &Smb2Header,
        raw: &[u8],
        st: &mut ConnState,
        stats: &Arc<Mutex<FakeStats>>,
    ) -> Vec<u8> {
        if st.reject_query_directory {
            return error_packet(req, STATUS_NOT_SUPPORTED, st);
        }
        let body = &raw[SMB2_HEADER_LEN..];
        if body.len() < 32 {
            return error_packet(req, STATUS_ACCESS_DENIED, st);
        }
        let flags = body[3];
        let mut fid = [0u8; 16];
        fid.copy_from_slice(&body[8..24]);
        let output_len =
            u32::from_le_bytes(body[28..32].try_into().unwrap()).min(QUERY_DIR_OUTPUT) as usize;
        stats.lock().expect("stats").query_dirs += 1;
        let (path, pos) = match st.files.get_mut(&fid) {
            Some(OpenObj::Dir { path, pos }) => {
                if flags & SMB2_RESTART_SCANS != 0 {
                    *pos = 0;
                }
                (path.clone(), *pos)
            }
            Some(OpenObj::File(_)) => return error_packet(req, STATUS_NOT_A_DIRECTORY, st),
            None => return error_packet(req, STATUS_OBJECT_NAME_NOT_FOUND, st),
        };
        let kids = dir_children(&path);
        if pos >= kids.len() {
            return error_packet(req, STATUS_NO_MORE_FILES, st);
        }
        let remaining = &kids[pos..];
        let (buf, n) = encode_file_directory_information(remaining, output_len.max(64));
        if n == 0 {
            return error_packet(req, STATUS_NO_MORE_FILES, st);
        }
        if let Some(OpenObj::Dir { pos, .. }) = st.files.get_mut(&fid) {
            *pos = pos.saturating_add(n);
        }
        let mut b = vec![0u8; 8];
        b[0..2].copy_from_slice(&9u16.to_le_bytes());
        let off = (SMB2_HEADER_LEN + 8) as u16;
        b[2..4].copy_from_slice(&off.to_le_bytes());
        b[4..8].copy_from_slice(&(buf.len() as u32).to_le_bytes());
        b.extend_from_slice(&buf);
        let h = reply_header(req, STATUS_SUCCESS, st.session_id, st.tree_id);
        maybe_sign(st, encode_packet(&h, &b))
    }

    fn cmd_query_info(req: &Smb2Header, raw: &[u8], st: &ConnState) -> Vec<u8> {
        let body = &raw[SMB2_HEADER_LEN..];
        if body.len() < 40 {
            return error_packet(req, STATUS_ACCESS_DENIED, st);
        }
        let info_class = body[3];
        let mut fid = [0u8; 16];
        fid.copy_from_slice(&body[24..40]);
        let attrs = match st.files.get(&fid) {
            Some(OpenObj::Dir { .. }) => FILE_ATTRIBUTE_DIRECTORY,
            Some(OpenObj::File(_)) => FILE_ATTRIBUTE_NORMAL,
            None => return error_packet(req, STATUS_OBJECT_NAME_NOT_FOUND, st),
        };
        if info_class != FILE_BASIC_INFORMATION {
            return error_packet(req, STATUS_NOT_SUPPORTED, st);
        }
        let mut info = vec![0u8; 40];
        info[32..36].copy_from_slice(&attrs.to_le_bytes());
        let mut b = vec![0u8; 8];
        b[0..2].copy_from_slice(&9u16.to_le_bytes());
        let off = (SMB2_HEADER_LEN + 8) as u16;
        b[2..4].copy_from_slice(&off.to_le_bytes());
        b[4..8].copy_from_slice(&(info.len() as u32).to_le_bytes());
        b.extend_from_slice(&info);
        let h = reply_header(req, STATUS_SUCCESS, st.session_id, st.tree_id);
        maybe_sign(st, encode_packet(&h, &b))
    }

    fn connect_guest(addr: SocketAddr) -> Smb2Client<TcpStream> {
        let mut c = Smb2Client::connect(addr).expect("connect");
        let d = c.negotiate().expect("NEGOTIATE");
        assert_eq!(d, DIALECT_202);
        c.session_setup_guest().expect("guest SESSION_SETUP");
        c.tree_connect("127.0.0.1", SHARE).expect("TREE_CONNECT");
        c
    }

    #[test]
    fn header_nbss_roundtrip() {
        let h = Smb2Header {
            credit_charge: 1,
            status: 0,
            command: SMB2_NEGOTIATE,
            credits: 1,
            flags: 0,
            next_command: 0,
            message_id: 7,
            process_id: 0xfeff,
            tree_id: 0,
            session_id: 0,
        };
        let raw = encode_smb2_header(&h);
        let p = parse_smb2_header(&raw).unwrap();
        assert_eq!(p.command, SMB2_NEGOTIATE);
        assert_eq!(p.message_id, 7);
        let framed = encode_nbss(&raw);
        assert_eq!(framed[0], 0);
        let n = decode_nbss_len(framed[..4].try_into().unwrap()).unwrap();
        assert_eq!(n, raw.len());
    }

    #[test]
    fn utf16_roundtrip() {
        assert_eq!(
            decode_utf16le(&encode_utf16le("payload.bin")),
            "payload.bin"
        );
    }

    fn unhex(s: &str) -> Vec<u8> {
        let hex: String = s.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Regression: NTLMv2_CLIENT_CHALLENGE is 28 bytes (Reserved3) and MS-NLMP 4.2.4 KAT.
    #[test]
    fn regression_smb2_ntlmv2_client_challenge_28_byte_kat() {
        // Encoder layout: ClientChallenge at offset 16, Reserved3 at 24.
        assert_eq!(NTLMV2_CLIENT_CHALLENGE_HDR.len(), 28);
        assert_eq!(&NTLMV2_CLIENT_CHALLENGE_HDR[0..2], &[0x01, 0x01]);
        assert_eq!(
            &NTLMV2_CLIENT_CHALLENGE_HDR[16..24],
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        );
        assert_eq!(&NTLMV2_CLIENT_CHALLENGE_HDR[24..28], &[0, 0, 0, 0]);
        let (t3_bytes, _) = ntlm_type3_v2("alice", "CORP", "s3cret", CHALLENGE, &[]);
        let t3 = parse_ntlm_type3(&t3_bytes).expect("Type3");
        assert!(t3.nt_response.len() >= 16 + 28);
        let temp = &t3.nt_response[16..];
        assert_eq!(&temp[..28], &NTLMV2_CLIENT_CHALLENGE_HDR);
        assert_eq!(
            &temp[16..24],
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]
        );

        // MS-NLMP 4.2.4 known-answer (not a self-HMAC of our encoder blob).
        const KAT_PASSWORD: &str = "Password";
        const KAT_USER: &str = "User";
        const KAT_DOMAIN: &str = "Domain";
        const KAT_RESPONSE_KEY_NT: &str = "0c868a403bfd7a93a3001ef22ef02e3f";
        const KAT_CHALLENGE: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
        const KAT_TEMP: &str = "01010000000000000000000011223344556677880000000000000000";
        const KAT_NT_PROOF: &str = "4ee6b0d655f232aca5d7b24da70c136a";
        const KAT_SESSION_BASE: &str = "e4a9a329aaa4eb0d48818d127f9f77eb";
        let rk = ntlmv2_response_key_nt(KAT_PASSWORD, KAT_USER, KAT_DOMAIN);
        assert_eq!(rk.as_slice(), unhex(KAT_RESPONSE_KEY_NT));
        let kat_temp = unhex(KAT_TEMP);
        assert_eq!(kat_temp.len(), 28);
        let proof = ntlmv2_nt_proof(&rk, KAT_CHALLENGE, &kat_temp);
        assert_eq!(proof.as_slice(), unhex(KAT_NT_PROOF));
        let skey = ntlmv2_session_base_key(&rk, &proof);
        assert_eq!(skey.as_slice(), unhex(KAT_SESSION_BASE));
    }

    #[test]
    fn guest_negotiate_session_tree_create_close() {
        let srv = FakeSmb::spawn(AuthMode::Guest);
        let mut c = connect_guest(srv.addr);
        let open = c.create(FILE_NAME).expect("CREATE");
        assert_eq!(open.end_of_file, OFFSET_1MIB + TAIL.len() as u64);
        c.close(open.file_id).expect("CLOSE");
        let stats = srv.stats();
        assert_eq!(stats.creates, vec![FILE_NAME]);
        assert!(stats.reads.is_empty());
    }

    /// Regression: READ at offset 1 MiB issues exactly one SMB2 READ with that offset.
    #[test]
    fn regression_smb2_read_at_offset_one_mib_issues_one_read() {
        let srv = FakeSmb::spawn(AuthMode::Guest);
        let mut c = connect_guest(srv.addr);
        let open = c.create(FILE_NAME).expect("CREATE");
        let got = c
            .read_at(open.file_id, OFFSET_1MIB, TAIL.len() as u32)
            .expect("READ");
        c.close(open.file_id).expect("CLOSE");
        assert_eq!(
            got, TAIL,
            "payload at 1 MiB must match without a prefix read"
        );
        let stats = srv.stats();
        assert_eq!(
            stats.reads,
            vec![(OFFSET_1MIB, TAIL.len() as u32)],
            "exactly one READ at 1 MiB; a from-0 slurp would show offset 0"
        );
    }

    #[test]
    fn read_at_zero_returns_head_prefix() {
        let srv = FakeSmb::spawn(AuthMode::Guest);
        let mut c = connect_guest(srv.addr);
        let open = c.create(FILE_NAME).expect("CREATE");
        let got = c.read_at(open.file_id, 0, HEAD.len() as u32).expect("READ");
        c.close(open.file_id).expect("CLOSE");
        assert_eq!(got, HEAD);
        assert_eq!(srv.stats().reads, vec![(0, HEAD.len() as u32)]);
    }

    #[test]
    fn read_past_eof_is_empty() {
        let srv = FakeSmb::spawn(AuthMode::Guest);
        let mut c = connect_guest(srv.addr);
        let open = c.create(FILE_NAME).expect("CREATE");
        let got = c
            .read_at(open.file_id, open.end_of_file, 16)
            .expect("EOF READ");
        c.close(open.file_id).expect("CLOSE");
        assert!(got.is_empty());
        assert_eq!(
            srv.stats().reads.last().map(|r| r.0),
            Some(open.end_of_file)
        );
    }

    #[test]
    fn create_missing_is_not_found() {
        let srv = FakeSmb::spawn(AuthMode::Guest);
        let mut c = connect_guest(srv.addr);
        let err = c.create("nope.bin").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(&format!("{STATUS_OBJECT_NAME_NOT_FOUND:#010x}")),
            "{msg}"
        );
    }

    #[test]
    fn ntlmv2_session_then_signed_read() {
        let srv = FakeSmb::spawn(AuthMode::Password {
            user: "alice".into(),
            domain: "CORP".into(),
            password: "s3cret".into(),
        });
        let mut c = Smb2Client::connect(srv.addr).expect("connect");
        c.negotiate().expect("NEGOTIATE");
        c.session_setup_ntlmv2("alice", "CORP", "s3cret")
            .expect("NTLMv2 SESSION_SETUP");
        c.tree_connect("127.0.0.1", SHARE).expect("TREE_CONNECT");
        let open = c.create(FILE_NAME).expect("CREATE");
        let got = c
            .read_at(open.file_id, OFFSET_1MIB, TAIL.len() as u32)
            .expect("signed READ");
        c.close(open.file_id).expect("CLOSE");
        assert_eq!(got, TAIL);
        assert_eq!(srv.stats().reads, vec![(OFFSET_1MIB, TAIL.len() as u32)]);
    }

    /// Regression: NTLMv2 session rejects an unsigned READ body (fail-closed).
    #[test]
    fn regression_smb2_ntlmv2_rejects_unsigned_read() {
        let mut opts = FakeOpts::password("alice", "CORP", "s3cret");
        opts.unsigned_read = true;
        let srv = FakeSmb::spawn_with(opts);
        let mut c = Smb2Client::connect(srv.addr).expect("connect");
        c.negotiate().expect("NEGOTIATE");
        c.session_setup_ntlmv2("alice", "CORP", "s3cret")
            .expect("NTLMv2 SESSION_SETUP");
        c.tree_connect("127.0.0.1", SHARE).expect("TREE_CONNECT");
        let open = c.create(FILE_NAME).expect("CREATE");
        let err = c
            .read_at(open.file_id, OFFSET_1MIB, TAIL.len() as u32)
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unsigned") || msg.contains("signature"),
            "{msg}"
        );
    }

    /// Regression: SUCCESS with DataLength 16 of a 32-byte request is not EOF.
    #[test]
    fn regression_smb2_short_success_read_is_not_eof() {
        let mut opts = FakeOpts::guest();
        opts.read_data_cap = Some(16);
        let srv = FakeSmb::spawn_with(opts);
        let mut c = connect_guest(srv.addr);
        let open = c.create(FILE_NAME).expect("CREATE");
        let got = c.read_at(open.file_id, 0, 32).expect("short SUCCESS");
        c.close(open.file_id).expect("CLOSE");
        assert_eq!(
            got.len(),
            16,
            "short SUCCESS must return 16 bytes, not empty"
        );
        assert_eq!(&got[..HEAD.len()], HEAD);
        assert_eq!(srv.stats().reads, vec![(0, 32)]);
    }

    /// Regression: SUCCESS DataLength 0 with requested > 0 is not EOF.
    #[test]
    fn regression_smb2_success_zero_data_is_not_eof() {
        let mut opts = FakeOpts::guest();
        opts.read_data_cap = Some(0);
        let srv = FakeSmb::spawn_with(opts);
        let mut c = connect_guest(srv.addr);
        let open = c.create(FILE_NAME).expect("CREATE");
        let err = c.read_at(open.file_id, 0, 16).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("DataLength 0") && msg.contains("END_OF_FILE"),
            "{msg}"
        );
    }

    #[test]
    fn guest_fails_when_signing_required() {
        let mut opts = FakeOpts::guest();
        opts.signing_required = true;
        let srv = FakeSmb::spawn_with(opts);
        let mut c = Smb2Client::connect(srv.addr).expect("connect");
        c.negotiate().expect("NEGOTIATE");
        assert!(c.signing_required());
        let err = c.session_setup_guest().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("SIGNING_REQUIRED") && msg.contains("guest"),
            "{msg}"
        );
    }

    #[test]
    fn read_at_caps_to_negotiated_max_read_size() {
        let mut opts = FakeOpts::guest();
        opts.max_read_size = 64 * 1024;
        let srv = FakeSmb::spawn_with(opts);
        let mut c = connect_guest(srv.addr);
        assert_eq!(c.max_read_size(), 64 * 1024);
        let open = c.create(FILE_NAME).expect("CREATE");
        let _ = c.read_at(open.file_id, 0, MAX_READ).expect("capped READ");
        c.close(open.file_id).expect("CLOSE");
        assert_eq!(srv.stats().reads, vec![(0, 64 * 1024)]);
    }

    #[test]
    fn ntlmv2_wrong_password_is_logon_failure() {
        let srv = FakeSmb::spawn(AuthMode::Password {
            user: "alice".into(),
            domain: "CORP".into(),
            password: "s3cret".into(),
        });
        let mut c = Smb2Client::connect(srv.addr).expect("connect");
        c.negotiate().expect("NEGOTIATE");
        let err = c
            .session_setup_ntlmv2("alice", "CORP", "wrong")
            .unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(&format!("{STATUS_LOGON_FAILURE:#010x}")),
            "{msg}"
        );
    }

    #[test]
    fn negotiate_unsupported_dialect_is_not_supported() {
        let srv = FakeSmb::spawn(AuthMode::RejectDialect);
        let mut c = Smb2Client::connect(srv.addr).expect("connect");
        let err = c.negotiate().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(&format!("{STATUS_NOT_SUPPORTED:#010x}"))
                || msg.to_ascii_lowercase().contains("dialect"),
            "{msg}"
        );
    }

    #[test]
    fn connect_refused_is_smb_error() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let err = Smb2Client::connect_timeout(addr, Duration::from_millis(200)).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("connect") || msg.contains("SMB"), "{msg}");
        // Connection refused is not a silent Ok.
        assert!(!matches!(
            err,
            RemoteError::Io(ref e) if e.kind() == ErrorKind::NotFound
        ));
    }

    /// Fake-server QUERY_DIRECTORY returns Depth-1 names + sizes.
    #[test]
    fn smb_listing_query_directory_returns_depth1_names_and_sizes() {
        let srv = FakeSmb::spawn(AuthMode::Guest);
        let mut c = connect_guest(srv.addr);
        let ents = c.list_directory("").expect("QUERY_DIRECTORY");
        assert!(
            ents.iter().any(|e| e.name == DIR_FILE_A
                && e.size == DIR_FILE_A_BODY.len() as u64
                && !e.is_dir),
            "{ents:?}"
        );
        assert!(
            ents.iter().any(|e| e.name == FILE_NAME
                && e.size == OFFSET_1MIB + TAIL.len() as u64
                && !e.is_dir),
            "{ents:?}"
        );
        assert!(
            ents.iter()
                .any(|e| e.name == DIR_SUB && e.is_dir && e.size == 0),
            "{ents:?}"
        );
        assert!(!ents.iter().any(|e| e.name == "." || e.name == ".."));
        assert!(
            !ents.iter().any(|e| e.name == "nested.bin"),
            "Depth-1 must not include nested children: {ents:?}"
        );
        assert!(srv.stats().query_dirs >= 1, "expected QUERY_DIRECTORY");
        let nested = c.list_directory(DIR_SUB).expect("subdir");
        assert!(
            nested
                .iter()
                .any(|e| e.name == "nested.bin" && e.size == 4 && !e.is_dir),
            "{nested:?}"
        );
    }

    #[test]
    fn smb_listing_query_directory_unsupported_is_not_empty_list() {
        let mut opts = FakeOpts::guest();
        opts.reject_query_directory = true;
        let srv = FakeSmb::spawn_with(opts);
        let mut c = connect_guest(srv.addr);
        let err = c.list_directory("").unwrap_err();
        let msg = err.to_string();
        let lower = msg.to_ascii_lowercase();
        assert!(
            lower.contains("not_supported")
                || msg.contains(&format!("{STATUS_NOT_SUPPORTED:#010x}")),
            "{msg}"
        );
        assert!(
            !msg.is_empty(),
            "QUERY_DIRECTORY unsupported must not look like an empty listing"
        );
    }

    #[test]
    fn smb_listing_query_directory_rejects_unbounded_name() {
        let too_long = (QUERY_DIR_NAME_MAX * 2) + 2;
        let mut buf = vec![0u8; 64 + too_long];
        buf[60..64].copy_from_slice(&(too_long as u32).to_le_bytes());
        let err = parse_file_directory_information(&buf).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("FileNameLength") || msg.contains("exceeds"),
            "{msg}"
        );
    }

    #[test]
    fn smb_listing_query_directory_rejects_bad_next_offset() {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(&8u32.to_le_bytes());
        let err = parse_file_directory_information(&buf).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("NextEntryOffset"), "{msg}");
    }

    #[test]
    fn query_info_basic_directory_attribute() {
        let srv = FakeSmb::spawn(AuthMode::Guest);
        let mut c = connect_guest(srv.addr);
        let open = c.create_dir("").expect("CREATE dir");
        assert!(open.is_dir());
        let attrs = c.query_info_basic(open.file_id).expect("QUERY_INFO");
        assert_ne!(attrs & FILE_ATTRIBUTE_DIRECTORY, 0);
        c.close(open.file_id).expect("CLOSE");
    }

    #[test]
    fn create_dir_on_file_is_not_a_directory() {
        let srv = FakeSmb::spawn(AuthMode::Guest);
        let mut c = connect_guest(srv.addr);
        let err = c.create_dir(FILE_NAME).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(&format!("{STATUS_NOT_A_DIRECTORY:#010x}")),
            "{msg}"
        );
    }
}
