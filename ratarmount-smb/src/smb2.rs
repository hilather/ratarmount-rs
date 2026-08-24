//! SMB 2.0.2 packet codec (Direct TCP) plus a tiny NTLMSSP/SPNEGO subset.
//!
//! No crates.io SMB server compiled on workspace MSRV 1.74 without raising
//! edition/rustc, so this module is the dialect.

use std::io::{self, ErrorKind};
use std::time::{SystemTime, UNIX_EPOCH};

// --- commands ---

pub const SMB2_NEGOTIATE: u16 = 0x0000;
pub const SMB2_SESSION_SETUP: u16 = 0x0001;
pub const SMB2_LOGOFF: u16 = 0x0002;
pub const SMB2_TREE_CONNECT: u16 = 0x0003;
pub const SMB2_TREE_DISCONNECT: u16 = 0x0004;
pub const SMB2_CREATE: u16 = 0x0005;
pub const SMB2_CLOSE: u16 = 0x0006;
pub const SMB2_FLUSH: u16 = 0x0007;
pub const SMB2_READ: u16 = 0x0008;
pub const SMB2_WRITE: u16 = 0x0009;
pub const SMB2_LOCK: u16 = 0x000A;
pub const SMB2_IOCTL: u16 = 0x000B;
pub const SMB2_CANCEL: u16 = 0x000C;
pub const SMB2_ECHO: u16 = 0x000D;
pub const SMB2_QUERY_DIRECTORY: u16 = 0x000E;
pub const SMB2_CHANGE_NOTIFY: u16 = 0x000F;
pub const SMB2_QUERY_INFO: u16 = 0x0010;
pub const SMB2_SET_INFO: u16 = 0x0011;

pub const SMB2_HEADER_LEN: usize = 64;
pub const SMB2_FLAGS_SERVER_TO_REDIR: u32 = 0x0000_0001;
pub const SMB2_FLAGS_RELATED: u32 = 0x0000_0004;

pub const DIALECT_202: u16 = 0x0202;
pub const DIALECT_210: u16 = 0x0210;
pub const DIALECT_300: u16 = 0x0300;
pub const DIALECT_302: u16 = 0x0302;

pub const NEGOTIATE_SIGNING_ENABLED: u16 = 0x0001;
pub const SESSION_FLAG_IS_GUEST: u16 = 0x0001;

pub const SHARE_TYPE_DISK: u8 = 0x01;
pub const SHARE_TYPE_PIPE: u8 = 0x02;

pub const FILE_ATTRIBUTE_READONLY: u32 = 0x0000_0001;
pub const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
pub const FILE_ATTRIBUTE_ARCHIVE: u32 = 0x0000_0020;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
pub const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

pub const FILE_SUPERSEDE: u32 = 0;
pub const FILE_OPEN: u32 = 1;
pub const FILE_CREATE: u32 = 2;
pub const FILE_OPEN_IF: u32 = 3;
pub const FILE_OVERWRITE: u32 = 4;
pub const FILE_OVERWRITE_IF: u32 = 5;

pub const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
pub const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

pub const DELETE: u32 = 0x0001_0000;
pub const GENERIC_WRITE: u32 = 0x4000_0000;
pub const GENERIC_ALL: u32 = 0x1000_0000;
pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
pub const FILE_WRITE_EA: u32 = 0x0000_0010;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;
pub const FILE_DELETE_CHILD: u32 = 0x0000_0040;

pub const WRITE_ACCESS_MASK: u32 = FILE_WRITE_DATA
    | FILE_APPEND_DATA
    | FILE_WRITE_EA
    | FILE_WRITE_ATTRIBUTES
    | FILE_DELETE_CHILD
    | DELETE
    | GENERIC_WRITE
    | GENERIC_ALL;

pub const SMB2_RESTART_SCANS: u8 = 0x01;
pub const SMB2_REOPEN: u8 = 0x10;

pub const FILE_DIRECTORY_INFORMATION: u8 = 1;
pub const FILE_FULL_DIRECTORY_INFORMATION: u8 = 2;
pub const FILE_BOTH_DIRECTORY_INFORMATION: u8 = 3;
pub const FILE_NAMES_INFORMATION: u8 = 12;
pub const FILE_ID_BOTH_DIRECTORY_INFORMATION: u8 = 37;
pub const FILE_ID_FULL_DIRECTORY_INFORMATION: u8 = 38;

pub const SMB2_0_INFO_FILE: u8 = 1;
pub const SMB2_0_INFO_FILESYSTEM: u8 = 2;

pub const FILE_BASIC_INFORMATION: u8 = 4;
pub const FILE_STANDARD_INFORMATION: u8 = 5;
pub const FILE_INTERNAL_INFORMATION: u8 = 6;
pub const FILE_EA_INFORMATION: u8 = 7;
pub const FILE_ACCESS_INFORMATION: u8 = 8;
pub const FILE_NAME_INFORMATION: u8 = 9;
pub const FILE_RENAME_INFORMATION: u8 = 10;
pub const FILE_DISPOSITION_INFORMATION: u8 = 13;
pub const FILE_POSITION_INFORMATION: u8 = 14;
pub const FILE_MODE_INFORMATION: u8 = 16;
pub const FILE_ALIGNMENT_INFORMATION: u8 = 17;
pub const FILE_ALL_INFORMATION: u8 = 18;
pub const FILE_END_OF_FILE_INFORMATION: u8 = 20;
pub const FILE_STREAM_INFORMATION: u8 = 22;
pub const FILE_NETWORK_OPEN_INFORMATION: u8 = 34;
pub const FILE_ATTRIBUTE_TAG_INFORMATION: u8 = 35;
pub const FILE_ID_INFORMATION: u8 = 59;

pub const FILE_FS_VOLUME_INFORMATION: u8 = 1;
pub const FILE_FS_SIZE_INFORMATION: u8 = 3;
pub const FILE_FS_DEVICE_INFORMATION: u8 = 4;
pub const FILE_FS_ATTRIBUTE_INFORMATION: u8 = 5;
pub const FILE_FS_FULL_SIZE_INFORMATION: u8 = 7;
pub const FILE_FS_OBJECT_ID_INFORMATION: u8 = 8;
pub const FILE_FS_SECTOR_SIZE_INFORMATION: u8 = 11;

pub const FILE_DEVICE_DISK: u32 = 7;
pub const FILE_DEVICE_IS_MOUNTED: u32 = 0x0000_0020;
pub const FILE_READ_ONLY_DEVICE: u32 = 0x0000_0002;
pub const FILE_READ_ONLY_VOLUME: u32 = 0x0008_0000;
pub const FILE_CASE_SENSITIVE_SEARCH: u32 = 0x0000_0001;
pub const FILE_CASE_PRESERVED_NAMES: u32 = 0x0000_0002;
pub const FILE_UNICODE_ON_DISK: u32 = 0x0000_0004;

pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;
pub const STATUS_NO_MORE_FILES: u32 = 0x8000_0006;
pub const STATUS_NO_SUCH_FILE: u32 = 0xC000_000F;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_ACCESS_DENIED: u32 = 0xC000_0022;
pub const STATUS_OBJECT_NAME_NOT_FOUND: u32 = 0xC000_0034;
pub const STATUS_OBJECT_NAME_COLLISION: u32 = 0xC000_0035;
pub const STATUS_OBJECT_PATH_NOT_FOUND: u32 = 0xC000_003A;
pub const STATUS_MEDIA_WRITE_PROTECTED: u32 = 0xC000_00A2;
pub const STATUS_FILE_IS_A_DIRECTORY: u32 = 0xC000_00BA;
pub const STATUS_NOT_SUPPORTED: u32 = 0xC000_00BB;
pub const STATUS_BAD_NETWORK_NAME: u32 = 0xC000_00CC;
pub const STATUS_FILE_CLOSED: u32 = 0xC000_0128;
pub const STATUS_NOT_A_DIRECTORY: u32 = 0xC000_0103;
pub const STATUS_DIRECTORY_NOT_EMPTY: u32 = 0xC000_0101;
pub const STATUS_LOGON_FAILURE: u32 = 0xC000_006D;
pub const STATUS_INVALID_INFO_CLASS: u32 = 0xC000_0003;
pub const STATUS_INFO_LENGTH_MISMATCH: u32 = 0xC000_0004;
pub const STATUS_NETWORK_NAME_DELETED: u32 = 0xC000_00C9;
pub const STATUS_USER_SESSION_DELETED: u32 = 0xC000_0203;
pub const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;
pub const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;

pub const MAX_FRAME: usize = 8 * 1024 * 1024;
pub const MAX_READ: u32 = 1024 * 1024;
pub const MAX_WRITE: u32 = 1024 * 1024;
pub const MAX_TRANSACT: u32 = 1024 * 1024;

pub const SERVER_GUID: [u8; 16] = *b"ratarmnt-smb\0\0\0\x02";
const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;

const NTLM_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a];
const SPNEGO_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x02];

pub const RELATED_FILE_ID: [u8; 16] = [0xff; 16];

// --- Direct TCP ---

pub fn encode_nbss(payload: &[u8]) -> Vec<u8> {
    let n = payload.len();
    let mut out = Vec::with_capacity(4 + n);
    out.push(0);
    out.push(((n >> 16) & 0xff) as u8);
    out.push(((n >> 8) & 0xff) as u8);
    out.push((n & 0xff) as u8);
    out.extend_from_slice(payload);
    out
}

pub fn decode_nbss_len(hdr: [u8; 4]) -> io::Result<usize> {
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

// --- header ---

#[derive(Clone, Debug)]
pub struct Smb2Header {
    pub credit_charge: u16,
    pub status: u32,
    pub command: u16,
    pub credits: u16,
    pub flags: u32,
    pub next_command: u32,
    pub message_id: u64,
    pub process_id: u32,
    pub tree_id: u32,
    pub session_id: u64,
}

impl Smb2Header {
    pub fn related(&self) -> bool {
        self.flags & SMB2_FLAGS_RELATED != 0
    }
}

pub fn parse_smb2_header(buf: &[u8]) -> io::Result<Smb2Header> {
    if buf.len() < SMB2_HEADER_LEN {
        return Err(io::Error::new(ErrorKind::UnexpectedEof, "SMB2 header"));
    }
    if buf[0] != 0xfe || &buf[1..4] != b"SMB" {
        return Err(io::Error::new(ErrorKind::InvalidData, "not SMB2"));
    }
    let structure_size = u16_at(buf, 4)?;
    if structure_size != 64 {
        return Err(io::Error::new(ErrorKind::InvalidData, "SMB2 StructureSize"));
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

pub fn encode_smb2_header(h: &Smb2Header) -> [u8; SMB2_HEADER_LEN] {
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

pub fn reply_header(req: &Smb2Header, status: u32, credits: u16) -> Smb2Header {
    Smb2Header {
        credit_charge: req.credit_charge.max(1),
        status,
        command: req.command,
        credits: credits.max(1),
        flags: SMB2_FLAGS_SERVER_TO_REDIR,
        next_command: 0,
        message_id: req.message_id,
        process_id: req.process_id,
        tree_id: req.tree_id,
        session_id: req.session_id,
    }
}

pub fn error_body() -> Vec<u8> {
    // SMB2 ERROR Response: StructureSize 9, reserved, ByteCount 0
    let mut b = vec![0u8; 8];
    b[0..2].copy_from_slice(&9u16.to_le_bytes());
    b[2] = 0;
    b[4..8].copy_from_slice(&0u32.to_le_bytes());
    b
}

pub fn encode_packet(header: &Smb2Header, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SMB2_HEADER_LEN + body.len());
    out.extend_from_slice(&encode_smb2_header(header));
    out.extend_from_slice(body);
    out
}

/// Split a Direct-TCP payload into compound SMB2 messages (unpadded slices).
pub fn split_compound(msg: &[u8]) -> io::Result<Vec<&[u8]>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    loop {
        if msg.len() < off + SMB2_HEADER_LEN {
            return Err(io::Error::new(ErrorKind::UnexpectedEof, "compound SMB2"));
        }
        let next = u32_at(&msg[off..], 20)? as usize;
        if next == 0 {
            out.push(&msg[off..]);
            break;
        }
        if next < SMB2_HEADER_LEN || off + next > msg.len() {
            return Err(io::Error::new(ErrorKind::InvalidData, "NextCommand"));
        }
        out.push(&msg[off..off + next]);
        off += next;
    }
    Ok(out)
}

pub fn stitch_compound(packets: &[Vec<u8>]) -> Vec<u8> {
    if packets.len() <= 1 {
        return packets.first().cloned().unwrap_or_default();
    }
    let mut out = Vec::new();
    for (i, pkt) in packets.iter().enumerate() {
        let last = i + 1 == packets.len();
        let mut chunk = pkt.clone();
        let pad = (8 - (chunk.len() % 8)) % 8;
        if !last {
            chunk.resize(chunk.len() + pad, 0);
            let next = chunk.len() as u32;
            chunk[20..24].copy_from_slice(&next.to_le_bytes());
        }
        out.extend_from_slice(&chunk);
    }
    out
}

pub fn is_smb1(buf: &[u8]) -> bool {
    buf.len() >= 4 && buf[0] == 0xff && &buf[1..4] == b"SMB"
}

pub fn smb1_has_smb2_dialect(buf: &[u8]) -> bool {
    // ByteCount at offset 33 after WordCount=0 (header 32 + 1).
    if buf.len() < 35 || buf.get(4) != Some(&0x72) {
        return false;
    }
    let Some(&wc) = buf.get(32) else {
        return false;
    };
    if wc != 0 {
        return false;
    }
    let Some(bc) = u16_at(buf, 33).ok() else {
        return false;
    };
    let start: usize = 35;
    let end = start.saturating_add(bc as usize).min(buf.len());
    let bytes = &buf[start..end];
    let s = String::from_utf8_lossy(bytes);
    s.contains("SMB 2.002") || s.contains("SMB 2.???") || s.contains("SMB 2.")
}

// --- integers / strings ---

pub fn u16_at(b: &[u8], o: usize) -> io::Result<u16> {
    let s = b
        .get(o..o + 2)
        .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "u16"))?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

pub fn u32_at(b: &[u8], o: usize) -> io::Result<u32> {
    let s = b
        .get(o..o + 4)
        .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "u32"))?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

pub fn u64_at(b: &[u8], o: usize) -> io::Result<u64> {
    let s = b
        .get(o..o + 8)
        .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "u64"))?;
    Ok(u64::from_le_bytes([
        s[0], s[1], s[2], s[3], s[4], s[5], s[6], s[7],
    ]))
}

pub fn file_id_at(b: &[u8], o: usize) -> io::Result<[u8; 16]> {
    let s = b
        .get(o..o + 16)
        .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "FileId"))?;
    let mut id = [0u8; 16];
    id.copy_from_slice(s);
    Ok(id)
}

pub fn encode_utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

pub fn decode_utf16le(bytes: &[u8]) -> String {
    let even = bytes.len() & !1;
    // `as_chunks` is rustc 1.88+; workspace MSRV is 1.74.
    #[allow(clippy::chunks_exact_to_as_chunks)]
    let u: Vec<u16> = bytes[..even]
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16_lossy(&u)
}

pub fn unix_float_to_filetime(t: f64) -> u64 {
    if !t.is_finite() || t <= 0.0 {
        return 0;
    }
    let sec = t.trunc().max(0.0) as u64;
    let nfrac = ((t.fract().max(0.0)) * 10_000_000.0) as u64;
    FILETIME_UNIX_EPOCH
        .saturating_add(sec.saturating_mul(10_000_000))
        .saturating_add(nfrac)
}

pub fn now_filetime() -> u64 {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    FILETIME_UNIX_EPOCH
        .saturating_add(t.as_secs().saturating_mul(10_000_000))
        .saturating_add(u64::from(t.subsec_nanos()) / 100)
}

pub fn alloc_size(size: u64) -> u64 {
    if size == 0 {
        0
    } else {
        size.saturating_add(4095) & !4095
    }
}

pub fn file_id_from_u64(id: u64) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[..8].copy_from_slice(&id.to_le_bytes());
    b[8..].copy_from_slice(&id.to_le_bytes());
    b
}

pub fn file_id_to_u64(id: &[u8; 16]) -> u64 {
    u64::from_le_bytes(id[..8].try_into().unwrap_or([0; 8]))
}

pub fn wants_write(access: u32) -> bool {
    access & WRITE_ACCESS_MASK != 0
}

// --- negotiate ---

pub fn parse_negotiate_dialects(cmd: &[u8]) -> io::Result<Vec<u16>> {
    let body = cmd
        .get(SMB2_HEADER_LEN..)
        .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "NEGOTIATE"))?;
    if body.len() < 36 {
        return Err(io::Error::new(ErrorKind::UnexpectedEof, "NEGOTIATE body"));
    }
    let count = u16_at(body, 2)? as usize;
    let mut dialects = Vec::with_capacity(count);
    let mut o = 36;
    for _ in 0..count {
        dialects.push(u16_at(body, o)?);
        o += 2;
    }
    Ok(dialects)
}

pub fn pick_dialect(dialects: &[u16]) -> Option<u16> {
    if dialects.contains(&DIALECT_202) {
        Some(DIALECT_202)
    } else if dialects.contains(&DIALECT_210) {
        Some(DIALECT_210)
    } else if dialects.contains(&DIALECT_300) {
        Some(DIALECT_300)
    } else if dialects.contains(&DIALECT_302) {
        Some(DIALECT_302)
    } else {
        None
    }
}

pub fn encode_negotiate_response(dialect: u16, sec_buf: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 64];
    b[0..2].copy_from_slice(&65u16.to_le_bytes());
    b[2..4].copy_from_slice(&NEGOTIATE_SIGNING_ENABLED.to_le_bytes());
    b[4..6].copy_from_slice(&dialect.to_le_bytes());
    b[8..24].copy_from_slice(&SERVER_GUID);
    // Capabilities: DFS=0, LEASING=0
    b[24..28].copy_from_slice(&0u32.to_le_bytes());
    b[28..32].copy_from_slice(&MAX_TRANSACT.to_le_bytes());
    b[32..36].copy_from_slice(&MAX_READ.to_le_bytes());
    b[36..40].copy_from_slice(&MAX_WRITE.to_le_bytes());
    b[40..48].copy_from_slice(&now_filetime().to_le_bytes());
    b[48..56].copy_from_slice(&0u64.to_le_bytes());
    let off = (SMB2_HEADER_LEN + 64) as u16;
    b[56..58].copy_from_slice(&off.to_le_bytes());
    b[58..60].copy_from_slice(&(sec_buf.len() as u16).to_le_bytes());
    b.extend_from_slice(sec_buf);
    b
}

// --- session setup ---

pub fn parse_session_setup_sec(cmd: &[u8]) -> io::Result<Vec<u8>> {
    let body = cmd
        .get(SMB2_HEADER_LEN..)
        .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "SESSION_SETUP"))?;
    if body.len() < 24 {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            "SESSION_SETUP body",
        ));
    }
    let off = u16_at(body, 12)? as usize;
    let len = u16_at(body, 14)? as usize;
    slice_from_cmd(cmd, off, len).map(|s| s.to_vec())
}

pub fn encode_session_setup_response(flags: u16, sec_buf: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 8];
    b[0..2].copy_from_slice(&9u16.to_le_bytes());
    b[2..4].copy_from_slice(&flags.to_le_bytes());
    let off = (SMB2_HEADER_LEN + 8) as u16;
    b[4..6].copy_from_slice(&off.to_le_bytes());
    b[6..8].copy_from_slice(&(sec_buf.len() as u16).to_le_bytes());
    b.extend_from_slice(sec_buf);
    b
}

// --- tree connect ---

pub fn parse_tree_connect_path(cmd: &[u8]) -> io::Result<String> {
    let body = cmd
        .get(SMB2_HEADER_LEN..)
        .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "TREE_CONNECT"))?;
    if body.len() < 8 {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            "TREE_CONNECT body",
        ));
    }
    let off = u16_at(body, 4)? as usize;
    let len = u16_at(body, 6)? as usize;
    Ok(decode_utf16le(slice_from_cmd(cmd, off, len)?))
}

pub fn share_name_from_unc(path: &str) -> Option<String> {
    let p = path.replace('/', "\\");
    let trimmed = p.trim_start_matches('\\');
    let mut parts = trimmed.split('\\').filter(|s| !s.is_empty());
    let _server = parts.next()?;
    parts.next().map(|s| s.to_string())
}

pub fn encode_tree_connect_response(share_type: u8, maximal_access: u32) -> Vec<u8> {
    let mut b = vec![0u8; 16];
    b[0..2].copy_from_slice(&16u16.to_le_bytes());
    b[2] = share_type;
    b[12..16].copy_from_slice(&maximal_access.to_le_bytes());
    b
}

// --- create ---

#[derive(Clone, Debug)]
pub struct CreateReq {
    pub desired_access: u32,
    pub create_disposition: u32,
    pub create_options: u32,
    pub name: String,
}

pub fn parse_create(cmd: &[u8]) -> io::Result<CreateReq> {
    let body = cmd
        .get(SMB2_HEADER_LEN..)
        .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "CREATE"))?;
    if body.len() < 56 {
        return Err(io::Error::new(ErrorKind::UnexpectedEof, "CREATE body"));
    }
    let desired_access = u32_at(body, 24)?;
    let create_disposition = u32_at(body, 36)?;
    let create_options = u32_at(body, 40)?;
    let name_off = u16_at(body, 44)? as usize;
    let name_len = u16_at(body, 46)? as usize;
    let name = if name_len == 0 {
        String::new()
    } else {
        decode_utf16le(slice_from_cmd(cmd, name_off, name_len)?)
    };
    Ok(CreateReq {
        desired_access,
        create_disposition,
        create_options,
        name,
    })
}

pub fn encode_create_response(
    action: u32,
    times: u64,
    size: u64,
    attrs: u32,
    file_id: [u8; 16],
) -> Vec<u8> {
    let mut b = vec![0u8; 88];
    b[0..2].copy_from_slice(&89u16.to_le_bytes());
    b[2] = 0; // oplock none
    b[4..8].copy_from_slice(&action.to_le_bytes());
    for off in [8usize, 16, 24, 32] {
        b[off..off + 8].copy_from_slice(&times.to_le_bytes());
    }
    b[40..48].copy_from_slice(&alloc_size(size).to_le_bytes());
    b[48..56].copy_from_slice(&size.to_le_bytes());
    b[56..60].copy_from_slice(&attrs.to_le_bytes());
    b[64..80].copy_from_slice(&file_id);
    b
}

pub const FILE_OPENED: u32 = 1;
pub const FILE_CREATED: u32 = 2;
pub const FILE_OVERWRITTEN: u32 = 3;

// --- close / flush / echo ---

pub fn parse_close_file_id(cmd: &[u8]) -> io::Result<[u8; 16]> {
    let body = cmd
        .get(SMB2_HEADER_LEN..)
        .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "CLOSE"))?;
    file_id_at(body, 8)
}

pub fn encode_close_response() -> Vec<u8> {
    let mut b = vec![0u8; 60];
    b[0..2].copy_from_slice(&60u16.to_le_bytes());
    b
}

pub fn encode_empty_sized(size: u16, bytes: usize) -> Vec<u8> {
    let mut b = vec![0u8; bytes];
    b[0..2].copy_from_slice(&size.to_le_bytes());
    b
}

// --- read / write ---

#[derive(Clone, Debug)]
pub struct ReadReq {
    pub file_id: [u8; 16],
    pub offset: u64,
    pub length: u32,
}

pub fn parse_read(cmd: &[u8]) -> io::Result<ReadReq> {
    let body = cmd
        .get(SMB2_HEADER_LEN..)
        .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "READ"))?;
    if body.len() < 48 {
        return Err(io::Error::new(ErrorKind::UnexpectedEof, "READ body"));
    }
    Ok(ReadReq {
        length: u32_at(body, 4)?,
        offset: u64_at(body, 8)?,
        file_id: file_id_at(body, 16)?,
    })
}

pub fn encode_read_response(data: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 16];
    b[0..2].copy_from_slice(&17u16.to_le_bytes());
    let data_off = (SMB2_HEADER_LEN + 16) as u8;
    b[2] = data_off;
    b[4..8].copy_from_slice(&(data.len() as u32).to_le_bytes());
    b.extend_from_slice(data);
    b
}

#[derive(Clone, Debug)]
pub struct WriteReq {
    pub file_id: [u8; 16],
    pub offset: u64,
    pub data: Vec<u8>,
}

pub fn parse_write(cmd: &[u8]) -> io::Result<WriteReq> {
    let body = cmd
        .get(SMB2_HEADER_LEN..)
        .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "WRITE"))?;
    if body.len() < 48 {
        return Err(io::Error::new(ErrorKind::UnexpectedEof, "WRITE body"));
    }
    let data_off = u16_at(body, 2)? as usize;
    let length = u32_at(body, 4)? as usize;
    let offset = u64_at(body, 8)?;
    let file_id = file_id_at(body, 16)?;
    let data = slice_from_cmd(cmd, data_off, length)?.to_vec();
    Ok(WriteReq {
        file_id,
        offset,
        data,
    })
}

pub fn encode_write_response(count: u32) -> Vec<u8> {
    let mut b = vec![0u8; 16];
    b[0..2].copy_from_slice(&17u16.to_le_bytes());
    b[4..8].copy_from_slice(&count.to_le_bytes());
    b
}

// --- query directory ---

#[derive(Clone, Debug)]
pub struct QueryDirReq {
    pub info_class: u8,
    pub flags: u8,
    pub file_id: [u8; 16],
    pub pattern: String,
    pub output_len: u32,
}

pub fn parse_query_directory(cmd: &[u8]) -> io::Result<QueryDirReq> {
    let body = cmd
        .get(SMB2_HEADER_LEN..)
        .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "QUERY_DIRECTORY"))?;
    if body.len() < 32 {
        return Err(io::Error::new(
            ErrorKind::UnexpectedEof,
            "QUERY_DIRECTORY body",
        ));
    }
    let info_class = body[2];
    let flags = body[3];
    let file_id = file_id_at(body, 8)?;
    let name_off = u16_at(body, 24)? as usize;
    let name_len = u16_at(body, 26)? as usize;
    let output_len = u32_at(body, 28)?;
    let pattern = if name_len == 0 {
        "*".into()
    } else {
        decode_utf16le(slice_from_cmd(cmd, name_off, name_len)?)
    };
    Ok(QueryDirReq {
        info_class,
        flags,
        file_id,
        pattern,
        output_len,
    })
}

pub fn encode_query_directory_response(buffer: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 8];
    b[0..2].copy_from_slice(&9u16.to_le_bytes());
    let off = (SMB2_HEADER_LEN + 8) as u16;
    b[2..4].copy_from_slice(&off.to_le_bytes());
    b[4..8].copy_from_slice(&(buffer.len() as u32).to_le_bytes());
    b.extend_from_slice(buffer);
    b
}

#[derive(Clone, Debug)]
pub struct DirEntry {
    pub name: String,
    pub inode: u64,
    pub size: u64,
    pub mtime: f64,
    pub is_dir: bool,
    pub is_lnk: bool,
}

pub fn encode_dir_entries(class: u8, entries: &[DirEntry], max: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut encoded: Vec<Vec<u8>> = Vec::new();
    for e in entries {
        let row = encode_one_dirent(class, e);
        if !encoded.is_empty() && out.len().saturating_add(row.len()) > max {
            break;
        }
        if encoded.is_empty() && row.len() > max {
            break;
        }
        out.extend_from_slice(&row);
        encoded.push(row);
    }
    // Patch NextEntryOffset: each record except the last.
    if encoded.len() >= 2 {
        let mut pos = 0usize;
        for row in encoded.iter().take(encoded.len() - 1) {
            let n = row.len() as u32;
            out[pos..pos + 4].copy_from_slice(&n.to_le_bytes());
            pos += row.len();
        }
    }
    out
}

fn encode_one_dirent(class: u8, e: &DirEntry) -> Vec<u8> {
    let name = encode_utf16le(&e.name);
    let times = unix_float_to_filetime(e.mtime);
    let mut attrs = if e.is_dir {
        FILE_ATTRIBUTE_DIRECTORY
    } else {
        FILE_ATTRIBUTE_ARCHIVE
    };
    if e.is_lnk {
        attrs |= FILE_ATTRIBUTE_REPARSE_POINT;
    }
    let mut b = Vec::new();
    match class {
        FILE_NAMES_INFORMATION => {
            b.extend_from_slice(&0u32.to_le_bytes()); // Next
            b.extend_from_slice(&0u32.to_le_bytes()); // FileIndex
            b.extend_from_slice(&(name.len() as u32).to_le_bytes());
            b.extend_from_slice(&name);
        }
        FILE_DIRECTORY_INFORMATION => {
            push_dir_times_core(&mut b, times, e.size, attrs, name.len() as u32);
            b.extend_from_slice(&name);
        }
        FILE_FULL_DIRECTORY_INFORMATION | FILE_ID_FULL_DIRECTORY_INFORMATION => {
            push_dir_times_core(&mut b, times, e.size, attrs, name.len() as u32);
            b.extend_from_slice(&0u32.to_le_bytes()); // EaSize
            if class == FILE_ID_FULL_DIRECTORY_INFORMATION {
                b.extend_from_slice(&e.inode.to_le_bytes());
            }
            b.extend_from_slice(&name);
        }
        FILE_BOTH_DIRECTORY_INFORMATION | FILE_ID_BOTH_DIRECTORY_INFORMATION => {
            push_dir_times_core(&mut b, times, e.size, attrs, name.len() as u32);
            b.extend_from_slice(&0u32.to_le_bytes()); // EaSize
            b.push(0); // ShortNameLength
            b.push(0); // Reserved
            b.extend_from_slice(&[0u8; 24]); // ShortName[12]
            if class == FILE_ID_BOTH_DIRECTORY_INFORMATION {
                // MS-FSCC FILE_ID_BOTH_DIR_INFORMATION: USHORT Reserved2 + FileId
                b.extend_from_slice(&0u16.to_le_bytes());
                b.extend_from_slice(&e.inode.to_le_bytes());
            }
            b.extend_from_slice(&name);
        }
        _ => {
            // Unknown class: emit FileIdBoth (what smbclient ls uses).
            push_dir_times_core(&mut b, times, e.size, attrs, name.len() as u32);
            b.extend_from_slice(&0u32.to_le_bytes());
            b.push(0);
            b.push(0);
            b.extend_from_slice(&[0u8; 24]);
            b.extend_from_slice(&0u16.to_le_bytes());
            b.extend_from_slice(&e.inode.to_le_bytes());
            b.extend_from_slice(&name);
        }
    }
    let pad = (8 - (b.len() % 8)) % 8;
    b.resize(b.len() + pad, 0);
    b
}

fn push_dir_times_core(b: &mut Vec<u8>, times: u64, size: u64, attrs: u32, name_len: u32) {
    b.extend_from_slice(&0u32.to_le_bytes());
    b.extend_from_slice(&0u32.to_le_bytes());
    for _ in 0..4 {
        b.extend_from_slice(&times.to_le_bytes());
    }
    b.extend_from_slice(&alloc_size(size).to_le_bytes());
    b.extend_from_slice(&size.to_le_bytes());
    b.extend_from_slice(&attrs.to_le_bytes());
    b.extend_from_slice(&name_len.to_le_bytes());
}

pub fn glob_match(pat: &str, name: &str) -> bool {
    let p = pat.trim();
    if p.is_empty() || p == "*" || p == "*.*" {
        return true;
    }
    fn rec(p: &[u8], n: &[u8]) -> bool {
        match (p.split_first(), n.split_first()) {
            (None, None) => true,
            (Some((b'*', rest)), _) => rec(rest, n) || (!n.is_empty() && rec(p, &n[1..])),
            (Some((b'?', rest)), Some((_, nrest))) => rec(rest, nrest),
            (Some((a, rest)), Some((b, nrest))) if a.eq_ignore_ascii_case(b) => rec(rest, nrest),
            _ => false,
        }
    }
    rec(p.as_bytes(), name.as_bytes())
}

// --- query / set info ---

#[derive(Clone, Debug)]
pub struct QueryInfoReq {
    pub info_type: u8,
    pub file_info_class: u8,
    pub file_id: [u8; 16],
    pub output_len: u32,
}

pub fn parse_query_info(cmd: &[u8]) -> io::Result<QueryInfoReq> {
    let body = cmd
        .get(SMB2_HEADER_LEN..)
        .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "QUERY_INFO"))?;
    if body.len() < 40 {
        return Err(io::Error::new(ErrorKind::UnexpectedEof, "QUERY_INFO body"));
    }
    Ok(QueryInfoReq {
        info_type: body[2],
        file_info_class: body[3],
        output_len: u32_at(body, 4)?,
        file_id: file_id_at(body, 24)?,
    })
}

pub fn encode_query_info_response(buffer: &[u8]) -> Vec<u8> {
    encode_query_directory_response(buffer)
}

#[derive(Clone, Debug)]
pub struct SetInfoReq {
    pub info_type: u8,
    pub file_info_class: u8,
    pub file_id: [u8; 16],
    pub buffer: Vec<u8>,
}

pub fn parse_set_info(cmd: &[u8]) -> io::Result<SetInfoReq> {
    let body = cmd
        .get(SMB2_HEADER_LEN..)
        .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "SET_INFO"))?;
    if body.len() < 32 {
        return Err(io::Error::new(ErrorKind::UnexpectedEof, "SET_INFO body"));
    }
    let info_type = body[2];
    let file_info_class = body[3];
    let buf_len = u32_at(body, 4)? as usize;
    let buf_off = u16_at(body, 8)? as usize;
    let file_id = file_id_at(body, 16)?;
    let buffer = if buf_len == 0 {
        Vec::new()
    } else {
        slice_from_cmd(cmd, buf_off, buf_len)?.to_vec()
    };
    Ok(SetInfoReq {
        info_type,
        file_info_class,
        file_id,
        buffer,
    })
}

pub fn encode_set_info_response() -> Vec<u8> {
    let mut b = vec![0u8; 2];
    b[0..2].copy_from_slice(&2u16.to_le_bytes());
    b
}

pub struct FileMeta {
    pub inode: u64,
    pub size: u64,
    pub mtime: f64,
    pub is_dir: bool,
    pub is_lnk: bool,
    pub name: String,
    pub readonly: bool,
}

pub fn encode_file_info(class: u8, m: &FileMeta) -> Option<Vec<u8>> {
    let times = unix_float_to_filetime(m.mtime);
    let mut attrs = if m.is_dir {
        FILE_ATTRIBUTE_DIRECTORY
    } else if m.size == 0 && !m.is_lnk {
        FILE_ATTRIBUTE_NORMAL
    } else {
        FILE_ATTRIBUTE_ARCHIVE
    };
    if m.is_lnk {
        attrs |= FILE_ATTRIBUTE_REPARSE_POINT;
    }
    if m.readonly {
        attrs |= FILE_ATTRIBUTE_READONLY;
    }
    match class {
        FILE_BASIC_INFORMATION => {
            let mut b = vec![0u8; 40];
            for off in [0usize, 8, 16, 24] {
                b[off..off + 8].copy_from_slice(&times.to_le_bytes());
            }
            b[32..36].copy_from_slice(&attrs.to_le_bytes());
            Some(b)
        }
        FILE_STANDARD_INFORMATION => {
            let mut b = vec![0u8; 24];
            b[0..8].copy_from_slice(&alloc_size(m.size).to_le_bytes());
            b[8..16].copy_from_slice(&m.size.to_le_bytes());
            b[16..20].copy_from_slice(&1u32.to_le_bytes());
            b[21] = u8::from(m.is_dir);
            Some(b)
        }
        FILE_INTERNAL_INFORMATION => Some(m.inode.to_le_bytes().to_vec()),
        FILE_EA_INFORMATION => Some(0u32.to_le_bytes().to_vec()),
        FILE_ACCESS_INFORMATION => Some(0x0012_0089u32.to_le_bytes().to_vec()),
        FILE_NAME_INFORMATION => Some(encode_name_info(&m.name)),
        FILE_POSITION_INFORMATION => Some(0u64.to_le_bytes().to_vec()),
        FILE_MODE_INFORMATION => Some(0u32.to_le_bytes().to_vec()),
        FILE_ALIGNMENT_INFORMATION => Some(0u32.to_le_bytes().to_vec()),
        FILE_NETWORK_OPEN_INFORMATION => {
            let mut b = vec![0u8; 56];
            for off in [0usize, 8, 16, 24] {
                b[off..off + 8].copy_from_slice(&times.to_le_bytes());
            }
            b[32..40].copy_from_slice(&alloc_size(m.size).to_le_bytes());
            b[40..48].copy_from_slice(&m.size.to_le_bytes());
            b[48..52].copy_from_slice(&attrs.to_le_bytes());
            Some(b)
        }
        FILE_ATTRIBUTE_TAG_INFORMATION => {
            let mut b = vec![0u8; 8];
            b[0..4].copy_from_slice(&attrs.to_le_bytes());
            Some(b)
        }
        FILE_STREAM_INFORMATION => {
            // One `::$DATA` stream.
            let stream = encode_utf16le("::$DATA");
            let mut b = Vec::new();
            b.extend_from_slice(&0u32.to_le_bytes());
            b.extend_from_slice(&(stream.len() as u32).to_le_bytes());
            b.extend_from_slice(&m.size.to_le_bytes());
            b.extend_from_slice(&alloc_size(m.size).to_le_bytes());
            b.extend_from_slice(&stream);
            let pad = (8 - (b.len() % 8)) % 8;
            b.resize(b.len() + pad, 0);
            Some(b)
        }
        FILE_ID_INFORMATION => {
            let mut b = vec![0u8; 24];
            b[8..16].copy_from_slice(&m.inode.to_le_bytes());
            Some(b)
        }
        FILE_ALL_INFORMATION => {
            let mut b = Vec::new();
            b.extend(encode_file_info(FILE_BASIC_INFORMATION, m)?);
            b.extend(encode_file_info(FILE_STANDARD_INFORMATION, m)?);
            b.extend(encode_file_info(FILE_INTERNAL_INFORMATION, m)?);
            b.extend(encode_file_info(FILE_EA_INFORMATION, m)?);
            b.extend(encode_file_info(FILE_ACCESS_INFORMATION, m)?);
            b.extend(encode_file_info(FILE_POSITION_INFORMATION, m)?);
            b.extend(encode_file_info(FILE_MODE_INFORMATION, m)?);
            b.extend(encode_file_info(FILE_ALIGNMENT_INFORMATION, m)?);
            b.extend(encode_file_info(FILE_NAME_INFORMATION, m)?);
            Some(b)
        }
        _ => None,
    }
}

fn encode_name_info(name: &str) -> Vec<u8> {
    let win = if name == "/" {
        "\\".to_string()
    } else {
        format!("\\{}", name.trim_start_matches('/').replace('/', "\\"))
    };
    let raw = encode_utf16le(&win);
    let mut b = Vec::with_capacity(4 + raw.len());
    b.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    b.extend_from_slice(&raw);
    b
}

pub fn encode_fs_info(class: u8, readonly: bool, volume: &str) -> Option<Vec<u8>> {
    match class {
        FILE_FS_VOLUME_INFORMATION => {
            let label = encode_utf16le(volume);
            let mut b = vec![0u8; 16];
            b[8..12].copy_from_slice(&0u32.to_le_bytes()); // serial
            b[12..16].copy_from_slice(&(label.len() as u32).to_le_bytes());
            b.push(0); // supports objects
            b.push(0);
            b.extend_from_slice(&label);
            Some(b)
        }
        FILE_FS_SIZE_INFORMATION | FILE_FS_FULL_SIZE_INFORMATION => {
            let mut b = vec![
                0u8;
                if class == FILE_FS_FULL_SIZE_INFORMATION {
                    32
                } else {
                    24
                }
            ];
            let units = 1_048_576u64;
            let avail = if readonly { 0 } else { units / 2 };
            b[0..8].copy_from_slice(&units.to_le_bytes());
            b[8..16].copy_from_slice(&avail.to_le_bytes());
            if class == FILE_FS_FULL_SIZE_INFORMATION {
                b[16..24].copy_from_slice(&avail.to_le_bytes());
                b[24..28].copy_from_slice(&1u32.to_le_bytes());
                b[28..32].copy_from_slice(&4096u32.to_le_bytes());
            } else {
                b[16..20].copy_from_slice(&1u32.to_le_bytes());
                b[20..24].copy_from_slice(&4096u32.to_le_bytes());
            }
            Some(b)
        }
        FILE_FS_DEVICE_INFORMATION => {
            let mut b = vec![0u8; 8];
            b[0..4].copy_from_slice(&FILE_DEVICE_DISK.to_le_bytes());
            let mut ch = FILE_DEVICE_IS_MOUNTED;
            if readonly {
                ch |= FILE_READ_ONLY_DEVICE;
            }
            b[4..8].copy_from_slice(&ch.to_le_bytes());
            Some(b)
        }
        FILE_FS_ATTRIBUTE_INFORMATION => {
            let fsname = encode_utf16le("NTFS");
            let mut attr =
                FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK | FILE_CASE_SENSITIVE_SEARCH;
            if readonly {
                attr |= FILE_READ_ONLY_VOLUME;
            }
            let mut b = Vec::new();
            b.extend_from_slice(&attr.to_le_bytes());
            b.extend_from_slice(&255u32.to_le_bytes());
            b.extend_from_slice(&(fsname.len() as u32).to_le_bytes());
            b.extend_from_slice(&fsname);
            Some(b)
        }
        FILE_FS_OBJECT_ID_INFORMATION => Some(vec![0u8; 64]),
        FILE_FS_SECTOR_SIZE_INFORMATION => {
            let mut b = vec![0u8; 28];
            for off in [0usize, 4, 8, 12] {
                b[off..off + 4].copy_from_slice(&4096u32.to_le_bytes());
            }
            Some(b)
        }
        _ => None,
    }
}

// --- NTLM / SPNEGO ---

pub fn extract_ntlm(buf: &[u8]) -> Option<&[u8]> {
    buf.windows(8)
        .position(|w| w == b"NTLMSSP\0")
        .map(|i| &buf[i..])
}

pub fn looks_like_spnego(buf: &[u8]) -> bool {
    matches!(buf.first(), Some(0x60 | 0xa0 | 0xa1))
}

fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else if n < 0x100 {
        vec![0x81, n as u8]
    } else {
        vec![0x82, (n >> 8) as u8, n as u8]
    }
}

fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(2 + body.len());
    v.push(tag);
    v.extend(der_len(body.len()));
    v.extend_from_slice(body);
    v
}

pub fn spnego_neg_token_init() -> Vec<u8> {
    let mech = der_tlv(0x06, NTLM_OID);
    let mechs = der_tlv(0xa0, &der_tlv(0x30, &mech));
    let inner = der_tlv(0x30, &mechs);
    let neg = der_tlv(0xa0, &inner);
    let oid = der_tlv(0x06, SPNEGO_OID);
    let mut body = oid;
    body.extend_from_slice(&neg);
    der_tlv(0x60, &body)
}

pub fn spnego_challenge(ntlm_type2: &[u8]) -> Vec<u8> {
    let state = der_tlv(0xa0, &[0x0a, 0x01, 0x01]);
    let mech = der_tlv(0xa1, &der_tlv(0x06, NTLM_OID));
    let tok = der_tlv(0xa2, &der_tlv(0x04, ntlm_type2));
    let mut seq = state;
    seq.extend_from_slice(&mech);
    seq.extend_from_slice(&tok);
    der_tlv(0xa1, &der_tlv(0x30, &seq))
}

pub fn spnego_accept() -> Vec<u8> {
    let state = der_tlv(0xa0, &[0x0a, 0x01, 0x00]);
    der_tlv(0xa1, &der_tlv(0x30, &state))
}

pub fn ntlm_type2(challenge: [u8; 8], target: &str) -> Vec<u8> {
    let name = encode_utf16le(target);
    // AV pairs: NbComputerName, NbDomainName, EOL
    let mut av = Vec::new();
    for id in [1u16, 2u16] {
        av.extend_from_slice(&id.to_le_bytes());
        av.extend_from_slice(&(name.len() as u16).to_le_bytes());
        av.extend_from_slice(&name);
    }
    av.extend_from_slice(&0u16.to_le_bytes());
    av.extend_from_slice(&0u16.to_le_bytes());

    const FLAGS: u32 = 0x0000_0001 // UNICODE
        | 0x0000_0004 // REQUEST_TARGET
        | 0x0000_0200 // NTLM
        | 0x0000_8000 // ALWAYS_SIGN
        | 0x0002_0000 // TARGET_TYPE_SERVER
        | 0x0008_0000 // EXTENDED_SESSIONSECURITY
        | 0x0080_0000 // TARGET_INFO
        | 0x2000_0000; // 128

    let mut b = Vec::from(&b"NTLMSSP\0"[..]);
    b.extend_from_slice(&2u32.to_le_bytes());
    // TargetName
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

pub fn ntlm_type(buf: &[u8]) -> Option<u32> {
    let n = extract_ntlm(buf)?;
    if n.len() < 12 {
        return None;
    }
    u32_at(n, 8).ok()
}

pub fn ntlm_type3_user(buf: &[u8]) -> Option<String> {
    let n = extract_ntlm(buf)?;
    if n.len() < 52 {
        return None;
    }
    let typ = u32_at(n, 8).ok()?;
    if typ != 3 {
        return None;
    }
    let len = u16_at(n, 36).ok()? as usize;
    let off = u32_at(n, 40).ok()? as usize;
    if off + len > n.len() {
        return None;
    }
    let raw = &n[off..off + len];
    let flags = u32_at(n, 60).unwrap_or(1);
    if flags & 1 != 0 {
        Some(decode_utf16le(raw))
    } else {
        Some(String::from_utf8_lossy(raw).into_owned())
    }
}

#[cfg(test)]
pub fn ntlm_type1() -> Vec<u8> {
    let mut b = Vec::from(&b"NTLMSSP\0"[..]);
    b.extend_from_slice(&1u32.to_le_bytes());
    let flags: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0004 | 0x0000_0200 | 0x0008_0000;
    b.extend_from_slice(&flags.to_le_bytes());
    // domain / workstation empty
    for _ in 0..4 {
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u32.to_le_bytes());
    }
    b
}

#[cfg(test)]
pub fn ntlm_type3_guest() -> Vec<u8> {
    ntlm_type3_with_user("")
}

#[cfg(test)]
pub fn ntlm_type3_with_user(user: &str) -> Vec<u8> {
    let raw = encode_utf16le(user);
    let mut b = Vec::from(&b"NTLMSSP\0"[..]);
    b.extend_from_slice(&3u32.to_le_bytes());
    let flags: u32 = 0x0000_0001 | 0x0000_0200;
    // LM, NT, Domain empty at offset 64
    for _ in 0..3 {
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&64u32.to_le_bytes());
    }
    b.extend_from_slice(&(raw.len() as u16).to_le_bytes());
    b.extend_from_slice(&(raw.len() as u16).to_le_bytes());
    b.extend_from_slice(&64u32.to_le_bytes());
    let after_user = 64 + raw.len() as u32;
    for _ in 0..2 {
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&0u16.to_le_bytes());
        b.extend_from_slice(&after_user.to_le_bytes());
    }
    b.extend_from_slice(&flags.to_le_bytes());
    debug_assert_eq!(b.len(), 64);
    b.extend_from_slice(&raw);
    b
}

pub fn challenge8() -> [u8; 8] {
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mix =
        t.as_nanos() as u64 ^ u64::from(std::process::id()).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    mix.to_le_bytes()
}

fn slice_from_cmd(cmd: &[u8], off: usize, len: usize) -> io::Result<&[u8]> {
    cmd.get(off..off + len)
        .ok_or_else(|| io::Error::new(ErrorKind::UnexpectedEof, "buffer offset"))
}

pub fn smb_path_to_unix(name: &str) -> String {
    let n = name.replace('\\', "/");
    ratarmount_core::normpath(&n)
}

pub fn basename_unix(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
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
        assert_eq!(p.process_id, 0xfeff);
    }

    #[test]
    fn nbss_len_roundtrip() {
        let payload = vec![0xfe, b'S', b'M', b'B', 0, 1, 2, 3];
        let framed = encode_nbss(&payload);
        assert_eq!(framed[0], 0);
        let n = decode_nbss_len(framed[..4].try_into().unwrap()).unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(&framed[4..], payload);
    }

    #[test]
    fn utf16_roundtrip() {
        let s = "ratarmount";
        assert_eq!(decode_utf16le(&encode_utf16le(s)), s);
    }

    #[test]
    fn extract_ntlm_from_spnego() {
        let t1 = ntlm_type1();
        let wrapped = {
            let tok = der_tlv(0xa2, &der_tlv(0x04, &t1));
            der_tlv(0xa0, &der_tlv(0x30, &tok))
        };
        let got = extract_ntlm(&wrapped).unwrap();
        assert_eq!(ntlm_type(got), Some(1));
        assert!(looks_like_spnego(&spnego_neg_token_init()));
        let t2 = ntlm_type2([1, 2, 3, 4, 5, 6, 7, 8], "RATARMOUNT");
        assert_eq!(ntlm_type(&t2), Some(2));
        assert!(extract_ntlm(&spnego_challenge(&t2)).is_some());
    }

    #[test]
    fn ntlm_type3_user_empty_is_guest() {
        let t3 = ntlm_type3_guest();
        assert_eq!(ntlm_type(&t3), Some(3));
        assert_eq!(ntlm_type3_user(&t3).as_deref(), Some(""));
    }

    #[test]
    fn dirent_next_offset_aligned() {
        let entries = vec![
            DirEntry {
                name: "a.txt".into(),
                inode: 3,
                size: 1,
                mtime: 1.0,
                is_dir: false,
                is_lnk: false,
            },
            DirEntry {
                name: "b".into(),
                inode: 4,
                size: 0,
                mtime: 1.0,
                is_dir: true,
                is_lnk: false,
            },
        ];
        let buf = encode_dir_entries(FILE_BOTH_DIRECTORY_INFORMATION, &entries, 4096);
        let next = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        assert_eq!(next % 8, 0);
        assert!(next > 0 && next < buf.len());
        let next2 = u32::from_le_bytes(buf[next..next + 4].try_into().unwrap());
        assert_eq!(next2, 0, "last NextEntryOffset is 0");
        assert!(glob_match("*", "hello.txt"));
        assert!(glob_match("hello.txt", "hello.txt"));
        assert!(!glob_match("nope", "hello.txt"));

        // MS-FSCC FILE_ID_BOTH_DIR_INFORMATION: FileId sits at offset 104.
        let id_both = encode_dir_entries(FILE_ID_BOTH_DIRECTORY_INFORMATION, &entries, 4096);
        assert_eq!(u32::from_le_bytes(id_both[0..4].try_into().unwrap()) % 8, 0);
        let file_id = u64::from_le_bytes(id_both[96..104].try_into().unwrap());
        assert_eq!(file_id, 3);
    }

    #[test]
    fn share_name_from_unc_paths() {
        assert_eq!(
            share_name_from_unc(r"\\127.0.0.1\ratarmount").as_deref(),
            Some("ratarmount")
        );
        assert_eq!(share_name_from_unc(r"\\*\IPC$").as_deref(), Some("IPC$"));
        assert_eq!(smb_path_to_unix(r"sub\child.txt"), "/sub/child.txt");
        assert_eq!(smb_path_to_unix(r"\hello.txt"), "/hello.txt");
        assert_eq!(smb_path_to_unix(""), "/");
    }

    #[test]
    fn pick_dialect_prefers_202() {
        assert_eq!(
            pick_dialect(&[0x0311, DIALECT_202, DIALECT_210]),
            Some(DIALECT_202)
        );
        assert_eq!(pick_dialect(&[0x0311]), None);
        assert_eq!(pick_dialect(&[DIALECT_210]), Some(DIALECT_210));
    }

    #[test]
    fn compound_split_and_stitch() {
        let h1 = Smb2Header {
            credit_charge: 1,
            status: 0,
            command: SMB2_ECHO,
            credits: 1,
            flags: 0,
            next_command: 0,
            message_id: 1,
            process_id: 0,
            tree_id: 0,
            session_id: 0,
        };
        let a = encode_packet(&h1, &encode_empty_sized(4, 4));
        let mut h2 = h1.clone();
        h2.message_id = 2;
        let b = encode_packet(&h2, &encode_empty_sized(4, 4));
        let joined = stitch_compound(&[a.clone(), b.clone()]);
        let parts = split_compound(&joined).unwrap();
        assert_eq!(parts.len(), 2);
        assert_eq!(parse_smb2_header(parts[0]).unwrap().message_id, 1);
        assert_eq!(parse_smb2_header(parts[1]).unwrap().message_id, 2);
    }

    #[test]
    fn smb1_negotiate_detects_smb2_dialect_string() {
        // Minimal SMB1 NEGOTIATE with "SMB 2.002"
        let mut buf = vec![0xff, b'S', b'M', b'B', 0x72];
        buf.resize(32, 0);
        buf.push(0); // WordCount
        let dialect = {
            let mut d = vec![0x02];
            d.extend_from_slice(b"SMB 2.002\0");
            d
        };
        buf.extend_from_slice(&(dialect.len() as u16).to_le_bytes());
        buf.extend_from_slice(&dialect);
        assert!(is_smb1(&buf));
        assert!(smb1_has_smb2_dialect(&buf));
    }
}
