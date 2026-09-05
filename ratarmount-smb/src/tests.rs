//! Crate-level SMB2 export tests (no factory / CLI).

use std::collections::BTreeMap;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use ratarmount_compositing::WriteOverlay;
use ratarmount_core::{
    create_root_file_info, CheapDirent, FileInfo, ListResult, MountSource, UserData, S_IFREG,
};
use ratarmount_export_core::fill_read;

use crate::smb2::{self, Smb2Header};
use crate::{
    parse_smb_bind, spawn_smb_thread, ExportServerHandle, ExportStop, SmbOptions, DEFAULT_SMB_BIND,
    DEFAULT_SMB_PORT, DEFAULT_SMB_SHARE,
};

/// One-byte / short-window `Read::read` — gzip inflate windows look like this.
struct ShortRead {
    inner: Cursor<Vec<u8>>,
    chunk: usize,
}

impl Read for ShortRead {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let n = buf.len().min(self.chunk.max(1));
        self.inner.read(&mut buf[..n])
    }
}

impl Seek for ShortRead {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        self.inner.seek(pos)
    }
}

struct MemFile {
    data: Vec<u8>,
    mtime: f64,
    short_chunk: Option<usize>,
}

struct MemFs {
    files: BTreeMap<String, MemFile>,
    dirs: BTreeMap<String, Vec<CheapDirent>>,
}

impl MemFs {
    fn fixture() -> Self {
        let hello = b"hello smb\n".to_vec();
        let gzip_payload: Vec<u8> = (0..80_000u32).map(|i| (i % 251) as u8).collect();
        let mut files = BTreeMap::new();
        files.insert(
            "/hello.txt".into(),
            MemFile {
                data: hello,
                mtime: 1_592_222_400.0,
                short_chunk: None,
            },
        );
        files.insert(
            "/gzip-member.bin".into(),
            MemFile {
                data: gzip_payload,
                mtime: 1_592_222_400.0,
                short_chunk: Some(64 * 1024 - 10),
            },
        );
        let mut dirs = BTreeMap::new();
        dirs.insert(
            "/".into(),
            vec![
                CheapDirent {
                    name: "hello.txt".into(),
                    mode: S_IFREG | 0o644,
                    size: 10,
                },
                CheapDirent {
                    name: "gzip-member.bin".into(),
                    mode: S_IFREG | 0o644,
                    size: 80_000,
                },
            ],
        );
        Self { files, dirs }
    }

    fn empty() -> Self {
        let mut dirs = BTreeMap::new();
        dirs.insert("/".into(), Vec::new());
        Self {
            files: BTreeMap::new(),
            dirs,
        }
    }

    fn file_info(path: &str, f: &MemFile) -> FileInfo {
        FileInfo {
            size: f.data.len() as u64,
            mtime: f.mtime,
            mode: S_IFREG | 0o644,
            linkname: String::new(),
            uid: 0,
            gid: 0,
            userdata: vec![UserData::Other(path.into())],
        }
    }
}

impl MountSource for MemFs {
    fn list(&self, path: &str) -> Option<ListResult> {
        let dents = self.dirs.get(path)?;
        Some(ListResult::Names(
            dents.iter().map(|d| d.name.clone()).collect(),
        ))
    }

    fn list_dirents(&self, path: &str) -> Option<Vec<CheapDirent>> {
        self.dirs.get(path).cloned()
    }

    fn lookup(&self, path: &str, _: i32) -> Option<FileInfo> {
        if path == "/" || self.dirs.contains_key(path) {
            let mut fi = create_root_file_info();
            if path != "/" {
                fi.userdata = vec![UserData::Other(path.into())];
            }
            return Some(fi);
        }
        self.files.get(path).map(|f| Self::file_info(path, f))
    }

    fn open(
        &self,
        file_info: &FileInfo,
        _: i32,
    ) -> io::Result<Box<dyn ratarmount_core::ArchiveRead>> {
        let path = match file_info.userdata.last() {
            Some(UserData::Other(p)) => p.as_str(),
            _ => {
                return Err(io::Error::new(io::ErrorKind::NotFound, "no path"));
            }
        };
        let f = self
            .files
            .get(path)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, path))?;
        match f.short_chunk {
            Some(chunk) => Ok(Box::new(ShortRead {
                inner: Cursor::new(f.data.clone()),
                chunk,
            })),
            None => Ok(Box::new(Cursor::new(f.data.clone()))),
        }
    }

    fn is_immutable(&self) -> bool {
        true
    }
}

struct Serving {
    handle: Option<ExportServerHandle>,
    stop: ExportStop,
    addr: SocketAddr,
}

impl Serving {
    fn start(src: Arc<dyn MountSource>, overlay: Option<Arc<WriteOverlay>>) -> Self {
        let stop = ExportStop::new();
        let opts = SmbOptions {
            bind: "127.0.0.1:0".parse().unwrap(),
            stop: Some(stop.clone()),
            overlay,
            ..SmbOptions::default()
        };
        let handle = spawn_smb_thread(src, opts).expect("bind SMB");
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, handle.port));
        Self {
            handle: Some(handle),
            stop,
            addr,
        }
    }

    fn start_fixture() -> Self {
        Self::start(Arc::new(MemFs::fixture()), None)
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.stop.request_stop();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

struct SmbClient {
    stream: TcpStream,
    mid: u64,
    session_id: u64,
    tree_id: u32,
    process_id: u32,
    session_key: Option<[u8; 16]>,
    dialect: u16,
    preauth: [u8; 64],
    signing_key: Option<[u8; 16]>,
    c2s_key: Option<[u8; 16]>,
    s2c_key: Option<[u8; 16]>,
    cipher: Option<smb2::SmbCipher>,
    encrypt_data: bool,
    nonce_ctr: u64,
}

impl SmbClient {
    fn connect_stream(addr: SocketAddr) -> TcpStream {
        let mut last = None;
        for _ in 0..40 {
            match TcpStream::connect_timeout(&addr, Duration::from_secs(1)) {
                Ok(stream) => {
                    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
                    stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
                    return stream;
                }
                Err(e) => {
                    last = Some(e);
                    std::thread::sleep(Duration::from_millis(25));
                }
            }
        }
        panic!("connect {addr}: {last:?}");
    }

    fn from_stream(stream: TcpStream) -> Self {
        Self {
            stream,
            mid: 0,
            session_id: 0,
            tree_id: 0,
            process_id: 0xfeff,
            session_key: None,
            dialect: 0,
            preauth: smb2::PREAUTH_ZERO,
            signing_key: None,
            c2s_key: None,
            s2c_key: None,
            cipher: None,
            encrypt_data: false,
            nonce_ctr: 0,
        }
    }

    fn connect(addr: SocketAddr) -> Self {
        let mut c = Self::from_stream(Self::connect_stream(addr));
        c.negotiate();
        c.session_setup_guest();
        c.tree_connect("ratarmount");
        c
    }

    fn connect_negotiate(addr: SocketAddr) -> Self {
        let mut c = Self::from_stream(Self::connect_stream(addr));
        c.negotiate();
        c
    }

    fn hdr(&mut self, cmd: u16) -> Smb2Header {
        let h = Smb2Header {
            credit_charge: 1,
            status: 0,
            command: cmd,
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

    fn roundtrip_raw(&mut self, pkt: &[u8]) -> Vec<u8> {
        let wire = if self.encrypt_data {
            self.encrypt_out(pkt)
        } else {
            pkt.to_vec()
        };
        self.stream
            .write_all(&smb2::encode_nbss(&wire))
            .expect("smb write");
        let mut nb = [0u8; 4];
        self.stream.read_exact(&mut nb).expect("nbss hdr");
        let n = smb2::decode_nbss_len(nb).expect("nbss len");
        let mut buf = vec![0u8; n];
        self.stream.read_exact(&mut buf).expect("smb body");
        if smb2::is_smb2_transform(&buf) {
            self.decrypt_in(&buf)
        } else {
            buf
        }
    }

    fn encrypt_out(&mut self, pkt: &[u8]) -> Vec<u8> {
        let key = self.c2s_key.expect("C2S key");
        let cipher = self.cipher.expect("cipher");
        self.nonce_ctr = self.nonce_ctr.saturating_add(1);
        let mut nonce = [0u8; 16];
        nonce[8..16].copy_from_slice(&self.nonce_ctr.to_le_bytes());
        smb2::encrypt_transform(pkt, self.session_id, &key, cipher, nonce).expect("encrypt")
    }

    fn decrypt_in(&self, frame: &[u8]) -> Vec<u8> {
        let key = self.s2c_key.expect("S2C key");
        let cipher = self.cipher.expect("cipher");
        smb2::decrypt_transform(frame, &key, cipher).expect("decrypt")
    }

    fn roundtrip(&mut self, pkt: &[u8]) -> (Smb2Header, Vec<u8>) {
        let buf = self.roundtrip_raw(pkt);
        let h = smb2::parse_smb2_header(&buf).expect("hdr");
        let body = buf[smb2::SMB2_HEADER_LEN..].to_vec();
        (h, body)
    }

    fn negotiate(&mut self) {
        let mut body = vec![0u8; 36];
        body[0..2].copy_from_slice(&36u16.to_le_bytes());
        body[2..4].copy_from_slice(&2u16.to_le_bytes());
        body[4..6].copy_from_slice(&1u16.to_le_bytes());
        body.extend_from_slice(&smb2::DIALECT_202.to_le_bytes());
        body.extend_from_slice(&smb2::DIALECT_210.to_le_bytes());
        let h = self.hdr(smb2::SMB2_NEGOTIATE);
        let (rh, _) = self.roundtrip(&smb2::encode_packet(&h, &body));
        assert_eq!(
            rh.status,
            smb2::STATUS_SUCCESS,
            "NEGOTIATE {:08x}",
            rh.status
        );
        self.dialect = smb2::DIALECT_202;
    }

    /// SMB 3.1.1-only NEGOTIATE with preauth (+ optional encryption) contexts.
    fn negotiate_311(&mut self, want_encrypt: bool) -> Vec<u8> {
        let body = encode_negotiate_311_body(want_encrypt);
        let h = self.hdr(smb2::SMB2_NEGOTIATE);
        let req = smb2::encode_packet(&h, &body);
        self.preauth = smb2::preauth_hash_update(&smb2::PREAUTH_ZERO, &req);
        let resp = self.roundtrip_raw(&req);
        let rh = smb2::parse_smb2_header(&resp).expect("hdr");
        assert_eq!(
            rh.status,
            smb2::STATUS_SUCCESS,
            "NEGOTIATE 3.1.1 {:08x}",
            rh.status
        );
        let nbody = &resp[smb2::SMB2_HEADER_LEN..];
        let dialect = u16::from_le_bytes(nbody[4..6].try_into().unwrap());
        assert_eq!(dialect, smb2::DIALECT_311, "server must pick 3.1.1");
        self.dialect = dialect;
        self.preauth = smb2::preauth_hash_update(&self.preauth, &resp);
        if want_encrypt {
            self.cipher = Some(smb2::SmbCipher::Aes128Gcm);
        }
        resp
    }

    fn session_setup_guest(&mut self) {
        let t1 = smb2::ntlm_type1();
        let (rh, _) = self.session_setup_sec(&t1);
        assert_eq!(
            rh.status,
            smb2::STATUS_MORE_PROCESSING_REQUIRED,
            "SESSION_SETUP type1 {:08x}",
            rh.status
        );
        self.session_id = rh.session_id;
        let t3 = smb2::ntlm_type3_guest();
        let (rh, _) = self.session_setup_sec(&t3);
        assert_eq!(
            rh.status,
            smb2::STATUS_SUCCESS,
            "SESSION_SETUP type3 {:08x}",
            rh.status
        );
        self.session_id = rh.session_id;
    }

    fn session_setup_sec_raw(&mut self, sec: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8; 24];
        body[0..2].copy_from_slice(&25u16.to_le_bytes());
        body[3] = 1; // signing enabled
        let off = (smb2::SMB2_HEADER_LEN + 24) as u16;
        body[12..14].copy_from_slice(&off.to_le_bytes());
        body[14..16].copy_from_slice(&(sec.len() as u16).to_le_bytes());
        body.extend_from_slice(sec);
        let h = self.hdr(smb2::SMB2_SESSION_SETUP);
        let pkt = smb2::encode_packet(&h, &body);
        if self.dialect == smb2::DIALECT_311 {
            self.preauth = smb2::preauth_hash_update(&self.preauth, &pkt);
        }
        let buf = self.roundtrip_raw(&pkt);
        if self.dialect == smb2::DIALECT_311 {
            if let Ok(rh) = smb2::parse_smb2_header(&buf) {
                if rh.status == smb2::STATUS_MORE_PROCESSING_REQUIRED {
                    self.preauth = smb2::preauth_hash_update(&self.preauth, &buf);
                }
            }
        }
        buf
    }

    fn session_setup_sec(&mut self, sec: &[u8]) -> (Smb2Header, Vec<u8>) {
        let buf = self.session_setup_sec_raw(sec);
        let h = smb2::parse_smb2_header(&buf).expect("hdr");
        let body = buf[smb2::SMB2_HEADER_LEN..].to_vec();
        (h, body)
    }

    fn tree_connect_status(&mut self, share: &str, sign: bool) -> (Smb2Header, Vec<u8>) {
        let unc = format!(r"\\127.0.0.1\{share}");
        let path = smb2::encode_utf16le(&unc);
        let mut body = vec![0u8; 8];
        body[0..2].copy_from_slice(&9u16.to_le_bytes());
        let off = (smb2::SMB2_HEADER_LEN + 8) as u16;
        body[4..6].copy_from_slice(&off.to_le_bytes());
        body[6..8].copy_from_slice(&(path.len() as u16).to_le_bytes());
        body.extend_from_slice(&path);
        let h = self.hdr(smb2::SMB2_TREE_CONNECT);
        let mut pkt = smb2::encode_packet(&h, &body);
        if sign && !self.encrypt_data {
            if let Some(key) = self.signing_key.or(self.session_key) {
                if self.dialect == smb2::DIALECT_311 {
                    smb2::smb3_sign_packet(&mut pkt, &key);
                } else {
                    smb2::smb2_sign_packet(&mut pkt, &key);
                }
            }
        }
        let (rh, body) = self.roundtrip(&pkt);
        if rh.status == smb2::STATUS_SUCCESS {
            self.tree_id = rh.tree_id;
        }
        (rh, body)
    }

    fn tree_connect(&mut self, share: &str) {
        let (rh, _) = self.tree_connect_status(share, self.session_key.is_some());
        assert_eq!(
            rh.status,
            smb2::STATUS_SUCCESS,
            "TREE_CONNECT {:08x}",
            rh.status
        );
    }

    fn create(
        &mut self,
        name: &str,
        access: u32,
        disp: u32,
        options: u32,
    ) -> Result<[u8; 16], u32> {
        let (rh, b) = self.create_resp(name, access, disp, options, 0, &[]);
        if rh.status != smb2::STATUS_SUCCESS {
            return Err(rh.status);
        }
        let mut fid = [0u8; 16];
        fid.copy_from_slice(&b[64..80]);
        Ok(fid)
    }

    #[allow(clippy::unused_self)]
    fn create_body(
        &self,
        name: &str,
        access: u32,
        disp: u32,
        options: u32,
        oplock: u8,
        contexts: &[Vec<u8>],
    ) -> Vec<u8> {
        let raw = smb2::encode_utf16le(name);
        let mut body = vec![0u8; 56];
        body[0..2].copy_from_slice(&57u16.to_le_bytes());
        body[3] = oplock;
        body[4..8].copy_from_slice(&2u32.to_le_bytes()); // impersonation
        body[24..28].copy_from_slice(&access.to_le_bytes());
        body[28..32].copy_from_slice(&smb2::FILE_ATTRIBUTE_NORMAL.to_le_bytes());
        body[32..36].copy_from_slice(&0x7u32.to_le_bytes()); // share r/w/d
        body[36..40].copy_from_slice(&disp.to_le_bytes());
        body[40..44].copy_from_slice(&options.to_le_bytes());
        let off = (smb2::SMB2_HEADER_LEN + 56) as u16;
        body[44..46].copy_from_slice(&off.to_le_bytes());
        body[46..48].copy_from_slice(&(raw.len() as u16).to_le_bytes());
        body.extend_from_slice(&raw);
        if !contexts.is_empty() {
            let pad = (8 - (body.len() % 8)) % 8;
            body.resize(body.len() + pad, 0);
            let blob = smb2::stitch_create_contexts(contexts);
            let ctx_off = (smb2::SMB2_HEADER_LEN + body.len()) as u32;
            body[48..52].copy_from_slice(&ctx_off.to_le_bytes());
            body[52..56].copy_from_slice(&(blob.len() as u32).to_le_bytes());
            body.extend_from_slice(&blob);
        }
        body
    }

    fn create_resp(
        &mut self,
        name: &str,
        access: u32,
        disp: u32,
        options: u32,
        oplock: u8,
        contexts: &[Vec<u8>],
    ) -> (Smb2Header, Vec<u8>) {
        let body = self.create_body(name, access, disp, options, oplock, contexts);
        let h = self.hdr(smb2::SMB2_CREATE);
        self.roundtrip(&smb2::encode_packet(&h, &body))
    }

    fn recv_raw(&mut self) -> Vec<u8> {
        let mut nb = [0u8; 4];
        self.stream.read_exact(&mut nb).expect("nbss hdr");
        let n = smb2::decode_nbss_len(nb).expect("nbss len");
        let mut buf = vec![0u8; n];
        self.stream.read_exact(&mut buf).expect("smb body");
        if smb2::is_smb2_transform(&buf) {
            self.decrypt_in(&buf)
        } else {
            buf
        }
    }

    fn send_raw(&mut self, pkt: &[u8]) {
        let wire = if self.encrypt_data {
            self.encrypt_out(pkt)
        } else {
            pkt.to_vec()
        };
        self.stream
            .write_all(&smb2::encode_nbss(&wire))
            .expect("smb write");
    }

    fn close(&mut self, fid: [u8; 16]) {
        let mut body = vec![0u8; 24];
        body[0..2].copy_from_slice(&24u16.to_le_bytes());
        body[8..24].copy_from_slice(&fid);
        let h = self.hdr(smb2::SMB2_CLOSE);
        let (rh, _) = self.roundtrip(&smb2::encode_packet(&h, &body));
        assert_eq!(rh.status, smb2::STATUS_SUCCESS, "CLOSE {:08x}", rh.status);
    }

    fn read(&mut self, fid: [u8; 16], offset: u64, length: u32) -> Result<Vec<u8>, u32> {
        let mut body = vec![0u8; 48];
        body[0..2].copy_from_slice(&49u16.to_le_bytes());
        body[4..8].copy_from_slice(&length.to_le_bytes());
        body[8..16].copy_from_slice(&offset.to_le_bytes());
        body[16..32].copy_from_slice(&fid);
        let h = self.hdr(smb2::SMB2_READ);
        let (rh, b) = self.roundtrip(&smb2::encode_packet(&h, &body));
        if rh.status != smb2::STATUS_SUCCESS {
            return Err(rh.status);
        }
        let data_off = b[2] as usize;
        let data_len = u32::from_le_bytes(b[4..8].try_into().unwrap()) as usize;
        let start = data_off.saturating_sub(smb2::SMB2_HEADER_LEN);
        Ok(b.get(start..start + data_len).unwrap_or(&[]).to_vec())
    }

    fn write(&mut self, fid: [u8; 16], offset: u64, data: &[u8]) -> Result<u32, u32> {
        let mut body = vec![0u8; 48];
        body[0..2].copy_from_slice(&49u16.to_le_bytes());
        let off = (smb2::SMB2_HEADER_LEN + 48) as u16;
        body[2..4].copy_from_slice(&off.to_le_bytes());
        body[4..8].copy_from_slice(&(data.len() as u32).to_le_bytes());
        body[8..16].copy_from_slice(&offset.to_le_bytes());
        body[16..32].copy_from_slice(&fid);
        body.extend_from_slice(data);
        let h = self.hdr(smb2::SMB2_WRITE);
        let (rh, b) = self.roundtrip(&smb2::encode_packet(&h, &body));
        if rh.status != smb2::STATUS_SUCCESS {
            return Err(rh.status);
        }
        Ok(u32::from_le_bytes(b[4..8].try_into().unwrap()))
    }

    fn query_dir_names(&mut self, fid: [u8; 16]) -> Result<Vec<String>, u32> {
        let pat = smb2::encode_utf16le("*");
        let mut body = vec![0u8; 32];
        body[0..2].copy_from_slice(&33u16.to_le_bytes());
        body[2] = smb2::FILE_NAMES_INFORMATION;
        body[3] = smb2::SMB2_RESTART_SCANS;
        body[8..24].copy_from_slice(&fid);
        let off = (smb2::SMB2_HEADER_LEN + 32) as u16;
        body[24..26].copy_from_slice(&off.to_le_bytes());
        body[26..28].copy_from_slice(&(pat.len() as u16).to_le_bytes());
        body[28..32].copy_from_slice(&65536u32.to_le_bytes());
        body.extend_from_slice(&pat);
        let h = self.hdr(smb2::SMB2_QUERY_DIRECTORY);
        let (rh, b) = self.roundtrip(&smb2::encode_packet(&h, &body));
        if rh.status != smb2::STATUS_SUCCESS {
            return Err(rh.status);
        }
        let buf_off = u16::from_le_bytes(b[2..4].try_into().unwrap()) as usize;
        let buf_len = u32::from_le_bytes(b[4..8].try_into().unwrap()) as usize;
        let start = buf_off.saturating_sub(smb2::SMB2_HEADER_LEN);
        let buf = b.get(start..start + buf_len).unwrap_or(&[]);
        Ok(parse_names_info(buf))
    }
}

fn encode_negotiate_311_body(want_encrypt: bool) -> Vec<u8> {
    let mut body = vec![0u8; 36];
    body[0..2].copy_from_slice(&36u16.to_le_bytes());
    body[2..4].copy_from_slice(&1u16.to_le_bytes());
    body[4..6].copy_from_slice(&1u16.to_le_bytes());
    if want_encrypt {
        body[8..12].copy_from_slice(&smb2::SMB2_GLOBAL_CAP_ENCRYPTION.to_le_bytes());
    }
    body.extend_from_slice(&smb2::DIALECT_311.to_le_bytes());
    let pad = (8 - (body.len() % 8)) % 8;
    body.resize(body.len() + pad, 0);
    let ctx_off = (smb2::SMB2_HEADER_LEN + body.len()) as u32;
    body[28..32].copy_from_slice(&ctx_off.to_le_bytes());
    let salt = [0x11u8; 32];
    let mut ctxs = smb2::encode_preauth_context(&salt);
    let mut nctx = 1u16;
    if want_encrypt {
        let mut data = Vec::new();
        data.extend_from_slice(&2u16.to_le_bytes());
        data.extend_from_slice(&smb2::CIPHER_AES128_GCM.to_le_bytes());
        data.extend_from_slice(&smb2::CIPHER_AES128_CCM.to_le_bytes());
        ctxs.extend_from_slice(&smb2::encode_negotiate_context(
            smb2::SMB2_ENCRYPTION_CAPABILITIES,
            &data,
        ));
        nctx = 2;
    }
    body[32..34].copy_from_slice(&nctx.to_le_bytes());
    body.extend_from_slice(&ctxs);
    body
}

fn parse_names_info(buf: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 12 <= buf.len() {
        let next = u32::from_le_bytes(buf[off..off + 4].try_into().unwrap()) as usize;
        let nlen = u32::from_le_bytes(buf[off + 8..off + 12].try_into().unwrap()) as usize;
        if off + 12 + nlen > buf.len() {
            break;
        }
        out.push(smb2::decode_utf16le(&buf[off + 12..off + 12 + nlen]));
        if next == 0 {
            break;
        }
        off += next;
    }
    out
}

#[test]
fn parse_smb_bind_empty_is_20445() {
    assert_eq!(parse_smb_bind("").unwrap(), DEFAULT_SMB_BIND);
    assert_eq!(parse_smb_bind("20445").unwrap().port(), DEFAULT_SMB_PORT);
    assert_eq!(DEFAULT_SMB_PORT, 20445);
    assert_ne!(DEFAULT_SMB_PORT, 20490);
    assert_eq!(DEFAULT_SMB_SHARE, "ratarmount");
}

#[test]
fn negotiate_210_advertises_leasing() {
    let srv = Serving::start_fixture();
    let mut c = SmbClient::from_stream(SmbClient::connect_stream(srv.addr));
    c.stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut body = vec![0u8; 36];
    body[0..2].copy_from_slice(&36u16.to_le_bytes());
    body[2..4].copy_from_slice(&1u16.to_le_bytes());
    body[4..6].copy_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&smb2::DIALECT_210.to_le_bytes());
    let h = c.hdr(smb2::SMB2_NEGOTIATE);
    let (rh, nbody) = c.roundtrip(&smb2::encode_packet(&h, &body));
    assert_eq!(rh.status, smb2::STATUS_SUCCESS);
    let dialect = u16::from_le_bytes(nbody[4..6].try_into().unwrap());
    assert_eq!(dialect, smb2::DIALECT_210);
    let caps = u32::from_le_bytes(nbody[24..28].try_into().unwrap());
    assert_eq!(
        caps & smb2::SMB2_GLOBAL_CAP_LEASING,
        smb2::SMB2_GLOBAL_CAP_LEASING
    );
}

#[test]
fn negotiate_session_tree_ls_get() {
    let srv = Serving::start_fixture();
    let mut c = SmbClient::connect(srv.addr);
    let root = c
        .create("", 0x0012_0089, smb2::FILE_OPEN, smb2::FILE_DIRECTORY_FILE)
        .expect("open root");
    let names = c.query_dir_names(root).expect("ls");
    c.close(root);
    assert!(names.iter().any(|n| n == "hello.txt"), "{names:?}");
    assert!(names.iter().any(|n| n == "gzip-member.bin"), "{names:?}");

    let fid = c
        .create(
            "hello.txt",
            0x0012_0089,
            smb2::FILE_OPEN,
            smb2::FILE_NON_DIRECTORY_FILE,
        )
        .expect("open hello");
    let body = c.read(fid, 0, 64).expect("get");
    c.close(fid);
    assert_eq!(body, b"hello smb\n");
}

/// Regression: SMB READ fill-loop — short `Read::read` is not treated as EOF.
#[test]
fn regression_smb_read_fill_loop() {
    let srv = Serving::start_fixture();
    let mut c = SmbClient::connect(srv.addr);
    let fid = c
        .create(
            "gzip-member.bin",
            0x0012_0089,
            smb2::FILE_OPEN,
            smb2::FILE_NON_DIRECTORY_FILE,
        )
        .expect("open gzip member");
    let body = c.read(fid, 0, 80_000).expect("read");
    c.close(fid);
    let want: Vec<u8> = (0..80_000u32).map(|i| (i % 251) as u8).collect();
    assert_eq!(
        body.len(),
        want.len(),
        "gzip-window short Read::read must be fill-looped, not treated as SMB EOF"
    );
    assert_eq!(body, want);
}

/// Lowest-layer fill_read loop (same contract as the SMB READ path).
#[test]
fn fill_read_loops_until_full() {
    let mut r = ShortRead {
        inner: Cursor::new(b"abcdef".to_vec()),
        chunk: 1,
    };
    let mut buf = [0u8; 6];
    let n = fill_read(&mut r, &mut buf).unwrap();
    assert_eq!(n, 6);
    assert_eq!(&buf, b"abcdef");
}

#[test]
fn create_without_overlay_is_access_denied() {
    let srv = Serving::start_fixture();
    let mut c = SmbClient::connect(srv.addr);
    let st = c
        .create(
            "new.txt",
            0x0012_01BF,
            smb2::FILE_CREATE,
            smb2::FILE_NON_DIRECTORY_FILE,
        )
        .unwrap_err();
    assert_eq!(st, smb2::STATUS_ACCESS_DENIED);
}

#[test]
fn overlay_create_write_read() {
    let td = tempfile::tempdir().unwrap();
    let ov = Arc::new(
        WriteOverlay::new(Arc::new(MemFs::empty()) as Arc<dyn MountSource>, td.path())
            .expect("overlay"),
    );
    let src: Arc<dyn MountSource> = Arc::clone(&ov) as Arc<dyn MountSource>;
    let srv = Serving::start(src, Some(Arc::clone(&ov)));
    let mut c = SmbClient::connect(srv.addr);
    let fid = c
        .create(
            "new.txt",
            0x0012_01BF,
            smb2::FILE_CREATE,
            smb2::FILE_NON_DIRECTORY_FILE,
        )
        .expect("create");
    let n = c.write(fid, 0, b"hello-overlay").expect("write");
    assert_eq!(n, 13);
    c.close(fid);

    let fid = c
        .create(
            "new.txt",
            0x0012_0089,
            smb2::FILE_OPEN,
            smb2::FILE_NON_DIRECTORY_FILE,
        )
        .expect("reopen");
    let body = c.read(fid, 0, 32).expect("read overlay");
    c.close(fid);
    assert_eq!(body, b"hello-overlay");

    let root = c
        .create("", 0x0012_0089, smb2::FILE_OPEN, smb2::FILE_DIRECTORY_FILE)
        .expect("root");
    let names = c.query_dir_names(root).expect("ls overlay");
    c.close(root);
    assert!(names.iter().any(|n| n == "new.txt"), "{names:?}");
}

fn lease_request_ctx(key: [u8; 16], state: u32) -> Vec<u8> {
    let mut data = vec![0u8; 32];
    data[..16].copy_from_slice(&key);
    data[16..20].copy_from_slice(&state.to_le_bytes());
    smb2::encode_create_context(smb2::CREATE_CTX_LEASE, &data)
}

fn create_packet_granted_lease(pkt: &[u8]) -> (u8, [u8; 16], Option<u32>) {
    let body = &pkt[smb2::SMB2_HEADER_LEN..];
    let oplock = body[2];
    let mut fid = [0u8; 16];
    fid.copy_from_slice(&body[64..80]);
    let ctx_off = u32::from_le_bytes(body[80..84].try_into().unwrap()) as usize;
    let ctx_len = u32::from_le_bytes(body[84..88].try_into().unwrap()) as usize;
    let mut granted = None;
    if ctx_len > 0 {
        let ctxs = smb2::parse_create_contexts(pkt, ctx_off, ctx_len).expect("contexts");
        for (name, data) in ctxs {
            if name == smb2::CREATE_CTX_LEASE && data.len() >= 20 {
                granted = Some(u32::from_le_bytes(data[16..20].try_into().unwrap()));
            }
        }
    }
    (oplock, fid, granted)
}

/// Packet test: CREATE with REQUEST_LEASE grants R or RH on a read-mostly export.
#[test]
fn create_with_lease_context_grants_r_or_rh() {
    let srv = Serving::start_fixture();
    let mut c = SmbClient::connect(srv.addr);
    let key = [0x11u8; 16];
    let ctx = lease_request_ctx(key, smb2::SMB2_LEASE_RWH);
    let body = c.create_body(
        "hello.txt",
        0x0012_0089,
        smb2::FILE_OPEN,
        smb2::FILE_NON_DIRECTORY_FILE,
        smb2::SMB2_OPLOCK_LEVEL_LEASE,
        &[ctx],
    );
    let h = c.hdr(smb2::SMB2_CREATE);
    let pkt = smb2::encode_packet(&h, &body);
    let resp = c.roundtrip_raw(&pkt);
    let rh = smb2::parse_smb2_header(&resp).unwrap();
    assert_eq!(rh.status, smb2::STATUS_SUCCESS, "CREATE {:08x}", rh.status);
    let (oplock, _fid, granted) = create_packet_granted_lease(&resp);
    assert_eq!(oplock, smb2::SMB2_OPLOCK_LEVEL_LEASE);
    let g = granted.expect("RESPONSE_LEASE");
    assert!(
        g == smb2::SMB2_LEASE_R || g == smb2::SMB2_LEASE_RH,
        "granted {g:#x} must be R or RH on a read-mostly export"
    );
    assert_eq!(g & smb2::SMB2_LEASE_WRITE_CACHING, 0);
}

/// Packet test: a second open of the same file sends LEASE_BREAK (handle caching).
#[test]
fn conflicting_open_sends_lease_break() {
    let srv = Serving::start_fixture();
    let mut c = SmbClient::connect(srv.addr);
    let key_a = [0xAAu8; 16];
    let ctx_a = lease_request_ctx(key_a, smb2::SMB2_LEASE_RH);
    let (rh, b) = c.create_resp(
        "hello.txt",
        0x0012_0089,
        smb2::FILE_OPEN,
        smb2::FILE_NON_DIRECTORY_FILE,
        smb2::SMB2_OPLOCK_LEVEL_LEASE,
        &[ctx_a],
    );
    assert_eq!(rh.status, smb2::STATUS_SUCCESS);
    let (oplock, _fid, granted) = create_packet_granted_lease(&smb2::encode_packet(&rh, &b));
    assert_eq!(oplock, smb2::SMB2_OPLOCK_LEVEL_LEASE);
    assert_eq!(granted, Some(smb2::SMB2_LEASE_RH));

    let key_b = [0xBBu8; 16];
    let ctx_b = lease_request_ctx(key_b, smb2::SMB2_LEASE_RH);
    let body = c.create_body(
        "hello.txt",
        0x0012_0089,
        smb2::FILE_OPEN,
        smb2::FILE_NON_DIRECTORY_FILE,
        smb2::SMB2_OPLOCK_LEVEL_LEASE,
        &[ctx_b],
    );
    let h = c.hdr(smb2::SMB2_CREATE);
    c.send_raw(&smb2::encode_packet(&h, &body));
    let first = c.recv_raw();
    let bh = smb2::parse_smb2_header(&first).unwrap();
    assert_eq!(
        bh.command,
        smb2::SMB2_OPLOCK_BREAK,
        "conflicting open must send LEASE_BREAK first, got cmd {:#x} status {:08x}",
        bh.command,
        bh.status
    );
    assert_eq!(bh.message_id, smb2::LEASE_BREAK_MESSAGE_ID);
    let br = &first[smb2::SMB2_HEADER_LEN..];
    assert_eq!(u16::from_le_bytes(br[0..2].try_into().unwrap()), 44);
    assert_eq!(&br[8..24], &key_a);
    let current = u32::from_le_bytes(br[24..28].try_into().unwrap());
    let new_state = u32::from_le_bytes(br[28..32].try_into().unwrap());
    assert_eq!(current, smb2::SMB2_LEASE_RH);
    assert_eq!(new_state, smb2::SMB2_LEASE_R);
    let flags = u32::from_le_bytes(br[4..8].try_into().unwrap());
    assert_eq!(flags, smb2::SMB2_NOTIFY_BREAK_LEASE_FLAG_ACK_REQUIRED);

    let second = c.recv_raw();
    let ch = smb2::parse_smb2_header(&second).unwrap();
    assert_eq!(ch.command, smb2::SMB2_CREATE);
    assert_eq!(ch.status, smb2::STATUS_SUCCESS);

    let mut ack = vec![0u8; 36];
    ack[0..2].copy_from_slice(&36u16.to_le_bytes());
    ack[8..24].copy_from_slice(&key_a);
    ack[24..28].copy_from_slice(&new_state.to_le_bytes());
    let ah = c.hdr(smb2::SMB2_OPLOCK_BREAK);
    let (arh, _) = c.roundtrip(&smb2::encode_packet(&ah, &ack));
    assert_eq!(arh.status, smb2::STATUS_SUCCESS, "LEASE_BREAK_ACK");
}

/// Overlay WRITE of a leased file sends LEASE_BREAK (R/W invalidation).
#[test]
fn overlay_write_sends_lease_break() {
    let td = tempfile::tempdir().unwrap();
    let ov = Arc::new(
        WriteOverlay::new(Arc::new(MemFs::empty()) as Arc<dyn MountSource>, td.path())
            .expect("overlay"),
    );
    let src: Arc<dyn MountSource> = Arc::clone(&ov) as Arc<dyn MountSource>;
    let srv = Serving::start(src, Some(Arc::clone(&ov)));
    let mut c = SmbClient::connect(srv.addr);
    let fid = c
        .create(
            "new.txt",
            0x0012_01BF,
            smb2::FILE_CREATE,
            smb2::FILE_NON_DIRECTORY_FILE,
        )
        .expect("create");
    c.close(fid);

    let key = [0xCCu8; 16];
    let ctx = lease_request_ctx(key, smb2::SMB2_LEASE_RH);
    let (rh, b) = c.create_resp(
        "new.txt",
        0x0012_0089,
        smb2::FILE_OPEN,
        smb2::FILE_NON_DIRECTORY_FILE,
        smb2::SMB2_OPLOCK_LEVEL_LEASE,
        &[ctx],
    );
    assert_eq!(rh.status, smb2::STATUS_SUCCESS);
    let mut fid = [0u8; 16];
    fid.copy_from_slice(&b[64..80]);

    let mut wbody = vec![0u8; 48];
    wbody[0..2].copy_from_slice(&49u16.to_le_bytes());
    let off = (smb2::SMB2_HEADER_LEN + 48) as u16;
    wbody[2..4].copy_from_slice(&off.to_le_bytes());
    wbody[4..8].copy_from_slice(&5u32.to_le_bytes());
    wbody[16..32].copy_from_slice(&fid);
    wbody.extend_from_slice(b"hello");
    let h = c.hdr(smb2::SMB2_WRITE);
    c.send_raw(&smb2::encode_packet(&h, &wbody));
    let first = c.recv_raw();
    let bh = smb2::parse_smb2_header(&first).unwrap();
    assert_eq!(
        bh.command,
        smb2::SMB2_OPLOCK_BREAK,
        "WRITE must send LEASE_BREAK, got cmd {:#x}",
        bh.command
    );
    let br = &first[smb2::SMB2_HEADER_LEN..];
    assert_eq!(&br[8..24], &key);
    let new_state = u32::from_le_bytes(br[28..32].try_into().unwrap());
    assert_eq!(new_state, smb2::SMB2_LEASE_NONE);
    let second = c.recv_raw();
    let wh = smb2::parse_smb2_header(&second).unwrap();
    assert_eq!(wh.command, smb2::SMB2_WRITE);
    assert_eq!(wh.status, smb2::STATUS_SUCCESS);
}

/// Durable-handle-v1: CREATE DHnQ then TCP drop; reconnect DHnC still READs.
#[test]
fn durable_reconnect_after_tcp_drop() {
    let srv = Serving::start_fixture();
    let key_fid;
    {
        let mut c = SmbClient::connect(srv.addr);
        let ctx = smb2::encode_create_context(smb2::CREATE_CTX_DURABLE_REQUEST, &[0u8; 16]);
        let (rh, b) = c.create_resp(
            "hello.txt",
            0x0012_0089,
            smb2::FILE_OPEN,
            smb2::FILE_NON_DIRECTORY_FILE,
            0,
            &[ctx],
        );
        assert_eq!(rh.status, smb2::STATUS_SUCCESS);
        let mut fid = [0u8; 16];
        fid.copy_from_slice(&b[64..80]);
        let ctx_off = u32::from_le_bytes(b[80..84].try_into().unwrap()) as usize;
        let ctx_len = u32::from_le_bytes(b[84..88].try_into().unwrap()) as usize;
        let mut pkt = vec![0u8; smb2::SMB2_HEADER_LEN];
        pkt.extend_from_slice(&b);
        let ctxs = smb2::parse_create_contexts(&pkt, ctx_off, ctx_len).unwrap();
        assert!(
            ctxs.iter()
                .any(|(n, _)| n == smb2::CREATE_CTX_DURABLE_RECONNECT),
            "CREATE must return durable handle response"
        );
        key_fid = fid;
        // Drop TCP without CLOSE so the durable fid stays in the shared table.
    }
    let mut c = SmbClient::connect(srv.addr);
    let ctx = smb2::encode_create_context(smb2::CREATE_CTX_DURABLE_RECONNECT, &key_fid);
    let mut last = None;
    let fid = (0..20).find_map(|_| {
        let (rh, b) = c.create_resp(
            "",
            0x0012_0089,
            smb2::FILE_OPEN,
            smb2::FILE_NON_DIRECTORY_FILE,
            0,
            std::slice::from_ref(&ctx),
        );
        if rh.status == smb2::STATUS_SUCCESS {
            let mut fid = [0u8; 16];
            fid.copy_from_slice(&b[64..80]);
            Some(fid)
        } else {
            last = Some(rh.status);
            std::thread::sleep(Duration::from_millis(25));
            None
        }
    });
    let fid = fid.unwrap_or_else(|| panic!("durable reconnect {:08x?}", last));
    assert_eq!(fid, key_fid);
    let body = c.read(fid, 0, 64).expect("read after durable reconnect");
    assert_eq!(body, b"hello smb\n");
}

#[test]
fn serve_returns_after_stop() {
    let stop = ExportStop::new();
    let opts = SmbOptions {
        bind: "127.0.0.1:0".parse().unwrap(),
        stop: Some(stop.clone()),
        ..SmbOptions::default()
    };
    let src: Arc<dyn MountSource> = Arc::new(MemFs::empty());
    let handle = spawn_smb_thread(src, opts).expect("bind");
    std::thread::sleep(Duration::from_millis(50));
    stop.request_stop();
    let start = std::time::Instant::now();
    handle.join().expect("serve join");
    assert!(
        start.elapsed() < Duration::from_secs(2),
        "ExportStop must unblock serve within the 200ms poll"
    );
}

#[test]
fn required_user_rejects_guest() {
    let stop = ExportStop::new();
    let opts = SmbOptions {
        bind: "127.0.0.1:0".parse().unwrap(),
        stop: Some(stop.clone()),
        username: Some("alice".into()),
        ..SmbOptions::default()
    };
    let src: Arc<dyn MountSource> = Arc::new(MemFs::fixture());
    let handle = spawn_smb_thread(src, opts).expect("bind");
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, handle.port));
    let mut last = None;
    let stream = (0..40)
        .find_map(
            |_| match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
                Ok(s) => Some(s),
                Err(e) => {
                    last = Some(e);
                    std::thread::sleep(Duration::from_millis(25));
                    None
                }
            },
        )
        .unwrap_or_else(|| panic!("connect {addr}: {last:?}"));
    let mut c = SmbClient::from_stream(stream);
    c.stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    c.negotiate();
    let t1 = smb2::ntlm_type1();
    let (rh, _) = c.session_setup_sec(&t1);
    assert_eq!(rh.status, smb2::STATUS_MORE_PROCESSING_REQUIRED);
    c.session_id = rh.session_id;
    let t3 = smb2::ntlm_type3_guest();
    let (rh, _) = c.session_setup_sec(&t3);
    assert_eq!(rh.status, smb2::STATUS_LOGON_FAILURE);
    stop.request_stop();
    let _ = handle.join();
}

fn smbclient_bin() -> Option<PathBuf> {
    Command::new("smbclient")
        .arg("-V")
        .output()
        .ok()
        .filter(|o| o.status.success() || !o.stdout.is_empty() || !o.stderr.is_empty())
        .map(|_| PathBuf::from("smbclient"))
}

/// Live `smbclient` ls/get against localhost. Skip if the binary is missing.
#[test]
fn smbclient_ls_get_localhost() {
    let Some(_) = smbclient_bin() else {
        eprintln!("skip: smbclient not on PATH");
        return;
    };
    let srv = Serving::start_fixture();
    let port = srv.addr.port().to_string();
    let unc = format!("//127.0.0.1/{DEFAULT_SMB_SHARE}");
    let conf = tempfile::NamedTempFile::new().expect("smb.conf");
    std::fs::write(
        conf.path(),
        "[global]\nclient min protocol = SMB2_02\nclient max protocol = SMB3\nclient signing = disabled\n",
    )
    .expect("write smb.conf");
    let ls = Command::new("smbclient")
        .args([
            &unc,
            "-p",
            &port,
            "-N",
            "-s",
            conf.path().to_str().unwrap(),
            "-c",
            "ls",
        ])
        .output()
        .expect("smbclient ls");
    let stdout = String::from_utf8_lossy(&ls.stdout);
    let stderr = String::from_utf8_lossy(&ls.stderr);
    assert!(
        ls.status.success(),
        "smbclient ls failed: status={:?} stdout={stdout} stderr={stderr}",
        ls.status
    );
    assert!(
        stdout.contains("hello.txt") || stderr.contains("hello.txt"),
        "ls listing: stdout={stdout} stderr={stderr}"
    );

    let dest = tempfile::NamedTempFile::new().expect("dest");
    let dest_path = dest.path().to_string_lossy().into_owned();
    let get_cmd = format!("get hello.txt {dest_path}");
    let get = Command::new("smbclient")
        .args([
            &unc,
            "-p",
            &port,
            "-N",
            "-s",
            conf.path().to_str().unwrap(),
            "-c",
            &get_cmd,
        ])
        .output()
        .expect("smbclient get");
    let g_err = String::from_utf8_lossy(&get.stderr);
    let g_out = String::from_utf8_lossy(&get.stdout);
    assert!(
        get.status.success(),
        "smbclient get failed: status={:?} stdout={g_out} stderr={g_err}",
        get.status
    );
    let got = std::fs::read(dest.path()).expect("read dest");
    assert_eq!(got, b"hello smb\n");
}

fn start_password_server(username: Option<&str>, password: &str) -> Serving {
    let stop = ExportStop::new();
    let opts = SmbOptions {
        bind: "127.0.0.1:0".parse().unwrap(),
        stop: Some(stop.clone()),
        username: username.map(|s| s.to_string()),
        password: Some(password.to_string()),
        ..SmbOptions::default()
    };
    let src: Arc<dyn MountSource> = Arc::new(MemFs::fixture());
    let handle = spawn_smb_thread(src, opts).expect("bind SMB");
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, handle.port));
    Serving {
        handle: Some(handle),
        stop,
        addr,
    }
}

fn session_setup_type3_v2(
    c: &mut SmbClient,
    user: &str,
    domain: &str,
    password: &str,
) -> (u32, u16) {
    let t1 = smb2::ntlm_type1();
    let (rh, body) = c.session_setup_sec(&t1);
    assert_eq!(
        rh.status,
        smb2::STATUS_MORE_PROCESSING_REQUIRED,
        "type1 {:08x}",
        rh.status
    );
    c.session_id = rh.session_id;
    let challenge = smb2::ntlm_type2_challenge(&body).expect("Type2 challenge");
    let (t3, key) = smb2::ntlm_type3_v2(user, domain, password, challenge);
    let buf = c.session_setup_sec_raw(&t3);
    let rh = smb2::parse_smb2_header(&buf).expect("type3 hdr");
    if rh.status == smb2::STATUS_SUCCESS {
        c.session_key = Some(key);
        let flags = if buf.len() >= smb2::SMB2_HEADER_LEN + 4 {
            u16::from_le_bytes(
                buf[smb2::SMB2_HEADER_LEN + 2..smb2::SMB2_HEADER_LEN + 4]
                    .try_into()
                    .unwrap(),
            )
        } else {
            0
        };
        if c.dialect == smb2::DIALECT_311 {
            c.signing_key = Some(smb2::smb311_signing_key(&key, &c.preauth));
            c.c2s_key = Some(smb2::smb311_c2s_key(&key, &c.preauth));
            c.s2c_key = Some(smb2::smb311_s2c_key(&key, &c.preauth));
            assert!(
                smb2::smb3_verify_packet(&buf, &c.signing_key.unwrap()),
                "Type3 SESSION_SETUP response must be AES-CMAC signed"
            );
            if flags & smb2::SESSION_FLAG_ENCRYPT_DATA != 0 {
                c.encrypt_data = true;
            }
        } else {
            assert!(
                smb2::smb2_verify_packet(&buf, &key),
                "Type3 SESSION_SETUP response must be signed"
            );
        }
        (rh.status, flags)
    } else {
        (rh.status, 0)
    }
}

/// Regression: guest Type3 still succeeds without NT proof when password unset
#[test]
fn guest_type3_succeeds_without_nt_proof_when_password_unset() {
    let srv = Serving::start_fixture();
    let mut c = SmbClient::connect_negotiate(srv.addr);
    c.session_setup_guest();
    c.tree_connect("ratarmount");
}

/// Regression: password-set rejects guest Type3
#[test]
fn password_set_rejects_guest_type3() {
    let srv = start_password_server(None, "Password");
    let mut c = SmbClient::connect_negotiate(srv.addr);
    let t1 = smb2::ntlm_type1();
    let (rh, _) = c.session_setup_sec(&t1);
    assert_eq!(rh.status, smb2::STATUS_MORE_PROCESSING_REQUIRED);
    c.session_id = rh.session_id;
    let t3 = smb2::ntlm_type3_guest();
    let (rh, _) = c.session_setup_sec(&t3);
    assert_eq!(rh.status, smb2::STATUS_LOGON_FAILURE);
}

/// Regression: password session rejects unsigned TREE_CONNECT
#[test]
fn password_session_rejects_unsigned_tree_connect() {
    let srv = start_password_server(None, "Password");
    let mut c = SmbClient::connect_negotiate(srv.addr);
    assert_eq!(
        session_setup_type3_v2(&mut c, "User", "Domain", "Password").0,
        smb2::STATUS_SUCCESS
    );
    let (rh, _) = c.tree_connect_status("ratarmount", false);
    assert_eq!(rh.status, smb2::STATUS_ACCESS_DENIED);
}

/// Regression: signed TREE_CONNECT accepted
#[test]
fn signed_tree_connect_accepted() {
    let srv = start_password_server(Some("User"), "Password");
    let mut c = SmbClient::connect_negotiate(srv.addr);
    assert_eq!(
        session_setup_type3_v2(&mut c, "User", "Domain", "Password").0,
        smb2::STATUS_SUCCESS
    );
    let unc = format!(r"\\127.0.0.1\{DEFAULT_SMB_SHARE}");
    let path = smb2::encode_utf16le(&unc);
    let mut body = vec![0u8; 8];
    body[0..2].copy_from_slice(&9u16.to_le_bytes());
    let off = (smb2::SMB2_HEADER_LEN + 8) as u16;
    body[4..6].copy_from_slice(&off.to_le_bytes());
    body[6..8].copy_from_slice(&(path.len() as u16).to_le_bytes());
    body.extend_from_slice(&path);
    let h = c.hdr(smb2::SMB2_TREE_CONNECT);
    let mut pkt = smb2::encode_packet(&h, &body);
    smb2::smb2_sign_packet(&mut pkt, &c.session_key.unwrap());
    let buf = c.roundtrip_raw(&pkt);
    let rh = smb2::parse_smb2_header(&buf).unwrap();
    assert_eq!(rh.status, smb2::STATUS_SUCCESS, "signed TREE_CONNECT");
    assert!(
        smb2::smb2_verify_packet(&buf, &c.session_key.unwrap()),
        "TREE_CONNECT response must be signed"
    );
}

/// Regression: username mismatch still LOGON_FAILURE (password set)
#[test]
fn password_username_mismatch_is_logon_failure() {
    let srv = start_password_server(Some("alice"), "Password");
    let mut c = SmbClient::connect_negotiate(srv.addr);
    assert_eq!(
        session_setup_type3_v2(&mut c, "User", "Domain", "Password").0,
        smb2::STATUS_LOGON_FAILURE
    );
}

/// Regression: NTLMv2 Type3 matching password is SUCCESS (live session)
#[test]
fn ntlmv2_type3_matching_password_live_success() {
    let srv = start_password_server(None, "Password");
    let mut c = SmbClient::connect_negotiate(srv.addr);
    assert_eq!(
        session_setup_type3_v2(&mut c, "User", "Domain", "Password").0,
        smb2::STATUS_SUCCESS
    );
    let (rh, _) = c.tree_connect_status("ratarmount", true);
    assert_eq!(rh.status, smb2::STATUS_SUCCESS);
}

/// Password-set NEGOTIATE advertises SIGNING_REQUIRED (0x0003).
#[test]
fn password_negotiate_signing_required() {
    let srv = start_password_server(None, "Password");
    let mut c = SmbClient::from_stream(SmbClient::connect_stream(srv.addr));
    let mut body = vec![0u8; 36];
    body[0..2].copy_from_slice(&36u16.to_le_bytes());
    body[2..4].copy_from_slice(&2u16.to_le_bytes());
    body[4..6].copy_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&smb2::DIALECT_202.to_le_bytes());
    body.extend_from_slice(&smb2::DIALECT_210.to_le_bytes());
    let h = c.hdr(smb2::SMB2_NEGOTIATE);
    let (rh, nbody) = c.roundtrip(&smb2::encode_packet(&h, &body));
    assert_eq!(rh.status, smb2::STATUS_SUCCESS);
    let mode = u16::from_le_bytes(nbody[2..4].try_into().unwrap());
    assert_eq!(
        mode,
        smb2::NEGOTIATE_SIGNING_ENABLED | smb2::NEGOTIATE_SIGNING_REQUIRED
    );
}

/// Regression: SMB 3.1.1 preauth hash of NEGOTIATE req+resp is SHA-512 chained.
#[test]
fn preauth_hash_negotiate_311_live() {
    let srv = Serving::start_fixture();
    let mut c = SmbClient::from_stream(SmbClient::connect_stream(srv.addr));
    c.stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let resp = c.negotiate_311(false);
    assert_ne!(c.preauth, smb2::PREAUTH_ZERO);
    let nbody = &resp[smb2::SMB2_HEADER_LEN..];
    let ctx_count = u16::from_le_bytes(nbody[6..8].try_into().unwrap());
    assert!(
        ctx_count >= 1,
        "3.1.1 NEGOTIATE response must include preauth context"
    );
    c.session_setup_guest();
    c.tree_connect("ratarmount");
}

/// Regression: guest 3.1.1 READ stays unencrypted (guest path).
#[test]
fn guest_311_read_unencrypted() {
    let srv = Serving::start_fixture();
    let mut c = SmbClient::from_stream(SmbClient::connect_stream(srv.addr));
    c.stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    c.negotiate_311(false);
    c.session_setup_guest();
    c.tree_connect("ratarmount");
    let fid = c
        .create(
            "hello.txt",
            0x0012_0089,
            smb2::FILE_OPEN,
            smb2::FILE_NON_DIRECTORY_FILE,
        )
        .expect("open hello");
    let h = c.hdr(smb2::SMB2_READ);
    let mut body = vec![0u8; 48];
    body[0..2].copy_from_slice(&49u16.to_le_bytes());
    body[4..8].copy_from_slice(&64u32.to_le_bytes());
    body[16..32].copy_from_slice(&fid);
    let pkt = smb2::encode_packet(&h, &body);
    c.stream
        .write_all(&smb2::encode_nbss(&pkt))
        .expect("smb write");
    let mut nb = [0u8; 4];
    c.stream.read_exact(&mut nb).expect("nbss hdr");
    let n = smb2::decode_nbss_len(nb).expect("nbss len");
    let mut buf = vec![0u8; n];
    c.stream.read_exact(&mut buf).expect("smb body");
    assert!(
        !smb2::is_smb2_transform(&buf),
        "guest 3.1.1 READ must not be TRANSFORM-encrypted"
    );
    let rh = smb2::parse_smb2_header(&buf).unwrap();
    assert_eq!(rh.status, smb2::STATUS_SUCCESS);
    let b = &buf[smb2::SMB2_HEADER_LEN..];
    let data_off = b[2] as usize;
    let data_len = u32::from_le_bytes(b[4..8].try_into().unwrap()) as usize;
    let start = data_off.saturating_sub(smb2::SMB2_HEADER_LEN);
    let got = b.get(start..start + data_len).unwrap_or(&[]).to_vec();
    assert_eq!(got, b"hello smb\n");
}

/// Regression: password + 3.1.1 + GCM encrypts READ (TRANSFORM_HEADER).
#[test]
fn encrypted_read_aes128_gcm() {
    let srv = start_password_server(None, "Password");
    let mut c = SmbClient::from_stream(SmbClient::connect_stream(srv.addr));
    c.stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    c.negotiate_311(true);
    let (st, flags) = session_setup_type3_v2(&mut c, "User", "Domain", "Password");
    assert_eq!(st, smb2::STATUS_SUCCESS);
    assert_eq!(
        flags & smb2::SESSION_FLAG_ENCRYPT_DATA,
        smb2::SESSION_FLAG_ENCRYPT_DATA,
        "Type3 SessionFlags must set SESSION_FLAG_ENCRYPT_DATA"
    );
    assert!(c.encrypt_data, "SESSION_FLAG_ENCRYPT_DATA arms transform");
    c.tree_connect("ratarmount");
    let fid = c
        .create(
            "hello.txt",
            0x0012_0089,
            smb2::FILE_OPEN,
            smb2::FILE_NON_DIRECTORY_FILE,
        )
        .expect("open hello");
    let mut body = vec![0u8; 48];
    body[0..2].copy_from_slice(&49u16.to_le_bytes());
    body[4..8].copy_from_slice(&64u32.to_le_bytes());
    body[16..32].copy_from_slice(&fid);
    let h = c.hdr(smb2::SMB2_READ);
    let pkt = smb2::encode_packet(&h, &body);
    let wire = c.encrypt_out(&pkt);
    assert!(smb2::is_smb2_transform(&wire), "client READ is TRANSFORM");
    c.stream
        .write_all(&smb2::encode_nbss(&wire))
        .expect("smb write");
    let mut nb = [0u8; 4];
    c.stream.read_exact(&mut nb).expect("nbss hdr");
    let n = smb2::decode_nbss_len(nb).expect("nbss len");
    let mut buf = vec![0u8; n];
    c.stream.read_exact(&mut buf).expect("smb body");
    assert!(
        smb2::is_smb2_transform(&buf),
        "encrypted READ response must be TRANSFORM"
    );
    let inner = c.decrypt_in(&buf);
    let rh = smb2::parse_smb2_header(&inner).unwrap();
    assert_eq!(rh.status, smb2::STATUS_SUCCESS, "READ {:08x}", rh.status);
    let b = &inner[smb2::SMB2_HEADER_LEN..];
    let data_off = b[2] as usize;
    let data_len = u32::from_le_bytes(b[4..8].try_into().unwrap()) as usize;
    let start = data_off.saturating_sub(smb2::SMB2_HEADER_LEN);
    let got = b.get(start..start + data_len).unwrap_or(&[]).to_vec();
    assert_eq!(got, b"hello smb\n");
}

/// Regression: LOGOFF keeps Connection.CipherId so re-auth can encrypt
#[test]
fn logoff_keeps_cipher_reauth_sets_encrypt_data() {
    let srv = start_password_server(None, "Password");
    let mut c = SmbClient::from_stream(SmbClient::connect_stream(srv.addr));
    c.stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    c.negotiate_311(true);
    let after_neg = c.preauth;
    let (st, flags) = session_setup_type3_v2(&mut c, "User", "Domain", "Password");
    assert_eq!(st, smb2::STATUS_SUCCESS);
    assert_eq!(
        flags & smb2::SESSION_FLAG_ENCRYPT_DATA,
        smb2::SESSION_FLAG_ENCRYPT_DATA
    );
    c.tree_connect("ratarmount");
    let h = c.hdr(smb2::SMB2_LOGOFF);
    let buf = c.roundtrip_raw(&smb2::encode_packet(&h, &smb2::encode_empty_sized(4, 4)));
    let rh = smb2::parse_smb2_header(&buf).unwrap();
    assert_eq!(rh.status, smb2::STATUS_SUCCESS, "LOGOFF {:08x}", rh.status);
    c.encrypt_data = false;
    c.session_key = None;
    c.signing_key = None;
    c.c2s_key = None;
    c.s2c_key = None;
    c.tree_id = 0;
    c.preauth = after_neg;
    let (st, flags) = session_setup_type3_v2(&mut c, "User", "Domain", "Password");
    assert_eq!(st, smb2::STATUS_SUCCESS);
    assert_eq!(
        flags & smb2::SESSION_FLAG_ENCRYPT_DATA,
        smb2::SESSION_FLAG_ENCRYPT_DATA,
        "LOGOFF must keep Connection.CipherId"
    );
}

/// Regression: 3.1.1 NEGOTIATE without SHA-512 is INVALID_PARAMETER
#[test]
fn negotiate_311_without_sha512_is_invalid_parameter() {
    let srv = Serving::start_fixture();
    let mut c = SmbClient::from_stream(SmbClient::connect_stream(srv.addr));
    c.stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    let mut body = vec![0u8; 36];
    body[0..2].copy_from_slice(&36u16.to_le_bytes());
    body[2..4].copy_from_slice(&1u16.to_le_bytes());
    body[4..6].copy_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&smb2::DIALECT_311.to_le_bytes());
    let pad = (8 - (body.len() % 8)) % 8;
    body.resize(body.len() + pad, 0);
    let ctx_off = (smb2::SMB2_HEADER_LEN + body.len()) as u32;
    body[28..32].copy_from_slice(&ctx_off.to_le_bytes());
    body[32..34].copy_from_slice(&1u16.to_le_bytes());
    let mut data = Vec::new();
    data.extend_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(&0u16.to_le_bytes());
    data.extend_from_slice(&0x0002u16.to_le_bytes());
    body.extend_from_slice(&smb2::encode_negotiate_context(
        smb2::SMB2_PREAUTH_INTEGRITY_CAPABILITIES,
        &data,
    ));
    let h = c.hdr(smb2::SMB2_NEGOTIATE);
    let (rh, _) = c.roundtrip(&smb2::encode_packet(&h, &body));
    assert_eq!(rh.status, smb2::STATUS_INVALID_PARAMETER);
}
