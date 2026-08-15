//! Bind / serve spike for embednfs 0.4.1 (`NfsServer` + `MemFs`).

use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use crate::NfsStop;

async fn wait_stop(stop: NfsStop) {
    while !stop.is_stopped() {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Bind `MemFs` on `bind` (typically `127.0.0.1:0`) and serve until `stop`.
///
/// Uses the documented `NfsServer::new` + `tokio::net::TcpListener::bind` +
/// `NfsServer::serve(listener)` path. Returns the bound port after the
/// server exits (stop or accept error).
pub async fn serve_v4_memfs_smoke(bind: SocketAddr, stop: NfsStop) -> io::Result<u16> {
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let port = listener.local_addr()?.port();
    let server = embednfs::NfsServer::new(embednfs::MemFs::new());
    tokio::select! {
        r = server.serve(listener) => r?,
        _ = wait_stop(stop) => {}
    }
    Ok(port)
}

/// `NfsServer::listen(addr)` string form (`"127.0.0.1:0"` / high port).
///
/// embednfs 0.4.1 implements this as `TcpListener::bind(addr)` then `serve`.
/// The port is not returned; callers that need `:0` should use
/// [`serve_v4_memfs_smoke`].
pub async fn listen_v4_memfs_smoke(addr: &str, stop: NfsStop) -> io::Result<()> {
    let server = embednfs::NfsServer::new(embednfs::MemFs::new());
    tokio::select! {
        r = server.listen(addr) => r,
        _ = wait_stop(stop) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    const NFS_PROGRAM: u32 = 100003;
    const NFS_V4: u32 = 4;
    const RPC_CALL: u32 = 0;
    const RPC_REPLY: u32 = 1;
    const RPC_MSG_ACCEPTED: u32 = 0;
    const RPC_SUCCESS: u32 = 0;
    const RPC_PROG_UNAVAIL: u32 = 1;
    const NFS_COMPOUND: u32 = 1;
    const OP_EXCHANGE_ID: u32 = 42;
    const NFS4_OK: u32 = 0;
    const RPC_LAST_FRAGMENT: u32 = 0x8000_0000;
    const RPC_FRAG_LEN_MASK: u32 = 0x7fff_ffff;

    fn xdr_u32(buf: &mut Vec<u8>, v: u32) {
        buf.extend_from_slice(&v.to_be_bytes());
    }

    fn xdr_opaque(buf: &mut Vec<u8>, data: &[u8]) {
        xdr_u32(buf, u32::try_from(data.len()).expect("opaque len"));
        buf.extend_from_slice(data);
        let pad = (4 - (data.len() % 4)) % 4;
        buf.extend_from_slice(&[0u8; 4][..pad]);
    }

    /// ONC-RPC NFSv4 COMPOUND `EXCHANGE_ID` (RFC 5531 + RFC 5661 §18.35).
    fn encode_exchange_id_call(xid: u32) -> Vec<u8> {
        let mut body = Vec::new();
        xdr_u32(&mut body, xid);
        xdr_u32(&mut body, RPC_CALL);
        xdr_u32(&mut body, 2);
        xdr_u32(&mut body, NFS_PROGRAM);
        xdr_u32(&mut body, NFS_V4);
        xdr_u32(&mut body, NFS_COMPOUND);
        xdr_u32(&mut body, 0);
        xdr_u32(&mut body, 0);
        xdr_u32(&mut body, 0);
        xdr_u32(&mut body, 0);

        xdr_u32(&mut body, 0);
        xdr_u32(&mut body, 1);
        xdr_u32(&mut body, 1);
        xdr_u32(&mut body, OP_EXCHANGE_ID);

        body.extend_from_slice(&[0u8; 8]);
        xdr_opaque(&mut body, b"ratarmount-nfs-spike");
        xdr_u32(&mut body, 0);
        xdr_u32(&mut body, 0);
        xdr_u32(&mut body, 0);

        let mut rec = Vec::with_capacity(4 + body.len());
        let frag = u32::try_from(body.len()).expect("rpc body") | RPC_LAST_FRAGMENT;
        rec.extend_from_slice(&frag.to_be_bytes());
        rec.extend_from_slice(&body);
        rec
    }

    fn read_u32(cur: &mut &[u8]) -> u32 {
        let (head, rest) = cur.split_at(4);
        *cur = rest;
        u32::from_be_bytes([head[0], head[1], head[2], head[3]])
    }

    async fn read_rpc_record(stream: &mut TcpStream) -> Vec<u8> {
        let mut rec = Vec::new();
        loop {
            let mut header = [0u8; 4];
            stream
                .read_exact(&mut header)
                .await
                .expect("rpc fragment header");
            let header_val = u32::from_be_bytes(header);
            let last = (header_val & RPC_LAST_FRAGMENT) != 0;
            let frag_len = (header_val & RPC_FRAG_LEN_MASK) as usize;
            let start = rec.len();
            rec.resize(start + frag_len, 0);
            stream
                .read_exact(&mut rec[start..])
                .await
                .expect("rpc fragment body");
            if last {
                break;
            }
        }
        rec
    }

    async fn connect_loopback(port: u16) -> TcpStream {
        let addr = format!("127.0.0.1:{port}");
        let mut last = None;
        for _ in 0..50 {
            match TcpStream::connect(&addr).await {
                Ok(s) => {
                    s.set_nodelay(true).ok();
                    return s;
                }
                Err(e) => last = Some(e),
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("connect 127.0.0.1:{port}: {last:?}");
    }

    #[tokio::test]
    async fn v4_bind_ipv4_high_port() {
        let stop = NfsStop::new();
        let bind = "127.0.0.1:0".parse().unwrap();
        let handle = tokio::spawn(serve_v4_memfs_smoke(bind, stop.clone()));
        tokio::time::sleep(Duration::from_millis(80)).await;
        stop.request_stop();
        let port = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("serve timed out")
            .expect("join")
            .expect("serve");
        assert!(port > 0, "ephemeral port");
    }

    #[tokio::test]
    async fn v4_listen_string_ipv4() {
        let stop = NfsStop::new();
        let handle = tokio::spawn(listen_v4_memfs_smoke("127.0.0.1:0", stop.clone()));
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(
            !handle.is_finished(),
            "listen(\"127.0.0.1:0\") exited before stop"
        );
        stop.request_stop();
        let r = tokio::time::timeout(Duration::from_secs(2), handle)
            .await
            .expect("listen timed out")
            .expect("join");
        assert!(r.is_ok(), "{r:?}");
    }

    /// Unprivileged TCP EXCHANGE_ID smoke. This is the PR 2 protocol gate.
    #[tokio::test]
    async fn v4_exchange_id_smoke() {
        let stop = NfsStop::new();
        let stop_serve = stop.clone();
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = tokio::net::TcpListener::bind(bind).await.expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        let serve = tokio::spawn(async move {
            let server = embednfs::NfsServer::new(embednfs::MemFs::new());
            tokio::select! {
                r = server.serve(listener) => r,
                _ = wait_stop(stop_serve) => Ok(()),
            }
        });

        let xid = 0x7274_6d31;
        let req = encode_exchange_id_call(xid);
        let mut stream = connect_loopback(port).await;
        stream.write_all(&req).await.expect("write EXCHANGE_ID");
        let reply = tokio::time::timeout(Duration::from_secs(2), read_rpc_record(&mut stream))
            .await
            .expect("EXCHANGE_ID reply timed out");

        assert!(reply.len() >= 32, "short RPC reply ({} bytes)", reply.len());
        let mut cur = reply.as_slice();
        let rxid = read_u32(&mut cur);
        assert_eq!(rxid, xid, "xid mismatch");
        let msg_type = read_u32(&mut cur);
        assert_eq!(msg_type, RPC_REPLY, "not an RPC REPLY ({msg_type})");
        let reply_stat = read_u32(&mut cur);
        assert_eq!(
            reply_stat, RPC_MSG_ACCEPTED,
            "RPC denied (reply_stat={reply_stat})"
        );
        let _verf_flavor = read_u32(&mut cur);
        let verf_len = read_u32(&mut cur) as usize;
        let pad = (4 - (verf_len % 4)) % 4;
        assert!(
            cur.len() >= verf_len + pad + 4,
            "truncated verifier / accept_stat"
        );
        cur = &cur[verf_len + pad..];
        let accept_stat = read_u32(&mut cur);
        assert_ne!(
            accept_stat, RPC_PROG_UNAVAIL,
            "PROG_UNAVAIL — embednfs did not advertise NFS program 100003"
        );
        assert_eq!(
            accept_stat, RPC_SUCCESS,
            "RPC accept_stat={accept_stat} (want SUCCESS)"
        );

        assert!(cur.len() >= 16, "truncated COMPOUND4res");
        let compound_status = read_u32(&mut cur);
        let tag_len = read_u32(&mut cur) as usize;
        let tag_pad = (4 - (tag_len % 4)) % 4;
        assert!(
            cur.len() >= tag_len + tag_pad + 8,
            "truncated COMPOUND tag / resarray"
        );
        cur = &cur[tag_len + tag_pad..];
        let numops = read_u32(&mut cur);
        assert_eq!(numops, 1, "expected one EXCHANGE_ID result, got {numops}");
        let opcode = read_u32(&mut cur);
        assert_eq!(opcode, OP_EXCHANGE_ID, "resop={opcode}, want EXCHANGE_ID");
        let eir_status = read_u32(&mut cur);
        assert_eq!(
            eir_status, NFS4_OK,
            "EXCHANGE_ID status={eir_status} (compound status={compound_status})"
        );
        assert_eq!(
            compound_status, NFS4_OK,
            "COMPOUND status={compound_status} after NFS4_OK EXCHANGE_ID"
        );

        drop(stream);
        stop.request_stop();
        let _ = tokio::time::timeout(Duration::from_secs(2), serve).await;
    }

    /// Optional live Linux `mount -t nfs`. Skip when unprivileged.
    /// Success is recorded in docs; skip is **not** a protocol kill.
    #[tokio::test]
    async fn v4_linux_kernel_mount_optional() {
        if !cfg!(target_os = "linux") {
            eprintln!("skip: not Linux");
            return;
        }
        let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = tokio::net::TcpListener::bind(bind).await.expect("bind");
        let port = listener.local_addr().expect("local_addr").port();
        let stop = NfsStop::new();
        let stop_serve = stop.clone();
        let serve = tokio::spawn(async move {
            let server = embednfs::NfsServer::new(embednfs::MemFs::new());
            tokio::select! {
                r = server.serve(listener) => r,
                _ = wait_stop(stop_serve) => Ok(()),
            }
        });

        let tmp = tempfile::tempdir().expect("tmpdir");
        let mnt = tmp.path();
        let status = std::process::Command::new("mount")
            .args([
                "-t",
                "nfs",
                "-o",
                &format!("vers=4.1,tcp,port={port},sec=sys"),
                "127.0.0.1:/",
                mnt.to_str().expect("utf8 mount path"),
            ])
            .output();
        match status {
            Ok(out) if out.status.success() => {
                let _ = std::process::Command::new("umount").arg(mnt).status();
                eprintln!(
                    "Linux kernel mount succeeded: vers=4.1,tcp,port={port},sec=sys 127.0.0.1:/"
                );
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                eprintln!(
                    "skip: Linux kernel client unverified (mount exit {:?}): {stderr}",
                    out.status.code()
                );
            }
            Err(e) => {
                eprintln!("skip: mount(8) not available: {e}");
            }
        }

        stop.request_stop();
        let _ = tokio::time::timeout(Duration::from_secs(2), serve).await;
    }
}
