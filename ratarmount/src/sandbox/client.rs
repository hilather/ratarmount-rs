//! Legacy JSON-lines client for the sandbox supervisor.

use super::protocol::{self, Request, Response, VERSION, VERSION_2};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

pub(super) fn call(socket: &Path, request: Request) -> Result<Response, String> {
    let mut stream = UnixStream::connect(socket).map_err(|e| e.to_string())?;
    // Includes queued requests and cleanup of a full batch; callers can retry reads,
    // but must not blindly retry mutations after a transport failure, except a
    // `new` or `finalize` retried with the same --request-id and arguments.
    let timeout = Some(Duration::from_secs(3600));
    stream
        .set_read_timeout(timeout)
        .and_then(|_| stream.set_write_timeout(timeout))
        .map_err(|e| e.to_string())?;
    let mut bytes = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    stream.write_all(&bytes).map_err(|e| e.to_string())?;
    let mut line = Vec::new();
    BufReader::new(stream)
        .take((protocol::MAX_RESPONSE + 1) as u64)
        .read_until(b'\n', &mut line)
        .map_err(|e| e.to_string())?;
    decode_response(&line, &request)
}

fn decode_response(line: &[u8], request: &Request) -> Result<Response, String> {
    if line.len() > protocol::MAX_RESPONSE || !line.ends_with(b"\n") {
        return Err("oversized or incomplete sandbox response".into());
    }
    let response: Response = serde_json::from_slice(line).map_err(|e| e.to_string())?;
    // An older daemon answers a v2 request with a v1 error (unsupported_version).
    let older_daemon = request.version == VERSION_2 && response.version == VERSION && !response.ok;
    if response.version != request.version && !older_daemon {
        return Err("unsupported response version".into());
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::super::protocol::Operation;
    use super::*;
    use std::os::unix::net::UnixListener;

    // Regression: extraction must preserve the OS connect error's Display.
    #[test]
    fn regression_sandbox_client_connect_error_preserves_io_display() {
        let error = call(
            Path::new("/nonexistent-rrs-client.sock"),
            Request::new(Operation::List { base: None }),
        )
        .unwrap_err();
        assert_eq!(
            error,
            std::io::Error::from_raw_os_error(libc::ENOENT).to_string()
        );
    }

    // Regression: extraction must reject oversized responses before JSON decoding.
    #[test]
    fn regression_sandbox_client_oversized_response_rejected() {
        let mut line = vec![b' '; protocol::MAX_RESPONSE + 1];
        *line.last_mut().unwrap() = b'\n';
        let request = Request::new(Operation::List { base: None });
        let error = decode_response(&line, &request).unwrap_err();
        assert_eq!(error, "oversized or incomplete sandbox response");
    }

    // Regression: extraction must reject EOF without a response's newline framing.
    #[test]
    fn regression_sandbox_client_missing_newline_rejected() {
        let dir = super::super::tests::private_tempdir();
        let socket = dir.path().join("client.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let peer = std::thread::spawn(move || {
            let deadline = std::time::Instant::now() + Duration::from_secs(30);
            let stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(std::time::Instant::now() < deadline, "no client");
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(e) => panic!("accept: {e}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(30)))
                .unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = Vec::new();
            reader.read_until(b'\n', &mut line).unwrap();
            reader
                .get_mut()
                .write_all(b"{\"version\":1,\"ok\":true,\"result\":null}")
                .unwrap();
        });
        let result = call(&socket, Request::new(Operation::List { base: None }));
        assert_eq!(
            result.unwrap_err(),
            "oversized or incomplete sandbox response"
        );
        peer.join().unwrap();
    }

    // Regression: extraction must preserve Serde's malformed-response error Display.
    #[test]
    fn regression_sandbox_client_decode_error_preserves_serde_display() {
        let line = b"{invalid json}\n";
        let expected = serde_json::from_slice::<Response>(line)
            .unwrap_err()
            .to_string();
        let request = Request::new(Operation::List { base: None });
        let error = decode_response(line, &request).unwrap_err();
        assert_eq!(error, expected);
    }
}
