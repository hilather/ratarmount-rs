//! Fill-loop for export READ/GET (copied from `fill_read_for_nfs`).
//!
//! A short `Read::read` from gzip/rapidgzip is **not** EOF. NFS READ, HTTP
//! GET, SMB READ, 9P read, and SFTP READ all treat a short reply as
//! end-of-file — same contract as FUSE.

use std::io;

/// Fill `buf` by looping `Read::read` until full or true EOF.
pub fn fill_read(r: &mut dyn std::io::Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match std::io::Read::read(r, &mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(filled)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Read};

    /// One-byte `Read::read` — would become false EOF without the fill loop.
    struct ShortRead(Cursor<Vec<u8>>);
    impl Read for ShortRead {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            self.0.read(&mut buf[..1])
        }
    }

    /// Regression: short `Read::read` is not EOF (gzip/rapidgzip windows).
    #[test]
    fn fill_loops_until_full() {
        let mut r = ShortRead(Cursor::new(b"abcdef".to_vec()));
        let mut buf = [0u8; 6];
        let n = fill_read(&mut r, &mut buf).unwrap();
        assert_eq!(n, 6);
        assert_eq!(&buf, b"abcdef");
    }

    #[test]
    fn true_eof_may_be_short() {
        let mut r = ShortRead(Cursor::new(b"ab".to_vec()));
        let mut buf = [0u8; 6];
        let n = fill_read(&mut r, &mut buf).unwrap();
        assert_eq!(n, 2);
        assert_eq!(&buf[..2], b"ab");
    }

    #[test]
    fn empty_buf_is_zero() {
        let mut r = ShortRead(Cursor::new(b"xyz".to_vec()));
        let n = fill_read(&mut r, &mut []).unwrap();
        assert_eq!(n, 0);
    }
}
