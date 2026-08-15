//! IPv4 `--nfs-bind` parser.
//!
//! nfsserve 0.11.0 `NFSTcpListener::bind` splits the listen string on the
//! **first** `:`. `[::1]:port` therefore cannot work. v1 is IPv4-only.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};

use thiserror::Error;

use crate::DEFAULT_NFS_PORT;

/// Default bind used when `--nfs` is set and `--nfs-bind` is omitted.
pub const DEFAULT_NFS_BIND: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, DEFAULT_NFS_PORT));

/// Why [`parse_nfs_bind`] rejected a string.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BindError {
    #[error("nfs-bind is IPv4-only; nfsserve bind splits on first ':'")]
    Ipv6Unsupported,
    #[error("invalid nfs-bind {0:?}: expected [host:]port")]
    Invalid(String),
}

/// Parse `[host:]port` into an IPv4 [`SocketAddr`].
///
/// Accepted:
/// * empty / whitespace → [`DEFAULT_NFS_BIND`] (`127.0.0.1:20490`)
/// * `20490` / `:20490` → `127.0.0.1:20490`
/// * `0.0.0.0:20490` / `192.168.1.10:20490`
///
/// Rejected: any IPv6 form (`[::1]:20491`, `::1`, extra colons).
pub fn parse_nfs_bind(s: &str) -> Result<SocketAddr, BindError> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(DEFAULT_NFS_BIND);
    }
    if s.contains('[') || s.matches(':').count() > 1 {
        return Err(BindError::Ipv6Unsupported);
    }
    if let Some(rest) = s.strip_prefix(':') {
        let port = parse_port(rest).ok_or_else(|| BindError::Invalid(s.into()))?;
        return Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
    }
    if !s.contains(':') {
        let port = parse_port(s).ok_or_else(|| BindError::Invalid(s.into()))?;
        return Ok(SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
    }
    let (host, port_str) = s
        .split_once(':')
        .ok_or_else(|| BindError::Invalid(s.into()))?;
    let port = parse_port(port_str).ok_or_else(|| BindError::Invalid(s.into()))?;
    let ip: Ipv4Addr = host.parse().map_err(|_| BindError::Invalid(s.into()))?;
    Ok(SocketAddr::from((ip, port)))
}

fn parse_port(s: &str) -> Option<u16> {
    s.parse().ok()
}

/// Format an IPv4 listen address for nfsserve `bind` (`a.b.c.d:port`).
///
/// Never call [`SocketAddr::to_string`] on a V6 address — that produces
/// `[::1]:port`, which `NFSTcpListener::bind` cannot parse.
pub fn nfs_bind_string(addr: SocketAddr) -> Result<String, BindError> {
    match addr.ip() {
        IpAddr::V4(ip) => Ok(format!("{ip}:{}", addr.port())),
        IpAddr::V6(_) => Err(BindError::Ipv6Unsupported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same split nfsserve 0.11.0 `tcp.rs` uses: first `:`, then `u16` port.
    fn nfsserve_split_bind(s: &str) -> Option<(String, u16)> {
        let (ip, port) = s.split_once(':')?;
        Some((ip.to_string(), port.parse().ok()?))
    }

    #[test]
    fn empty_is_default() {
        assert_eq!(parse_nfs_bind("").unwrap(), DEFAULT_NFS_BIND);
        assert_eq!(parse_nfs_bind("  ").unwrap(), DEFAULT_NFS_BIND);
        assert_eq!(
            DEFAULT_NFS_BIND,
            SocketAddr::from((Ipv4Addr::LOCALHOST, 20490))
        );
    }

    #[test]
    fn bare_port_and_colon_port() {
        let want = SocketAddr::from((Ipv4Addr::LOCALHOST, 20490));
        assert_eq!(parse_nfs_bind("20490").unwrap(), want);
        assert_eq!(parse_nfs_bind(":20490").unwrap(), want);
    }

    #[test]
    fn ipv4_host_port() {
        assert_eq!(
            parse_nfs_bind("0.0.0.0:20490").unwrap(),
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 20490))
        );
        assert_eq!(
            parse_nfs_bind("192.168.1.10:20490").unwrap(),
            SocketAddr::from(([192, 168, 1, 10], 20490))
        );
    }

    #[test]
    fn ipv6_rejected() {
        assert_eq!(
            parse_nfs_bind("[::1]:20491").unwrap_err(),
            BindError::Ipv6Unsupported
        );
        assert_eq!(
            parse_nfs_bind("::1").unwrap_err(),
            BindError::Ipv6Unsupported
        );
        assert_eq!(
            parse_nfs_bind("::1:20490").unwrap_err(),
            BindError::Ipv6Unsupported
        );
    }

    #[test]
    fn invalid_host_or_port() {
        assert!(matches!(
            parse_nfs_bind("not-an-ip:20490"),
            Err(BindError::Invalid(_))
        ));
        assert!(matches!(
            parse_nfs_bind("127.0.0.1:notaport"),
            Err(BindError::Invalid(_))
        ));
        assert!(matches!(parse_nfs_bind("abc"), Err(BindError::Invalid(_))));
    }

    #[test]
    fn nfs_bind_string_survives_nfsserve_split() {
        let addr = parse_nfs_bind("127.0.0.1:20490").unwrap();
        let s = nfs_bind_string(addr).unwrap();
        assert_eq!(s, "127.0.0.1:20490");
        let (ip, port) = nfsserve_split_bind(&s).expect("nfsserve split");
        assert_eq!(ip, "127.0.0.1");
        assert_eq!(port, 20490);

        let any = parse_nfs_bind("0.0.0.0:0").unwrap();
        let s = nfs_bind_string(any).unwrap();
        let (ip, port) = nfsserve_split_bind(&s).unwrap();
        assert_eq!(ip, "0.0.0.0");
        assert_eq!(port, 0);
    }

    #[test]
    fn nfs_bind_string_rejects_v6() {
        let v6: SocketAddr = "[::1]:20491".parse().unwrap();
        assert_eq!(nfs_bind_string(v6).unwrap_err(), BindError::Ipv6Unsupported);
    }
}
