//! IPv4 `[host:]port` parser for export listeners.
//!
//! Copied from `ratarmount-nfs::parse_nfs_bind` (`DEFAULT_NFS_BIND` =
//! `127.0.0.1:20490`). nfsserve 0.11.0 `NFSTcpListener::bind` splits the
//! listen string on the **first** `:`, so `[::1]:port` cannot work. New
//! exports keep the same IPv4-only shape and pass their own `default_port`
//! so they never share 20490.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use thiserror::Error;

/// Default `--http-bind` port (unprivileged; not 80/8080).
pub const DEFAULT_HTTP_PORT: u16 = 20491;
/// Default `--webdav-bind` port (unprivileged; not 80).
pub const DEFAULT_WEBDAV_PORT: u16 = 20492;
/// Default `--ninep-bind` port (unprivileged; not 564).
pub const DEFAULT_NINEP_PORT: u16 = 20493;
/// Default `--sftp-bind` port (unprivileged; not 22).
pub const DEFAULT_SFTP_PORT: u16 = 20222;
/// Default `--smb-bind` port (unprivileged; not 445).
pub const DEFAULT_SMB_PORT: u16 = 20445;

/// Why [`parse_export_bind`] rejected a string.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BindError {
    #[error("export bind is IPv4-only; bind strings split on first ':'")]
    Ipv6Unsupported,
    #[error("invalid export bind {0:?}: expected [host:]port")]
    Invalid(String),
}

/// `127.0.0.1:port` — the empty-string result of [`parse_export_bind`].
pub fn default_export_bind(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, port))
}

/// Parse `[host:]port` into an IPv4 [`SocketAddr`].
///
/// Accepted:
/// * empty / whitespace → `127.0.0.1:{default_port}`
/// * `20491` / `:20491` → `127.0.0.1:20491`
/// * `0.0.0.0:20491` / `192.168.1.10:20491`
///
/// Rejected: any IPv6 form (`[::1]:20491`, `::1`, extra colons).
pub fn parse_export_bind(s: &str, default_port: u16) -> Result<SocketAddr, BindError> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(default_export_bind(default_port));
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

/// Format an IPv4 listen address as `a.b.c.d:port`.
///
/// Never call [`SocketAddr::to_string`] on a V6 address — that produces
/// `[::1]:port`, which first-colon split cannot parse.
pub fn export_bind_string(addr: SocketAddr) -> Result<String, BindError> {
    match addr.ip() {
        IpAddr::V4(ip) => Ok(format!("{ip}:{}", addr.port())),
        IpAddr::V6(_) => Err(BindError::Ipv6Unsupported),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Same split nfsserve 0.11.0 `tcp.rs` uses: first `:`, then `u16` port.
    fn first_colon_split_bind(s: &str) -> Option<(String, u16)> {
        let (ip, port) = s.split_once(':')?;
        Some((ip.to_string(), port.parse().ok()?))
    }

    /// Regression: empty bind uses the caller port, not NFS 20490.
    #[test]
    fn empty_is_default_port() {
        assert_eq!(
            parse_export_bind("", DEFAULT_HTTP_PORT).unwrap(),
            default_export_bind(DEFAULT_HTTP_PORT)
        );
        assert_eq!(
            parse_export_bind("  ", DEFAULT_SMB_PORT).unwrap(),
            default_export_bind(DEFAULT_SMB_PORT)
        );
        assert_eq!(
            default_export_bind(DEFAULT_HTTP_PORT),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 20491))
        );
        assert_ne!(
            parse_export_bind("", DEFAULT_HTTP_PORT).unwrap().port(),
            20490
        );
        assert_ne!(
            parse_export_bind("", DEFAULT_SMB_PORT).unwrap().port(),
            20490
        );
    }

    #[test]
    fn bare_port_and_colon_port() {
        let want = SocketAddr::from((Ipv4Addr::LOCALHOST, 20491));
        assert_eq!(parse_export_bind("20491", DEFAULT_HTTP_PORT).unwrap(), want);
        assert_eq!(
            parse_export_bind(":20491", DEFAULT_HTTP_PORT).unwrap(),
            want
        );
        assert_eq!(
            parse_export_bind("2049", DEFAULT_HTTP_PORT).unwrap(),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 2049))
        );
    }

    #[test]
    fn ipv4_host_port() {
        assert_eq!(
            parse_export_bind("0.0.0.0:20491", DEFAULT_HTTP_PORT).unwrap(),
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 20491))
        );
        assert_eq!(
            parse_export_bind("192.168.1.10:20445", DEFAULT_SMB_PORT).unwrap(),
            SocketAddr::from(([192, 168, 1, 10], 20445))
        );
    }

    /// Regression: IPv6 / extra-colon binds are rejected (first-colon split).
    #[test]
    fn ipv6_rejected() {
        assert_eq!(
            parse_export_bind("[::1]:20491", DEFAULT_HTTP_PORT).unwrap_err(),
            BindError::Ipv6Unsupported
        );
        assert_eq!(
            parse_export_bind("::1", DEFAULT_HTTP_PORT).unwrap_err(),
            BindError::Ipv6Unsupported
        );
        assert_eq!(
            parse_export_bind("::1:20490", DEFAULT_HTTP_PORT).unwrap_err(),
            BindError::Ipv6Unsupported
        );
    }

    #[test]
    fn invalid_host_or_port() {
        assert!(matches!(
            parse_export_bind("not-an-ip:20491", DEFAULT_HTTP_PORT),
            Err(BindError::Invalid(_))
        ));
        assert!(matches!(
            parse_export_bind("127.0.0.1:notaport", DEFAULT_HTTP_PORT),
            Err(BindError::Invalid(_))
        ));
        assert!(matches!(
            parse_export_bind("abc", DEFAULT_HTTP_PORT),
            Err(BindError::Invalid(_))
        ));
    }

    #[test]
    fn export_bind_string_survives_first_colon_split() {
        let addr = parse_export_bind("127.0.0.1:20491", DEFAULT_HTTP_PORT).unwrap();
        let s = export_bind_string(addr).unwrap();
        assert_eq!(s, "127.0.0.1:20491");
        let (ip, port) = first_colon_split_bind(&s).expect("first-colon split");
        assert_eq!(ip, "127.0.0.1");
        assert_eq!(port, 20491);

        let any = parse_export_bind("0.0.0.0:0", DEFAULT_HTTP_PORT).unwrap();
        let s = export_bind_string(any).unwrap();
        let (ip, port) = first_colon_split_bind(&s).unwrap();
        assert_eq!(ip, "0.0.0.0");
        assert_eq!(port, 0);
    }

    #[test]
    fn export_bind_string_rejects_v6() {
        let v6: SocketAddr = "[::1]:20491".parse().unwrap();
        assert_eq!(
            export_bind_string(v6).unwrap_err(),
            BindError::Ipv6Unsupported
        );
    }

    #[test]
    fn default_ports_do_not_collide() {
        let ports = [
            DEFAULT_HTTP_PORT,
            DEFAULT_WEBDAV_PORT,
            DEFAULT_NINEP_PORT,
            DEFAULT_SFTP_PORT,
            DEFAULT_SMB_PORT,
        ];
        for (i, a) in ports.iter().enumerate() {
            for b in ports.iter().skip(i + 1) {
                assert_ne!(a, b);
            }
        }
        assert!(!ports.contains(&20490));
    }
}
