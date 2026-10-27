//! `--healthcheck` mode: queries the health endpoint of a server running in
//! the same container. The image has no curl, so the binary checks itself.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::server::HEALTH_PATH;

const TIMEOUT: Duration = Duration::from_secs(5);
/// Upper bound on the health response that is read.
const MAX_RESPONSE: u64 = 64 * 1024;

/// Maps a wildcard listen address to the matching loopback address.
fn target(listen: SocketAddr) -> SocketAddr {
    let ip = match listen.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        ip => ip,
    };
    SocketAddr::new(ip, listen.port())
}

/// Returns the response body if the server at `listen` reports healthy.
pub fn check(listen: SocketAddr) -> Result<String> {
    let addr = target(listen);
    let mut stream = TcpStream::connect_timeout(&addr, TIMEOUT)
        .with_context(|| format!("connecting to {addr}"))?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    write!(
        stream,
        "GET {HEALTH_PATH} HTTP/1.0\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
    )?;

    let mut raw = Vec::new();
    stream
        .take(MAX_RESPONSE)
        .read_to_end(&mut raw)
        .context("reading health response")?;
    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head.lines().next().unwrap_or_default();
    let code = status.split_whitespace().nth(1).unwrap_or_default();
    if code != "200" {
        bail!("{status}: {}", body.trim());
    }
    Ok(body.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::repo::Scanner;
    use crate::server::{AppState, router};

    #[test]
    fn wildcard_addresses_map_to_loopback() {
        let t = |s: &str| target(s.parse().unwrap()).to_string();
        assert_eq!(t("0.0.0.0:8080"), "127.0.0.1:8080");
        assert_eq!(t("[::]:8080"), "[::1]:8080");
        assert_eq!(t("10.1.2.3:80"), "10.1.2.3:80");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn reports_server_health() {
        let dir = tempfile::tempdir().unwrap();
        let repo = Scanner::new(dir.path().to_owned(), None)
            .scan()
            .unwrap()
            .unwrap();
        let state = AppState::new(repo, "test".into(), None);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(axum::serve(listener, router(state.clone())).into_future());

        let body = tokio::task::spawn_blocking(move || check(addr))
            .await
            .unwrap()
            .unwrap();
        assert!(body.starts_with("ok packages=0 revision="), "{body}");

        state.set_scan_error(Some("reading directory /srv/rpms".into()));
        let err = tokio::task::spawn_blocking(move || check(addr))
            .await
            .unwrap()
            .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("503"), "{msg}");
        assert!(msg.contains("reading directory /srv/rpms"), "{msg}");
    }

    #[test]
    fn nothing_listening_is_unhealthy() {
        // Bind and drop to get a port that is very likely closed.
        let addr = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap();
        assert!(check(addr).is_err());
    }
}
