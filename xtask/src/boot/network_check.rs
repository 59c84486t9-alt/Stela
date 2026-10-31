//! An independent HTTP response fixture for after-EBS driver checks. The
//! response spans many NIC descriptors and TCP windows; comparing its digest
//! catches corrupt DMA contents, missed segments and ring-wrap mistakes.
use anyhow::{Context, Result};
use std::{
    io::{self, Read, Write},
    net::{TcpListener, TcpStream},
    thread,
    time::Duration,
};

pub const BODY_BYTES: usize = 200_000;
const MAX_REQUEST: usize = 8192;
const PATH: &str = "/stela-driver-check";

pub struct Fixture {
    pub url: String,
    pub sha256: String,
    port: u16,
}

impl Fixture {
    pub fn start() -> Result<Self> {
        let server = TcpListener::bind(("127.0.0.1", 0))?;
        let port = server.local_addr()?.port();
        let body: Vec<u8> = (0..BODY_BYTES)
            .map(|index| index.wrapping_mul(73).wrapping_add(index >> 8) as u8)
            .collect();
        let sha256 = stela_formats::sha256(&body);
        thread::spawn(move || {
            let result = server
                .accept()
                .and_then(|(socket, _)| respond(socket, &body));
            if let Err(error) = result {
                eprintln!("network check fixture: {error}");
            }
        });
        Ok(Self {
            // A name exercises DNS, as well as DHCP and TCP.
            url: format!("http://localhost:{port}{PATH}"),
            sha256,
            port,
        })
    }
}

fn respond(mut socket: TcpStream, body: &[u8]) -> io::Result<()> {
    socket.set_read_timeout(Some(Duration::from_secs(30)))?;
    socket.set_write_timeout(Some(Duration::from_secs(30)))?;
    let mut request = Vec::new();
    let mut byte = [0];
    while !request.ends_with(b"\r\n\r\n") {
        if request.len() == MAX_REQUEST {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "network check request is too large",
            ));
        }
        socket.read_exact(&mut byte)?;
        request.push(byte[0]);
    }
    if !request.starts_with(format!("POST {PATH} HTTP/1.1\r\n").as_bytes()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected network check request",
        ));
    }
    write!(
        socket,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    socket.write_all(body)
}

/// The missing observation that prevents a network fixture from passing.
#[derive(Debug, PartialEq, Eq)]
pub enum VerificationError {
    MissingResult,
    BodyMismatch { expected_sha256: String },
    WrongDriver { expected: String },
    IncompleteLease,
    MissingDnsQuery,
    MissingConnection { port: u16 },
    MissingRequest { port: u16 },
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingResult => {
                output.write_str("the mount did not report a successful network check")
            }
            Self::BodyMismatch { expected_sha256 } => write!(
                output,
                "the mount did not reproduce the complete network fixture body (bytes={BODY_BYTES} sha256={expected_sha256})"
            ),
            Self::WrongDriver { expected } => write!(
                output,
                "the mount did not use the requested host network driver ({expected})"
            ),
            Self::IncompleteLease => {
                output.write_str("the network peer did not record a complete DHCP lease")
            }
            Self::MissingDnsQuery => {
                output.write_str("the network peer did not record the fixture DNS query")
            }
            Self::MissingConnection { port } => write!(
                output,
                "the network peer did not connect to the fixture server (127.0.0.1:{port})"
            ),
            Self::MissingRequest { port } => write!(
                output,
                "the network peer did not relay the check's TCP connection to port {port}"
            ),
        }
    }
}

impl std::error::Error for VerificationError {}

/// The TCP port `url` names, or its scheme's: 443 for HTTPS, 80 for HTTP.
pub fn port(url: &str) -> Result<u16> {
    let uri = stela_formats::uri::Uri::new(url)
        .ok()
        .context("the network check URL is not an RFC 3986 URI")?;
    let authority = uri
        .authority_components()
        .context("the network check URL names no host")?;
    match authority.port().filter(|port| !port.is_empty()) {
        Some(port) => port.parse().context("the network check URL's port"),
        None if uri.scheme_str().eq_ignore_ascii_case("https") => Ok(443),
        None => Ok(80),
    }
}

/// A successful translation run does not establish that its requested
/// network check ran. Require the mount's explicit after-EBS result, the
/// peer's relay of a requested URL's connection (so an HTTPS check's
/// success is the mount's own TLS session with that server), and the
/// entire fixture body when running the deterministic driver check.
pub fn verify(
    serial: &str,
    fixture: Option<&Fixture>,
    port: Option<u16>,
    expected_driver: &str,
    peer: &str,
) -> Result<(), VerificationError> {
    if !serial.lines().any(|line| line == "NETWORK CHECK passed") {
        return Err(VerificationError::MissingResult);
    }
    if let Some(port) = port {
        let destination = format!(":{port} open");
        if !peer
            .lines()
            .any(|line| line.starts_with("TCP 10.0.2.15:") && line.ends_with(&destination))
        {
            return Err(VerificationError::MissingRequest { port });
        }
    }
    if let Some(fixture) = fixture {
        let expected = format!(
            "NETWORK CHECK body bytes={BODY_BYTES} sha256={}",
            fixture.sha256
        );
        if !serial.lines().any(|line| line == expected) {
            return Err(VerificationError::BodyMismatch {
                expected_sha256: fixture.sha256.clone(),
            });
        }
        let expected = format!("NETWORK driver={expected_driver}");
        if !serial.lines().any(|line| line == expected) {
            return Err(VerificationError::WrongDriver {
                expected: expected_driver.into(),
            });
        }
        // These independent peer observations prevent a serial success marker
        // from crediting DHCP/DNS paths the check did not exercise.
        if !peer
            .lines()
            .any(|line| line.starts_with("DHCP OFFER 10.0.2.15 to "))
            || !peer
                .lines()
                .any(|line| line.starts_with("DHCP ACK 10.0.2.15 to "))
        {
            return Err(VerificationError::IncompleteLease);
        }
        if !peer
            .lines()
            .any(|line| line == "DNS query localhost type 1")
        {
            return Err(VerificationError::MissingDnsQuery);
        }
        let destination = format!(" -> 127.0.0.1:{} open", fixture.port);
        if !peer
            .lines()
            .any(|line| line.starts_with("TCP 10.0.2.15:") && line.ends_with(&destination))
        {
            return Err(VerificationError::MissingConnection { port: fixture.port });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_fixture_serves_complete_body() {
        let fixture = Fixture::start().unwrap();
        let mut socket = TcpStream::connect(("127.0.0.1", fixture.port)).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        socket
            .write_all(
                format!("POST {PATH} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n")
                    .as_bytes(),
            )
            .unwrap();
        let mut response = Vec::new();
        socket.read_to_end(&mut response).unwrap();
        let split = response
            .windows(4)
            .position(|bytes| bytes == b"\r\n\r\n")
            .unwrap()
            + 4;
        let headers = core::str::from_utf8(&response[..split]).unwrap();
        assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(headers.contains(&format!("\r\nContent-Length: {BODY_BYTES}\r\n")));
        let body = &response[split..];
        assert_eq!(body.len(), BODY_BYTES);
        assert_eq!(stela_formats::sha256(body), fixture.sha256);
        assert_eq!(
            fixture.sha256,
            "1f1747c499dd2b60e4aad488fd4cb9ba0d4df3f9be8f91827f2d6bb90f94384e"
        );
    }

    #[test]
    fn fixture_refuses_the_wrong_request_and_oversized_headers() {
        for request in [
            b"GET /stela-driver-check HTTP/1.1\r\n\r\n".to_vec(),
            b"POST /wrong HTTP/1.1\r\n\r\n".to_vec(),
            vec![b'x'; MAX_REQUEST],
        ] {
            let server = TcpListener::bind(("127.0.0.1", 0)).unwrap();
            let address = server.local_addr().unwrap();
            let served = thread::spawn(move || {
                let (socket, _) = server.accept().unwrap();
                respond(socket, b"must not be returned").unwrap_err().kind()
            });
            let mut socket = TcpStream::connect(address).unwrap();
            socket.write_all(&request).unwrap();
            assert_eq!(served.join().unwrap(), io::ErrorKind::InvalidData);
        }
    }

    #[test]
    fn requested_urls_name_their_port() {
        for (url, expected) in [
            ("https://gs.apple.com/TSS/controller?action=2", 443),
            ("HTTPS://h:8443/p", 8443),
            ("http://h/p", 80),
            ("http://h:/p", 80),
            ("http://[2001:db8::1]:8080/p", 8080),
        ] {
            assert_eq!(port(url).unwrap(), expected, "{url}");
        }
        for url in ["http:/p", "http://h:99999/p", "http://h:x/p"] {
            assert!(port(url).is_err(), "{url}");
        }
    }

    #[test]
    fn requested_urls_require_the_peers_relay() {
        let serial = "NETWORK CHECK passed\n";
        let peer = "TCP 10.0.2.15:50581 -> 17.32.214.236:443 open\n";
        assert!(verify(serial, None, Some(443), "virtio-net", peer).is_ok());
        for peer in [
            "",
            "TCP 10.0.2.15:50581 -> 17.32.214.236:80 open\n",
            "TCP 10.0.2.15:50581 -> 17.32.214.236:443 refused\n",
            "GUEST| TCP 10.0.2.15:50581 -> 17.32.214.236:443 open\n",
        ] {
            assert_eq!(
                verify(serial, None, Some(443), "virtio-net", peer),
                Err(VerificationError::MissingRequest { port: 443 })
            );
        }
    }

    #[test]
    fn requested_checks_require_the_mounts_result() {
        assert!(
            verify(
                "NETWORK CHECK passed\nSTOP idle\n",
                None,
                None,
                "e1000e",
                ""
            )
            .is_ok()
        );
        for serial in [
            "STOP idle\n",
            "NETWORK POST http://localhost/check sent=0 received=1\n",
            "NETWORK CHECK passed extra\n",
            "GUEST| NETWORK CHECK passed\n",
        ] {
            assert_eq!(
                verify(serial, None, None, "e1000e", ""),
                Err(VerificationError::MissingResult)
            );
        }
    }

    #[test]
    fn network_verification_rejects_incomplete_body() {
        let fixture = Fixture {
            url: "http://localhost/check".into(),
            sha256: "0123456789abcdef".repeat(4),
            port: 12345,
        };
        let digest = &fixture.sha256;
        let serial = format!(
            "NETWORK driver=e1000e\nNETWORK CHECK body bytes={BODY_BYTES} sha256={digest}\nNETWORK CHECK passed\n"
        );
        let peer = "DHCP OFFER 10.0.2.15 to 52:54:00:12:34:56\n\
                    DHCP ACK 10.0.2.15 to 52:54:00:12:34:56\n\
                    DNS query localhost type 1\n\
                    TCP 10.0.2.15:50581 -> 127.0.0.1:12345 open\n";
        assert!(verify(&serial, Some(&fixture), None, "e1000e", peer).is_ok());
        assert_eq!(
            verify(&serial, Some(&fixture), None, "virtio-net", peer),
            Err(VerificationError::WrongDriver {
                expected: "virtio-net".into()
            })
        );
        for missing in peer.lines() {
            let incomplete = peer.replace(missing, "");
            assert!(verify(&serial, Some(&fixture), None, "e1000e", &incomplete).is_err());
        }
        assert!(
            verify(
                &serial,
                Some(&fixture),
                None,
                "e1000e",
                &peer.replace(":12345 open", ":9999 open")
            )
            .is_err()
        );
        assert!(
            verify(
                &serial,
                Some(&fixture),
                None,
                "e1000e",
                &peer.replace("DNS query", "GUEST| DNS query")
            )
            .is_err()
        );

        assert!(
            verify(
                "NETWORK CHECK passed\n",
                Some(&fixture),
                None,
                "e1000e",
                peer
            )
            .is_err()
        );
        assert!(
            verify(
                &serial.replace("200000", "199999"),
                Some(&fixture),
                None,
                "e1000e",
                peer
            )
            .is_err()
        );
        assert!(
            verify(
                &serial.replace(digest, &"f".repeat(64)),
                Some(&fixture),
                None,
                "e1000e",
                peer
            )
            .is_err()
        );
        assert!(
            verify(
                &serial.replace("NETWORK CHECK passed\n", ""),
                Some(&fixture),
                None,
                "e1000e",
                peer,
            )
            .is_err()
        );
    }
}
