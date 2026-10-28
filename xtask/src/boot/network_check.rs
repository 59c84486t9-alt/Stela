//! An independent HTTP response fixture for after-EBS driver checks. The
//! response spans many NIC descriptors and TCP windows; comparing its digest
//! catches corrupt DMA contents, missed segments and ring-wrap mistakes.
use anyhow::Result;
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
            // A name deliberately exercises DNS, as well as DHCP and TCP.
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

/// A successful translation run does not establish that its requested
/// network check ran. Require the mount's explicit after-EBS result, and
/// the entire fixture body when running the deterministic driver check.
pub fn verify(
    serial: &str,
    fixture: Option<&Fixture>,
    expected_driver: &str,
    peer: &str,
) -> Result<(), &'static str> {
    if !serial.lines().any(|line| line == "NETWORK CHECK passed") {
        return Err("the mount did not report a successful network check");
    }
    if let Some(fixture) = fixture {
        let expected = format!(
            "NETWORK CHECK body bytes={BODY_BYTES} sha256={}",
            fixture.sha256
        );
        if !serial.lines().any(|line| line == expected) {
            return Err("the mount did not reproduce the complete network fixture body");
        }
        let expected = format!("NETWORK driver={expected_driver}");
        if !serial.lines().any(|line| line == expected) {
            return Err("the mount did not use the requested host network driver");
        }
        // These independent peer observations prevent a serial success marker
        // from crediting DHCP/DNS paths the check did not actually exercise.
        if !peer
            .lines()
            .any(|line| line.starts_with("DHCP OFFER 10.0.2.15 to "))
            || !peer
                .lines()
                .any(|line| line.starts_with("DHCP ACK 10.0.2.15 to "))
        {
            return Err("the network peer did not record a complete DHCP lease");
        }
        if !peer
            .lines()
            .any(|line| line == "DNS query localhost type 1")
        {
            return Err("the network peer did not record the fixture DNS query");
        }
        let destination = format!(" -> 127.0.0.1:{} open", fixture.port);
        if !peer
            .lines()
            .any(|line| line.starts_with("TCP 10.0.2.15:") && line.ends_with(&destination))
        {
            return Err("the network peer did not connect to the fixture server");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixture_serves_the_entire_known_body_over_a_real_http_connection() {
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
    fn requested_checks_require_the_mounts_result() {
        assert!(verify("NETWORK CHECK passed\nSTOP idle\n", None, "e1000e", "").is_ok());
        for serial in [
            "STOP idle\n",
            "NETWORK POST http://localhost/check sent=0 received=1\n",
            "NETWORK CHECK passed extra\n",
            "GUEST| NETWORK CHECK passed\n",
        ] {
            assert!(verify(serial, None, "e1000e", "").is_err());
        }
    }

    #[test]
    fn fixture_checks_reject_a_missing_truncated_or_corrupted_body() {
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
        assert!(verify(&serial, Some(&fixture), "e1000e", peer).is_ok());
        assert!(verify(&serial, Some(&fixture), "virtio-net", peer).is_err());
        for missing in peer.lines() {
            let incomplete = peer.replace(missing, "");
            assert!(verify(&serial, Some(&fixture), "e1000e", &incomplete).is_err());
        }
        assert!(
            verify(
                &serial,
                Some(&fixture),
                "e1000e",
                &peer.replace(":12345 open", ":9999 open")
            )
            .is_err()
        );
        assert!(
            verify(
                &serial,
                Some(&fixture),
                "e1000e",
                &peer.replace("DNS query", "GUEST| DNS query")
            )
            .is_err()
        );

        assert!(verify("NETWORK CHECK passed\n", Some(&fixture), "e1000e", peer).is_err());
        assert!(
            verify(
                &serial.replace("200000", "199999"),
                Some(&fixture),
                "e1000e",
                peer
            )
            .is_err()
        );
        assert!(
            verify(
                &serial.replace(digest, &"f".repeat(64)),
                Some(&fixture),
                "e1000e",
                peer
            )
            .is_err()
        );
        assert!(
            verify(
                &serial.replace("NETWORK CHECK passed\n", ""),
                Some(&fixture),
                "e1000e",
                peer,
            )
            .is_err()
        );
    }
}
