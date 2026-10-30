//! Real Rustls server over the same authored smoltcp Ethernet peer.
use super::*;
use alloc::sync::Arc;
use rustls::{
    ClientConfig, ServerConfig, ServerConnection,
    crypto::GetRandomFailed,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer, UnixTime},
    time_provider::TimeProvider,
};
use std::io::{Cursor, Read, Write};
use stela_tls::{EntropySource, ProviderOwner};
use zeroize::Zeroizing;

struct Random;
impl EntropySource for Random {
    fn fill(&self, output: &mut [u8]) -> Result<(), GetRandomFailed> {
        let mut bytes = Zeroizing::new(vec![0; output.len()]);
        getrandom::getrandom(&mut bytes).map_err(|_| GetRandomFailed)?;
        output.copy_from_slice(&bytes);
        Ok(())
    }
}
#[derive(Debug)]
struct Utc;
impl TimeProvider for Utc {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(core::time::Duration::from_secs(
            1_793_232_000,
        )))
    }
}
fn client_config_with_time(time: Arc<dyn TimeProvider>) -> Arc<ClientConfig> {
    static OWNER: std::sync::OnceLock<ProviderOwner> = std::sync::OnceLock::new();
    let owner = OWNER.get_or_init(|| ProviderOwner::new(Arc::new(Random)));
    client_config_for(owner, time)
}
fn client_config_for(
    owner: &'static ProviderOwner,
    time: Arc<dyn TimeProvider>,
) -> Arc<ClientConfig> {
    client_config_with_ca(
        owner,
        time,
        &include_bytes!("../../../../../../stela-tls/tests/fixtures/ec-ca.der")[..],
    )
}
fn client_config_with_ca(
    owner: &'static ProviderOwner,
    time: Arc<dyn TimeProvider>,
    ca: &'static [u8],
) -> Arc<ClientConfig> {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(ca)).unwrap();
    Arc::new(
        ClientConfig::builder_with_details(Arc::new(owner.provider()), time)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}
struct Peer {
    lan: Lan,
    tls: ServerConnection,
    outgoing: Vec<u8>,
    sent: usize,
    request: Vec<u8>,
    replied: bool,
    paused: bool,
    redirect: Option<SocketHandle>,
    http_request: Vec<u8>,
    http_sent: usize,
}
impl Peer {
    fn new(clock: TestClock) -> Self {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(
                    &include_bytes!("../../../../../../stela-tls/tests/fixtures/ec-leaf.der")[..],
                )],
                PrivatePkcs8KeyDer::from(
                    &include_bytes!("../../../../../../stela-tls/tests/fixtures/ec-key.der")[..],
                )
                .into(),
            )
            .unwrap();
        Self {
            lan: Lan::new(1 << 20, clock),
            tls: ServerConnection::new(Arc::new(config)).unwrap(),
            outgoing: Vec::new(),
            sent: 0,
            request: Vec::new(),
            replied: false,
            paused: false,
            redirect: None,
            http_request: Vec::new(),
            http_sent: 0,
        }
    }
    fn upgrade(clock: TestClock) -> Self {
        let mut peer = Self::new(clock);
        peer.redirect = Some(peer.lan.listener);
        let mut socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 1 << 20]),
            tcp::SocketBuffer::new(vec![0; 1 << 20]),
        );
        socket.listen(443).unwrap();
        peer.lan.listener = peer.lan.sockets.add(socket);
        peer
    }
    fn step(&mut self) {
        let now = Instant::from_micros(self.lan.clock.0.get() as i64);
        self.lan
            .iface
            .poll(now, &mut self.lan.server, &mut self.lan.sockets);
        if let Some(handle) = self.redirect {
            let socket = self.lan.sockets.get_mut::<tcp::Socket>(handle);
            while socket.can_recv() {
                socket
                    .recv(|bytes| {
                        self.http_request.extend_from_slice(bytes);
                        (bytes.len(), ())
                    })
                    .unwrap();
            }
            if self.http_request.windows(4).any(|w| w == b"\r\n\r\n") && socket.can_send() {
                let reply=b"HTTP/1.1 307 Temporary Redirect\r\nLocation: https://valid.test/next?sig=%2b\r\nContent-Length: 0\r\n\r\n";
                if self.http_sent < reply.len() {
                    self.http_sent += socket.send_slice(&reply[self.http_sent..]).unwrap();
                }
                if self.http_sent == reply.len() {
                    socket.close();
                }
            }
        }
        let socket = self.lan.sockets.get_mut::<tcp::Socket>(self.lan.listener);
        while socket.can_recv() {
            socket
                .recv(|bytes| {
                    self.tls.read_tls(&mut Cursor::new(&*bytes)).unwrap();
                    (bytes.len(), ())
                })
                .unwrap();
        }
        self.tls.process_new_packets().unwrap();
        let mut plain = [0u8; 4096];
        loop {
            match self.tls.reader().read(&mut plain) {
                Ok(0) => break,
                Ok(n) => self.request.extend_from_slice(&plain[..n]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("{error}"),
            }
        }
        if !self.replied && self.request.windows(4).any(|w| w == b"\r\n\r\n") {
            self.replied = true;
            self.tls.set_buffer_limit(Some(512 * 1024));
            let body = vec![0x5a; 256 * 1024];
            self.tls
                .writer()
                .write_all(
                    alloc::format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", body.len())
                        .as_bytes(),
                )
                .unwrap();
            self.tls.writer().write_all(&body).unwrap();
            self.tls.send_close_notify();
        }
        while self.tls.wants_write() {
            self.tls.write_tls(&mut self.outgoing).unwrap();
        }
        if socket.can_send() && self.sent < self.outgoing.len() {
            self.sent += socket.send_slice(&self.outgoing[self.sent..]).unwrap();
        }
        if self.replied && self.sent == self.outgoing.len() {
            socket.close();
        }
        self.lan
            .iface
            .poll(now, &mut self.lan.server, &mut self.lan.sockets);
    }
}
impl Link for Peer {
    fn mac(&self) -> Mac {
        CLIENT
    }
    fn transmit(&mut self, frame: &[u8]) -> Result<(), LinkError> {
        self.lan.client.transmit(frame)
    }
    fn receive(&mut self) -> Result<Option<Vec<u8>>, LinkError> {
        if self.paused {
            return Ok(None);
        }
        if self.lan.client.into.borrow().0.is_empty() {
            self.step();
        }
        self.lan.client.receive()
    }
}
#[test]
fn authenticated_tls_stream_preserves_request_and_small_window_backpressure() {
    let clock = TestClock::default();
    let mut stack = Stack::new(Peer::new(clock.clone()), clock, 7).unwrap();
    stack
        .set_config(Config {
            address: Ipv4Cidr::new(CLIENT_IP, 24),
            router: None,
            dns: Vec::new(),
        })
        .unwrap();
    stack
        .resolved
        .push((String::from("valid.test"), SERVER_IP.into(), 0));
    let url = http::Url::parse("https://valid.test:80/a%2fb?sig=%2B%3D").unwrap();
    let request = http::get_range(url.authority, url.target, 0, 1, None).unwrap();
    let mut transfer = stack
        .open_tls(
            url,
            request.clone(),
            1024,
            client_config_with_time(Arc::new(Utc)),
        )
        .unwrap();
    let mut reply = Vec::new();
    let mut done = false;
    for _ in 0..100_000 {
        done = stack
            .read_tls(&mut transfer, |bytes, eof| {
                reply.extend_from_slice(bytes);
                Ok(http::response(&reply, eof)?.is_some())
            })
            .unwrap();
        if done {
            break;
        }
    }
    assert!(done);
    assert_eq!(stack.link_mut().request, request);
    assert_eq!(
        http::response(&reply, false).unwrap().unwrap().body,
        vec![0x5a; 256 * 1024]
    );
    stack.close_tls(transfer);
    assert_eq!(
        stack
            .sockets
            .iter()
            .filter(|(_, socket)| matches!(socket, smoltcp::socket::Socket::Tcp(_)))
            .count(),
        0
    );
}

#[derive(Debug)]
struct UnavailableTime;
impl TimeProvider for UnavailableTime {
    fn current_time(&self) -> Option<UnixTime> {
        None
    }
}
#[test]
fn unavailable_time_refuses_before_tcp_or_tls_publication() {
    let clock = TestClock::default();
    let mut stack = Stack::new(Peer::new(clock.clone()), clock, 7).unwrap();
    let url = http::Url::parse("https://valid.test:80/path").unwrap();
    let result = stack.open_tls(
        url,
        Vec::new(),
        1024,
        client_config_with_time(Arc::new(UnavailableTime)),
    );
    assert!(matches!(result,Err(NetError::Tls(reason)) if reason.contains("TimeUnavailable")));
    assert_eq!(
        stack
            .sockets
            .iter()
            .filter(|(_, socket)| matches!(socket, smoltcp::socket::Socket::Tcp(_)))
            .count(),
        0
    );
    assert!(stack.phy.link.lan.client.out.borrow().0.is_empty());
}

#[derive(Debug)]
struct RevocableTime(core::sync::atomic::AtomicBool);
impl TimeProvider for RevocableTime {
    fn current_time(&self) -> Option<UnixTime> {
        self.0
            .load(core::sync::atomic::Ordering::Acquire)
            .then(|| Utc.current_time().unwrap())
    }
}
#[test]
fn lost_time_refuses_before_pending_socket_output_can_progress() {
    let clock = TestClock::default();
    let mut stack = Stack::new(Peer::new(clock.clone()), clock, 7).unwrap();
    stack
        .set_config(Config {
            address: Ipv4Cidr::new(CLIENT_IP, 24),
            router: None,
            dns: Vec::new(),
        })
        .unwrap();
    stack
        .resolved
        .push((String::from("valid.test"), SERVER_IP.into(), 0));
    let time = Arc::new(RevocableTime(core::sync::atomic::AtomicBool::new(true)));
    let mut transfer = stack
        .open_tls(
            http::Url::parse("https://valid.test:80/p").unwrap(),
            Vec::new(),
            1024,
            client_config_with_time(time.clone()),
        )
        .unwrap();
    // Leave the real TCP handshake blocked, so the first call encodes a
    // ClientHello but cannot consume its pending TLS output.
    stack.link_mut().paused = true;
    assert!(
        !stack
            .read_tls(&mut transfer, |_, _| panic!("handshake is blocked"))
            .unwrap()
    );
    let published = stack.phy.link.lan.client.out.borrow().0.len();
    time.0.store(false, core::sync::atomic::Ordering::Release);
    let result = stack.read_tls(&mut transfer, |_, _| panic!("no unauthenticated output"));
    assert!(matches!(result,Err(NetError::Tls(reason)) if reason.contains("TimeUnavailable")));
    assert_eq!(stack.phy.link.lan.client.out.borrow().0.len(), published);
    stack.close_tls(transfer);
    assert_eq!(
        stack
            .sockets
            .iter()
            .filter(|(_, socket)| matches!(socket, smoltcp::socket::Socket::Tcp(_)))
            .count(),
        0
    );
}

struct UnavailableEntropy;
impl EntropySource for UnavailableEntropy {
    fn fill(&self, _: &mut [u8]) -> Result<(), GetRandomFailed> {
        Err(GetRandomFailed)
    }
}
#[test]
fn entropy_failure_refuses_before_tcp_or_tls_publication() {
    static OWNER: std::sync::OnceLock<ProviderOwner> = std::sync::OnceLock::new();
    let owner = OWNER.get_or_init(|| ProviderOwner::new(Arc::new(UnavailableEntropy)));
    let clock = TestClock::default();
    let mut stack = Stack::new(Peer::new(clock.clone()), clock, 7).unwrap();
    let result = stack.open_tls(
        http::Url::parse("https://valid.test:80/p").unwrap(),
        Vec::new(),
        1024,
        client_config_for(owner, Arc::new(Utc)),
    );
    assert!(
        matches!(result,Err(NetError::Tls(reason)) if reason.contains("FailedToGetRandomBytes"))
    );
    assert_eq!(
        stack
            .sockets
            .iter()
            .filter(|(_, socket)| matches!(socket, smoltcp::socket::Socket::Tcp(_)))
            .count(),
        0
    );
    assert!(stack.phy.link.lan.client.out.borrow().0.is_empty());
}

#[test]
fn url_aware_https_request_delivers_authenticated_response_and_retires_socket() {
    let clock = TestClock::default();
    let mut stack = Stack::new(Peer::new(clock.clone()), clock, 7).unwrap();
    stack
        .set_config(Config {
            address: Ipv4Cidr::new(CLIENT_IP, 24),
            router: None,
            dns: Vec::new(),
        })
        .unwrap();
    stack
        .resolved
        .push((String::from("valid.test"), SERVER_IP.into(), 0));
    let mut transfer = stack
        .open_http(
            "https://valid.test:80/p?sig=%2b",
            HttpRequest::post(&[], "text/plain", b""),
            1024,
            Ok(client_config_with_time(Arc::new(Utc))),
        )
        .unwrap();
    let mut reply = Vec::new();
    let mut done = false;
    for _ in 0..100_000 {
        done = stack
            .read_http(&mut transfer, |bytes, eof| {
                reply.extend_from_slice(bytes);
                Ok(http::response(&reply, eof)?.is_some())
            })
            .unwrap();
        if done {
            break;
        }
    }
    assert!(done);
    assert_eq!(
        http::response(&reply, false).unwrap().unwrap().body,
        vec![0x5a; 256 * 1024]
    );
    assert!(
        core::str::from_utf8(&stack.link_mut().request)
            .unwrap()
            .starts_with("POST /p?sig=%2b HTTP/1.1\r\nHost: valid.test:80\r\n")
    );
    assert_eq!(
        stack
            .sockets
            .iter()
            .filter(|(_, s)| matches!(s, smoltcp::socket::Socket::Tcp(_)))
            .count(),
        0
    );
    stack.close_http(transfer);
}

#[test]
fn same_host_post_upgrade_replays_only_after_tls_verification() {
    let clock = TestClock::default();
    let mut stack = Stack::new(Peer::upgrade(clock.clone()), clock, 7).unwrap();
    stack
        .set_config(Config {
            address: Ipv4Cidr::new(CLIENT_IP, 24),
            router: None,
            dns: Vec::new(),
        })
        .unwrap();
    stack
        .resolved
        .push((String::from("valid.test"), SERVER_IP.into(), 0));
    let mut transfer = stack
        .open_http(
            "http://valid.test/start",
            HttpRequest::post(
                &[("Authorization", "Bearer fixture")],
                "text/plain",
                b"owned-body",
            ),
            1024,
            Ok(client_config_with_time(Arc::new(Utc))),
        )
        .unwrap();
    let mut response = Vec::new();
    let mut done = false;
    for _ in 0..100_000 {
        done = stack
            .read_http(&mut transfer, |bytes, eof| {
                response.extend_from_slice(bytes);
                Ok(http::response(&response, eof)?.is_some())
            })
            .unwrap();
        if done {
            break;
        }
    }
    assert!(done);
    assert_eq!(transfer.url(), "https://valid.test/next?sig=%2b");
    let peer = stack.link_mut();
    assert!(peer.http_request.ends_with(b"owned-body"));
    assert!(
        peer.request
            .starts_with(b"POST /next?sig=%2b HTTP/1.1\r\nHost: valid.test\r\n")
    );
    assert!(peer.request.ends_with(b"owned-body"));
    assert!(
        core::str::from_utf8(&peer.request)
            .unwrap()
            .contains("Authorization: Bearer fixture\r\n")
    );
    stack.close_http(transfer);
}
#[test]
fn untrusted_certificate_blocks_the_upgraded_post_body() {
    static OWNER: std::sync::OnceLock<ProviderOwner> = std::sync::OnceLock::new();
    let owner = OWNER.get_or_init(|| ProviderOwner::new(Arc::new(Random)));
    let clock = TestClock::default();
    let mut stack = Stack::new(Peer::upgrade(clock.clone()), clock, 7).unwrap();
    stack
        .set_config(Config {
            address: Ipv4Cidr::new(CLIENT_IP, 24),
            router: None,
            dns: Vec::new(),
        })
        .unwrap();
    stack
        .resolved
        .push((String::from("valid.test"), SERVER_IP.into(), 0));
    let config = client_config_with_ca(
        owner,
        Arc::new(Utc),
        &include_bytes!("../../../../../../stela-tls/tests/fixtures/rsa-ca.der")[..],
    );
    let mut transfer = stack
        .open_http(
            "http://valid.test/start",
            HttpRequest::post(&[], "text/plain", b"private-body"),
            1024,
            Ok(config),
        )
        .unwrap();
    let mut failure = None;
    for _ in 0..100_000 {
        if let Err(error) = stack.read_http(&mut transfer, |_, _| panic!("untrusted response")) {
            failure = Some(error);
            break;
        }
    }
    assert!(matches!(failure,Some(NetError::Tls(reason)) if reason.contains("InvalidCertificate")));
    assert!(stack.link_mut().http_request.ends_with(b"private-body"));
    assert!(stack.link_mut().request.is_empty());
    stack.close_http(transfer);
}
