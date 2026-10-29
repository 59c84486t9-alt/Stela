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
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(
            &include_bytes!("../../../../../../stela-tls/tests/fixtures/ec-ca.der")[..],
        ))
        .unwrap();
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
        }
    }
    fn step(&mut self) {
        let now = Instant::from_micros(self.lan.clock.0.get() as i64);
        self.lan
            .iface
            .poll(now, &mut self.lan.server, &mut self.lan.sockets);
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
    let mut stack = Stack::new(Peer::new(clock.clone()), clock, 7);
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
    let mut stack = Stack::new(Peer::new(clock.clone()), clock, 7);
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
    let mut stack = Stack::new(Peer::new(clock.clone()), clock, 7);
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
    let mut stack = Stack::new(Peer::new(clock.clone()), clock, 7);
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
