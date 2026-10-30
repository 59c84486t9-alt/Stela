use super::*;
use crate::channel::{Channel, ChannelError, Progress};
use crate::provider::{
    EntropySource, PolicyError, ProviderOwner, client_config_with_roots as client_config,
};
use alloc::vec;
use alloc::vec::Vec;
#[cfg(feature = "native-reference-peer")]
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::{NamedGroup, crypto::GetRandomFailed};
use rustls::{
    pki_types::{CertificateDer, ServerName, UnixTime},
    time_provider::TimeProvider,
};
use std::io::{Read, Write};
use zeroize::Zeroizing;
struct OsEntropy;
impl EntropySource for OsEntropy {
    fn fill(&self, out: &mut [u8]) -> Result<(), GetRandomFailed> {
        let mut bytes = Zeroizing::new(vec![0; out.len()]);
        getrandom::getrandom(&mut bytes).map_err(|_| GetRandomFailed)?;
        out.copy_from_slice(&bytes);
        Ok(())
    }
}
#[derive(Debug)]
struct Clock(Option<u64>);
impl TimeProvider for Clock {
    fn current_time(&self) -> Option<UnixTime> {
        self.0
            .map(|seconds| UnixTime::since_unix_epoch(core::time::Duration::from_secs(seconds)))
    }
}
fn now() -> u64 {
    1_793_232_000
} // Controlled UTC fixture: 2026-10-29.
fn owner() -> &'static ProviderOwner {
    static OWNER: std::sync::OnceLock<ProviderOwner> = std::sync::OnceLock::new();
    OWNER.get_or_init(|| ProviderOwner::new(Arc::new(OsEntropy)))
}
fn certs(rsa: bool) -> (&'static [u8], &'static [u8], &'static [u8]) {
    if rsa {
        (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/rsa-ca.der"
            )),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/rsa-leaf.der"
            )),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/rsa-key.der"
            )),
        )
    } else {
        (
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/ec-ca.der"
            )),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/ec-leaf.der"
            )),
            include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/ec-key.der"
            )),
        )
    }
}
#[cfg(feature = "native-reference-peer")]
struct Case<'a> {
    version: &'static rustls::SupportedProtocolVersion,
    group: NamedGroup,
    rsa: bool,
    name: &'a str,
    trusted: bool,
    time: u64,
    interval: Option<(u64, u64)>,
    tamper: bool,
    suite: Option<rustls::CipherSuite>,
}
#[cfg(feature = "native-reference-peer")]
impl Default for Case<'_> {
    fn default() -> Self {
        Self {
            version: &rustls::version::TLS13,
            group: NamedGroup::X25519,
            rsa: false,
            name: "localhost",
            trusted: true,
            time: now(),
            interval: None,
            tamper: false,
            suite: None,
        }
    }
}
#[cfg(feature = "native-reference-peer")]
fn exchange(case: Case<'_>) -> Result<Vec<u8>, ChannelError> {
    let Case {
        version,
        group,
        rsa,
        name,
        trusted,
        time,
        interval,
        tamper,
        suite,
    } = case;
    let (ca, leaf, key) = certs(rsa);
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(if trusted {
            ca
        } else {
            certs(!rsa).0
        }))
        .unwrap();
    let config = if let Some((earliest, latest)) = interval {
        #[derive(Debug)]
        struct Fixed(crate::time::UtcInterval);
        impl crate::time::UtcSource for Fixed {
            fn interval(&self) -> Result<crate::time::UtcInterval, crate::time::TimeError> {
                Ok(self.0)
            }
        }
        crate::time::client_config_with_roots(
            owner(),
            Arc::new(Fixed(
                crate::time::UtcInterval::new(earliest, latest).unwrap(),
            )),
            roots,
        )
        .unwrap()
    } else {
        client_config(owner(), Arc::new(Clock(Some(time))), roots).unwrap()
    };
    let name = ServerName::try_from(alloc::string::String::from(name)).unwrap();
    let mut client = Channel::new(config, name)?;
    let mut provider = rustls::crypto::ring::default_provider();
    if let Some(suite) = suite {
        provider
            .cipher_suites
            .retain(|candidate| candidate.suite() == suite);
    }
    provider
        .kx_groups
        .retain(|candidate| candidate.name() == group);
    let server = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[version])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf)],
            PrivatePkcs8KeyDer::from(key.to_vec()).into(),
        )
        .unwrap();
    let mut server = rustls::ServerConnection::new(Arc::new(server)).unwrap();
    let request = b"GET /source HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    let mut sent = 0;
    let mut received = Vec::new();
    let mut server_request = Vec::new();
    let mut replied = false;
    let response = b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nauthenticated";
    let mut network = alloc::collections::VecDeque::new();
    let mut corrupted = false;
    for _ in 0..20000 {
        match client.advance(&request[sent..])? {
            Progress::Accepted(count) => sent += count,
            Progress::Received(bytes) => received.extend_from_slice(&bytes),
            Progress::Closed => {
                assert_eq!(client.protocol_version(), Some(version.version));
                assert_eq!(server_request, request);
                return Ok(received);
            }
            _ => {}
        }
        if !client.output().is_empty() {
            // Exercise real partial network writes instead of acknowledging a
            // complete Rustls transmit before TCP has accepted all its bytes.
            let length = client.output().len().min(23);
            let mut bytes = &client.output()[..length];
            let read = server.read_tls(&mut bytes).unwrap();
            server.process_new_packets().unwrap();
            client.consume_output(read)?;
        }
        let mut buf = [0; 4096];
        loop {
            match server.reader().read(&mut buf) {
                Ok(0) => break,
                Ok(length) => server_request.extend_from_slice(&buf[..length]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("server read {error:?}"),
            }
        }
        if !replied && server_request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            server.writer().write_all(response).unwrap();
            server.send_close_notify();
            replied = true;
        }
        while server.wants_write() {
            let mut bytes = Vec::new();
            server.write_tls(&mut bytes).unwrap();
            if tamper && replied && !corrupted && !bytes.is_empty() {
                let last = bytes.len() - 1;
                bytes[last] ^= 1;
                corrupted = true;
            }
            network.extend(bytes);
        }
        if !network.is_empty() {
            let count = network.len().min(17).min(client.input_capacity());
            let bytes = network.drain(..count).collect::<Vec<_>>();
            client.feed(&bytes, false)?;
        }
    }
    panic!("bounded TLS interoperability pump did not complete")
}
#[cfg(feature = "native-reference-peer")]
#[test]
fn tls_interoperates_with_ring_for_every_suite() {
    let _serial = SERIAL.lock().unwrap();
    initialize();
    for suite in owner().provider().cipher_suites {
        let version = if suite.version().version == rustls::ProtocolVersion::TLSv1_2 {
            &rustls::version::TLS12
        } else {
            &rustls::version::TLS13
        };
        for group in [NamedGroup::X25519, NamedGroup::secp256r1] {
            for rsa in [false, true] {
                let compatible = match suite.suite() {
                    rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                    | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                    | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => rsa,
                    rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                    | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
                    | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => !rsa,
                    _ => true,
                };
                if !compatible {
                    continue;
                }
                let response = exchange(Case {
                    version,
                    group,
                    rsa,
                    suite: Some(suite.suite()),
                    ..Case::default()
                })
                .unwrap();
                assert_eq!(
                    response,
                    b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nauthenticated"
                );
            }
        }
    }
}
#[cfg(feature = "native-reference-peer")]
#[test]
fn ordinary_verification_rejects_unknown_roots_names_and_invalid_validity() {
    let _serial = SERIAL.lock().unwrap();
    initialize();
    for (name, trusted, time) in [
        ("bad.test", true, now()),
        ("localhost", false, now()),
        ("localhost", true, 1_830_297_600),
        ("localhost", true, 1_735_689_600),
    ] {
        assert!(matches!(
            exchange(Case {
                name,
                trusted,
                time,
                ..Case::default()
            }),
            Err(ChannelError::Tls(rustls::Error::InvalidCertificate(_)))
        ));
    }
    assert!(
        exchange(Case {
            tamper: true,
            ..Case::default()
        })
        .is_err()
    );
}
#[test]
fn absent_clock_or_trust_and_truncated_tcp_are_explicit_failures() {
    let _serial = SERIAL.lock().unwrap();
    initialize();
    let roots = rustls::RootCertStore::empty();
    assert!(matches!(
        client_config(owner(), Arc::new(Clock(Some(now()))), roots),
        Err(PolicyError::TrustUnavailable)
    ));
    assert!(matches!(
        client_config(
            owner(),
            Arc::new(Clock(None)),
            rustls::RootCertStore::empty()
        ),
        Err(PolicyError::TimeUnavailable)
    ));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(certs(false).0)).unwrap();
    let config = client_config(owner(), Arc::new(Clock(Some(now()))), roots).unwrap();
    let mut channel = Channel::new(config, ServerName::try_from("localhost").unwrap()).unwrap();
    loop {
        match channel.advance(&[]) {
            Ok(Progress::NeedWrite) => {
                let length = channel.output().len();
                channel.consume_output(length).unwrap();
            }
            Ok(Progress::NeedRead) => break,
            other => panic!("unexpected handshake state {other:?}"),
        }
    }
    channel.feed(&[], true).unwrap();
    assert!(matches!(channel.advance(&[]), Err(ChannelError::Truncated)));
}

#[test]
#[ignore = "oracle: STELA_TEST_OPENSSL_PYTHON"]
fn independent_openssl_protocol_peer_accepts_every_suite_and_key_exchange() {
    use std::{
        io::{BufRead, BufReader},
        net::TcpStream,
        process::{Child, Command, Stdio},
        time::{Duration, Instant},
    };
    let _serial = SERIAL.lock().unwrap();
    initialize();
    struct Peer(Child);
    impl Drop for Peer {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    for suite in owner().provider().cipher_suites {
        for group in [NamedGroup::X25519, NamedGroup::secp256r1] {
            let version = suite.version();
            let certificate = match suite.suite() {
                rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
                | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
                | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => "rsa",
                _ => "ec",
            };
            let script =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/openssl_peer.py");
            let version_arg = if version.version == rustls::ProtocolVersion::TLSv1_2 {
                "12"
            } else {
                "13"
            };
            let group_arg = if group == NamedGroup::X25519 {
                "x25519"
            } else {
                "p256"
            };
            let mut peer = Peer(
                Command::new(
                    std::env::var_os("STELA_TEST_OPENSSL_PYTHON")
                        .expect("oracle requires explicit Python/OpenSSL executable"),
                )
                .args([
                    script.to_str().unwrap(),
                    version_arg,
                    group_arg,
                    certificate,
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
            );
            let stdout = peer.0.stdout.take().unwrap();
            let mut stdout = BufReader::new(stdout);
            let mut port = std::string::String::new();
            stdout.read_line(&mut port).unwrap();
            let port: u16 = port
                .trim()
                .parse()
                .expect("independent server actual listening port");
            let mut tcp = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).unwrap();
            tcp.set_nonblocking(true).unwrap();
            let mut provider = owner().provider();
            provider.cipher_suites = vec![suite];
            // OpenSSL's single-group server policy selects the exchange.
            // Keep the client's production supported-groups list: TLS1.2 also
            // applies that extension to ECDSA certificate-curve admission, so
            // advertising only X25519 would incorrectly exclude P256 signing.

            let mut roots = rustls::RootCertStore::empty();
            roots
                .add(CertificateDer::from(certs(certificate == "rsa").0))
                .unwrap();
            let config = rustls::ClientConfig::builder_with_details(
                Arc::new(provider),
                Arc::new(Clock(Some(now()))),
            )
            .with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
            let mut client =
                Channel::new(Arc::new(config), ServerName::try_from("localhost").unwrap()).unwrap();
            let request = b"GET /source HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
            let mut sent = 0;
            let mut received = Vec::new();
            let start = Instant::now();
            loop {
                assert!(
                    start.elapsed() < Duration::from_secs(5),
                    "bounded independent TLS peer exchange"
                );
                match client.advance(&request[sent..]).unwrap() {
                    Progress::Accepted(count) => sent += count,
                    Progress::Received(bytes) => received.extend_from_slice(&bytes),
                    Progress::Closed => break,
                    _ => {}
                }
                let mut progress = false;
                if !client.output().is_empty() {
                    let count = client.output().len().min(23);
                    match tcp.write(&client.output()[..count]) {
                        Ok(count) => {
                            assert_ne!(count, 0);
                            client.consume_output(count).unwrap();
                            progress = true
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(error) => panic!("TCP write: {error}"),
                    }
                }
                if client.input_capacity() != 0 {
                    let mut bytes = [0; 17];
                    let count = bytes.len().min(client.input_capacity());
                    match tcp.read(&mut bytes[..count]) {
                        Ok(count) => {
                            client.feed(&bytes[..count], count == 0).unwrap();
                            progress |= count != 0
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(error) => panic!("TCP read: {error}"),
                    }
                }
                if !progress {
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
            assert_eq!(
                received,
                b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\n\r\nauthenticated"
            );
            assert_eq!(client.protocol_version(), Some(version.version));
            let start = Instant::now();
            while peer.0.try_wait().unwrap().is_none() {
                assert!(start.elapsed() < Duration::from_secs(5));
                std::thread::sleep(Duration::from_millis(1));
            }
            assert!(peer.0.wait().unwrap().success());
            let mut record = std::string::String::new();
            stdout.read_to_string(&mut record).unwrap();
            std::println!(
                "independent peer suite={:?} group={group:?} {record}",
                suite.suite()
            );
        }
    }
}

#[test]
fn entropy_refusal_prevents_the_client_hello_or_a_private_key_share() {
    let _serial = SERIAL.lock().unwrap();
    initialize();
    struct Refuse;
    impl EntropySource for Refuse {
        fn fill(&self, _: &mut [u8]) -> Result<(), GetRandomFailed> {
            Err(GetRandomFailed)
        }
    }
    static OWNER: std::sync::OnceLock<ProviderOwner> = std::sync::OnceLock::new();
    let owner = OWNER.get_or_init(|| ProviderOwner::new(Arc::new(Refuse)));
    for group in owner.provider().kx_groups {
        assert!(matches!(
            group.start(),
            Err(rustls::Error::FailedToGetRandomBytes)
        ));
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(certs(false).0)).unwrap();
    let config = client_config(owner, Arc::new(Clock(Some(now()))), roots).unwrap();
    assert!(matches!(
        Channel::new(config, ServerName::try_from("localhost").unwrap()),
        Err(ChannelError::Tls(rustls::Error::FailedToGetRandomBytes))
    ));
}
#[test]
fn loss_of_time_admission_clears_pending_records_and_permanently_refuses_the_channel() {
    use core::sync::atomic::{AtomicBool, Ordering};
    let _serial = SERIAL.lock().unwrap();
    initialize();
    #[derive(Debug)]
    struct Revocable(AtomicBool);
    impl TimeProvider for Revocable {
        fn current_time(&self) -> Option<UnixTime> {
            self.0
                .load(Ordering::Acquire)
                .then(|| UnixTime::since_unix_epoch(core::time::Duration::from_secs(now())))
        }
    }
    let clock = Arc::new(Revocable(AtomicBool::new(true)));
    let mut roots = rustls::RootCertStore::empty();
    roots.add(CertificateDer::from(certs(false).0)).unwrap();
    let config = client_config(owner(), clock.clone(), roots).unwrap();
    let mut channel = Channel::new(config, ServerName::try_from("localhost").unwrap()).unwrap();
    assert!(matches!(channel.advance(&[]), Ok(Progress::NeedWrite)));
    assert!(!channel.output().is_empty());
    clock.0.store(false, Ordering::Release);
    assert!(matches!(
        channel.advance(&[]),
        Err(ChannelError::TimeUnavailable)
    ));
    assert!(channel.output().is_empty());
    clock.0.store(true, Ordering::Release);
    assert!(matches!(
        channel.advance(&[]),
        Err(ChannelError::TimeUnavailable)
    ));
}

#[cfg(feature = "native-reference-peer")]
#[test]
fn utc_interval_verification_survives_real_tls12_and_tls13_handshakes() {
    let _serial = SERIAL.lock().unwrap();
    initialize();
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        for rsa in [false, true] {
            assert!(
                !exchange(Case {
                    version,
                    rsa,
                    interval: Some((now() - 86_400, now() + 86_400)),
                    ..Case::default()
                })
                .unwrap()
                .is_empty()
            );
            for interval in [(1_735_689_600, now()), (now(), 1_830_297_600)] {
                assert!(matches!(
                    exchange(Case {
                        version,
                        rsa,
                        interval: Some(interval),
                        ..Case::default()
                    }),
                    Err(ChannelError::Tls(rustls::Error::InvalidCertificate(_)))
                ));
            }
        }
    }
}
