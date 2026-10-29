//! Reused real peer/cache controls for interval-specific resumption policy.
use super::*;
use rustls::{HandshakeKind, ServerConfig, ServerConnection, pki_types::PrivatePkcs8KeyDer};
use std::io::{Cursor, Read, Write};

fn exchange(config: Arc<ClientConfig>, server: Arc<ServerConfig>) -> HandshakeKind {
    let mut client =
        rustls::ClientConnection::new(config, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut server = ServerConnection::new(server).unwrap();
    let request = b"request";
    let response = b"response";
    let mut sent = false;
    let mut received = Vec::new();
    let mut request_seen = Vec::new();
    let mut replied = false;
    for _ in 0..1000 {
        if !client.is_handshaking() && !sent {
            client.writer().write_all(request).unwrap();
            sent = true;
        }
        while client.wants_write() {
            let mut bytes = Vec::new();
            client.write_tls(&mut bytes).unwrap();
            server.read_tls(&mut Cursor::new(bytes)).unwrap();
            server.process_new_packets().unwrap();
        }
        let mut bytes = [0; 64];
        loop {
            match server.reader().read(&mut bytes) {
                Ok(0) => break,
                Ok(count) => request_seen.extend_from_slice(&bytes[..count]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("reference server read {error:?}"),
            }
        }
        if !replied && request_seen == request {
            server.writer().write_all(response).unwrap();
            server.send_close_notify();
            replied = true;
        }
        while server.wants_write() {
            let mut bytes = Vec::new();
            server.write_tls(&mut bytes).unwrap();
            client.read_tls(&mut Cursor::new(bytes)).unwrap();
            client.process_new_packets().unwrap();
        }
        loop {
            match client.reader().read(&mut bytes) {
                Ok(0) => {
                    assert_eq!(received, response);
                    return server.handshake_kind().unwrap();
                }
                Ok(count) => received.extend_from_slice(&bytes[..count]),
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) => panic!("reference client read {error:?}"),
            }
        }
    }
    panic!("bounded real peer handshake did not finish")
}
fn server(version: &'static rustls::SupportedProtocolVersion) -> Arc<ServerConfig> {
    let mut config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                alloc::vec![CertificateDer::from(
                    &include_bytes!("../../../tests/fixtures/ec-leaf.der")[..]
                )],
                PrivatePkcs8KeyDer::from(&include_bytes!("../../../tests/fixtures/ec-key.der")[..])
                    .into(),
            )
            .unwrap();
    config.ticketer = rustls::crypto::ring::Ticketer::new().unwrap();
    Arc::new(config)
}
#[test]
fn repeated_connections_require_fresh_full_handshakes_while_the_control_resumes() {
    let _serial = crate::allocator::observation::SERIAL.lock().unwrap();
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let mut config = Arc::try_unwrap(
            client_config_with_roots(owner(), source(1_793_232_000, 1_793_232_001), roots())
                .unwrap(),
        )
        .unwrap();
        // A real cache-enabled control establishes that the reference server
        // and record pump offer and process usable resumptions.
        config.resumption = rustls::client::Resumption::default();
        let control = Arc::new(config);
        let peer = server(version);
        assert_eq!(exchange(control.clone(), peer.clone()), HandshakeKind::Full);
        assert_eq!(
            exchange(control, peer),
            HandshakeKind::Resumed,
            "{:?}",
            version.version
        );
        let config =
            client_config_with_roots(owner(), source(1_793_232_000, 1_793_232_001), roots())
                .unwrap();
        let peer = server(version);
        assert_eq!(exchange(config.clone(), peer.clone()), HandshakeKind::Full);
        assert_eq!(exchange(config, peer), HandshakeKind::Full);
    }
}
