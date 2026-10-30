//! The station drives the managed link from scan to an open port against
//! the device model and a software authenticator.
use super::*;
use crate::wifi::{
    connection::security::Security,
    mediatek::station::Station,
    network::{Network, Secret},
    supplicant::tests::Authenticator,
};
use stela_driver_base::entropy::{Entropy, EntropyError};

struct Fixed;
impl Entropy for Fixed {
    fn fill(&self, output: &mut [u8]) -> Result<(), EntropyError> {
        output.fill(0x5c);
        Ok(())
    }
}

/// An EAPOL frame from the AP, as the device receives it in the clear.
fn eapol(model: &Model, payload: &[u8]) {
    let mut bytes = data(false);
    bytes.truncate(24);
    bytes.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e]);
    bytes.extend_from_slice(payload);
    bytes[1] &= !0x40;
    let mut raw = incoming_bytes(&bytes, None, false);
    raw[4] = 1;
    device_receive(&model.queues[&0xd4520], &raw, true, 0);
}

/// The EAPOL payload of the station's last transmitted data frame.
fn sent_eapol(model: &Model) -> Vec<u8> {
    let frame = finish_tx(model).pop().unwrap();
    let at = frame
        .windows(8)
        .position(|w| w == [0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e])
        .unwrap();
    frame[at + 8..].to_vec()
}

#[test]
fn the_station_scans_joins_and_opens_the_port_after_the_4_way_handshake() {
    let (client, model) = setup_modern();
    let (_, bss) = modern_inputs(&client);
    let client = ManagedClient::new(client, country(), Environment::Indoor).unwrap();
    let link = ManagedLink::new(
        client,
        Provider(Arc::new(AtomicUsize::new(0)), Default::default()),
    )
    .unwrap();
    let network = Network {
        ssid: b"x".to_vec(),
        secret: Secret::parse(b"correct horse battery").unwrap(),
        country: None,
    };
    let pmk = network.secret.pmk(&network.ssid);
    let security = Security::select(&bss.elements).unwrap();
    let mut ap = Authenticator::between(security.suites(), pmk, AP, LOCAL, security.element());
    let mut station = Station::new(
        link,
        profile().interface,
        country(),
        network,
        Arc::new(Fixed),
        crate::Clock {
            ticks_per_microsecond: 1,
        },
    );
    // The first poll scans; the AP's beacon answers it.
    assert!(!station.carrier());
    let mut body = vec![0; 8];
    body.extend_from_slice(&100u16.to_le_bytes());
    body.extend_from_slice(&bss.capabilities.to_le_bytes());
    body.extend_from_slice(&bss.elements);
    let mut beacon = response(0x80, &body);
    beacon[4..10].copy_from_slice(&Mac::BROADCAST.0);
    incoming(&model, &beacon, None, false);
    assert!(!station.carrier());
    // The scan ends: the station authenticates, then associates.
    done(&model);
    assert!(!station.carrier());
    assert_eq!(finish_tx(&model)[0][..2], [0xb0, 0]);
    station.carrier();
    incoming(&model, &response(0xb0, &[0, 0, 2, 0, 0, 0]), None, false);
    station.carrier();
    assert_eq!(finish_tx(&model)[0][..2], [0, 0]);
    station.carrier();
    let mut association = vec![0x11, 0, 0, 0, 1, 0xc0];
    association.extend_from_slice(&bss.elements);
    incoming(&model, &response(0x10, &association), None, false);
    assert!(!station.carrier());
    // Messages 1 and 2.
    eapol(&model, &ap.message_1());
    assert!(!station.carrier());
    ap.message_2(&sent_eapol(&model));
    // Message 3 installs the keys and opens the port after message 4.
    let rsn = crate::wifi::connection::find(&bss.elements, 48).unwrap();
    let mut whole = vec![48, rsn.len() as u8];
    whole.extend_from_slice(rsn);
    eapol(&model, &ap.message_3(&whole));
    assert!(station.carrier());
    // Message 4: pairwise, MIC and secure.
    ap.signed_reply(&sent_eapol(&model), 0x308);
}
