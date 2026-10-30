//! The station drives the managed link from scan to an open port against
//! the device model and a software authenticator.
use super::*;
use crate::wifi::mediatek::bootstrap::client::policy::tests::{
    passive_country, setup_passive_five,
};
use crate::wifi::{
    connection::security::Security,
    mediatek::{bootstrap::client::modern::tests::pmf_controls::inputs_akm, station::Station},
    network::{Network, Secret},
    sae::{Derivation, Exchange},
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
    let security = Security::select(&bss.elements, true).unwrap();
    let mut ap = Authenticator::between(security.suites(), pmk, AP, LOCAL, security.element(None));
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

/// The station's last transmitted SAE frame: its transaction, status and
/// data.
fn sent_sae(model: &Model) -> (u16, u16, Vec<u8>) {
    let frame = finish_tx(model).pop().unwrap();
    assert_eq!(frame[..2], [0xb0, 0]);
    assert_eq!(frame[24..26], [3, 0]);
    let field = |at: usize| u16::from_le_bytes([frame[at], frame[at + 1]]);
    (field(26), field(28), frame[30..].to_vec())
}

/// An SAE frame from the AP.
fn sae_from_ap(model: &Model, frame: &crate::wifi::sae::Frame) {
    let mut body = vec![3, 0];
    body.extend_from_slice(&frame.transaction.to_le_bytes());
    body.extend_from_slice(&frame.status.to_le_bytes());
    body.extend_from_slice(&frame.data);
    incoming(model, &response(0xb0, &body), None, false);
}

#[test]
fn a_passphrase_network_offering_sae_authenticates_by_it_before_the_handshake() {
    let (client, model) = setup_modern();
    let (_, bss) = inputs_akm(&client, 8);
    let client = ManagedClient::new(client, country(), Environment::Indoor).unwrap();
    let link = ManagedLink::new(
        client,
        Provider(
            Arc::new(AtomicUsize::new(0)),
            core::sync::atomic::AtomicBool::new(false),
        ),
    )
    .unwrap();
    let password = b"correct horse battery";
    let network = Network {
        ssid: b"x".to_vec(),
        secret: Secret::parse(password).unwrap(),
        country: None,
    };
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
    assert!(!station.carrier());
    let mut body = vec![0; 8];
    body.extend_from_slice(&100u16.to_le_bytes());
    body.extend_from_slice(&0x11u16.to_le_bytes());
    body.extend_from_slice(&bss.elements);
    let mut beacon = response(0x80, &body);
    beacon[4..10].copy_from_slice(&Mac::BROADCAST.0);
    incoming(&model, &beacon, None, false);
    assert!(!station.carrier());
    // The scan ends: the station commits instead of open-system
    // authentication.
    done(&model);
    assert!(!station.carrier());
    let (transaction, status, commit) = sent_sae(&model);
    assert_eq!((transaction, status), (1, 0));
    let mut random = 7u8;
    let mut next = || {
        random = random.wrapping_add(1);
        [random; 32]
    };
    let mut sae = Exchange::new(
        Derivation::HuntingAndPecking,
        password,
        None,
        None,
        AP,
        LOCAL,
        &mut next,
    )
    .unwrap();
    let confirm = sae.receive(1, 0, &commit).unwrap().unwrap();
    station.carrier();
    // The AP's commit draws the station's confirm; its confirm then
    // authenticates the station, which associates.
    sae_from_ap(&model, &sae.commit());
    assert!(!station.carrier());
    let (transaction, status, own_confirm) = sent_sae(&model);
    assert_eq!((transaction, status), (2, 0));
    assert_eq!(sae.receive(2, 0, &own_confirm).unwrap(), None);
    assert!(sae.accepted());
    station.carrier();
    sae_from_ap(&model, &confirm);
    assert!(!station.carrier());
    let request = finish_tx(&model).pop().unwrap();
    assert_eq!(request[..2], [0, 0]);
    let pmkid = sae.pmkid().unwrap();
    let security = Security::select(&bss.elements, true).unwrap();
    let own_rsn = security.element(Some(&pmkid));
    assert!(request.windows(own_rsn.len()).any(|w| w == own_rsn));
    station.carrier();
    // An AP's association response carries no RSN element outside FT.
    let mut association = vec![0x11, 0, 0, 0, 1, 0xc0];
    let mut rest = &bss.elements[..];
    while let [id, length, tail @ ..] = rest {
        let (body, next) = tail.split_at(usize::from(*length));
        if *id != 48 {
            association.extend_from_slice(&[*id, *length]);
            association.extend_from_slice(body);
        }
        rest = next;
    }
    incoming(&model, &response(0x10, &association), None, false);
    assert!(!station.carrier());
    // The 4-way handshake proves the SAE PMK and delivers the IGTK.
    let mut ap = Authenticator::between(security.suites(), sae.pmk().unwrap(), AP, LOCAL, own_rsn);
    eapol(&model, &ap.message_1());
    assert!(!station.carrier());
    ap.message_2(&sent_eapol(&model));
    let rsn = crate::wifi::connection::find(&bss.elements, 48).unwrap();
    let mut whole = vec![48, rsn.len() as u8];
    whole.extend_from_slice(rsn);
    let mut igtk = vec![0xdd, 4 + 8 + 16, 0x00, 0x0f, 0xac, 9, 4, 0];
    igtk.extend_from_slice(&[0; 6]);
    igtk.extend_from_slice(&[0x77; 16]);
    eapol(&model, &ap.message_3_with(&whole, &igtk));
    assert!(!station.carrier());
    ap.signed_reply(&sent_eapol(&model), 0x308);
    // Once message 4 drained, the IGTK installs and the port opens.
    assert!(station.carrier());
}

#[test]
fn a_protected_psk_association_opens_its_port_once_the_igtk_installs() {
    let (client, model) = setup_modern();
    let (_, bss) = inputs_akm(&client, 2);
    let client = ManagedClient::new(client, country(), Environment::Indoor).unwrap();
    let link = ManagedLink::new(
        client,
        Provider(
            Arc::new(AtomicUsize::new(0)),
            core::sync::atomic::AtomicBool::new(false),
        ),
    )
    .unwrap();
    let network = Network {
        ssid: b"x".to_vec(),
        secret: Secret::parse(b"correct horse battery").unwrap(),
        country: None,
    };
    let pmk = network.secret.pmk(&network.ssid);
    let security = Security::select(&bss.elements, true).unwrap();
    assert!(security.management.is_some());
    let mut ap = Authenticator::between(security.suites(), pmk, AP, LOCAL, security.element(None));
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
    assert!(!station.carrier());
    let mut body = vec![0; 8];
    body.extend_from_slice(&100u16.to_le_bytes());
    body.extend_from_slice(&0x11u16.to_le_bytes());
    body.extend_from_slice(&bss.elements);
    let mut beacon = response(0x80, &body);
    beacon[4..10].copy_from_slice(&Mac::BROADCAST.0);
    incoming(&model, &beacon, None, false);
    assert!(!station.carrier());
    done(&model);
    assert!(!station.carrier());
    assert_eq!(finish_tx(&model)[0][..2], [0xb0, 0]);
    station.carrier();
    incoming(&model, &response(0xb0, &[0, 0, 2, 0, 0, 0]), None, false);
    station.carrier();
    assert_eq!(finish_tx(&model)[0][..2], [0, 0]);
    station.carrier();
    // An AP's association response carries no RSN element outside FT.
    let mut association = vec![0x11, 0, 0, 0, 1, 0xc0];
    let mut rest = &bss.elements[..];
    while let [id, length, tail @ ..] = rest {
        let (body, next) = tail.split_at(usize::from(*length));
        if *id != 48 {
            association.extend_from_slice(&[*id, *length]);
            association.extend_from_slice(body);
        }
        rest = next;
    }
    incoming(&model, &response(0x10, &association), None, false);
    assert!(!station.carrier());
    eapol(&model, &ap.message_1());
    assert!(!station.carrier());
    ap.message_2(&sent_eapol(&model));
    let rsn = crate::wifi::connection::find(&bss.elements, 48).unwrap();
    let mut whole = vec![48, rsn.len() as u8];
    whole.extend_from_slice(rsn);
    let mut igtk = vec![0xdd, 4 + 8 + 16, 0x00, 0x0f, 0xac, 9, 4, 0];
    igtk.extend_from_slice(&[0; 6]);
    igtk.extend_from_slice(&[0x77; 16]);
    eapol(&model, &ap.message_3_with(&whole, &igtk));
    // Message 4 is queued ahead of the IGTK, which installs once it drained;
    // only then does the port open.
    assert!(!station.carrier());
    ap.signed_reply(&sent_eapol(&model), 0x308);
    assert!(station.carrier());
}

#[test]
fn a_scan_listens_where_its_channels_bar_probes_and_finds_the_ap_there() {
    let (client, model) = setup_passive_five();
    let (_, bss) = modern_inputs(&client);
    let client = ManagedClient::new(client, passive_country(), Environment::Indoor).unwrap();
    let link = ManagedLink::new(
        client,
        Provider(Arc::new(AtomicUsize::new(0)), Default::default()),
    )
    .unwrap();
    assert!(link.probes(Channel {
        band: Band::Ghz2,
        number: 1,
        frequency_mhz: 2412,
    }));
    assert!(!link.probes(CHANNEL));
    let network = Network {
        ssid: b"x".to_vec(),
        secret: Secret::parse(b"correct horse battery").unwrap(),
        country: None,
    };
    let mut station = Station::new(
        link,
        profile().interface,
        passive_country(),
        network,
        Arc::new(Fixed),
        crate::Clock {
            ticks_per_microsecond: 1,
        },
    );
    // The first part probes 2.4 GHz and finds nothing.
    assert!(!station.carrier());
    done(&model);
    assert!(!station.carrier());
    // The second listens on 5 GHz, where the AP beacons; both parts' BSSes
    // stay known for the choice, which authenticates with the AP.
    let mut body = vec![0; 8];
    body.extend_from_slice(&100u16.to_le_bytes());
    body.extend_from_slice(&bss.capabilities.to_le_bytes());
    body.extend_from_slice(&bss.elements);
    let mut beacon = response(0x80, &body);
    beacon[4..10].copy_from_slice(&Mac::BROADCAST.0);
    incoming(&model, &beacon, None, false);
    assert!(!station.carrier());
    done(&model);
    assert!(!station.carrier());
    assert_eq!(finish_tx(&model)[0][..2], [0xb0, 0]);
}
