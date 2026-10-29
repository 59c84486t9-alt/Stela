use super::*;

#[test]
fn data_frames_classify_like_cfg80211_classify8021d() {
    let frame = |ethertype: u16, body: &[u8]| {
        let mut frame = vec![0; 12];
        frame.extend_from_slice(&ethertype.to_be_bytes());
        frame.extend_from_slice(body);
        frame
    };
    let mut ipv4 = [0u8; 20];
    ipv4[1] = 46 << 2; // EF, which RFC 8325 maps to 6.
    assert_eq!(classify8021d(&frame(0x0800, &ipv4), None), 6);
    assert_eq!(classify8021d(&frame(0x0800, &ipv4[..19]), None), 0);
    let mut ipv6 = [0u8; 40];
    ipv6[0] = 0x60 | (56 << 2) >> 4; // CS7
    assert_eq!(classify8021d(&frame(0x86dd, &ipv6), None), 7);
    assert_eq!(classify8021d(&frame(0x8847, &[0, 0, 0b1010, 0]), None), 5);
    assert_eq!(classify8021d(&frame(0x8917, &[]), None), 7);
    assert_eq!(classify8021d(&frame(0x0806, &[0; 28]), None), 0);
    let dscp = |value: u8| {
        let mut ipv4 = [0u8; 20];
        ipv4[1] = value << 2;
        frame(0x0800, &ipv4)
    };
    let rfc8325 = [10, 16, 18, 24, 30, 40, 44, 48].map(|d| classify8021d(&dscp(d), None));
    assert_eq!(rfc8325, [0, 0, 3, 4, 4, 5, 6, 7]);
    // A tagged frame's PCP, or its inner protocol when the PCP is zero.
    let mut tagged = frame(0x8100, &[0x60, 0, 0x08, 0]);
    tagged.extend_from_slice(&ipv4);
    assert_eq!(classify8021d(&tagged, None), 3);
    tagged[14] = 0;
    assert_eq!(classify8021d(&tagged, None), 6);
    // A QoS Map's exception, then its ranges, then RFC 8325.
    let mut set = vec![46, 5];
    for up in 0..8u8 {
        set.extend_from_slice(&[up * 8, up * 8 + 3]);
    }
    let map = QosMap::parse(&set).unwrap();
    let mapped = [46, 18, 7].map(|d| classify8021d(&dscp(d), Some(&map)));
    assert_eq!(mapped, [5, 2, 0]);
    assert!(QosMap::parse(&set[1..]).is_err());
    set[1] = 8;
    assert!(QosMap::parse(&set).is_err());
}

#[test]
#[ignore = "oracle: STELA_WIFI_AMSDU_ORACLE"]
fn full_source_amsdu_station_conversion_matches_all_bytes() {
    extern crate std;
    let path = std::env::var_os("STELA_WIFI_AMSDU_ORACLE").expect("fresh unchanged Linux trace");
    let trace = std::fs::read(path).unwrap();
    let mut bytes = trace.as_slice();
    fn take_u32(bytes: &mut &[u8]) -> usize {
        let value = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        *bytes = &bytes[4..];
        value
    }
    for case in 0..512 {
        let length = take_u32(&mut bytes);
        let input = &bytes[..length];
        bytes = &bytes[length..];
        let count = take_u32(&mut bytes);
        let mut expected = Vec::new();
        for _ in 0..count {
            let length = take_u32(&mut bytes);
            expected.push(bytes[..length].to_vec());
            bytes = &bytes[length..];
        }
        match subframes(input, Mac([2, 1, 2, 3, 4, 5]), false) {
            Ok(actual) => assert_eq!(actual, expected, "full source case{case}"),
            Err(_) => assert!(expected.is_empty(), "source forwarded refused case{case}"),
        }
    }
    assert!(bytes.is_empty());
}
use crate::net::wifi::{
    Band, RadioStatus, RawRate,
    security::{Cipher, InstallOutcome, Integrity, ReplaySeed, SecurityStatus, TransmitSeed},
    station::{Join, wire::AssociationRequest},
};

const LOCAL: Mac = Mac([2, 1, 2, 3, 4, 5]);
const AP: Mac = Mac([2, 6, 7, 8, 9, 10]);
const SOURCE: Mac = Mac([4, 1, 2, 3, 4, 5]);
struct Policy(bool);
impl RegulatoryPolicy for Policy {
    fn allow_management_tx(&mut self, _: Channel) -> bool {
        self.0
    }
    fn allow_data_tx(&mut self, _: Channel) -> bool {
        self.0
    }
}

fn key(slot: u16, scope: KeyScope, seed: TransmitSeed) -> KeySlot {
    // Pure model has no physical slots, DMA, or deferred users.
    // SAFETY: this test owns the key slot number alone.
    let mut result = unsafe { KeySlot::new(slot).unwrap() };
    let index = if matches!(scope, KeyScope::Pairwise(_)) {
        0
    } else {
        2
    };
    let ticket = result
        .begin_install(
            index,
            Cipher::Ccmp128,
            &[slot as u8; 16],
            ReplaySeed::ZERO,
            scope,
            seed,
        )
        .unwrap();
    result
        .complete_install(ticket, InstallOutcome::Accepted)
        .unwrap();
    result
}

fn station(policy: PortPolicy, host: bool) -> (Station, Vec<KeySlot>) {
    // The full association/ACK transition is covered by parent tests;
    // these fixtures start at its established input boundary.
    let mut elements = vec![0, 1, b'x', 1, 1, 0x8c];
    if policy == PortPolicy::Controlled {
        elements.extend_from_slice(&[
            48, 18, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2,
        ]);
    }
    let mut station = Station::new(LOCAL).unwrap();
    station.phase = Phase::Associated;
    station.epoch = 42;
    station.join = Some(Join {
        bssid: AP,
        channel: Channel {
            band: Band::Ghz5,
            number: 36,
            frequency_mhz: 5180,
        },
        policy,
        request: AssociationRequest::new(
            if policy == PortPolicy::Open { 1 } else { 0x11 },
            10,
            elements,
        )
        .unwrap(),
    });
    let seed = if host {
        TransmitSeed::host(PacketNumber::new(0).unwrap())
    } else {
        TransmitSeed::FIRMWARE_FRESH
    };
    let keys = vec![
        key(1, KeyScope::Pairwise(AP), seed),
        key(2, KeyScope::Group(AP), TransmitSeed::RECEIVE_ONLY),
    ];
    (station, keys)
}

fn packet(destination: Mac, protocol: u16, security: SecurityStatus) -> Mpdu {
    let mut bytes = vec![0; 24];
    bytes[..2].copy_from_slice(
        &(if security.key.is_some() {
            0x4208_u16
        } else {
            0x0208_u16
        })
        .to_le_bytes(),
    );
    bytes[4..10].copy_from_slice(&destination.0);
    bytes[10..16].copy_from_slice(&AP.0);
    bytes[16..22].copy_from_slice(&SOURCE.0);
    bytes.extend_from_slice(&RFC1042);
    bytes.extend_from_slice(&protocol.to_be_bytes());
    bytes.extend_from_slice(&[1, 2, 3]);
    Mpdu::new(
        bytes,
        RadioStatus {
            band: Band::Ghz5,
            channel: 36,
            frequency_mhz: 5180,
            signal_dbm: Some(-40),
            chain_signal_dbm: [None; 4],
            rate: RawRate {
                layout: 1,
                words: [0; 4],
            },
            rx_rate: None,
            tsf: None,
        },
        security,
    )
    .unwrap()
}

fn protected(key: KeyIdentity, pn: u64) -> SecurityStatus {
    SecurityStatus {
        key: Some(key),
        pn: PacketNumber::new(pn),
        decrypted: true,
        integrity: Integrity::Verified,
        iv_stripped: true,
        mic_stripped: true,
        ..SecurityStatus::default()
    }
}

fn eth(destination: Mac, protocol: u16) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&destination.0);
    bytes.extend_from_slice(&LOCAL.0);
    bytes.extend_from_slice(&protocol.to_be_bytes());
    bytes.extend_from_slice(&[1, 2, 3]);
    bytes
}

#[test]
fn separately_boxed_keys_keep_original_replay_and_publication_guards() {
    use alloc::boxed::Box;
    let (mut station, mut original) = station(PortPolicy::Controlled, false);
    let mut gtk = Box::new(original.pop().unwrap());
    let mut ptk = Box::new(original.pop().unwrap());
    let mut unrelated = Box::new(key(9, KeyScope::Group(AP), TransmitSeed::RECEIVE_ONLY));
    let ptk_id = ptk.installed().unwrap();
    let gtk_id = gtk.installed().unwrap();
    station.authorize_port(42, &ptk, &gtk).unwrap();
    let plan = station
        .prepare_msdu_refs(
            42,
            &eth(SOURCE, 0x0800),
            TxClass::Data,
            SequenceOwner::Device,
            &mut [&mut *gtk, &mut *ptk, &mut *unrelated],
            &mut Policy(true),
        )
        .unwrap();
    assert_eq!(plan.protection(), Protection::Firmware { key: ptk_id });
    station
        .validate_tx_plan_refs(&plan, &[&*unrelated, &*ptk, &*gtk], &mut Policy(true))
        .unwrap();
    assert_eq!(
        station.validate_tx_plan_refs(&plan, &[&*ptk], &mut Policy(true)),
        Err(Error::ClosedPort)
    );
    assert_eq!(
        station.validate_tx_plan_refs(&plan, &[&*ptk, &*gtk], &mut Policy(false)),
        Err(Error::Regulatory)
    );
    let pair = packet(LOCAL, 0x0800, protected(ptk_id, 7));
    assert!(matches!(
        station.receive_msdu_refs(41, &pair, &mut [&mut *ptk, &mut *gtk]),
        Err(Error::Stale)
    ));
    assert!(matches!(
        station.receive_msdu_refs(42, &pair, &mut [&mut *gtk, &mut *unrelated, &mut *ptk]),
        Ok(Ingress::Data(_))
    ));
    // The same original owner observes replay even outside the borrowed array.
    assert!(matches!(ptk.authorize(&pair), Err(security::Error::Replay)));
    let group = packet(Mac::BROADCAST, 0x0800, protected(gtk_id, 7));
    assert!(matches!(
        station.receive_msdu_refs(42, &group, &mut [&mut *ptk, &mut *gtk]),
        Ok(Ingress::Data(_))
    ));
    assert!(matches!(
        gtk.authorize(&group),
        Err(security::Error::Replay)
    ));
    // Unrelated same-scope slots do not acquire another slot's replay state.
    let foreign = packet(
        Mac::BROADCAST,
        0x0800,
        protected(unrelated.installed().unwrap(), 7),
    );
    assert!(unrelated.authorize(&foreign).is_ok());
    ptk.invalidate();
    assert_eq!(
        station.validate_tx_plan_refs(&plan, &[&*ptk, &*gtk], &mut Policy(true)),
        Err(Error::ClosedPort)
    );
    assert!(matches!(
        station.receive_msdu_refs(42, &pair, &mut [&mut *ptk, &mut *gtk]),
        Err(Error::WrongKey)
    ));
}

#[test]
fn open_data_bridge_uses_real_station_addresses_and_rfc1042() {
    let (station, mut keys) = station(PortPolicy::Open, false);
    let Ingress::Data(bytes) = station
        .receive_msdu(
            42,
            &packet(LOCAL, 0x0800, SecurityStatus::default()),
            &mut keys,
        )
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(&bytes[..6], LOCAL.0);
    assert_eq!(&bytes[6..12], SOURCE.0);
    assert_eq!(&bytes[12..], &[8, 0, 1, 2, 3]);
}

#[test]
fn closed_port_routes_only_eapol_to_the_real_authentication_owner() {
    let (station, mut keys) = station(PortPolicy::Controlled, false);
    assert!(matches!(
        station.receive_msdu(
            42,
            &packet(LOCAL, 0x0800, SecurityStatus::default()),
            &mut keys
        ),
        Err(Error::ClosedPort)
    ));
    for destination in [LOCAL, PAE_GROUP] {
        assert!(matches!(
            station.receive_msdu(
                42,
                &packet(destination, EAPOL, SecurityStatus::default()),
                &mut keys
            ),
            Ok(Ingress::ControlPort {
                encrypted: false,
                key: None,
                ..
            })
        ));
    }
    assert!(matches!(
        station.receive_msdu(
            42,
            &packet(Mac::BROADCAST, EAPOL, SecurityStatus::default()),
            &mut keys
        ),
        Err(Error::WrongPeer)
    ));
}

#[test]
fn authenticated_key_does_not_implicitly_authorize_data_but_allows_eapol() {
    let (mut station, mut keys) = station(PortPolicy::Controlled, false);
    let ptk = keys[0].installed().unwrap();
    assert!(matches!(
        station.receive_msdu(42, &packet(LOCAL, EAPOL, protected(ptk, 1)), &mut keys),
        Ok(Ingress::ControlPort {
            encrypted: true,
            key: Some(_),
            ..
        })
    ));
    assert!(matches!(
        station.receive_msdu(42, &packet(LOCAL, 0x0800, protected(ptk, 2)), &mut keys),
        Err(Error::ClosedPort)
    ));
    station.authorize_port(42, &keys[0], &keys[1]).unwrap();
    assert!(matches!(
        station.receive_msdu(42, &packet(LOCAL, 0x0800, protected(ptk, 3)), &mut keys),
        Ok(Ingress::Data(_))
    ));
    assert!(matches!(
        station.receive_msdu(42, &packet(LOCAL, 0x0800, protected(ptk, 3)), &mut keys),
        Err(Error::Crypto(security::Error::Replay))
    ));
    assert!(matches!(
        station.receive_msdu(
            42,
            &packet(LOCAL, 0x0800, SecurityStatus::default()),
            &mut keys
        ),
        Err(Error::Unencrypted)
    ));
}

#[test]
fn key_scope_and_generation_are_not_interchangeable() {
    let (mut station, mut keys) = station(PortPolicy::Controlled, false);
    let ptk = keys[0].installed().unwrap();
    let gtk = keys[1].installed().unwrap();
    station.authorize_port(42, &keys[0], &keys[1]).unwrap();
    assert!(matches!(
        station.receive_msdu(
            42,
            &packet(Mac::BROADCAST, 0x0800, protected(ptk, 1)),
            &mut keys
        ),
        Err(Error::WrongKey)
    ));
    assert!(matches!(
        station.receive_msdu(
            42,
            &packet(Mac::BROADCAST, 0x0800, protected(gtk, 1)),
            &mut keys
        ),
        Ok(Ingress::Data(_))
    ));
    keys[0].invalidate();
    assert!(matches!(
        station.receive_msdu(42, &packet(LOCAL, 0x0800, protected(ptk, 2)), &mut keys),
        Err(Error::WrongKey)
    ));
}

#[test]
fn stale_channel_integrity_and_aggregate_failures_do_not_advance_replay() {
    let (mut station, mut keys) = station(PortPolicy::Controlled, false);
    station.authorize_port(42, &keys[0], &keys[1]).unwrap();
    let key = keys[0].installed().unwrap();
    let packet = packet(LOCAL, 0x0800, protected(key, 1));
    assert!(matches!(
        station.receive_msdu(41, &packet, &mut keys),
        Err(Error::Stale)
    ));
    let mut altered = packet.clone();
    altered.radio.channel = 40;
    assert!(matches!(
        station.receive_msdu(42, &altered, &mut keys),
        Err(Error::WrongChannel)
    ));
    altered = packet.clone();
    altered.fcs_error = true;
    assert!(matches!(
        station.receive_msdu(42, &altered, &mut keys),
        Err(Error::Integrity)
    ));
    altered = packet.clone();
    altered.aggregation.ampdu = Some(1);
    assert!(matches!(
        station.receive_msdu(42, &altered, &mut keys),
        Err(Error::Unsupported(_))
    ));
    assert!(matches!(
        station.receive_msdu(42, &packet, &mut keys),
        Ok(Ingress::Data(_))
    ));
}

#[test]
fn host_iv_plan_reserves_pn_and_keeps_cipher_mic_as_explicit_hardware_work() {
    let (mut station, mut keys) = station(PortPolicy::Controlled, true);
    station.authorize_port(42, &keys[0], &keys[1]).unwrap();
    let key = keys[0].installed().unwrap();
    let first = station
        .prepare_msdu(
            42,
            &eth(SOURCE, 0x0800),
            TxClass::Data,
            SequenceOwner::Host,
            &mut keys,
            &mut Policy(true),
        )
        .unwrap();
    assert_eq!(
        first.protection(),
        Protection::HostIv {
            key,
            pn: PacketNumber::new(1).unwrap()
        }
    );
    assert_eq!(
        &first.plaintext_mpdu()[24..32],
        &[1, 0, 0, 0x20, 0, 0, 0, 0]
    );
    assert_eq!(
        &first.plaintext_mpdu()[32..],
        &[0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 1, 2, 3]
    );
    let next = station
        .prepare_msdu(
            42,
            &eth(SOURCE, 0x0800),
            TxClass::Data,
            SequenceOwner::Host,
            &mut keys,
            &mut Policy(true),
        )
        .unwrap();
    assert!(matches!(next.protection(),Protection::HostIv{pn,..} if pn.value()==2));
}

#[test]
fn firmware_crypto_has_no_host_iv_and_eapol_policy_cannot_leak_data() {
    let (mut station, mut keys) = station(PortPolicy::Controlled, false);
    let key = keys[0].installed().unwrap();
    assert!(matches!(
        station.prepare_msdu(
            42,
            &eth(SOURCE, 0x0800),
            TxClass::Data,
            SequenceOwner::Host,
            &mut keys,
            &mut Policy(true)
        ),
        Err(Error::ClosedPort)
    ));
    let eapol = station
        .prepare_msdu(
            42,
            &eth(AP, EAPOL),
            TxClass::ControlPortProtected(key),
            SequenceOwner::Host,
            &mut keys,
            &mut Policy(true),
        )
        .unwrap();
    assert_eq!(eapol.protection(), Protection::Firmware { key });
    assert!(eapol.control_port());
    assert_eq!(
        &eapol.plaintext_mpdu()[24..],
        &[0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e, 1, 2, 3]
    );
    assert!(matches!(
        station.prepare_msdu(
            42,
            &eth(AP, 0x0800),
            TxClass::ControlPortPlaintext,
            SequenceOwner::Host,
            &mut keys,
            &mut Policy(true)
        ),
        Err(Error::WrongPeer)
    ));
    assert!(matches!(
        station.prepare_msdu(
            42,
            &eth(AP, EAPOL),
            TxClass::Data,
            SequenceOwner::Host,
            &mut keys,
            &mut Policy(true)
        ),
        Err(Error::Unsupported(_))
    ));
}

#[test]
fn regulatory_denial_does_not_reserve_nonce_and_host_generation_is_rechecked() {
    let (mut station, mut keys) = station(PortPolicy::Controlled, true);
    station.authorize_port(42, &keys[0], &keys[1]).unwrap();
    let key = keys[0].installed().unwrap();
    assert!(matches!(
        station.prepare_msdu(
            42,
            &eth(SOURCE, 0x0800),
            TxClass::Data,
            SequenceOwner::Host,
            &mut keys,
            &mut Policy(false)
        ),
        Err(Error::Regulatory)
    ));
    assert_eq!(keys[0].host_tx_counter(key).unwrap().value(), 0);
    keys[0].invalidate();
    assert!(matches!(
        station.prepare_msdu(
            42,
            &eth(SOURCE, 0x0800),
            TxClass::Data,
            SequenceOwner::Host,
            &mut keys,
            &mut Policy(true)
        ),
        Err(Error::ClosedPort)
    ));
}

#[test]
fn rfc1042_aarp_ipx_exceptions_and_bridge_tunnel_match_linux() {
    for protocol in [0x0800, AARP, IPX] {
        let mut payload = RFC1042.to_vec();
        payload.extend_from_slice(&protocol.to_be_bytes());
        payload.extend_from_slice(&[1, 2, 3]);
        let output = ethernet(LOCAL, SOURCE, &payload).unwrap();
        if matches!(protocol, AARP | IPX) {
            assert_eq!(&output[12..14], &[0, 11]);
            assert_eq!(&output[14..], payload);
        } else {
            assert_eq!(&output[12..], &[8, 0, 1, 2, 3]);
        }
        payload[..6].copy_from_slice(&BRIDGE_TUNNEL);
        assert_eq!(
            &ethernet(LOCAL, SOURCE, &payload).unwrap()[12..14],
            &protocol.to_be_bytes()
        );
    }
}

#[test]
fn all_protocol_conversions_match_unchanged_linux_sanitizer_oracle() {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    for prefix in [RFC1042, BRIDGE_TUNNEL, [0xab, 0xaa, 3, 0, 0, 0]] {
        for protocol in 0..=u16::MAX {
            let mut payload = prefix.to_vec();
            payload.extend_from_slice(&protocol.to_be_bytes());
            payload.extend_from_slice(&[1, 2, 3]);
            let converted = ethernet(LOCAL, SOURCE, &payload).unwrap();
            digest.update((converted.len() as u16).to_le_bytes());
            digest.update(&converted);
        }
    }
    // Reproduce using tests/reference/wifi_data_oracle.py: full unchanged
    // ieee80211_data_to_8023_exthdr and dependencies, ASan/UBSan, 196608 PDUs.
    assert_eq!(
        <[u8; 32]>::from(digest.finalize()),
        [
            0xa5, 0x09, 0x08, 0x95, 0xf7, 0x0e, 0x3a, 0x9f, 0xb0, 0x62, 0x3d, 0x1f, 0x6d, 0x04,
            0xa9, 0x2a, 0xbf, 0xe0, 0xf3, 0xd8, 0x04, 0xf3, 0xdf, 0x42, 0xd4, 0x19, 0xd0, 0x3e,
            0x29, 0xa4, 0x76, 0xe8,
        ]
    );
}

#[test]
fn short_llc_and_exact_mtu_bounds_are_preserved() {
    for length in 0..8 {
        let payload = &RFC1042.repeat(2)[..length];
        let converted = ethernet(LOCAL, SOURCE, payload).unwrap();
        assert_eq!(&converted[12..14], &(length as u16).to_be_bytes());
        assert_eq!(&converted[14..], payload);
    }
    let mut payload = RFC1042.to_vec();
    payload.extend_from_slice(&[8, 0]);
    payload.extend_from_slice(&vec![0x5a; MAX_FRAME - 14]);
    let converted = ethernet(LOCAL, SOURCE, &payload).unwrap();
    assert_eq!(converted.len(), MAX_FRAME);
    assert_eq!(msdu(&converted).unwrap().3, payload);
    payload.push(0);
    assert_eq!(
        ethernet(LOCAL, SOURCE, &payload),
        Err(Error::InvalidEthernet)
    );
    assert_eq!(msdu(&converted[..13]), Err(Error::InvalidEthernet));
    assert_eq!(msdu(&vec![0; MAX_FRAME + 1]), Err(Error::InvalidEthernet));
    let mut invalid_length = eth(SOURCE, 4);
    assert_eq!(msdu(&invalid_length), Err(Error::InvalidEthernet));
    invalid_length[12..14].copy_from_slice(&3_u16.to_be_bytes());
    assert_eq!(msdu(&invalid_length).unwrap().3, [1, 2, 3]);
}

#[test]
fn queued_plan_permission_is_revoked_by_port_epoch_key_or_policy_change() {
    let (mut station, mut keys) = station(PortPolicy::Controlled, true);
    station.authorize_port(42, &keys[0], &keys[1]).unwrap();
    let plan = station
        .prepare_msdu(
            42,
            &eth(SOURCE, 0x0800),
            TxClass::Data,
            SequenceOwner::Host,
            &mut keys,
            &mut Policy(true),
        )
        .unwrap();
    station
        .validate_tx_plan(&plan, &keys, &mut Policy(true))
        .unwrap();
    assert_eq!(
        station.validate_tx_plan(&plan, &keys, &mut Policy(false)),
        Err(Error::Regulatory)
    );
    station.close_port();
    assert_eq!(
        station.validate_tx_plan(&plan, &keys, &mut Policy(true)),
        Err(Error::ClosedPort)
    );
    station.authorize_port(42, &keys[0], &keys[1]).unwrap();
    station.epoch = 43;
    assert_eq!(
        station.validate_tx_plan(&plan, &keys, &mut Policy(true)),
        Err(Error::Stale)
    );
    station.epoch = 42;
    keys[0].invalidate();
    assert_eq!(
        station.validate_tx_plan(&plan, &keys, &mut Policy(true)),
        Err(Error::ClosedPort)
    );
}

#[test]
fn protected_eapol_plan_cannot_outlive_its_acknowledged_key() {
    let (mut station, mut keys) = station(PortPolicy::Controlled, false);
    let key = keys[0].installed().unwrap();
    let plan = station
        .prepare_msdu(
            42,
            &eth(AP, EAPOL),
            TxClass::ControlPortProtected(key),
            SequenceOwner::Host,
            &mut keys,
            &mut Policy(true),
        )
        .unwrap();
    station
        .validate_tx_plan(&plan, &keys, &mut Policy(true))
        .unwrap();
    keys[0].invalidate();
    assert_eq!(
        station.validate_tx_plan(&plan, &keys, &mut Policy(true)),
        Err(Error::WrongKey)
    );
    assert!(matches!(
        station.prepare_msdu(
            42,
            &eth(AP, EAPOL),
            TxClass::ControlPortProtected(key),
            SequenceOwner::Host,
            &mut keys,
            &mut Policy(true)
        ),
        Err(Error::WrongKey)
    ));
}

#[test]
fn eapol_cannot_bypass_negotiated_cipher_or_unsupported_pairwise_key_id() {
    for (index, cipher) in [(1, Cipher::Ccmp128), (0, Cipher::Gcmp128)] {
        let (mut station, mut keys) = station(PortPolicy::Controlled, true);
        // Isolated model; this synthetic physical slot has no DMA/work users.
        // SAFETY: this test owns the key slot number alone.
        let mut alternate = unsafe { KeySlot::new(34).unwrap() };
        let ticket = alternate
            .begin_install(
                index,
                cipher,
                &[0x5a; 16],
                ReplaySeed::ZERO,
                KeyScope::Pairwise(AP),
                TransmitSeed::host(PacketNumber::new(0).unwrap()),
            )
            .unwrap();
        alternate
            .complete_install(ticket, InstallOutcome::Accepted)
            .unwrap();
        keys[0] = alternate;
        let key = keys[0].installed().unwrap();
        assert!(matches!(
            station.receive_msdu(42, &packet(LOCAL, EAPOL, protected(key, 1)), &mut keys),
            Err(Error::Unsupported(_)) | Err(Error::WrongKey)
        ));
        assert!(matches!(
            station.prepare_msdu(
                42,
                &eth(AP, EAPOL),
                TxClass::ControlPortProtected(key),
                SequenceOwner::Host,
                &mut keys,
                &mut Policy(true)
            ),
            Err(Error::Unsupported(_)) | Err(Error::WrongKey)
        ));
        assert_eq!(keys[0].host_tx_counter(key).unwrap().value(), 0);
    }
}

#[test]
fn foreign_ap_receiver_fragment_and_monitor_frames_cannot_poison_replay() {
    let (mut station, mut keys) = station(PortPolicy::Controlled, false);
    station.authorize_port(42, &keys[0], &keys[1]).unwrap();
    let key = keys[0].installed().unwrap();
    let valid = packet(LOCAL, 0x0800, protected(key, 1));
    for variant in 0..5 {
        let mut bytes = valid.bytes().to_vec();
        match variant {
            0 => bytes[10] ^= 4, // AP transmitter mismatch
            1 => bytes[4] ^= 4,  // foreign unicast receiver
            2 => bytes[1] |= 4,  // more fragments
            3 => bytes[22] |= 1, // nonzero fragment number
            _ => {}
        }
        let mut invalid = Mpdu::new(bytes, valid.radio.clone(), valid.security).unwrap();
        invalid.monitor_only = variant == 4;
        assert!(station.receive_msdu(42, &invalid, &mut keys).is_err());
    }
    assert!(matches!(
        station.receive_msdu(42, &valid, &mut keys),
        Ok(Ingress::Data(_))
    ));
}

#[test]
fn sequence_ownership_is_independent_of_air_status() {
    let (mut station, mut keys) = station(PortPolicy::Open, false);
    station.sequence = 0xfff;
    for (owner, expected, bytes) in [
        (
            SequenceOwner::Host,
            SequenceAssignment::Host(0xfff),
            [0xf0, 0xff],
        ),
        (SequenceOwner::Device, SequenceAssignment::Device, [0, 0]),
        (SequenceOwner::Host, SequenceAssignment::Host(0), [0, 0]),
    ] {
        let plan = station
            .prepare_msdu(
                42,
                &eth(SOURCE, 0x0800),
                TxClass::Data,
                owner,
                &mut keys,
                &mut Policy(true),
            )
            .unwrap();
        assert_eq!(plan.sequence(), expected);
        assert_eq!(&plan.plaintext_mpdu()[22..24], bytes);
        assert_eq!(plan.into_parts().4, expected);
    }
    assert_eq!(station.sequence, 1);
}
