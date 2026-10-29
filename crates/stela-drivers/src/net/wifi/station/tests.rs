use super::*;
use crate::net::wifi::{
    Band, RadioStatus, RawRate,
    scan::result::{Bss, Kind},
    security::{Cipher, InstallOutcome, ReplaySeed, SecurityStatus},
    station::phy::{Mode, Width},
};
use alloc::vec;

pub(crate) const LOCAL: Mac = Mac([2, 1, 2, 3, 4, 5]);
pub(crate) const AP: Mac = Mac([2, 6, 7, 8, 9, 10]);
pub(crate) struct Policy(pub(crate) bool);
impl RegulatoryPolicy for Policy {
    fn allow_management_tx(&mut self, _: Channel) -> bool {
        self.0
    }
    fn allow_data_tx(&mut self, _: Channel) -> bool {
        self.0
    }
}
pub(crate) fn join(policy: PortPolicy) -> Join {
    let mut elements = vec![0, 1, b'x', 1, 3, 0x8c, 0x98, 0xb0];
    if policy == PortPolicy::Controlled {
        elements.extend_from_slice(&[
            48, 18, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 2,
        ]);
    }
    Join {
        bssid: AP,
        channel: Channel {
            band: Band::Ghz5,
            number: 36,
            frequency_mhz: 5180,
        },
        policy,
        request: wire::AssociationRequest::new(
            if policy == PortPolicy::Open { 1 } else { 0x11 },
            10,
            elements,
        )
        .unwrap(),
    }
}
pub(crate) fn ticket(action: &Action) -> Ticket {
    match action {
        Action::Transmit { ticket, .. }
        | Action::Configure { ticket, .. }
        | Action::Remove { ticket, .. } => *ticket,
    }
}
pub(crate) fn response(control: u16, body: &[u8]) -> Mpdu {
    let mut bytes = vec![0; 24];
    bytes[..2].copy_from_slice(&control.to_le_bytes());
    bytes[4..10].copy_from_slice(&LOCAL.0);
    bytes[10..16].copy_from_slice(&AP.0);
    bytes[16..22].copy_from_slice(&AP.0);
    bytes.extend_from_slice(body);
    Mpdu::new(
        bytes,
        RadioStatus {
            band: Band::Ghz5,
            channel: 36,
            frequency_mhz: 5180,
            signal_dbm: Some(-45),
            chain_signal_dbm: [None; 4],
            rate: RawRate {
                layout: 1,
                words: [0; 4],
            },
            rx_rate: None,
            tsf: None,
        },
        SecurityStatus::default(),
    )
    .unwrap()
}
pub(crate) fn configure(station: &mut Station, policy: PortPolicy) -> Ticket {
    let auth = station.begin(join(policy), 1, &mut Policy(true)).unwrap();
    let epoch = ticket(&auth).epoch();
    assert!(!station.port_open(None, None));
    station.submitted(ticket(&auth)).unwrap();
    let assoc = station
        .receive(
            epoch,
            &response(0xb0, &[0, 0, 2, 0, 0, 0]),
            2,
            &mut Policy(true),
        )
        .unwrap();
    station.submitted(ticket(&assoc)).unwrap();
    let config = station
        .receive(
            epoch,
            &response(0x10, &[1, 0, 0, 0, 7, 0xc0, 1, 3, 0x8c, 0x98, 0xb0]),
            3,
            &mut Policy(true),
        )
        .unwrap();
    assert!(matches!(config, Action::Configure { .. }));
    ticket(&config)
}
pub(crate) fn key(slot: u16, scope: KeyScope) -> KeySlot {
    // Independent protocol fixture has no real slots, DMA or deferred RX.
    // SAFETY: this test owns the key slot number alone.
    let mut key = unsafe { KeySlot::new(slot).unwrap() };
    let index = if matches!(scope, KeyScope::Pairwise(_)) {
        0
    } else {
        2
    };
    let ticket = key
        .begin_install(
            index,
            Cipher::Ccmp128,
            &[slot as u8; 16],
            ReplaySeed::ZERO,
            scope,
            if matches!(scope, KeyScope::Pairwise(_)) {
                crate::net::wifi::security::TransmitSeed::FIRMWARE_FRESH
            } else {
                crate::net::wifi::security::TransmitSeed::RECEIVE_ONLY
            },
        )
        .unwrap();
    key.complete_install(ticket, InstallOutcome::Accepted)
        .unwrap();
    key
}
pub(crate) fn broadcast(frame: Mpdu) -> Mpdu {
    let mut bytes = frame.bytes().to_vec();
    bytes[4..10].copy_from_slice(&Mac::BROADCAST.0);
    Mpdu::new(bytes, frame.radio, frame.security).unwrap()
}
pub(crate) fn ie(out: &mut Vec<u8>, id: u8, b: &[u8]) {
    out.extend_from_slice(&[id, b.len() as u8]);
    out.extend_from_slice(b);
}
pub(crate) fn extension(out: &mut Vec<u8>, id: u8, b: &[u8]) {
    let mut v = vec![id];
    v.extend_from_slice(b);
    ie(out, 255, &v);
}
impl crate::net::wifi::scan::Policy for Policy {
    fn allow_receive(&mut self, _: Channel) -> bool {
        self.0
    }
    fn allow_probe(&mut self, _: Channel) -> bool {
        self.0
    }
    fn lookup_channel(&mut self, band: Band, number: u16) -> Option<Channel> {
        Some(Channel {
            band,
            number,
            frequency_mhz: 5180,
        })
    }
}
pub(crate) fn modern_ies(ap: bool) -> Vec<u8> {
    let mut out = vec![0, 1, b'x', 1, 3, 0x8c, 0x98, 0xb0];
    let mut ht = [0; 26];
    ht[0] = 2;
    ht[2] = 3;
    ht[3] = 0xff;
    ht[15] = 1;
    ie(&mut out, 45, &ht);
    let mut vht = [0; 12];
    vht[..4].copy_from_slice(&4_u32.to_le_bytes());
    vht[4..6].copy_from_slice(&0xfffe_u16.to_le_bytes());
    vht[8..10].copy_from_slice(&0xfffe_u16.to_le_bytes());
    ie(&mut out, 191, &vht);
    let mut he = vec![0; 17];
    he[6] = 12;
    for _ in 0..2 {
        he.extend_from_slice(&[0xfe, 0xff, 0xfe, 0xff]);
    }
    extension(&mut out, 35, &he);
    let mut eht = vec![0; 11];
    eht.extend_from_slice(&[0x11; 6]);
    extension(&mut out, 108, &eht);
    if ap {
        ie(
            &mut out,
            221,
            &[
                0, 0x50, 0xf2, 2, 1, 1, 0x80, 0, 3, 0xa4, 0, 0, 0x27, 0xa4, 0, 0, 0x42, 0x43, 94,
                0, 0x62, 0x32, 47, 0,
            ],
        );
        let mut ht_op = [0; 22];
        ht_op[0] = 36;
        ht_op[1] = 5;
        ht_op[2] = 3;
        ie(&mut out, 61, &ht_op);
        ie(&mut out, 192, &[1, 42, 0, 0xff, 0xff]);
        extension(&mut out, 36, &[3, 0x20, 0, 0x2a, 0xff, 0xff]);
        extension(&mut out, 106, &[1, 0, 0, 0, 0, 2, 42, 0]);
        ie(&mut out, 5, &[0, 3, 0, 0]);
    } else {
        ie(&mut out, 221, &[0, 0x50, 0xf2, 2, 0, 1, 0]);
    }
    out
}
pub(crate) fn modern_join() -> Join {
    let mut j = join(PortPolicy::Open);
    j.request = wire::AssociationRequest::new_modern(
        1,
        10,
        modern_ies(false),
        Band::Ghz5,
        Mode::Eht,
        Width::Mhz80,
    )
    .unwrap();
    j
}
pub(crate) fn beacon(j: &Join) -> Bss {
    let scan = crate::net::wifi::scan::Scanner::new(LOCAL)
        .unwrap()
        .begin(
            crate::net::wifi::scan::Request::new(vec![j.channel], vec![], vec![]).unwrap(),
            0,
            100,
            &mut Policy(true),
        )
        .unwrap();
    Bss {
        ticket: scan,
        kind: Kind::Beacon,
        bssid: AP,
        transmitter: AP,
        timestamp: 100,
        beacon_interval: 100,
        capabilities: 1,
        channel: j.channel,
        observed: response(0xb0, &[0; 6]).radio,
        signal_dbm: Some(-45),
        ssid: Some(vec![b'x']),
        elements: modern_ies(true),
    }
}
pub(crate) fn configuration(s: &mut Station, j: Join, bss: Bss) -> Result<Action, Error> {
    let start = s.now;
    let a = s.begin_modern(j, bss, start, &mut Policy(true))?;
    s.submitted(ticket(&a))?;
    let a = s.receive(
        s.association_epoch().unwrap(),
        &response(0xb0, &[0, 0, 2, 0, 0, 0]),
        start + 1,
        &mut Policy(true),
    )?;
    s.submitted(ticket(&a))?;
    let mut body = vec![1, 0, 0, 0, 1, 0xc0];
    body.extend_from_slice(&modern_ies(true));
    s.receive(
        s.association_epoch().unwrap(),
        &response(0x10, &body),
        start + 2,
        &mut Policy(true),
    )
}
pub(crate) fn response_metadata(elements: Vec<u8>) -> wire::AssociationResponse {
    wire::AssociationResponse {
        capabilities: 1,
        status: 0,
        raw_aid: 0xc001,
        aid: 1,
        power_save_allowed: true,
        elements,
    }
}
pub(crate) fn filtered(mut bytes: &[u8], remove: impl Fn(u8, &[u8]) -> bool) -> Vec<u8> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let length = usize::from(bytes[1]);
        let b = &bytes[2..2 + length];
        if !remove(bytes[0], b) {
            out.extend_from_slice(&bytes[..2 + length]);
        }
        bytes = &bytes[2 + length..];
    }
    out
}
pub(crate) fn edit_elements(mut bytes: &mut [u8], mut edit: impl FnMut(u8, &mut [u8])) {
    while !bytes.is_empty() {
        let n = usize::from(bytes[1]);
        let id = bytes[0];
        edit(id, &mut bytes[2..2 + n]);
        bytes = &mut bytes[2 + n..];
    }
}

#[test]
fn open_port_needs_auth_association_and_firmware_ack() {
    let mut station = Station::new(LOCAL).unwrap();
    let config = configure(&mut station, PortPolicy::Open);
    assert_eq!(station.phase(), Phase::Configuring);
    assert!(!station.port_open(None, None));
    station
        .complete_configuration(config, Completion::Accepted, 4)
        .unwrap();
    assert!(station.port_open(None, None));
    assert_eq!(
        station.complete_configuration(config, Completion::Accepted, 4),
        Err(Error::Stale)
    );
}

#[test]
fn shared_key_auth_answers_the_challenge_like_ieee80211_auth_challenge() {
    use crate::net::wifi::security::wep;
    let key = wep::Key::new(&[1, 2, 3, 4, 5], 1).unwrap();
    let mut join = join(PortPolicy::Open);
    join.policy = PortPolicy::Controlled;
    join.request = wire::AssociationRequest::new(0x11, 10, join.request.elements().to_vec())
        .unwrap()
        .with_wep(key.clone(), wire::SHARED_KEY, 0x03_feff)
        .unwrap();
    assert_eq!(
        join.request.key_ciphers(),
        Some((Cipher::Wep40, Cipher::Wep40))
    );
    let mut station = Station::new(LOCAL).unwrap();
    let first = station.begin(join, 1, &mut Policy(true)).unwrap();
    let Action::Transmit { bytes, .. } = &first else {
        panic!()
    };
    assert_eq!(bytes[24..], [1, 0, 1, 0, 0, 0]);
    let epoch = ticket(&first).epoch();
    station.submitted(ticket(&first)).unwrap();
    // Another algorithm, and a reply without its challenge, are ignored.
    for body in [&[0, 0, 2, 0, 0, 0][..], &[1, 0, 2, 0, 0, 0]] {
        assert!(
            station
                .receive(epoch, &response(0xb0, body), 2, &mut Policy(true))
                .is_err()
        );
    }
    let challenge = [1, 0, 2, 0, 0, 0, 16, 4, 9, 8, 7, 6];
    let third = station
        .receive(epoch, &response(0xb0, &challenge), 3, &mut Policy(true))
        .unwrap();
    let Action::Transmit { bytes, .. } = &third else {
        panic!()
    };
    // The IV after 0x03feff skips the weak 0x03ff00.
    let expected = wire::shared_key_response(LOCAL, AP, 0, &[9, 8, 7, 6], &key, [4, 0, 0]);
    assert_eq!(bytes[..2], [0xb0, 0x40]);
    assert_eq!(bytes[24..], expected.unwrap()[24..]);
    assert_eq!(bytes[24..28], [4, 0, 0, 1 << 6]);
    station.submitted(ticket(&third)).unwrap();
    // Transaction 2 again is now unexpected; 4 completes authentication.
    assert!(
        station
            .receive(epoch, &response(0xb0, &challenge), 4, &mut Policy(true))
            .is_err()
    );
    let assoc = station
        .receive(
            epoch,
            &response(0xb0, &[1, 0, 4, 0, 0, 0]),
            5,
            &mut Policy(true),
        )
        .unwrap();
    let Action::Transmit { bytes, .. } = &assoc else {
        panic!()
    };
    assert_eq!(bytes[0], 0);
    assert_eq!(station.phase(), Phase::Associating);
}

#[test]
fn a_lost_shared_key_exchange_restarts_at_transaction_one_like_ieee80211_auth() {
    use crate::net::wifi::security::wep;
    let mut join = join(PortPolicy::Open);
    join.policy = PortPolicy::Controlled;
    join.request = wire::AssociationRequest::new(0x11, 10, join.request.elements().to_vec())
        .unwrap()
        .with_wep(wep::Key::new(&[7; 13], 0).unwrap(), wire::SHARED_KEY, 0)
        .unwrap();
    let mut station = Station::new(LOCAL).unwrap();
    let first = station.begin(join, 1, &mut Policy(true)).unwrap();
    let epoch = ticket(&first).epoch();
    station.submitted(ticket(&first)).unwrap();
    let third = station
        .receive(
            epoch,
            &response(0xb0, &[1, 0, 2, 0, 0, 0, 16, 1, 5]),
            2,
            &mut Policy(true),
        )
        .unwrap();
    station.submitted(ticket(&third)).unwrap();
    let retry = station
        .poll(1 + MANAGEMENT_RESPONSE_TIMEOUT_US, &mut Policy(true))
        .unwrap()
        .unwrap();
    let Action::Transmit { bytes, .. } = &retry else {
        panic!()
    };
    assert_eq!(bytes[24..], [1, 0, 1, 0, 0, 0]);
    // WEP keeps the association legacy, and needs the privacy bit.
    let elements = vec![0, 1, b'x', 1, 1, 0x8c];
    let key = wep::Key::new(&[7; 5], 0).unwrap();
    assert!(
        wire::AssociationRequest::new(1, 10, elements.clone())
            .unwrap()
            .with_wep(key.clone(), wire::OPEN_SYSTEM, 0)
            .is_err()
    );
    let open_wep = wire::AssociationRequest::new(0x11, 10, elements)
        .unwrap()
        .with_wep(key, wire::OPEN_SYSTEM, 0)
        .unwrap();
    assert!(open_wep.validate_policy(PortPolicy::Controlled).is_ok());
    assert!(open_wep.validate_policy(PortPolicy::Open).is_err());
}

#[test]
fn secured_port_needs_frontend_command_and_current_keys() {
    let mut station = Station::new(LOCAL).unwrap();
    let config = configure(&mut station, PortPolicy::Controlled);
    station
        .complete_configuration(config, Completion::Accepted, 4)
        .unwrap();
    let mut ptk = key(1, KeyScope::Pairwise(AP));
    let gtk = key(2, KeyScope::Group(AP));
    assert!(!station.port_open(Some(&ptk), Some(&gtk)));
    assert_eq!(
        station.authorize_port(config.epoch() + 1, &ptk, &gtk),
        Err(Error::NotAssociated)
    );
    station.authorize_port(config.epoch(), &ptk, &gtk).unwrap();
    assert!(station.port_open(Some(&ptk), Some(&gtk)));
    assert!(!station.port_open(Some(&ptk), None));
    ptk.invalidate();
    assert!(!station.port_open(Some(&ptk), Some(&gtk)));
}

#[test]
fn wrong_bss_purpose_or_key_ack_cannot_open_port() {
    let mut station = Station::new(LOCAL).unwrap();
    let config = configure(&mut station, PortPolicy::Controlled);
    station
        .complete_configuration(config, Completion::Accepted, 4)
        .unwrap();
    let ptk = key(1, KeyScope::Pairwise(Mac([2, 0, 0, 0, 0, 1])));
    let gtk = key(2, KeyScope::Group(AP));
    assert_eq!(
        station.authorize_port(config.epoch(), &ptk, &gtk),
        Err(Error::WrongKey)
    );
    assert_eq!(
        station.authorize_port(config.epoch(), &gtk, &gtk),
        Err(Error::WrongKey)
    );
    assert!(!station.port_open(Some(&ptk), Some(&gtk)));
}

#[test]
fn old_epoch_unsubmitted_and_wrong_channel_responses_do_not_advance() {
    let mut station = Station::new(LOCAL).unwrap();
    let auth = station
        .begin(join(PortPolicy::Open), 1, &mut Policy(true))
        .unwrap();
    let epoch = ticket(&auth).epoch();
    let frame = response(0xb0, &[0, 0, 2, 0, 0, 0]);
    assert!(matches!(
        station.receive(epoch, &frame, 2, &mut Policy(true)),
        Err(Error::NotQueued)
    ));
    station.submitted(ticket(&auth)).unwrap();
    assert!(matches!(
        station.receive(epoch + 1, &frame, 3, &mut Policy(true)),
        Err(Error::Stale)
    ));
    let mut wrong = frame.clone();
    wrong.radio.channel = 40;
    assert!(matches!(
        station.receive(epoch, &wrong, 4, &mut Policy(true)),
        Err(Error::WrongChannel)
    ));
    assert_eq!(station.phase(), Phase::Authenticating);
    assert!(station.receive(epoch, &frame, 5, &mut Policy(true)).is_ok());
}

#[test]
fn negative_peer_response_requires_real_removal_before_retry() {
    let mut station = Station::new(LOCAL).unwrap();
    let auth = station
        .begin(join(PortPolicy::Open), 1, &mut Policy(true))
        .unwrap();
    station.submitted(ticket(&auth)).unwrap();
    let remove = station
        .receive(
            ticket(&auth).epoch(),
            &response(0xb0, &[0, 0, 2, 0, 13, 0]),
            2,
            &mut Policy(true),
        )
        .unwrap();
    assert!(matches!(
        remove,
        Action::Remove {
            failure: Some(Failure::PeerRejected(13)),
            ..
        }
    ));
    assert_eq!(station.phase(), Phase::Disconnecting);
    assert!(matches!(
        station.begin(join(PortPolicy::Open), 3, &mut Policy(true)),
        Err(Error::Busy)
    ));
    station
        .complete_removal(ticket(&remove), Completion::Accepted)
        .unwrap();
    let next = station
        .begin(join(PortPolicy::Open), 4, &mut Policy(true))
        .unwrap();
    assert_ne!(ticket(&next).epoch(), ticket(&auth).epoch());
    assert_eq!(station.submitted(ticket(&auth)), Err(Error::Stale));
}

#[test]
fn three_attempt_timeout_closes_session_and_does_not_assume_idle() {
    let mut station = Station::new(LOCAL).unwrap();
    let first = station
        .begin(join(PortPolicy::Open), 0, &mut Policy(true))
        .unwrap();
    station.submitted(ticket(&first)).unwrap();
    for now in [500_000, 1_000_000] {
        let next = station.poll(now, &mut Policy(true)).unwrap().unwrap();
        assert!(matches!(next, Action::Transmit { .. }));
        station.submitted(ticket(&next)).unwrap();
    }
    let remove = station.poll(1_500_000, &mut Policy(true)).unwrap().unwrap();
    assert!(matches!(
        remove,
        Action::Remove {
            failure: Some(Failure::Timeout),
            ..
        }
    ));
    station
        .complete_removal(ticket(&remove), Completion::Uncertain)
        .unwrap();
    assert_eq!(station.phase(), Phase::Quarantined);
    assert!(!station.port_open(None, None));
}

#[test]
fn tx_status_paces_management_retries_like_ieee80211_sta_work() {
    let mut station = Station::new(LOCAL).unwrap();
    let first = station
        .begin(join(PortPolicy::Open), 0, &mut Policy(true))
        .unwrap();
    station.submitted(ticket(&first)).unwrap();
    // An acknowledged request waits IEEE80211_AUTH_TIMEOUT_SHORT; a lost
    // one goes again at once.
    station.management_status(true, 10).unwrap();
    assert!(station.poll(100_009, &mut Policy(true)).unwrap().is_none());
    let next = station.poll(100_010, &mut Policy(true)).unwrap().unwrap();
    assert!(matches!(next, Action::Transmit { .. }));
    station.submitted(ticket(&next)).unwrap();
    station.management_status(false, 100_020).unwrap();
    let next = station.poll(100_020, &mut Policy(true)).unwrap().unwrap();
    assert!(matches!(next, Action::Transmit { .. }));
}

#[test]
fn regulator_and_clock_failures_do_not_create_carrier_or_firmware_success() {
    let mut station = Station::new(LOCAL).unwrap();
    assert!(matches!(
        station.begin(join(PortPolicy::Open), 10, &mut Policy(false)),
        Err(Error::Regulatory)
    ));
    assert_eq!(station.phase(), Phase::Idle);
    assert!(matches!(
        station.begin(join(PortPolicy::Open), 9, &mut Policy(true)),
        Err(Error::ClockRegressed)
    ));
    let config = {
        let mut fresh = Station::new(LOCAL).unwrap();
        let config = configure(&mut fresh, PortPolicy::Open);
        station = fresh;
        config
    };
    assert!(matches!(
        station.poll(500_003, &mut Policy(true)),
        Err(Error::Timeout)
    ));
    assert_eq!(station.phase(), Phase::Quarantined);
    assert_eq!(
        station.complete_configuration(config, Completion::Accepted, 500_003),
        Err(Error::Stale)
    );
}

#[test]
fn peer_departure_closes_open_port_before_device_teardown() {
    let mut station = Station::new(LOCAL).unwrap();
    let config = configure(&mut station, PortPolicy::Open);
    station
        .complete_configuration(config, Completion::Accepted, 4)
        .unwrap();
    let remove = station
        .receive(
            config.epoch(),
            &response(0xc0, &[3, 0]),
            4,
            &mut Policy(true),
        )
        .unwrap();
    assert!(matches!(
        remove,
        Action::Remove {
            failure: Some(Failure::PeerDeparture(3)),
            ..
        }
    ));
    assert!(!station.port_open(None, None));
}

#[test]
fn invalid_aid_preserves_linux_no_power_save_fallback() {
    for (aid, expected) in [(0, 0), (1, 1), (2007, 2007), (2008, 0), (2047, 0)] {
        let raw = aid | 0xc000_u16;
        let [low, high] = raw.to_le_bytes();
        let frame = response(0x10, &[1, 0, 0, 0, low, high, 1, 3, 0x8c, 0x98, 0xb0]);
        let parsed = wire::association_response(&frame).unwrap();
        assert_eq!(parsed.raw_aid, raw);
        assert_eq!(parsed.aid, expected);
        assert_eq!(parsed.power_save_allowed, expected != 0);
    }
}

#[test]
fn truncated_or_wrong_peer_management_cannot_advance_authentication() {
    let mut station = Station::new(LOCAL).unwrap();
    let auth = station
        .begin(join(PortPolicy::Open), 0, &mut Policy(true))
        .unwrap();
    station.submitted(ticket(&auth)).unwrap();
    for length in 0..6 {
        assert!(
            station
                .receive(
                    ticket(&auth).epoch(),
                    &response(0xb0, &[0, 0, 2, 0, 0, 0][..length]),
                    1,
                    &mut Policy(true)
                )
                .is_err()
        );
    }
    for offset in [4, 10, 16] {
        let original = response(0xb0, &[0, 0, 2, 0, 0, 0]);
        let mut bytes = original.bytes().to_vec();
        bytes[offset] ^= 2;
        let altered = Mpdu::new(bytes, original.radio.clone(), original.security).unwrap();
        assert!(matches!(
            station.receive(ticket(&auth).epoch(), &altered, 2, &mut Policy(true)),
            Err(Error::Wire(wire::Error::WrongPeer))
        ));
    }
    assert_eq!(station.phase(), Phase::Authenticating);
    assert!(!station.port_open(None, None));
}

#[test]
fn uncertain_configuration_and_deadline_overflow_stay_closed() {
    let mut station = Station::new(LOCAL).unwrap();
    let config = configure(&mut station, PortPolicy::Open);
    station
        .complete_configuration(config, Completion::Uncertain, 4)
        .unwrap();
    assert_eq!(station.phase(), Phase::Quarantined);
    assert!(!station.port_open(None, None));
    let mut fresh = Station::new(LOCAL).unwrap();
    assert!(matches!(
        fresh.begin(join(PortPolicy::Open), u64::MAX - 1, &mut Policy(true)),
        Err(Error::Overflow)
    ));
    assert_eq!(fresh.phase(), Phase::Idle);
    assert!(!fresh.port_open(None, None));
}

#[test]
fn late_success_cannot_bypass_response_or_configuration_deadline() {
    let mut station = Station::new(LOCAL).unwrap();
    let auth = station
        .begin(join(PortPolicy::Open), 0, &mut Policy(true))
        .unwrap();
    station.submitted(ticket(&auth)).unwrap();
    let retry = station
        .receive(
            ticket(&auth).epoch(),
            &response(0xb0, &[0, 0, 2, 0, 0, 0]),
            500_000,
            &mut Policy(true),
        )
        .unwrap();
    assert!(matches!(retry, Action::Transmit { .. }));
    assert_eq!(station.phase(), Phase::Authenticating);
    assert_ne!(ticket(&retry), ticket(&auth));
    let mut fresh = Station::new(LOCAL).unwrap();
    let config = configure(&mut fresh, PortPolicy::Open);
    assert_eq!(
        fresh.complete_configuration(config, Completion::Accepted, 500_003),
        Err(Error::Timeout)
    );
    assert_eq!(fresh.phase(), Phase::Quarantined);
    assert!(!fresh.port_open(None, None));
}

#[test]
fn broadcast_ap_departures_close_authorized_controlled_port() {
    for subtype in [0xa0, 0xc0] {
        let mut station = Station::new(LOCAL).unwrap();
        let config = configure(&mut station, PortPolicy::Controlled);
        station
            .complete_configuration(config, Completion::Accepted, 4)
            .unwrap();
        let ptk = key(1, KeyScope::Pairwise(AP));
        let gtk = key(2, KeyScope::Group(AP));
        station.authorize_port(config.epoch(), &ptk, &gtk).unwrap();
        assert!(station.port_open(Some(&ptk), Some(&gtk)));
        let action = station
            .receive(
                config.epoch(),
                &broadcast(response(subtype, &[3, 0])),
                5,
                &mut Policy(true),
            )
            .unwrap();
        assert!(matches!(
            action,
            Action::Remove {
                failure: Some(Failure::PeerDeparture(3)),
                ..
            }
        ));
        assert_eq!(station.phase(), Phase::Disconnecting);
        assert!(!station.port_open(Some(&ptk), Some(&gtk)));
    }
}

#[test]
fn broadcast_departure_from_wrong_ap_does_not_close_port() {
    for subtype in [0xa0, 0xc0] {
        let mut station = Station::new(LOCAL).unwrap();
        let config = configure(&mut station, PortPolicy::Controlled);
        station
            .complete_configuration(config, Completion::Accepted, 4)
            .unwrap();
        let ptk = key(1, KeyScope::Pairwise(AP));
        let gtk = key(2, KeyScope::Group(AP));
        station.authorize_port(config.epoch(), &ptk, &gtk).unwrap();
        for offset in [10, 16] {
            let frame = broadcast(response(subtype, &[3, 0]));
            let mut bytes = frame.bytes().to_vec();
            bytes[offset] ^= 2;
            let wrong = Mpdu::new(bytes, frame.radio, frame.security).unwrap();
            assert!(matches!(
                station.receive(config.epoch(), &wrong, 5, &mut Policy(true)),
                Err(Error::Wire(wire::Error::WrongPeer))
            ));
            assert!(station.port_open(Some(&ptk), Some(&gtk)));
        }
    }
}

#[test]
fn broadcast_authentication_and_association_responses_are_not_accepted() {
    let mut station = Station::new(LOCAL).unwrap();
    let auth = station
        .begin(join(PortPolicy::Open), 0, &mut Policy(true))
        .unwrap();
    station.submitted(ticket(&auth)).unwrap();
    let epoch = ticket(&auth).epoch();
    assert!(matches!(
        station.receive(
            epoch,
            &broadcast(response(0xb0, &[0, 0, 2, 0, 0, 0])),
            1,
            &mut Policy(true)
        ),
        Err(Error::Wire(wire::Error::WrongPeer))
    ));
    assert_eq!(station.phase(), Phase::Authenticating);
    let assoc = station
        .receive(
            epoch,
            &response(0xb0, &[0, 0, 2, 0, 0, 0]),
            2,
            &mut Policy(true),
        )
        .unwrap();
    station.submitted(ticket(&assoc)).unwrap();
    assert!(matches!(
        station.receive(
            epoch,
            &broadcast(response(
                0x10,
                &[1, 0, 0, 0, 7, 0xc0, 1, 3, 0x8c, 0x98, 0xb0]
            )),
            3,
            &mut Policy(true)
        ),
        Err(Error::Wire(wire::Error::WrongPeer))
    ));
    assert_eq!(station.phase(), Phase::Associating);
    assert!(!station.port_open(None, None));
}

#[test]
fn receive_only_pairwise_key_cannot_authorize_a_data_port() {
    use crate::net::wifi::security::{NonceOwner, TransmitSeed};
    let mut station = Station::new(LOCAL).unwrap();
    let config = configure(&mut station, PortPolicy::Controlled);
    station
        .complete_configuration(config, Completion::Accepted, 4)
        .unwrap();
    // SAFETY: this test owns the key slot number alone.
    let mut ptk = unsafe { KeySlot::new(1).unwrap() };
    let ticket = ptk
        .begin_install(
            0,
            Cipher::Ccmp128,
            &[1; 16],
            ReplaySeed::ZERO,
            KeyScope::Pairwise(AP),
            TransmitSeed::RECEIVE_ONLY,
        )
        .unwrap();
    ptk.complete_install(ticket, InstallOutcome::Accepted)
        .unwrap();
    assert_eq!(
        ptk.installed().unwrap().nonce_owner(),
        NonceOwner::ReceiveOnly
    );
    let gtk = key(2, KeyScope::Group(AP));
    assert_eq!(
        station.authorize_port(config.epoch(), &ptk, &gtk),
        Err(Error::WrongKey)
    );
    assert!(!station.port_open(Some(&ptk), Some(&gtk)));
}

#[test]
fn host_nonce_exhaustion_closes_a_previously_authorized_data_port() {
    use crate::net::wifi::security::{PacketNumber, TransmitSeed};
    let mut station = Station::new(LOCAL).unwrap();
    let config = configure(&mut station, PortPolicy::Controlled);
    station
        .complete_configuration(config, Completion::Accepted, 4)
        .unwrap();
    // SAFETY: this test owns the key slot number alone.
    let mut ptk = unsafe { KeySlot::new(1).unwrap() };
    let ticket = ptk
        .begin_install(
            0,
            Cipher::Ccmp128,
            &[1; 16],
            ReplaySeed::ZERO,
            KeyScope::Pairwise(AP),
            TransmitSeed::host(PacketNumber::new((1_u64 << 48) - 2).unwrap()),
        )
        .unwrap();
    ptk.complete_install(ticket, InstallOutcome::Accepted)
        .unwrap();
    let identity = ptk.installed().unwrap();
    let gtk = key(2, KeyScope::Group(AP));
    station.authorize_port(config.epoch(), &ptk, &gtk).unwrap();
    assert!(station.port_open(Some(&ptk), Some(&gtk)));
    assert!(ptk.reserve_host_tx_nonce(identity).is_ok());
    assert!(ptk.reserve_host_tx_nonce(identity).is_err());
    assert!(!station.port_open(Some(&ptk), Some(&gtk)));
}

#[test]
fn modern_configuration_is_kept_bound_and_invalidated_before_removal() {
    let mut s = Station::new(LOCAL).unwrap();
    let j = modern_join();
    assert!(matches!(
        s.begin(j.clone(), 0, &mut Policy(true)),
        Err(Error::Unsupported(_))
    ));
    let a = configuration(&mut s, j.clone(), beacon(&j)).unwrap();
    let Action::Configure {
        ticket,
        context: Some(context),
        ..
    } = a
    else {
        panic!("modern context required")
    };
    assert_eq!(context.ticket(), ticket);
    assert_eq!(context.bssid(), AP);
    assert_eq!(context.definition().center1_mhz, 5210);
    assert_eq!(context.definition().width, Width::Mhz80);
    assert_eq!(context.dtim_period(), 3);
    assert_eq!(context.negotiated().mode, Mode::Eht);
    assert_eq!(context.operations().ht.as_ref().unwrap().protection, 3);
    let he = context.operations().he.as_ref().unwrap();
    assert_eq!(
        (he.packet_extension(), he.rts_threshold(), he.color()),
        (3, 512, 42)
    );
    s.validate_association_context(&context).unwrap();
    s.complete_configuration(ticket, Completion::Accepted, 3)
        .unwrap();
    s.validate_association_context(&context).unwrap();
    let removal = s.disconnect().unwrap();
    assert!(s.validate_association_context(&context).is_err());
    assert!(s.association_context().is_none());
    s.complete_removal(tests::ticket(&removal), Completion::Accepted)
        .unwrap();
    let a = configuration(&mut s, j.clone(), beacon(&j)).unwrap();
    let Action::Configure {
        context: Some(next),
        ..
    } = a
    else {
        panic!()
    };
    assert_ne!(next.ticket().epoch(), context.ticket().epoch());
    assert!(s.validate_association_context(&context).is_err());
    s.validate_association_context(&next).unwrap();
}
#[test]
fn modern_uncertainty_keeps_configuration_but_never_usable_identity() {
    let mut s = Station::new(LOCAL).unwrap();
    let j = modern_join();
    let a = configuration(&mut s, j.clone(), beacon(&j)).unwrap();
    let Action::Configure {
        ticket,
        context: Some(context),
        ..
    } = a
    else {
        panic!()
    };
    s.complete_configuration(ticket, Completion::Uncertain, 3)
        .unwrap();
    assert!(s.association_context().is_none());
    assert!(s.validate_association_context(&context).is_err());
    assert!(s.context.is_some());
    assert!(!s.port_open(None, None));
    assert!(matches!(
        s.begin_modern(j.clone(), beacon(&j), 4, &mut Policy(true)),
        Err(Error::Busy)
    ));
}
#[test]
fn selected_beacon_timing_peer_ssid_and_width_are_required_not_defaulted() {
    let j = modern_join();
    for damage in 0..6 {
        let mut b = beacon(&j);
        match damage {
            0 => b.beacon_interval = 0,
            1 => b.kind = Kind::ProbeResponse,
            2 => b.ssid = Some(vec![b'y']),
            3 => b.elements.truncate(b.elements.len() - 6),
            4 => {
                let n = b.elements.len();
                b.elements[n - 3] = 0;
            }
            _ => b.transmitter = LOCAL,
        }
        assert!(
            configuration(&mut Station::new(LOCAL).unwrap(), j.clone(), b).is_err(),
            "damage {damage}"
        );
    }
    let mut j = modern_join();
    j.request = wire::AssociationRequest::new_modern(
        1,
        10,
        modern_ies(false),
        Band::Ghz5,
        Mode::Eht,
        Width::Mhz160,
    )
    .unwrap();
    assert!(configuration(&mut Station::new(LOCAL).unwrap(), j.clone(), beacon(&j)).is_err());
}

#[test]
fn admission_controlled_categories_downgrade_like_ieee80211_downgrade_queue() {
    let j = modern_join();
    let b = beacon(&j);
    // Voice and video require admission control.
    let mut elements = modern_ies(true);
    let mut at = 0;
    while at + 2 <= elements.len() {
        let len = usize::from(elements[at + 1]);
        if elements[at] == 221 && elements[at + 2..at + 6] == [0, 0x50, 0xf2, 2] {
            for record in (at + 10..at + 2 + len).step_by(4) {
                if (elements[record] >> 5) & 3 >= 2 {
                    elements[record] |= 0x10;
                }
            }
        }
        at += 2 + len;
    }
    let ticket = Ticket {
        epoch: 1,
        serial: 2,
    };
    let context = AssociationContext::build(ticket, &j, &b, &response_metadata(elements)).unwrap();
    let mut ef = vec![0; 34];
    ef[12..16].copy_from_slice(&[8, 0, 0x45, 46 << 2]);
    let mut eapol = vec![0; 14];
    eapol[12..].copy_from_slice(&[0x88, 0x8e]);
    let mut cs1 = ef.clone();
    cs1[15] = 8 << 2;
    assert_eq!(
        [&ef, &eapol, &cs1].map(|frame| data::data_tid(&context, None, None, frame)),
        [Some(3), Some(3), Some(1)]
    );
}

#[test]
fn generic_missing_ht_vht_wmm_fallback_keeps_beacon_but_not_he_eht() {
    let j = modern_join();
    let b = beacon(&j);
    let elements = filtered(&modern_ies(true), |id, _| {
        matches!(id, 45 | 61 | 191 | 192 | 221)
    });
    let response = response_metadata(elements);
    let context = AssociationContext::build(
        Ticket {
            epoch: 1,
            serial: 2,
        },
        &j,
        &b,
        &response,
    )
    .unwrap();
    assert!(context.negotiated().wmm.is_some());
    assert!(context.operations().ht.is_some());
    assert_eq!(context.response().elements, response.elements);
    for id in [35, 36, 106, 108] {
        let elements = filtered(&modern_ies(true), |other, b| other == 255 && b[0] == id);
        assert!(
            AssociationContext::build(
                Ticket {
                    epoch: 1,
                    serial: 2
                },
                &j,
                &b,
                &response_metadata(elements)
            )
            .is_err()
        );
    }
}
#[test]
fn normal_basic_rules_keep_he_eht_and_real_rates_but_not_strict_only_ht_checks() {
    let j = modern_join();
    let b = beacon(&j);
    for kind in 0..4 {
        let mut bytes = modern_ies(true);
        let mut rest = bytes.as_mut_slice();
        while !rest.is_empty() {
            let length = usize::from(rest[1]);
            let id = rest[0];
            let data = &mut rest[2..2 + length];
            match kind {
                0 if id == 1 => data[1] &= 0x7f,
                1 if id == 61 => data[7] = 1,
                2 if id == 255 && data[0] == 36 => {
                    data[5] = 0xf0;
                    data[6] = 0xff;
                }
                3 if id == 255 && data[0] == 106 => data[2] = 2,
                _ => (),
            }
            rest = &mut rest[2 + length..];
        }
        assert_eq!(
            AssociationContext::build(
                Ticket {
                    epoch: 1,
                    serial: 2
                },
                &j,
                &b,
                &response_metadata(bytes)
            )
            .is_ok(),
            kind == 1,
            "kind{kind}"
        );
    }
}

#[test]
fn final_vht_operation_uses_source_capability_width_not_raw_segments_alone() {
    let mut j = modern_join();
    j.request = wire::AssociationRequest::new_modern(
        1,
        10,
        modern_ies(false),
        Band::Ghz5,
        Mode::He,
        Width::Mhz160,
    )
    .unwrap();
    let mut b = beacon(&j);
    let mut elements = modern_ies(true);
    for bytes in [&mut b.elements, &mut elements] {
        let mut rest = bytes.as_mut_slice();
        while !rest.is_empty() {
            let n = usize::from(rest[1]);
            if rest[0] == 191 {
                rest[2..6].copy_from_slice(&0_u32.to_le_bytes());
            }
            if rest[0] == 192 {
                rest[4] = 50;
            } // raw ccfs1 suggests160, source ignores it for peer width0.
            rest = &mut rest[2 + n..];
        }
    }
    assert!(
        AssociationContext::build(
            Ticket {
                epoch: 1,
                serial: 2
            },
            &j,
            &b,
            &response_metadata(elements)
        )
        .is_err()
    );
}

#[test]
fn review_eht_basic_mcs_cannot_ignore_advertised_wider_local_map() {
    let mut local = modern_ies(false);
    let mutate = |bytes: &mut Vec<u8>, own: bool| {
        let mut at = 0;
        while at < bytes.len() {
            let len = usize::from(bytes[at + 1]);
            let id = bytes[at];
            let b = &mut bytes[at + 2..at + 2 + len];
            if id == 255 && b[0] == 108 {
                b[12..15].fill(0x22);
                b[15..18].fill(if own { 0x11 } else { 0x22 });
            }
            if id == 255 && b[0] == 106 {
                b[2..6].fill(0x22);
            }
            at += 2 + len;
        }
    };
    mutate(&mut local, true);
    let mut j = modern_join();
    j.request =
        wire::AssociationRequest::new_modern(1, 10, local, Band::Ghz5, Mode::Eht, Width::Mhz80)
            .unwrap();
    let mut b = beacon(&j);
    mutate(&mut b.elements, false);
    let mut elements = modern_ies(true);
    mutate(&mut elements, false);
    let result = AssociationContext::build(
        Ticket {
            epoch: 1,
            serial: 2,
        },
        &j,
        &b,
        &response_metadata(elements),
    );
    assert!(
        result.is_err(),
        "local advertised160 map fails actual EHT basic2NSS even when selected80 passes, got {result:?}"
    );
}

#[test]
fn basic_eht_local_rx_tx_orientation_is_not_selected_common_orientation() {
    fn maps(bytes: &mut [u8], cap: u8, basic: u8) {
        let mut at = 0;
        while at < bytes.len() {
            let n = usize::from(bytes[at + 1]);
            let id = bytes[at];
            let b = &mut bytes[at + 2..at + 2 + n];
            if id == 255 && b[0] == 108 {
                b[12..].fill(cap);
            }
            if id == 255 && b[0] == 106 {
                b[2..6].fill(basic);
            }
            at += 2 + n;
        }
    }
    let mut own = modern_ies(false);
    maps(&mut own, 0x12, 0);
    let mut j = modern_join();
    j.request =
        wire::AssociationRequest::new_modern(1, 10, own, Band::Ghz5, Mode::Eht, Width::Mhz80)
            .unwrap();
    for (basic, accepted) in [(0x12, true), (0x21, false)] {
        let mut beacon = beacon(&j);
        maps(&mut beacon.elements, 0x22, basic);
        let mut response = modern_ies(true);
        maps(&mut response, 0x22, basic);
        let result = AssociationContext::build(
            Ticket {
                epoch: 1,
                serial: 2,
            },
            &j,
            &beacon,
            &response_metadata(response),
        );
        assert_eq!(result.is_ok(), accepted, "basic {basic:#x}: {result:?}");
    }
}

#[test]
fn unselected_ap_mlo_never_changes_single_link_context_bssid_or_outgoing_request() {
    let j = modern_join();
    let mut b = beacon(&j);
    let baseline = AssociationContext::build(
        Ticket {
            epoch: 1,
            serial: 2,
        },
        &j,
        &b,
        &response_metadata(modern_ies(true)),
    )
    .unwrap();
    let mut raw = Vec::new();
    extension(&mut raw, 107, &[0, 0, 7, 2, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]);
    b.elements.extend_from_slice(&raw);
    let mut response = modern_ies(true);
    response.extend_from_slice(&raw);
    let c = AssociationContext::build(
        Ticket {
            epoch: 1,
            serial: 2,
        },
        &j,
        &b,
        &response_metadata(response),
    )
    .unwrap();
    assert_eq!(c.intent(), AssociationIntent::SingleLink);
    assert_eq!(c.bssid(), AP);
    assert_eq!(c.definition(), baseline.definition());
    assert_eq!(c.negotiated().eht, baseline.negotiated().eht);
    assert_eq!(c.negotiated().peer().unselected_multi_link_elements(), raw);
    assert!(
        j.request
            .modern()
            .unwrap()
            .capabilities()
            .unselected_multi_link_elements()
            .is_empty()
    );
    assert_eq!(j.request.elements(), modern_ies(false));
    let mut requested = modern_ies(false);
    requested.extend_from_slice(&raw);
    assert!(matches!(
        wire::AssociationRequest::new_modern(1, 10, requested, Band::Ghz5, Mode::Eht, Width::Mhz80),
        Err(wire::Error::Unsupported(_))
    ));
}
#[test]
fn malformed_unselected_ml_body_and_fragment_cannot_replace_single_link_operation() {
    let j = modern_join();
    let mut b = beacon(&j);
    let mut response = modern_ies(true);
    let mut body = vec![0; 254];
    body[..3].copy_from_slice(&[7, 0, 255]);
    let mut raw = Vec::new();
    extension(&mut raw, 107, &body);
    ie(&mut raw, 242, &[61, 2, 149, 3, 192, 3, 3, 155, 171]);
    b.elements.extend_from_slice(&raw);
    response.extend_from_slice(&raw);
    let c = AssociationContext::build(
        Ticket {
            epoch: 1,
            serial: 2,
        },
        &j,
        &b,
        &response_metadata(response),
    )
    .unwrap();
    assert_eq!(c.intent(), AssociationIntent::SingleLink);
    assert_eq!(c.bssid(), AP);
    assert_eq!(c.channel().number, 36);
    assert_eq!(c.definition().center1_mhz, 5210);
    assert_eq!(c.negotiated().peer().unselected_multi_link_elements(), raw);
}

#[test]
fn review_source_eht_basic_local_support_does_not_require_peer_common_envelope() {
    let mutate = |bytes: &mut Vec<u8>, own: bool| {
        let mut at = 0;
        while at < bytes.len() {
            let len = usize::from(bytes[at + 1]);
            let id = bytes[at];
            let b = &mut bytes[at + 2..at + 2 + len];
            if id == 255 && b[0] == 108 {
                b[12..18].fill(if own { 0x22 } else { 0x12 });
            }
            if id == 255 && b[0] == 106 {
                b[2..6].fill(0x22);
            }
            at += 2 + len;
        }
    };
    let mut local = modern_ies(false);
    mutate(&mut local, true);
    let mut j = modern_join();
    j.request =
        wire::AssociationRequest::new_modern(1, 10, local, Band::Ghz5, Mode::Eht, Width::Mhz80)
            .unwrap();
    assert!(
        j.request
            .modern()
            .unwrap()
            .capabilities()
            .meets_eht_basic([0x22; 4])
    );
    let mut b = beacon(&j);
    mutate(&mut b.elements, false);
    let mut elements = modern_ies(true);
    mutate(&mut elements, false);
    let peer = phy::Capabilities::parse(Band::Ghz5, phy::Role::AccessPoint, &elements).unwrap();
    let n = phy::Negotiated::between(
        j.request.modern().unwrap().capabilities(),
        &peer,
        Mode::Eht,
        Width::Mhz80,
    )
    .unwrap();
    assert!(n.rx_nss > 0 && n.tx_nss > 0);
    let result = AssociationContext::build(
        Ticket {
            epoch: 1,
            serial: 2,
        },
        &j,
        &b,
        &response_metadata(elements),
    );
    assert!(
        result.is_ok(),
        "source local requirement passes; usable asymmetric common envelope is not a second Basic predicate: {result:?}"
    );
}

#[test]
fn default_ht_vht_basic_claims_remain_raw_without_rejecting_usable_profiles() {
    for (mode, width) in [(Mode::Ht, Width::Mhz40), (Mode::Vht, Width::Mhz80)] {
        for basic in [0, 0x5555_u16, 0xffff] {
            let mut j = modern_join();
            j.request = wire::AssociationRequest::new_modern(
                1,
                10,
                modern_ies(false),
                Band::Ghz5,
                mode,
                width,
            )
            .unwrap();
            let mut b = beacon(&j);
            let mut response = modern_ies(true);
            for bytes in [&mut b.elements, &mut response] {
                edit_elements(bytes, |id, data| {
                    if id == 61 {
                        data[6..16].fill(0xff);
                    }
                    if id == 192 {
                        data[3..5].copy_from_slice(&basic.to_le_bytes());
                    }
                });
            }
            let c = AssociationContext::build(
                Ticket {
                    epoch: 1,
                    serial: 2,
                },
                &j,
                &b,
                &response_metadata(response),
            )
            .unwrap();
            assert_eq!(c.negotiated().mode, mode);
            assert_eq!(c.definition().width, width);
            assert!(c.negotiated().rx_nss > 0 && c.negotiated().tx_nss > 0);
            assert_eq!(
                &c.operations().ht.as_ref().unwrap().basic_mcs[..10],
                &[0xff; 10]
            );
            assert_eq!(c.operations().vht.as_ref().unwrap().basic_mcs, basic);
        }
    }
}
#[test]
fn zero_he_basic_compatibility_cannot_invent_streams_or_bypass_peer_one_ss() {
    let j = modern_join();
    let b = beacon(&j);
    let mut response = modern_ies(true);
    edit_elements(&mut response, |id, data| {
        if id == 255 && data[0] == 36 {
            data[5..7].fill(0);
        }
    });
    let c = AssociationContext::build(
        Ticket {
            epoch: 1,
            serial: 2,
        },
        &j,
        &b,
        &response_metadata(response.clone()),
    )
    .unwrap();
    assert_eq!((c.negotiated().rx_nss, c.negotiated().tx_nss), (1, 1));
    assert_eq!(c.operations().he.as_ref().unwrap().basic_mcs, 0);
    for start in [18, 20] {
        let mut broken = response.clone();
        edit_elements(&mut broken, |id, data| {
            if id == 255 && data[0] == 35 {
                data[start..start + 2].fill(0xff);
            }
        });
        assert!(
            AssociationContext::build(
                Ticket {
                    epoch: 1,
                    serial: 2
                },
                &j,
                &b,
                &response_metadata(broken)
            )
            .is_err()
        );
    }
}
#[test]
fn full_local_he_source_slots_are_explicit_and_preserve_normal_one_width_semantics() {
    let own = modern_ies(false);
    let local = phy::Capabilities::parse(Band::Ghz5, phy::Role::Station, &own).unwrap();
    let he = local.he().unwrap();
    let m = he.mcs_80;
    let source = [m, he.mcs_160.unwrap(), phy::McsMaps { rx: 0, tx: 0 }];
    assert_eq!(he.mcs_80p80, None);
    assert_eq!(local.local_he_source_maps(), None);
    let mut j = modern_join();
    let mut b = beacon(&j);
    let mut response = modern_ies(true);
    for bytes in [&mut b.elements, &mut response] {
        edit_elements(bytes, |id, data| {
            if id == 255 && data[0] == 35 {
                data[18..22].copy_from_slice(&[0xf0, 0xff, 0xf0, 0xff]);
            }
            if id == 255 && data[0] == 36 {
                data[5..7].copy_from_slice(&0xfff0_u16.to_le_bytes());
            }
        });
    }
    let result = AssociationContext::build(
        Ticket {
            epoch: 1,
            serial: 2,
        },
        &j,
        &b,
        &response_metadata(response.clone()),
    );
    assert!(matches!(
        result,
        Err(Error::Phy(phy::Error::Missing(
            "complete local HE source MCS slots"
        )))
    ));
    let local = local.with_local_he_source_maps(source).unwrap();
    let mut changed = own.clone();
    edit_elements(&mut changed, |id, b| {
        if id == 45 {
            b[0] ^= 1;
        }
    });
    assert!(
        wire::AssociationRequest::new_modern_with_local(
            1,
            10,
            changed,
            local.clone(),
            Mode::Eht,
            Width::Mhz80
        )
        .is_err()
    );
    j.request =
        wire::AssociationRequest::new_modern_with_local(1, 10, own, local, Mode::Eht, Width::Mhz80)
            .unwrap();
    let c = AssociationContext::build(
        Ticket {
            epoch: 1,
            serial: 2,
        },
        &j,
        &b,
        &response_metadata(response),
    )
    .unwrap();
    assert_eq!(c.negotiated().local().local_he_source_maps(), Some(&source));
    assert_eq!(c.negotiated().local().he().unwrap().mcs_80p80, None);
    assert_eq!((c.negotiated().rx_nss, c.negotiated().tx_nss), (1, 1));
}

#[test]
fn transmitted_bssid_ignores_opaque_nested_profiles_and_keeps_outer_facts() {
    let j = modern_join();
    let mut bss = beacon(&j);
    let mut nested = vec![1, 0, 25]; // max indicator, opaque subelement
    ie(&mut nested, 83, &[0x11, 0]);
    ie(&mut nested, 0, b"other");
    ie(&mut nested, 85, &[1, 9, 8]);
    ie(&mut nested, 3, &[149]);
    ie(&mut nested, 48, &[1, 0, 0, 0]);
    ie(&mut bss.elements, 71, &nested);
    // An invalid inner subelement still cannot become profile permission.
    ie(&mut bss.elements, 71, &[255, 0, 255]);
    let raw = bss.elements.clone();
    let mut station = Station::new(LOCAL).unwrap();
    let Action::Configure {
        context: Some(c), ..
    } = configuration(&mut station, j.clone(), bss).unwrap()
    else {
        panic!("modern context")
    };
    assert_eq!(c.bssid(), j.bssid);
    assert_eq!(c.beacon().transmitter, j.bssid);
    assert_eq!(c.beacon().ssid, Some(vec![b'x']));
    assert_eq!(c.beacon().capabilities, 1);
    assert_eq!(c.beacon().elements, raw);
    assert_eq!((c.dtim_count(), c.dtim_period()), (0, 3));
    assert_eq!(c.channel(), j.channel);
    assert_eq!(c.definition().center1_mhz, 5210);
    assert_eq!(c.operations().ht.as_ref().unwrap().primary, 36);
}

#[test]
fn transmitted_bssid_keeps_outer_bounds_and_refuses_profile_selection() {
    let j = modern_join();
    let mut bss = beacon(&j);
    bss.elements.extend_from_slice(&[71, 5, 1]);
    assert!(configuration(&mut Station::new(LOCAL).unwrap(), j.clone(), bss).is_err());
    let mut bss = beacon(&j);
    ie(&mut bss.elements, 85, &[1, 9, 8]);
    assert!(matches!(
        configuration(&mut Station::new(LOCAL).unwrap(), j.clone(), bss),
        Err(Error::Unsupported(_))
    ));
    let mut bss = beacon(&j);
    bss.transmitter = Mac([4; 6]);
    ie(&mut bss.elements, 71, &[1]);
    assert!(matches!(
        configuration(&mut Station::new(LOCAL).unwrap(), j, bss),
        Err(Error::Unsupported(_))
    ));
}
