use super::*;
use crate::net::{
    Mac,
    wifi::{RadioStatus, RawRate, frame::Mpdu, security::SecurityStatus},
};
use alloc::vec;

const LOCAL: Mac = Mac([2, 1, 2, 3, 4, 5]);
const AP: Mac = Mac([2, 6, 7, 8, 9, 10]);
const CH1: Channel = Channel {
    band: Band::Ghz2,
    number: 1,
    frequency_mhz: 2412,
};
const CH6: Channel = Channel {
    band: Band::Ghz2,
    number: 6,
    frequency_mhz: 2437,
};
const CH36: Channel = Channel {
    band: Band::Ghz5,
    number: 36,
    frequency_mhz: 5180,
};
const SIX1: Channel = Channel {
    band: Band::Ghz6,
    number: 1,
    frequency_mhz: 5955,
};
const SIX5: Channel = Channel {
    band: Band::Ghz6,
    number: 5,
    frequency_mhz: 5975,
};
struct TestPolicy {
    receive: bool,
    probe: bool,
    deny_six: bool,
    deny_six_ghz_five: bool,
}
impl Policy for TestPolicy {
    fn allow_receive(&mut self, channel: Channel) -> bool {
        self.receive
            && !(self.deny_six && channel == CH6)
            && !(self.deny_six_ghz_five && channel == SIX5)
    }
    fn allow_probe(&mut self, _: Channel) -> bool {
        self.probe
    }
    fn lookup_channel(&mut self, band: Band, number: u16) -> Option<Channel> {
        [CH1, CH6, CH36, SIX1, SIX5]
            .into_iter()
            .find(|channel| channel.band == band && channel.number == number)
    }
}
fn policy() -> TestPolicy {
    TestPolicy {
        receive: true,
        probe: true,
        deny_six: false,
        deny_six_ghz_five: false,
    }
}
fn request() -> Request {
    Request::new(vec![CH1, CH36], vec![], vec![]).unwrap()
}
fn scanner() -> (Scanner, Ticket) {
    let mut scanner = Scanner::new(LOCAL).unwrap();
    let ticket = scanner.begin(request(), 100, 1000, &mut policy()).unwrap();
    scanner
        .validate_submission(ticket, 100, &mut policy())
        .unwrap();
    scanner.submitted(ticket).unwrap();
    (scanner, ticket)
}
fn frame(control: u16, destination: Mac, ies: &[u8], channel: Channel) -> Mpdu {
    let mut bytes = vec![0; 36];
    bytes[..2].copy_from_slice(&control.to_le_bytes());
    bytes[4..10].copy_from_slice(&destination.0);
    bytes[10..16].copy_from_slice(&AP.0);
    bytes[16..22].copy_from_slice(&AP.0);
    bytes[24..32].copy_from_slice(&0x123456789abcdef0_u64.to_le_bytes());
    bytes[32..34].copy_from_slice(&100_u16.to_le_bytes());
    bytes[34..36].copy_from_slice(&0x11_u16.to_le_bytes());
    bytes.extend_from_slice(ies);
    Mpdu::new(
        bytes,
        RadioStatus {
            band: channel.band,
            channel: channel.number,
            frequency_mhz: channel.frequency_mhz,
            signal_dbm: Some(-42),
            chain_signal_dbm: [Some(-44), None, None, None],
            rate: RawRate {
                layout: 1,
                words: [3, 0, 0, 0],
            },
            rx_rate: None,
            tsf: None,
        },
        SecurityStatus::default(),
    )
    .unwrap()
}

#[test]
fn withdrawn_prepublication_request_cannot_withdraw_a_submitted_generation() {
    let mut scanner = Scanner::new(LOCAL).unwrap();
    let mut p = policy();
    let request = Request::new(vec![CH36], vec![], vec![]).unwrap();
    let old = scanner.begin(request, 0, 100, &mut p).unwrap();
    let request = scanner.withdraw_unsubmitted(old).unwrap();
    assert_eq!(scanner.phase(), Phase::Idle);
    let next = scanner.begin(request, 1, 100, &mut p).unwrap();
    assert!(matches!(
        scanner.withdraw_unsubmitted(old),
        Err(Error::Stale)
    ));
    scanner.submitted(next).unwrap();
    assert!(matches!(
        scanner.withdraw_unsubmitted(next),
        Err(Error::WrongPhase)
    ));
    assert_eq!(scanner.phase(), Phase::Submitted);
    assert!(scanner.request().is_some());
}

#[test]
fn prepared_active_six_ghz_targets_do_not_bypass_probe_policy_or_indices() {
    let target = SixGhz {
        channel_index: 0,
        bssid: AP,
        short_ssid: Some(42),
        unsolicited_probe: true,
        psc_no_listen: false,
        psd_20: -70,
    };
    assert!(Request::with_six_ghz(vec![CH36], vec![vec![]], vec![], vec![target]).is_err());
    assert!(
        Request::with_six_ghz(
            vec![SIX1],
            vec![vec![]],
            vec![],
            vec![SixGhz {
                channel_index: 1,
                ..target
            }]
        )
        .is_err()
    );
    let mut scanner = Scanner::new(LOCAL).unwrap();
    let mut p = policy();
    p.probe = false;
    let request = Request::with_six_ghz(vec![SIX1], vec![vec![]], vec![], vec![target]).unwrap();
    assert!(matches!(
        scanner.begin(request, 0, 100, &mut p),
        Err(Error::Regulatory)
    ));
    p.probe = true;
    let request = Request::with_six_ghz(vec![SIX1], vec![vec![]], vec![], vec![target]).unwrap();
    assert!(scanner.begin(request, 1, 100, &mut p).is_ok());
}
#[test]
fn six_ghz_passive_scan_preserves_policy_and_he_operating_channel() {
    let mut policy = policy();
    policy.probe = false;
    let passive = Request::new(vec![SIX1], vec![], vec![]).unwrap();
    let mut scanner = Scanner::new(LOCAL).unwrap();
    let ticket = scanner.begin(passive, 100, 1000, &mut policy).unwrap();
    scanner
        .validate_submission(ticket, 100, &mut policy)
        .unwrap();
    scanner.submitted(ticket).unwrap();
    // The first DS claim is from the wrong band. 6GHz uses
    // the complete HE Operation extension's primary channel instead.
    let mut ies = vec![3, 1, 6, 255, 12, 36, 0, 0, 2, 0, 0, 0, 5, 0, 5, 0, 6];
    let result = scanner
        .observe(
            ticket,
            &frame(0x80, Mac::BROADCAST, &ies, SIX1),
            &mut policy,
        )
        .unwrap();
    assert_eq!(result.channel, SIX5);
    assert_eq!(result.observed.channel, SIX1.number);
    assert_eq!(result.signal_dbm, None);
    assert_eq!(
        scanner
            .observe(
                ticket,
                &frame(0x50, Mac::BROADCAST, &ies, SIX1),
                &mut policy
            )
            .unwrap()
            .kind,
        result::Kind::ProbeResponse
    );
    assert_eq!(
        scanner
            .observe(
                ticket,
                &frame(0x50, Mac([2, 9, 9, 9, 9, 9]), &ies, SIX1),
                &mut policy
            )
            .unwrap_err(),
        Error::WrongPeer
    );
    policy.deny_six_ghz_five = true;
    assert_eq!(
        scanner
            .observe(
                ticket,
                &frame(0x80, Mac::BROADCAST, &ies, SIX1),
                &mut policy
            )
            .unwrap_err(),
        Error::Regulatory
    );
    policy.deny_six_ghz_five = false;
    // An advertised unknown 6GHz channel cannot fall back to observed RX.
    ies[12] = 233;
    assert_eq!(
        scanner
            .observe(
                ticket,
                &frame(0x80, Mac::BROADCAST, &ies, SIX1),
                &mut policy
            )
            .unwrap_err(),
        Error::Regulatory
    );
    // Incomplete optional fields carry no corrected channel, matching
    // cfg80211; the admitted receive observation stays available.
    let partial = [255, 7, 36, 0, 0, 2, 0, 0, 0];
    assert_eq!(
        scanner
            .observe(
                ticket,
                &frame(0x80, Mac::BROADCAST, &partial, SIX1),
                &mut policy
            )
            .unwrap()
            .channel,
        SIX1
    );
    policy.receive = false;
    assert_eq!(
        scanner
            .observe(ticket, &frame(0x80, Mac::BROADCAST, &[], SIX1), &mut policy)
            .unwrap_err(),
        Error::Regulatory
    );
    // mt7925_mcu_hw_scan probes 6 GHz with or without RNR targets.
    for channels in [vec![SIX1], vec![CH1, SIX1]] {
        assert!(
            Request::new(channels, vec![vec![]], vec![])
                .unwrap()
                .active()
        );
    }
}

#[test]
fn explicit_request_limits_never_fall_back_to_full_scan() {
    assert!(matches!(
        Request::new(vec![], vec![], vec![]),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        Request::new(vec![CH1; 65], vec![], vec![]),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        Request::new(vec![CH1, CH1], vec![], vec![]),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        Request::new(vec![CH1], vec![vec![]; 5], vec![]),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        Request::new(vec![CH1], vec![vec![0; 33]], vec![]),
        Err(Error::Invalid(_))
    ));
    assert!(matches!(
        Request::new(vec![CH1], vec![], vec![0; 385]),
        Err(Error::Invalid(_))
    ));
    for ies in [vec![221], vec![221, 2, 1], vec![0, 0]] {
        assert!(matches!(
            Request::new(vec![CH1], vec![], ies),
            Err(Error::Invalid(_))
        ));
    }
}

#[test]
fn passive_active_wildcard_and_binary_ssids_remain_distinct() {
    let mut p = policy();
    p.probe = false;
    let mut scanner = Scanner::new(LOCAL).unwrap();
    let passive = Request::new(vec![CH1], vec![], vec![]).unwrap();
    assert!(!passive.active());
    scanner.begin(passive, 0, 100, &mut p).unwrap();
    let active = Request::new(vec![CH1], vec![vec![]], vec![]).unwrap();
    assert!(active.active());
    assert_eq!(
        Scanner::new(LOCAL).unwrap().begin(active, 0, 100, &mut p),
        Err(Error::Regulatory)
    );
    let binary = Request::new(vec![CH1], vec![vec![0, 255, 1]], vec![221, 1, 0xab]).unwrap();
    assert_eq!(binary.ssids(), &[vec![0, 255, 1]]);
    assert_eq!(binary.extra_elements(), [221, 1, 0xab]);
}

#[test]
fn canonical_channel_and_regulatory_checks_precede_start() {
    let mut bad = CH1;
    bad.frequency_mhz = 5180;
    let bad_request = Request::new(vec![bad], vec![], vec![]).unwrap();
    assert_eq!(
        Scanner::new(LOCAL)
            .unwrap()
            .begin(bad_request, 0, 100, &mut policy()),
        Err(Error::Regulatory)
    );
    let mut denied = policy();
    denied.receive = false;
    assert_eq!(
        Scanner::new(LOCAL)
            .unwrap()
            .begin(request(), 0, 100, &mut denied),
        Err(Error::Regulatory)
    );
    assert!(Scanner::new(Mac::BROADCAST).is_err());
    assert!(Scanner::new(Mac([0; 6])).is_err());
}

#[test]
fn success_requires_submission_terminal_event_and_retirement() {
    let mut scanner = Scanner::new(LOCAL).unwrap();
    let ticket = scanner.begin(request(), 0, 100, &mut policy()).unwrap();
    assert_eq!(
        scanner.completed(ticket, Outcome::Completed),
        Err(Error::WrongPhase)
    );
    assert_eq!(
        scanner.retire(ticket, Retirement::Confirmed),
        Err(Error::WrongPhase)
    );
    scanner
        .validate_submission(ticket, 0, &mut policy())
        .unwrap();
    scanner.submitted(ticket).unwrap();
    assert_eq!(
        scanner.begin(request(), 1, 100, &mut policy()),
        Err(Error::Busy)
    );
    scanner.completed(ticket, Outcome::Completed).unwrap();
    assert!(scanner.request().is_some());
    assert_eq!(scanner.phase(), Phase::Retiring);
    assert_eq!(
        scanner.retire(ticket, Retirement::Confirmed).unwrap(),
        Some(Outcome::Completed)
    );
    assert_eq!(scanner.phase(), Phase::Idle);
    assert!(scanner.request().is_none());
    assert_eq!(
        scanner.completed(ticket, Outcome::Completed),
        Err(Error::Stale)
    );
}

#[test]
fn timeout_and_cancel_keep_resources_until_drain() {
    let (mut scanner, ticket) = scanner();
    assert!(!scanner.poll(ticket, 1099).unwrap());
    assert!(scanner.poll(ticket, 1100).unwrap());
    assert_eq!(scanner.phase(), Phase::Cancelling);
    assert!(!scanner.cancel(ticket).unwrap());
    assert!(scanner.request().is_some());
    assert_eq!(
        scanner.begin(request(), 1200, 100, &mut policy()),
        Err(Error::Busy)
    );
    assert_eq!(
        scanner.retire(ticket, Retirement::Confirmed),
        Err(Error::WrongPhase)
    );
    // Natural completion racing cancellation is still reported aborted.
    scanner.completed(ticket, Outcome::Completed).unwrap();
    assert_eq!(
        scanner.retire(ticket, Retirement::Confirmed).unwrap(),
        Some(Outcome::Aborted)
    );
}

#[test]
fn uncertain_retirement_requires_independent_checked_reset() {
    let (mut scanner, ticket) = scanner();
    scanner.completed(ticket, Outcome::Aborted).unwrap();
    assert_eq!(scanner.retire(ticket, Retirement::Uncertain).unwrap(), None);
    assert_eq!(scanner.phase(), Phase::Quarantined);
    assert!(scanner.request().is_some());
    assert_eq!(
        scanner.retire(ticket, Retirement::Confirmed),
        Err(Error::WrongPhase)
    );
    assert_eq!(
        scanner.begin(request(), 200, 100, &mut policy()),
        Err(Error::Busy)
    );
    // Pure protocol fixture has no physical radio, DMA or old event users.
    assert_eq!(
        // SAFETY: the model device is stopped and drained, so nothing still uses what this
        // releases.
        unsafe { scanner.reset_drained(ticket) }.unwrap(),
        Outcome::Aborted
    );
    let newer = scanner.begin(request(), 200, 100, &mut policy()).unwrap();
    assert_ne!(newer, ticket);
    assert_eq!(
        scanner.completed(ticket, Outcome::Completed),
        Err(Error::Stale)
    );
    assert_eq!(scanner.phase(), Phase::Starting);
}

#[test]
fn real_start_rejection_and_clock_errors_never_make_success() {
    let (mut scanner, ticket) = scanner();
    assert_eq!(scanner.poll(ticket, 99), Err(Error::ClockRegressed));
    scanner.start_rejected(ticket, 0x17).unwrap();
    assert_eq!(
        scanner.retire(ticket, Retirement::Confirmed).unwrap(),
        Some(Outcome::Failed(0x17))
    );
    assert_eq!(
        scanner.begin(request(), u64::MAX, 1, &mut policy()),
        Err(Error::Overflow)
    );
}

#[test]
fn observed_beacon_preserves_binary_ssid_unknown_ies_and_exact_fixed_fields() {
    let (scanner, ticket) = scanner();
    let ies = [0, 3, 0, 255, 1, 221, 2, 0xab, 0xcd];
    let bss = scanner
        .observe(
            ticket,
            &frame(0x80, Mac::BROADCAST, &ies, CH1),
            &mut policy(),
        )
        .unwrap();
    assert_eq!(bss.ticket, ticket);
    assert_eq!(bss.kind, result::Kind::Beacon);
    assert_eq!(bss.bssid, AP);
    assert_eq!(bss.timestamp, 0x123456789abcdef0);
    assert_eq!(bss.beacon_interval, 100);
    assert_eq!(bss.capabilities, 0x11);
    assert_eq!(bss.ssid, Some(vec![0, 255, 1]));
    assert_eq!(bss.elements, ies);
    assert_eq!(bss.signal_dbm, Some(-42));
}

#[test]
fn receiver_filter_matches_initial_linux_station_scan_profile() {
    let (scanner, ticket) = scanner();
    assert!(
        scanner
            .observe(ticket, &frame(0x50, LOCAL, &[0, 0], CH1), &mut policy())
            .is_ok()
    );
    for (control, destination) in [(0x50, Mac::BROADCAST), (0x50, AP), (0x80, LOCAL)] {
        assert!(matches!(
            scanner.observe(
                ticket,
                &frame(control, destination, &[0, 0], CH1),
                &mut policy()
            ),
            Err(Error::WrongPeer)
        ));
    }
}

#[test]
fn neighboring_channel_correction_does_not_reuse_its_signal_measurement() {
    let (scanner, ticket) = scanner();
    let bss = scanner
        .observe(
            ticket,
            &frame(0x80, Mac::BROADCAST, &[0, 0, 3, 1, 6], CH1),
            &mut policy(),
        )
        .unwrap();
    assert_eq!(bss.channel, CH6);
    assert_eq!(bss.observed.channel, 1);
    assert_eq!(bss.observed.signal_dbm, Some(-42));
    assert_eq!(bss.signal_dbm, None);
    let mut denied = policy();
    denied.deny_six = true;
    assert!(matches!(
        scanner.observe(
            ticket,
            &frame(0x80, Mac::BROADCAST, &[0, 0, 3, 1, 6], CH1),
            &mut denied
        ),
        Err(Error::Regulatory)
    ));
}

#[test]
fn ds_ht_channel_precedence_and_unknown_channel_rules_match_linux() {
    let (scanner, ticket) = scanner();
    let mut ies = vec![3, 1, 1, 61, 22, 6];
    ies.extend_from_slice(&[0; 21]);
    assert_eq!(
        scanner
            .observe(
                ticket,
                &frame(0x80, Mac::BROADCAST, &ies, CH1),
                &mut policy()
            )
            .unwrap()
            .channel,
        CH1
    );
    ies.splice(..3, [3, 0]); // malformed DS is ignored in favor of complete HT.
    assert_eq!(
        scanner
            .observe(
                ticket,
                &frame(0x80, Mac::BROADCAST, &ies, CH1),
                &mut policy()
            )
            .unwrap()
            .channel,
        CH6
    );
    assert!(matches!(
        scanner.observe(
            ticket,
            &frame(0x80, Mac::BROADCAST, &[3, 1, 255], CH1),
            &mut policy()
        ),
        Err(Error::Regulatory)
    ));
    assert_eq!(
        scanner
            .observe(
                ticket,
                &frame(0x80, Mac::BROADCAST, &[3, 1, 255], CH36),
                &mut policy()
            )
            .unwrap()
            .channel,
        CH36
    );
}

#[test]
fn bad_scan_frames_and_old_ticket_never_reach_frontend() {
    let (mut scanner, ticket) = scanner();
    let good = frame(0x80, Mac::BROADCAST, &[0, 0], CH1);
    for variant in 0..4 {
        let mut bad = good.clone();
        match variant {
            0 => bad.fcs_error = true,
            1 => bad.monitor_only = true,
            _ => {
                let mut bytes = bad.bytes().to_vec();
                bytes[1] |= if variant == 2 { 0x40 } else { 4 };
                bad = Mpdu::new(bytes, bad.radio, bad.security).unwrap();
            }
        }
        assert!(scanner.observe(ticket, &bad, &mut policy()).is_err());
    }
    scanner.completed(ticket, Outcome::Completed).unwrap();
    assert!(matches!(
        scanner.observe(ticket, &good, &mut policy()),
        Err(Error::WrongPhase)
    ));
    scanner.retire(ticket, Retirement::Confirmed).unwrap();
    let new = scanner.begin(request(), 200, 100, &mut policy()).unwrap();
    scanner
        .validate_submission(new, 200, &mut policy())
        .unwrap();
    scanner.submitted(new).unwrap();
    assert!(matches!(
        scanner.observe(ticket, &good, &mut policy()),
        Err(Error::Stale)
    ));
    assert!(scanner.observe(new, &good, &mut policy()).is_ok());
}

#[test]
fn hidden_absent_and_malformed_ssids_are_not_conflated() {
    let (scanner, ticket) = scanner();
    for (ies, expected) in [(vec![], None), (vec![0, 0], Some(vec![]))] {
        assert_eq!(
            scanner
                .observe(
                    ticket,
                    &frame(0x80, Mac::BROADCAST, &ies, CH1),
                    &mut policy()
                )
                .unwrap()
                .ssid,
            expected
        );
    }
    for ies in [vec![0, 0, 0, 0], vec![221], vec![221, 2, 1]] {
        assert!(matches!(
            scanner.observe(
                ticket,
                &frame(0x80, Mac::BROADCAST, &ies, CH1),
                &mut policy()
            ),
            Err(Error::Invalid(_))
        ));
    }
    let mut long = vec![0, 33];
    long.extend_from_slice(&[0; 33]);
    assert!(
        scanner
            .observe(
                ticket,
                &frame(0x80, Mac::BROADCAST, &long, CH1),
                &mut policy()
            )
            .is_err()
    );
}

#[test]
fn advanced_observations_are_kept_without_advertising_probe_support() {
    let (scanner, ticket) = scanner();
    let ies = [255, 2, 107, 0x5a];
    assert_eq!(
        scanner
            .observe(
                ticket,
                &frame(0x80, Mac::BROADCAST, &ies, CH1),
                &mut policy()
            )
            .unwrap()
            .elements,
        ies
    );
    assert!(matches!(
        Request::new(vec![CH1], vec![vec![]], ies.to_vec()),
        Err(Error::Unsupported(_))
    ));
}

#[test]
fn fixed_fields_truncations_and_ie_bounds_are_rejected_without_success() {
    let (scanner, ticket) = scanner();
    let good = frame(0x80, Mac::BROADCAST, &[0, 0], CH1);
    for length in 24..36 {
        let short = Mpdu::new(
            good.bytes()[..length].to_vec(),
            good.radio.clone(),
            good.security,
        )
        .unwrap();
        assert!(matches!(
            scanner.observe(ticket, &short, &mut policy()),
            Err(Error::Invalid(_))
        ));
    }
    let long = frame(0x80, Mac::BROADCAST, &vec![0; 2302], CH1);
    assert!(matches!(
        scanner.observe(ticket, &long, &mut policy()),
        Err(Error::Invalid(_))
    ));
    let mut wrong_frequency = good.clone();
    wrong_frequency.radio.frequency_mhz = 2437;
    assert!(matches!(
        scanner.observe(ticket, &wrong_frequency, &mut policy()),
        Err(Error::WrongChannel)
    ));
}

#[test]
fn scanner_recreation_cannot_retag_old_terminal_events() {
    let (old, ticket) = scanner();
    let (mut newer, new_ticket) = scanner();
    assert_ne!(ticket, new_ticket);
    assert_eq!(
        newer.completed(ticket, Outcome::Completed),
        Err(Error::Stale)
    );
    assert_eq!(newer.phase(), Phase::Submitted);
    assert!(old.request().is_some());
    assert!(newer.request().is_some());
}

#[test]
fn queued_request_must_recheck_policy_deadline_and_cancellation_at_publication() {
    let mut scanner = Scanner::new(LOCAL).unwrap();
    let ticket = scanner.begin(request(), 100, 1000, &mut policy()).unwrap();
    let mut denied = policy();
    denied.receive = false;
    assert_eq!(
        scanner.validate_submission(ticket, 101, &mut denied),
        Err(Error::Regulatory)
    );
    assert_eq!(scanner.phase(), Phase::Starting);
    scanner
        .validate_submission(ticket, 102, &mut policy())
        .unwrap();
    assert_eq!(
        scanner.validate_submission(ticket, 1100, &mut policy()),
        Err(Error::TimedOut)
    );
    assert_eq!(scanner.phase(), Phase::Cancelling);
    assert!(scanner.request().is_some());
    assert_eq!(scanner.submitted(ticket), Err(Error::WrongPhase));
    assert_eq!(
        scanner.validate_submission(ticket, 1101, &mut policy()),
        Err(Error::WrongPhase)
    );
}

#[test]
fn terminal_scan_outcome_survives_late_retirement_poll_without_releasing_request() {
    for terminal in [Outcome::Completed, Outcome::Aborted, Outcome::Failed(7)] {
        let (mut scanner, ticket) = scanner();
        assert!(!scanner.poll(ticket, 1099).unwrap());
        scanner.completed(ticket, terminal).unwrap();
        assert!(!scanner.poll(ticket, 2200).unwrap());
        assert_eq!(scanner.phase(), Phase::Retiring);
        assert!(scanner.request().is_some());
        assert_eq!(
            scanner.retire(ticket, Retirement::Confirmed).unwrap(),
            Some(terminal)
        );
    }
}
