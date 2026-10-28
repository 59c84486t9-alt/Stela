use super::*;
use crate::net::wifi::{RadioStatus, RawRate, scan::Ticket};
use alloc::vec;

const NET: &[u8] = b"net";
const A: Mac = Mac([2, 0, 0, 0, 0, 1]);
const B: Mac = Mac([2, 0, 0, 0, 0, 2]);
const C: Mac = Mac([2, 0, 0, 0, 0, 3]);
const COLOC: u8 = COLOC_AP;

fn channel(band: Band, number: u16) -> Channel {
    let frequency_mhz = match band {
        Band::Ghz2 => 2407 + 5 * number,
        Band::Ghz5 => 5000 + 5 * number,
        Band::Ghz6 => 5950 + 5 * number,
    };
    Channel {
        band,
        number,
        frequency_mhz,
    }
}
fn six(number: u16) -> Channel {
    channel(Band::Ghz6, number)
}
fn ie(id: u8, data: &[u8]) -> Vec<u8> {
    [&[id, data.len() as u8][..], data].concat()
}
/// One neighbor AP info of `entries`, each `length` bytes long.
fn info(op_class: u8, channel: u8, length: u8, entries: &[Vec<u8>]) -> Vec<u8> {
    let mut out = vec![(entries.len() as u8 - 1) << 4, length, op_class, channel];
    for entry in entries {
        assert_eq!(entry.len(), usize::from(length));
        out.extend_from_slice(entry);
    }
    out
}
/// An ieee80211_tbtt_info_ge_11 of 13 bytes, with the PSD.
fn long(bssid: Mac, short: u32, params: u8, psd: i8) -> Vec<u8> {
    [
        &[0][..],
        &bssid.0,
        &short.to_le_bytes(),
        &[params, psd as u8],
    ]
    .concat()
}
fn bss(bssid: Mac, channel: Channel, elements: Vec<u8>) -> result::Bss {
    result::Bss {
        ticket: Ticket(0),
        kind: result::Kind::Beacon,
        bssid,
        transmitter: bssid,
        timestamp: 0,
        beacon_interval: 100,
        capabilities: 0x11,
        channel,
        observed: RadioStatus {
            band: channel.band,
            channel: channel.number,
            frequency_mhz: channel.frequency_mhz,
            signal_dbm: None,
            chain_signal_dbm: [None; 4],
            rate: RawRate {
                layout: 0,
                words: [0; 4],
            },
            rx_rate: None,
            tsf: None,
        },
        signal_dbm: None,
        ssid: ssid(&elements).map(<[u8]>::to_vec),
        elements,
    }
}

#[test]
fn short_ssid_is_the_ieee_crc32() {
    assert_eq!(short_ssid(b"123456789"), 0xcbf4_3926);
}

#[test]
fn colocated_aps_parse_like_cfg80211_parse_colocated_ap() {
    let rnr = [
        // A 5 GHz neighbor is not a 6 GHz scan target.
        info(115, 36, 13, &[long(A, 1, COLOC, 0)]),
        info(
            131,
            37,
            13,
            &[
                long(A, 7, COLOC | SAME_SSID | PROBE_ACTIVE | COLOC_ESS, -6),
                // Not colocated, then a duplicate BSSID on the same channel.
                long(B, 8, 0, 0),
                long(A, 9, COLOC, 0),
            ],
        ),
        // ieee80211_tbtt_info_7_8_9 with its PSD, and without a short SSID.
        info(
            133,
            33,
            9,
            &[[&[0][..], &C.0, &[COLOC | MULTI_BSSID, 5]].concat()],
        ),
    ]
    .concat();
    let elements = [ie(0, NET), ie(201, &rnr)].concat();
    let aps = colocated(&elements);
    assert_eq!(aps.len(), 2);
    assert_eq!(aps[0].bssid, A);
    assert_eq!(aps[0].channel, 37);
    assert_eq!(aps[0].ssid.as_deref(), Some(NET));
    assert_eq!(aps[0].short_ssid, Some(short_ssid(NET)));
    assert!(aps[0].unsolicited_probe && aps[0].colocated_ess);
    assert_eq!(aps[0].psd_20, -6);
    assert_eq!(
        (
            aps[1].bssid,
            aps[1].channel,
            aps[1].short_ssid,
            aps[1].psd_20
        ),
        (C, 33, None, 5)
    );
    assert!(aps[1].multi_bss && !aps[1].transmitted_bssid);
    // A disabled MLD link is ignored.
    let mut disabled = long(B, 1, COLOC, 0);
    disabled.extend_from_slice(&[0, 0, 0x20]);
    let elements = [ie(0, NET), ie(201, &info(131, 5, 16, &[disabled]))].concat();
    assert!(colocated(&elements).is_empty());
    // No SSID, an overrunning count or a trailing byte drops the whole report.
    assert!(colocated(&ie(201, &rnr)).is_empty());
    let mut overrun = info(131, 37, 13, &[long(A, 1, COLOC, 0)]);
    overrun[0] = 1 << 4;
    assert!(colocated(&[ie(0, NET), ie(201, &overrun)].concat()).is_empty());
    let trailing = [rnr.clone(), vec![0]].concat();
    assert!(colocated(&[ie(0, NET), ie(201, &trailing)].concat()).is_empty());
}

#[test]
fn split_scans_follow_cfg80211_scan_6ghz() {
    let channels = vec![channel(Band::Ghz2, 1), six(5), six(37), six(33)];
    let request = |ssids: Vec<Vec<u8>>| Request::new(channels.clone(), ssids, vec![]).unwrap();
    let first = first_part(&request(vec![vec![]])).unwrap().unwrap();
    assert_eq!(first.channels(), &[channel(Band::Ghz2, 1)]);
    assert!(
        first_part(&Request::new(vec![six(5)], vec![], vec![]).unwrap())
            .unwrap()
            .is_none()
    );

    let rnr = [
        info(
            131,
            33,
            13,
            &[long(A, 0, COLOC | SAME_SSID | PROBE_ACTIVE, 3)],
        ),
        info(131, 37, 13, &[long(B, 0, COLOC | SAME_SSID | COLOC_ESS, 4)]),
        info(131, 5, 13, &[long(C, 0, COLOC | MULTI_BSSID, 0)]),
    ]
    .concat();
    let known = [bss(
        A,
        channel(Band::Ghz2, 1),
        [ie(0, NET), ie(201, &rnr)].concat(),
    )];
    let colocated = Options {
        colocated: true,
        bssid: None,
    };

    // Without NL80211_SCAN_FLAG_COLOCATED_6GHZ every 6 GHz channel is scanned.
    let all = second_part(&request(vec![vec![]]), Options::default(), &known)
        .unwrap()
        .unwrap();
    assert_eq!(all.channels(), &[six(5), six(37), six(33)]);
    assert!(all.six_ghz().is_empty());

    // A wildcard scan takes the PSCs and the reported APs, skipping the
    // multi-BSSID member that is not transmitted.
    let wild = second_part(&request(vec![vec![]]), colocated, &known)
        .unwrap()
        .unwrap();
    assert_eq!(wild.channels(), &[six(5), six(37), six(33)]);
    let targets = wild.six_ghz();
    assert_eq!(targets.len(), 2);
    assert_eq!((targets[0].channel_index, targets[0].bssid), (2, A));
    assert_eq!(targets[0].short_ssid, Some(short_ssid(NET)));
    assert!(targets[0].unsolicited_probe && !targets[0].psc_no_listen);
    assert_eq!((targets[1].channel_index, targets[1].bssid), (1, B));
    assert_eq!(targets[1].psd_20, 4);

    // A direct scan whose ESS is colocated skips the PSC listen.
    let direct = second_part(&request(vec![NET.to_vec()]), colocated, &known)
        .unwrap()
        .unwrap();
    assert_eq!(direct.channels(), &[six(33), six(37)]);
    assert_eq!(direct.six_ghz().len(), 2);
    assert!(!direct.six_ghz()[0].psc_no_listen);
    assert!(direct.six_ghz()[1].psc_no_listen);

    // Another SSID matches no report; a BSSID keeps only its own AP.
    let other = second_part(&request(vec![b"other".to_vec()]), colocated, &known)
        .unwrap()
        .unwrap();
    assert_eq!(other.channels(), &[six(5), six(37)]);
    assert!(other.six_ghz().is_empty());
    let only_a = Options {
        bssid: Some(A),
        ..colocated
    };
    let only = second_part(&request(vec![vec![]]), only_a, &known)
        .unwrap()
        .unwrap();
    assert_eq!(only.six_ghz().len(), 1);
    assert_eq!(only.six_ghz()[0].bssid, A);

    // A known 6 GHz BSS that the scan names is probed directly.
    let named = [bss(C, six(33), ie(0, NET))];
    let direct_bssid = Options {
        bssid: Some(C),
        ..colocated
    };
    let only_six = Request::new(vec![six(33)], vec![vec![]], vec![]).unwrap();
    let probed = second_part(&only_six, direct_bssid, &named)
        .unwrap()
        .unwrap();
    assert_eq!(probed.six_ghz()[0].bssid, C);
    // Nothing selected ends the scan.
    assert!(second_part(&only_six, colocated, &[]).unwrap().is_none());
}
