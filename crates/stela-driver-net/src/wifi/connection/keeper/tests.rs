//! The AP MLD links an association requests, as `ieee80211_mgd_assoc` and
//! `mt76_select_links` pick them.
use super::*;
use crate::wifi::station::tests::{beacon, join};

const AP_MLD: Mac = Mac([2, 9, 9, 9, 9, 9]);
const CHANNEL_1: Channel = Channel {
    band: Band::Ghz2,
    number: 1,
    frequency_mhz: 2412,
};
const CHANNEL_44: Channel = Channel {
    band: Band::Ghz5,
    number: 44,
    frequency_mhz: 5220,
};

/// The AP of link `link_id` of `mld` on `channel`, its RNR naming `reported`
/// APs of its own AP MLD: link ID, last BSSID byte and channel number each.
fn ap(link_id: u8, last: u8, channel: Channel, mld: Mac, reported: &[(u8, u8, u8)]) -> Bss {
    let mut elements = Basic {
        address: mld,
        link_id: Some(link_id),
        ..Basic::default()
    }
    .encode();
    for &(link_id, last, number) in reported {
        // One ieee80211_tbtt_info_ge_11 with MLD parameters, AP MLD ID 0.
        let mut rnr = vec![
            0x00, 16, 0, number, 0, 2, 0, 0, 0, 0, last, 0, 0, 0, 0, 0x40, 0, 0,
        ];
        rnr.extend_from_slice(&u16::from(link_id).to_le_bytes());
        elements.extend_from_slice(&[201, rnr.len() as u8]);
        elements.extend_from_slice(&rnr);
    }
    Bss {
        bssid: Mac([2, 0, 0, 0, 0, last]),
        channel,
        elements,
        ..beacon(&join(PortPolicy::Controlled))
    }
}

#[test]
fn an_ap_mld_names_itself_and_the_link_its_bss_is() {
    let setup = ap(0, 1, CHANNEL_44, AP_MLD, &[]);
    assert_eq!(ap_mld(&setup), Some((AP_MLD, 0)));
    let mut single = setup.clone();
    single.elements.clear();
    assert_eq!(ap_mld(&single), None);
}

/// mt76_select_links: the setup link and the first other link by ID on
/// another band, which the scan observed as a link of the same AP MLD.
#[test]
fn the_other_link_is_the_first_observed_on_another_band() {
    let setup = ap(
        0,
        1,
        CHANNEL_44,
        AP_MLD,
        &[(3, 3, 1), (2, 2, 1), (1, 4, 48)],
    );
    // Link 1 shares the setup link's band; link 3 comes after link 2.
    let same_band = ap(
        1,
        4,
        Channel {
            number: 48,
            frequency_mhz: 5240,
            ..CHANNEL_44
        },
        AP_MLD,
        &[],
    );
    let two = ap(2, 2, CHANNEL_1, AP_MLD, &[]);
    let three = ap(3, 3, CHANNEL_1, AP_MLD, &[]);
    let observed = [(10, &same_band), (30, &three), (20, &two)];
    let any = |_: &Bss| true;
    assert_eq!(
        other_link(&setup, AP_MLD, &observed, any).map(|(id, handle, _)| (id, handle)),
        Some((2, 20))
    );
    // A link the station may not use passes to the next.
    let not_two = |other: &Bss| other.bssid != two.bssid;
    assert_eq!(
        other_link(&setup, AP_MLD, &observed, not_two).map(|(id, handle, _)| (id, handle)),
        Some((3, 30))
    );
    // An AP the RNR names as another AP MLD's, or unobserved, is no link.
    let foreign = ap(2, 2, CHANNEL_1, Mac([2, 8, 8, 8, 8, 8]), &[]);
    assert!(other_link(&setup, AP_MLD, &[(20, &foreign)], any).is_none());
    assert!(other_link(&setup, AP_MLD, &[(10, &same_band)], any).is_none());
}

/// wpa_supplicant's `sm->mlo` link: the AP's whole RSN element and RSNXE.
#[test]
fn a_keyed_link_carries_its_aps_whole_rsn_element_and_rsnxe() {
    let mut bss = ap(1, 2, CHANNEL_1, AP_MLD, &[]);
    bss.elements = vec![48, 2, 1, 0, 244, 1, 0x20];
    let link = keyed_link(1, Mac([2, 0xa, 0, 0, 0, 1]), &bss);
    assert_eq!(
        (link.ap, link.rsn, link.rsnxe, link.accepted),
        (
            bss.bssid,
            vec![48, 2, 1, 0],
            Some(vec![244, 1, 0x20]),
            false
        )
    );
}
