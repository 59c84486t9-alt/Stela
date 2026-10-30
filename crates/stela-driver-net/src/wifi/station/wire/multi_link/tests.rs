use super::*;
use alloc::vec;

const MLD: Mac = Mac([2, 0, 0, 0, 0, 1]);
const LINK: Mac = Mac([2, 0, 0, 0, 0, 2]);

/// The element `ieee80211_assoc_add_ml_elem` writes for a non-AP MLD with
/// one other link: MLD capabilities and a complete profile naming the link's
/// address, its capability field and elements.
#[test]
fn an_association_element_is_laid_out_as_mac80211_writes_it() {
    let element = Basic {
        address: MLD,
        mld_capabilities: Some(0),
        profiles: vec![Profile {
            link_id: 1,
            complete: true,
            address: Some(LINK),
            body: vec![0x11, 0, 1, 1, 0x8c],
            ..Profile::default()
        }],
        ..Basic::default()
    };
    let mut expected = vec![255, 28, 107, 0x00, 0x01, 9];
    expected.extend_from_slice(&MLD.0);
    expected.extend_from_slice(&[0, 0]);
    expected.extend_from_slice(&[0, 14, 0x31, 0x00, 7]);
    expected.extend_from_slice(&LINK.0);
    expected.extend_from_slice(&[0x11, 0, 1, 1, 0x8c]);
    assert_eq!(element.encode(), expected);
    assert_eq!(Basic::find(&expected).unwrap(), Some(element));
}

#[test]
fn long_profiles_and_elements_fragment_and_join_again() {
    let element = Basic {
        address: MLD,
        link_id: Some(0),
        bss_parameters_change_count: Some(3),
        medium_sync_delay: Some(0x10ac),
        eml_capabilities: Some(1),
        mld_capabilities: Some(0x2000),
        mld_id: Some(0),
        extended_mld_capabilities: Some(4),
        enhanced_critical_update: Some(9),
        profiles: (1..=2)
            .map(|link_id| Profile {
                link_id,
                complete: true,
                address: Some(LINK),
                beacon_interval: Some(100),
                tsf_offset: Some(0x0102_0304_0506_0708),
                dtim: Some((0, 2)),
                nstr: Some(vec![1, 2]),
                bss_parameters_change_count: Some(5),
                enhanced_critical_update: Some(6),
                ap_conducted_tx_power: Some(7),
                body: (0..300).map(|i| i as u8).collect(),
            })
            .collect(),
    };
    let encoded = element.encode();
    // Each profile spills into a subelement fragment, and the element into
    // Fragment elements.
    assert!(encoded.len() > 600);
    let mut others = vec![0, 1, b'x'];
    others.extend_from_slice(&encoded);
    others.extend_from_slice(&[221, 3, 1, 2, 3]);
    assert_eq!(Basic::find(&others).unwrap(), Some(element));
}

#[test]
fn malformed_elements_are_refused_and_other_types_skipped() {
    // A Probe Request multi-link element is not a Basic one.
    assert_eq!(Basic::find(&[255, 4, 107, 0x01, 0, 1]).unwrap(), None);
    // The link ID is present but the common information ends before it.
    let mut short = vec![255, 10, 107, 0x10, 0x00, 7];
    short.extend_from_slice(&MLD.0);
    assert!(matches!(Basic::find(&short), Err(Error::Invalid(_))));
    // A common information length past the element.
    let mut over = vec![255, 10, 107, 0x00, 0x00, 20];
    over.extend_from_slice(&MLD.0);
    assert_eq!(Basic::find(&over), Err(Error::Truncated));
    // A per-STA profile whose STA information names an absent address.
    let mut profile = vec![255, 15, 107, 0x00, 0x00, 7];
    profile.extend_from_slice(&MLD.0);
    profile.extend_from_slice(&[0, 3, 0x21, 0x00, 1]);
    assert!(matches!(Basic::find(&profile), Err(Error::Invalid(_))));
}

/// One `ieee80211_tbtt_info_ge_11` entry with MLD parameters.
fn tbtt(bssid: u8, mld_id: u8, parameters: u16) -> Vec<u8> {
    let mut entry = vec![0, 2, 0, 0, 0, 0, bssid, 0, 0, 0, 0, 0x40, 0, mld_id];
    entry.extend_from_slice(&parameters.to_le_bytes());
    entry
}

#[test]
fn a_reduced_neighbor_report_names_the_reporting_mlds_other_links() {
    let mut rnr = vec![0x20, 16, 131, 37];
    // Link 2 of the reporter's MLD, another MLD's AP, a disabled link.
    rnr.extend_from_slice(&tbtt(9, 0, 2 | 4 << 4));
    rnr.extend_from_slice(&tbtt(8, 1, 3));
    rnr.extend_from_slice(&tbtt(7, 0, 4 | 0x2000));
    // An entry without MLD parameters names no link.
    rnr.extend_from_slice(&[0x00, 13, 128, 36]);
    rnr.extend_from_slice(&[0; 13]);
    let mut elements = vec![201, rnr.len() as u8];
    elements.extend_from_slice(&rnr);
    assert_eq!(
        affiliated(&elements).unwrap(),
        [Affiliated {
            link_id: 2,
            bssid: Mac([2, 0, 0, 0, 0, 9]),
            operating_class: 131,
            channel: 37,
            bss_parameters_change_count: 4,
        }]
    );
    elements[1] -= 1;
    elements.pop();
    assert!(affiliated(&elements).is_err());
}
