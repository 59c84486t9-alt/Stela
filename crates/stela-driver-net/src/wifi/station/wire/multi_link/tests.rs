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

/// A 5 GHz association requesting a 6 GHz link: the link's profile carries
/// its rates and HE, HE 6 GHz and EHT capabilities, and refuses the outer HT
/// and VHT capabilities it lacks; SSID, RSN and WMM stay inherited.
#[test]
fn a_requested_link_profile_refuses_the_outer_elements_it_lacks() {
    let outer = [
        0, 1, b'n', 1, 1, 0x8c, 48, 2, 1, 0, 45, 1, 0xaa, 191, 1, 0xbb, 255, 2, 35, 1, 255, 2, 108,
        2, 221, 1, 0x50,
    ];
    let six = [
        0, 1, b'n', 1, 1, 0x8c, 48, 2, 1, 0, 255, 2, 35, 3, 255, 2, 59, 4, 255, 2, 108, 5,
    ];
    let element = association_request(
        MLD,
        0,
        0,
        &outer,
        &[Requested {
            link_id: 2,
            address: LINK,
            capability: 0x0010,
            elements: &six,
        }],
    );
    let basic = Basic::find(&element).unwrap().unwrap();
    assert_eq!(basic.mld_capabilities, Some(0));
    assert_eq!(basic.eml_capabilities, None);
    let profile = &basic.profiles[0];
    assert_eq!((profile.link_id, profile.address), (2, Some(LINK)));
    assert_eq!(
        profile.body,
        [
            0x10, 0, 1, 1, 0x8c, 255, 2, 35, 3, 255, 2, 59, 4, 255, 2, 108, 5, 255, 5, 56, 2, 45,
            191, 0
        ]
    );
    // EMLSR support adds the EML capabilities.
    let eml = association_request(MLD, 0, 0x0001, &outer, &[]);
    assert_eq!(
        Basic::find(&eml).unwrap().unwrap().eml_capabilities,
        Some(1)
    );
}

fn answer(link_id: u8, status: u16, count: Option<u8>, elements: &[u8]) -> Profile {
    let mut body = 0x0010u16.to_le_bytes().to_vec();
    body.extend_from_slice(&status.to_le_bytes());
    body.extend_from_slice(elements);
    Profile {
        link_id,
        complete: true,
        address: Some(LINK),
        bss_parameters_change_count: count,
        body,
        ..Profile::default()
    }
}

#[test]
fn a_response_answers_each_requested_link_with_its_inherited_elements() {
    let response = |profiles| {
        let mut elements = vec![1, 1, 0x8c, 45, 1, 0xaa, 221, 1, 0x50];
        elements.extend(
            Basic {
                address: MLD,
                link_id: Some(0),
                mld_capabilities: Some(0),
                profiles,
                ..Basic::default()
            }
            .encode(),
        );
        elements
    };
    // The 6 GHz link refuses the outer HT operation; WMM is inherited.
    let accepted = answer(2, 0, Some(1), &[1, 1, 0x8c, 255, 4, 56, 1, 45, 0]);
    let refused = answer(3, 17, None, &[]);
    let elements = response(vec![accepted, refused]);
    let (basic, answers) = association_response(MLD, &elements, &[2, 3]).unwrap();
    assert_eq!(basic.link_id, Some(0));
    assert_eq!(
        answers,
        [
            Answer {
                link_id: 2,
                status: 0,
                capability: 0x10,
                elements: vec![1, 1, 0x8c, 221, 1, 0x50],
            },
            Answer {
                link_id: 3,
                status: 17,
                capability: 0x10,
                elements: vec![1, 1, 0x8c, 45, 1, 0xaa, 221, 1, 0x50],
            },
        ]
    );
    // Another AP MLD, a missing link and an accepted link without its
    // change count end the association.
    assert_eq!(
        association_response(LINK, &elements, &[2]).unwrap_err(),
        Error::WrongPeer
    );
    assert!(association_response(MLD, &elements, &[4]).is_err());
    let uncounted = response(vec![answer(2, 0, None, &[])]);
    assert!(association_response(MLD, &uncounted, &[2]).is_err());
}

#[test]
fn an_authentication_names_the_mld_alone() {
    let mut expected = vec![255, 10, 107, 0x00, 0x00, 7];
    expected.extend_from_slice(&MLD.0);
    assert_eq!(authentication(MLD), expected);
}
