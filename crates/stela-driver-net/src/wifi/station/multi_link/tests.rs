//! A multi-link setup through the station: SAE between the MLDs on the
//! setup link, then an association requesting another link.
use super::super::tests::{
    AP, LOCAL, Policy, beacon, edit_elements, ie, join, modern_ies, response,
};
use super::*;
use crate::wifi::{
    Band, Channel,
    frame::Mpdu,
    scan::result::Bss,
    security::SecurityStatus,
    station::{
        Action, Failure, Join, PortPolicy, Station,
        external::{Frame, Peer, Session},
        phy::{Capabilities, Role, Width},
        wire::multi_link::{Basic, Profile, authentication},
    },
};
use alloc::vec;

const AP_MLD: Mac = Mac([2, 9, 9, 9, 9, 9]);
/// The AP of the other link.
const OTHER: Mac = Mac([2, 6, 7, 8, 9, 11]);
const SETUP_LINK: Mac = Mac([2, 0xa, 0, 0, 0, 1]);
const OTHER_LINK: Mac = Mac([2, 0xa, 0, 0, 0, 2]);
const CHANNEL_149: Channel = Channel {
    band: Band::Ghz5,
    number: 149,
    frequency_mhz: 5745,
};
/// An SAE-only RSN with protected management frames capable.
const RSN: [u8; 26] = [
    1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 4, 1, 0, 0, 15, 172, 8, 0x80, 0, 0, 0, 0, 15, 172, 6,
];

fn affiliation() -> Affiliation {
    Affiliation {
        mld: Mld {
            local: LOCAL,
            ap: AP_MLD,
        },
        link_id: 0,
        local: SETUP_LINK,
    }
}

/// The AP's elements on a primary channel whose 80 MHz center is `center`.
fn ap_elements(primary: u8, center: u8) -> Vec<u8> {
    let mut elements = modern_ies(true);
    edit_elements(&mut elements, |id, body| match (id, body.first()) {
        (61, _) => body[0] = primary,
        (192, _) => body[1] = center,
        (255, Some(106)) => body[7] = center,
        _ => {}
    });
    ie(&mut elements, 48, &RSN);
    elements
}

fn sae_request(mut elements: Vec<u8>) -> wire::AssociationRequest {
    ie(&mut elements, 48, &RSN);
    let local = Capabilities::parse(Band::Ghz5, Role::Station, &elements).unwrap();
    wire::AssociationRequest::new_modern_with_local_pmf(
        0x11,
        10,
        elements,
        local,
        Mode::Eht,
        Width::Mhz80,
    )
    .unwrap()
}

fn observed(bssid: Mac, channel: Channel, elements: Vec<u8>) -> Arc<NativeBssObservation> {
    let bss = Bss {
        bssid,
        transmitter: bssid,
        capabilities: 0x11,
        channel,
        elements,
        ..beacon(&join(PortPolicy::Controlled))
    };
    Arc::new(NativeBssObservation { bss })
}

/// A frame from the setup link's AP to the station's setup link.
fn from_ap(control: u16, body: &[u8]) -> Mpdu {
    let mut bytes = vec![0; 24];
    bytes[..2].copy_from_slice(&control.to_le_bytes());
    bytes[4..10].copy_from_slice(&SETUP_LINK.0);
    bytes[10..16].copy_from_slice(&AP.0);
    bytes[16..22].copy_from_slice(&AP.0);
    bytes.extend_from_slice(body);
    Mpdu::new(bytes, response(0, &[]).radio, SecurityStatus::default()).unwrap()
}

/// A station that authenticated with the AP MLD by SAE on link 0, the
/// setup's join requesting link 1, and the setup link's observation.
fn authenticated() -> (Station, Arc<Session>, Join, Arc<NativeBssObservation>) {
    let mut station = Station::new(LOCAL).unwrap();
    let mut policy = Policy(true);
    let channel = join(PortPolicy::Controlled).channel;
    let session = station
        .begin_external_authentication(
            Peer {
                bssid: AP,
                channel,
                ssid: vec![b'x'],
                multi_link: Some(affiliation()),
            },
            0,
            1_000_000,
            &mut policy,
        )
        .unwrap();
    for (transaction, status, now) in [(1, 126, 1), (2, 0, 3)] {
        let frame = Frame {
            transaction,
            status,
            data: &[19, 0],
        };
        let bytes = station
            .external_authentication_transmit(&session, frame, now, &mut policy)
            .unwrap();
        // The frame leaves from the link address and names the MLD.
        assert_eq!(bytes[10..16], SETUP_LINK.0);
        assert!(bytes.ends_with(&authentication(LOCAL)));
        let mut body = vec![3, 0, transaction as u8, 0, status as u8, 0, 19, 0];
        body.extend(
            Basic {
                address: AP_MLD,
                ..Basic::default()
            }
            .encode(),
        );
        station
            .receive_external_authentication(&session, from_ap(0xb0, &body), now + 1)
            .unwrap()
            .unwrap();
    }
    assert!(station.external_authenticated());
    let setup = Setup {
        association: affiliation(),
        mld_capabilities: 0,
        eml_capabilities: 0,
        links: vec![Link {
            link_id: 1,
            local: OTHER_LINK,
            observation: observed(OTHER, CHANNEL_149, ap_elements(149, 155)),
            request: sae_request(modern_ies(false)),
        }],
    };
    let join = Join {
        request: sae_request(modern_ies(false))
            .with_multi_link(setup)
            .unwrap(),
        ..join(PortPolicy::Controlled)
    };
    let observation = observed(AP, channel, ap_elements(36, 42));
    (station, session, join, observation)
}

/// The AP MLD's association response accepting link 0 with `profiles`.
pub(crate) fn association_response(profiles: Vec<Profile>) -> Mpdu {
    let mut body = vec![0x11, 0, 0, 0, 1, 0xc0];
    body.extend_from_slice(&ap_elements(36, 42));
    body.extend(
        Basic {
            address: AP_MLD,
            link_id: Some(0),
            mld_capabilities: Some(0),
            profiles,
            ..Basic::default()
        }
        .encode(),
    );
    from_ap(0x10, &body)
}

/// The AP MLD's answer for link 1.
pub(crate) fn answer(status: u16) -> Profile {
    let mut body = vec![0x11, 0];
    body.extend_from_slice(&status.to_le_bytes());
    body.extend_from_slice(&ap_elements(149, 155));
    Profile {
        link_id: 1,
        complete: true,
        address: Some(OTHER),
        bss_parameters_change_count: Some(0),
        body,
        ..Profile::default()
    }
}

/// Associate on the setup link and take the AP MLD's `response`.
fn associate(response: Mpdu) -> Action {
    associate_station(response).1
}

/// The station associating on the setup link and its action on the AP
/// MLD's `response`.
pub(crate) fn associate_station(response: Mpdu) -> (Station, Action) {
    let (mut station, session, join, observation) = authenticated();
    let mut policy = Policy(true);
    let Action::Transmit { ticket, bytes, .. } = station
        .associate_external_pmf(&session, join, observation, 10, &mut policy)
        .unwrap()
    else {
        panic!("association request");
    };
    assert_eq!(bytes[10..16], SETUP_LINK.0);
    let basic = Basic::find(&bytes[28..]).unwrap().unwrap();
    assert_eq!(basic.address, LOCAL);
    assert_eq!(
        (basic.profiles[0].link_id, basic.profiles[0].address),
        (1, Some(OTHER_LINK))
    );
    station.submitted(ticket).unwrap();
    let epoch = station.association_epoch().unwrap();
    let action = station.receive(epoch, &response, 11, &mut policy).unwrap();
    (station, action)
}

#[test]
fn an_ap_mld_accepting_another_link_configures_it_under_its_own_addresses() {
    let Action::Configure {
        context: Some(context),
        links,
        ..
    } = associate(association_response(vec![answer(0)]))
    else {
        panic!("configuration");
    };
    assert_eq!(context.affiliation(), Some(&affiliation()));
    let [link] = &links[..] else {
        panic!("one other link");
    };
    assert_eq!((link.bssid(), link.channel()), (OTHER, CHANNEL_149));
    assert_eq!(
        link.affiliation(),
        Some(&Affiliation {
            link_id: 1,
            local: OTHER_LINK,
            ..affiliation()
        })
    );
    assert_eq!(link.response().aid, 1);
}

#[test]
fn a_refused_link_is_left_out_and_a_missing_one_abandons_the_setup() {
    let Action::Configure { links, .. } = associate(association_response(vec![answer(17)])) else {
        panic!("configuration");
    };
    assert!(links.is_empty());
    assert!(matches!(
        associate(association_response(Vec::new())),
        Action::Remove {
            failure: Some(Failure::MultiLink),
            ..
        }
    ));
}

#[test]
fn a_setup_needs_distinct_links_and_addresses() {
    let (_, _, join, _) = authenticated();
    let mut setup = join.request.multi_link().unwrap().clone();
    assert!(setup.validate().is_ok());
    setup.links[0].link_id = 0;
    assert!(setup.validate().is_err());
    setup.links[0].link_id = 1;
    setup.links[0].local = SETUP_LINK;
    assert!(matches!(setup.validate(), Err(Error::InvalidAddress)));
    // A request carries one setup.
    setup.links[0].local = OTHER_LINK;
    assert!(
        sae_request(modern_ies(false))
            .with_multi_link(setup.clone())
            .unwrap()
            .with_multi_link(setup)
            .is_err()
    );
}

/// A data frame on the air: from `ap` to `receiver` on `channel`, its
/// third address `source`, carrying EAPOL.
fn eapol_on_air(ap: Mac, receiver: Mac, source: Mac, channel: Channel) -> Mpdu {
    let mut bytes = vec![0x08, 0x02, 0, 0];
    for address in [receiver, ap, source] {
        bytes.extend_from_slice(&address.0);
    }
    bytes.extend_from_slice(&[0, 0, 0xaa, 0xaa, 3, 0, 0, 0, 0x88, 0x8e, 1, 3]);
    let mut frame = response(0, &[]);
    frame = Mpdu::new(bytes, frame.radio, SecurityStatus::default()).unwrap();
    frame.radio.band = channel.band;
    frame.radio.channel = channel.number;
    frame.radio.frequency_mhz = channel.frequency_mhz;
    frame
}

/// mac80211's MLD addressing once the setup made both links: a unicast
/// frame on either link reaches the OS between the MLDs, a group-addressed
/// one keeps its link's AP, and frames sent address the MLDs.
#[test]
fn an_mld_association_addresses_the_mlds_on_every_link() {
    use crate::wifi::station::{
        Completion,
        data::{Ingress, SequenceOwner, TxClass},
    };
    let (mut station, action) = associate_station(association_response(vec![answer(0)]));
    let Action::Configure {
        context: Some(context),
        ..
    } = action
    else {
        panic!("configuration");
    };
    station
        .complete_configuration(context.ticket(), Completion::Accepted, 12)
        .unwrap();
    let epoch = station.association_epoch().unwrap();
    let setup = join(PortPolicy::Controlled).channel;
    assert_eq!(
        station.on_air().collect::<Vec<_>>(),
        [(SETUP_LINK, AP, setup), (OTHER_LINK, OTHER, CHANNEL_149)]
            .map(|(local, ap, channel)| OnAir { local, ap, channel })
    );
    for (ap, local, channel) in [(AP, SETUP_LINK, setup), (OTHER, OTHER_LINK, CHANNEL_149)] {
        let frame = eapol_on_air(ap, local, AP_MLD, channel);
        let (view, link) = station.mld_view(&frame).unwrap();
        assert_eq!((link.ap, link.channel), (ap, channel));
        assert_eq!(
            (view.header().receiver, view.header().transmitter),
            (LOCAL, Some(AP_MLD))
        );
        let Ingress::ControlPort { ethernet, .. } =
            station.receive_msdu(epoch, &frame, &mut []).unwrap()
        else {
            panic!("EAPOL");
        };
        assert_eq!(
            (&ethernet[..6], &ethernet[6..12]),
            (&LOCAL.0[..], &AP_MLD.0[..])
        );
    }
    // A group-addressed frame keeps the link's own addresses.
    let group = eapol_on_air(OTHER, Mac::BROADCAST, OTHER, CHANNEL_149);
    let (view, _) = station.mld_view(&group).unwrap();
    assert_eq!(view.header().transmitter, Some(OTHER));
    // No link of the association runs on another channel.
    let mut stray = eapol_on_air(OTHER, OTHER_LINK, AP_MLD, CHANNEL_149);
    stray.radio.frequency_mhz += 5;
    assert!(matches!(station.mld_view(&stray), Err(Error::WrongChannel)));
    let mut ethernet = AP_MLD.0.to_vec();
    ethernet.extend_from_slice(&LOCAL.0);
    ethernet.extend_from_slice(&[0x88, 0x8e, 1, 3]);
    let plan = station
        .prepare_msdu(
            epoch,
            &ethernet,
            TxClass::ControlPortPlaintext,
            SequenceOwner::Host,
            &mut [],
            &mut Policy(true),
        )
        .unwrap();
    assert_eq!(
        (
            &plan.plaintext_mpdu()[4..10],
            &plan.plaintext_mpdu()[10..16]
        ),
        (&AP_MLD.0[..], &LOCAL.0[..])
    );
}

/// An MLD association's port opens with the MLDs' PTK and each link's own
/// GTK, every link's keys in the order of its links.
#[test]
fn an_mld_port_opens_with_a_ptk_and_gtk_on_every_link() {
    use crate::wifi::{
        security::KeyScope,
        station::{Completion, tests::key},
    };
    let (mut station, action) = associate_station(association_response(vec![answer(0)]));
    let Action::Configure {
        context: Some(context),
        ..
    } = action
    else {
        panic!("configuration");
    };
    station
        .complete_configuration(context.ticket(), Completion::Accepted, 12)
        .unwrap();
    let epoch = station.association_epoch().unwrap();
    let ptk = key(1, KeyScope::Pairwise(AP_MLD));
    let gtk = key(19, KeyScope::Group(AP));
    let link_ptk = key(2, KeyScope::Pairwise(AP_MLD));
    let link_gtk = key(18, KeyScope::Group(OTHER));
    for links in [
        // Each link needs its keys.
        &[(&ptk, &gtk)][..],
        // A link's GTK is its own AP's.
        &[(&ptk, &gtk), (&link_ptk, &gtk)][..],
        // The PTK is the AP MLD's, not a link's AP's.
        &[
            (&key(1, KeyScope::Pairwise(AP)), &gtk),
            (&link_ptk, &link_gtk),
        ][..],
    ] {
        assert_eq!(
            station.authorize_protected_port(&context, epoch, links),
            Err(Error::WrongKey)
        );
    }
    station
        .authorize_protected_port(&context, epoch, &[(&ptk, &gtk), (&link_ptk, &link_gtk)])
        .unwrap();
    assert!(station.port_open(&[&ptk, &gtk, &link_ptk, &link_gtk]));
    assert!(!station.port_open(&[&ptk, &gtk]));
}
