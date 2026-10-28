// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! MediaTek PMF port fixtures.
use super::*;

#[test]
fn port_requires_key_acks_and_os_handshake() {
    let (mut driver, model, mut owner, state, protection) = configured();
    protection.authenticated.set(true);
    let session = attach(&mut driver, &mut owner);
    let epoch = driver.station().association_epoch().unwrap();
    assert!(driver.authorize_port(epoch).is_err());
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    assert!(
        // SAFETY: The current session and key acknowledgements remain retained, but the
        // modeled OS has not granted its port flag. Fresh guards must reject this call
        // without enabling the port.
        unsafe { driver.authorize_port_pmf(&mut owner, admission, &session) }.is_err()
    );
    protection.port.set(true);
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    // SAFETY: The fixture now grants its authenticated port flag for the current
    // acknowledged session. Original native memory, key owners and both serialized
    // model guards remain retained.
    unsafe { driver.authorize_port_pmf(&mut owner, admission, &session) }.unwrap();
    assert!(driver.station().port_open(
        Some(driver.state().ptk.as_ref().unwrap().slot()),
        Some(driver.state().gtk.as_ref().unwrap().slot())
    ));
    assert_eq!(
        model.response.lock().unwrap().keys[&19],
        [vec![0x44; 16], vec![0x55; 16]].concat()
    );
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    let before = model.response.lock().unwrap().client_commands.len();
    // Revocation after preflight cannot inherit the earlier protected-port grant.
    protection.port.set(false);
    assert!(
        // SAFETY: The receipt still names this live context and session, but its OS port
        // grant was revoked after preflight. Revalidation must deny authorization before
        // a new modeled command.
        unsafe { driver.authorize_port_pmf(&mut owner, admission, &session) }.is_err()
    );
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    // Open cached PTK/GTK permission cannot bypass fresh authenticated Data policy.
    let admission = permit(&mut owner, &driver, AssociationUse::Receive);
    protection.authenticated.set(false);
    incoming(&model, &data(false), Some((1, 0, 1)), false);
    assert!(
        // SAFETY: The queued RX storage and original requester remain retained.
        // Authentication was revoked after preflight; current hardware/OS guards must
        // deny data handling without exposing the pending frame.
        unsafe {
            driver.poll_pmf(
                &mut owner,
                admission,
                110,
                &PmfSource(state.clone()),
                &mut Policy(true),
            )
        }
        .is_err()
    );
    assert!(!state.hardware.get() && !state.os.get());
    protection.authenticated.set(true);
    let events = poll(&mut driver, &mut owner, &state, 111).unwrap();
    assert!(
        events
            .iter()
            .any(|event| matches!(event, Event::Ingress(station::data::Ingress::Data(_))))
    );
    // Once keyed, an unprotected departure is reported and dropped, as is a
    // group one without an MMIE.
    let mut group = response(0xc0, &[7, 0]);
    group[4..10].fill(255);
    for frame in [response(0xc0, &[7, 0]), group] {
        incoming(&model, &frame, None, false);
        let events = poll(&mut driver, &mut owner, &state, 112).unwrap();
        assert!(matches!(
            events.as_slice(),
            [Event::UnprotectedDeparture(_)]
        ));
        assert_eq!(driver.station().phase(), station::Phase::Associated);
    }
    // An authenticated SA Query response is the OS's. Its delayed effect must
    // reacquire current OS guards.
    incoming(
        &model,
        &response(0x40d0, &[8, 1, 3, 4]),
        Some((1, 0, 2)),
        false,
    );
    let mut events = poll(&mut driver, &mut owner, &state, 112).unwrap();
    let Event::ProtectedManagement(received) = events.pop().unwrap() else {
        panic!("authenticated PMF envelope")
    };
    assert_eq!(driver.station().phase(), station::Phase::Associated);
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    let value =
    // SAFETY: received is the retained envelope for this current PMF session and
    // requester. Both guards scope the callback; it copies body bytes and lets no
    // borrowed view outlive those guards.
    unsafe {
        driver.with_management_modern(&mut owner, admission, received, |_, body, _| {
            assert!(state.hardware.get() && state.os.get());
            body.to_vec()
        })
    }
    .unwrap();
    assert_eq!(value, [8, 1, 3, 4]);
    let admission = permit(&mut owner, &driver, AssociationUse::Management);
    // SAFETY: The current acknowledged session and native backing remain retained,
    // and this modeled OS grants management transmission. Both serialized leases
    // cover source allocation and the retained queued frame.
    unsafe {
        driver.transmit_management_modern(
            &mut owner,
            admission,
            &session,
            Transmit::SaQueryRequest([3, 4]),
            &PmfSource(state.clone()),
        )
    }
    .unwrap();
    let sent = finish_tx(&model);
    assert_eq!(sent.len(), 1);
    assert_eq!(
        u16::from_le_bytes(sent[0][..2].try_into().unwrap()) & 0x4000,
        0x4000
    );
    assert_eq!(&sent[0][24..], &[8, 0, 3, 4]);
    poll(&mut driver, &mut owner, &state, 113).unwrap();
    driver.poll_released().unwrap();
    // ieee80211_rx_mgmt_deauth: the AP's authenticated departure ends the
    // association, and the OS sees it.
    incoming(&model, &response(0x40c0, &[7, 0]), Some((1, 0, 3)), false);
    let events = poll(&mut driver, &mut owner, &state, 114).unwrap();
    assert!(events.iter().any(|event| matches!(
        event,
        Event::ProtectedManagement(rx) if rx.body() == [7, 0]
    )));
    assert_eq!(driver.station().phase(), station::Phase::Disconnecting);
}
