//! Actual firmware-key ACK + completed requester-DMA RX model. PMF station
//! delivery remains refused; this calls the selected-key management boundary
//! after the existing real peer/key/radio normalizer, without inventing an ACK.
use super::tests::*;
use super::*;
use crate::net::wifi::mediatek::{
    bootstrap::tests::{Bar, NativeGuard, Q},
    ring::{rx::tests::device_receive, tests::Source},
};
use core::sync::atomic::Ordering;

fn completed(
    driver: &mut Client<Bar, Q, NativeGuard>,
    model: &Model,
    raw: &[u8],
) -> Result<Mpdu, Error> {
    device_receive(&model.queues[&0xd4520], raw, true, 0);
    let received = driver
        .state_mut()
        .controller
        .poll_data()
        .map_err(Error::Bootstrap)?
        .unwrap();
    Client::normalized(
        driver.state_mut(),
        &received.bytes,
        false,
        &mut Policy(true),
    )
}
fn raw(pn: u64) -> Vec<u8> {
    incoming_bytes(&response(0x40c0, &[7, 0]), Some((1, 0, pn)), false)
}
#[test]
fn actual_completed_ptk_management_rx_preserves_data_pn_and_retires_with_peer() {
    let (mut driver, model) = setup();
    associated(&mut driver, &model, 0);
    let ptk = driver
        .install_key(true, 0, &[1; 16], ReplaySeed::ZERO)
        .unwrap();
    driver
        .install_key(false, 2, &[2; 16], ReplaySeed::ZERO)
        .unwrap();
    let epoch = driver.station().association_epoch().unwrap();
    driver.authorize_port(epoch).unwrap();
    for case in 0..12 {
        let mut bad = raw(9);
        match case {
            0 => bad[4] = 2,                     // wrong actual raw peer WCID
            1 => bad[6] |= 1 << 5,               // wrong key index
            2 => bad[10] = (bad[10] & !31) | 11, // GCMP status cannot bind CCMP PTK
            3 => bad[7] |= 1 << 1,               // actual ICV failure
            4 => {
                bad.drain(32..48);
                bad[6] &= !1;
            } // no group1 PN
            5 => bad[6] |= 1 << 7,               // cipher mismatch
            6 => bad[7] |= 1,                    // cipher length mismatch
            7 => bad[48 + 10] ^= 2,              // wrong transmitter
            8 => bad[48 + 16] ^= 2,              // wrong BSSID
            9 => bad[48 + 4] ^= 2,               // wrong local receiver
            10 => bad[13] = 40,                  // wrong actual channel
            _ => {
                bad.pop();
            } // incomplete reason code
        }
        if let Ok(frame) = completed(&mut driver, &model, &bad) {
            assert!(
                driver
                    .state_mut()
                    .ptk
                    .as_mut()
                    .unwrap()
                    .authorize_unicast_management(&frame, LOCAL)
                    .is_err(),
                "case {case}"
            );
        }
    }
    let frame = completed(&mut driver, &model, &raw(9)).unwrap();
    assert_eq!(frame.security.key, Some(ptk));
    assert_eq!(frame.radio.rate.layout, 0x7925);
    let proof = driver
        .state_mut()
        .ptk
        .as_mut()
        .unwrap()
        .authorize_unicast_management(&frame, LOCAL)
        .unwrap();
    assert_eq!(proof.key(), ptk);
    assert_eq!(proof.body(), &[7, 0]);
    assert_eq!(proof.packet_number().value(), 9);
    // This crypto proof itself changes neither station phase nor controlled port.
    assert_eq!(driver.phase(), Phase::Associated);
    let again = completed(&mut driver, &model, &raw(9)).unwrap();
    assert!(matches!(
        driver
            .state_mut()
            .ptk
            .as_mut()
            .unwrap()
            .authorize_unicast_management(&again, LOCAL),
        Err(wifi::security::Error::Replay)
    ));
    incoming(&model, &data(false), Some((1, 0, 9)), false);
    assert!(matches!(
        driver
            .poll(frontend_tick(12), &Source, &mut Policy(true))
            .unwrap()
            .as_slice(),
        [Event::Ingress(Ingress::Data(_))]
    ));
    // Native exact reinstall is a no-op and cannot rewind management counter16.
    assert_eq!(
        driver
            .install_key(true, 0, &[1; 16], ReplaySeed::ZERO)
            .unwrap(),
        ptk
    );
    assert!(matches!(
        driver
            .state_mut()
            .ptk
            .as_mut()
            .unwrap()
            .authorize_unicast_management(&again, LOCAL),
        Err(wifi::security::Error::Replay)
    ));
    driver.disconnect().unwrap();
    assert!(matches!(
        driver
            .state_mut()
            .ptk
            .as_mut()
            .unwrap()
            .authorize_unicast_management(&frame, LOCAL),
        Err(wifi::security::Error::NoInstalledKey)
    ));
    // SAFETY: explicit model peer removal ACK, no firmware/DMA/IRQ/deferred old users.
    unsafe { driver.retire_peer_after_drain() }.unwrap();
    associated(&mut driver, &model, 30);
    let next = driver
        .install_key(true, 0, &[3; 16], ReplaySeed::ZERO)
        .unwrap();
    assert_ne!(next.generation(), ptk.generation());
    assert!(matches!(
        driver
            .state_mut()
            .ptk
            .as_mut()
            .unwrap()
            .authorize_unicast_management(&frame, LOCAL),
        Err(wifi::security::Error::WrongKey)
    ));
    let fresh = completed(&mut driver, &model, &raw(1)).unwrap();
    driver
        .state_mut()
        .ptk
        .as_mut()
        .unwrap()
        .authorize_unicast_management(&fresh, LOCAL)
        .unwrap();
    driver.disconnect().unwrap();
    // SAFETY: the model has explicitly completed removal and all old users.
    unsafe { driver.retire_peer_after_drain() }.unwrap();
    driver.stop().unwrap();
    model.response.lock().unwrap().clc_processing = false;
    model.bar.0.lock().unwrap().values.insert(0xd4208, 0);
    // SAFETY: independent complete modeled controller/radio/DMA/work quiescence.
    unsafe { driver.stop_after_quiesce() }.unwrap();
    drop(driver);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
    assert!(model.memory.lock().unwrap().mappings.is_empty());
}

#[test]
fn uncertain_ptk_publication_never_authenticates_management_or_releases_owner() {
    for dropped in [false, true] {
        let (mut driver, model) = setup();
        associated(&mut driver, &model, 0);
        // First real GTK ACK also completes the BSS cipher update. Faults below
        // therefore reach the real PTK publication rather than an earlier BSS.
        let gtk = driver
            .install_key(false, 2, &[2; 16], ReplaySeed::ZERO)
            .unwrap();
        {
            let mut fault = model.response.lock().unwrap();
            if dropped {
                fault.drop = true;
            } else {
                fault.status = 0xdead;
            }
        }
        assert!(
            driver
                .install_key(true, 0, &[1; 16], ReplaySeed::ZERO)
                .is_err()
        );
        assert_eq!(driver.phase(), Phase::Quarantined);
        assert!(model.response.lock().unwrap().keys.contains_key(&1));
        assert!(completed(&mut driver, &model, &raw(9)).is_err());
        let copied = Mpdu::new(
            response(0x40c0, &[7, 0]),
            wifi::RadioStatus {
                band: wifi::Band::Ghz5,
                channel: 36,
                frequency_mhz: 5180,
                signal_dbm: None,
                chain_signal_dbm: [None; 4],
                rate: wifi::RawRate {
                    layout: 0x7925,
                    words: [0; 4],
                },
                tsf: None,
            },
            SecurityStatus {
                key: Some(gtk),
                pn: PacketNumber::new(9),
                decrypted: true,
                integrity: Integrity::Verified,
                iv_stripped: true,
                mic_stripped: true,
                ..SecurityStatus::default()
            },
        )
        .unwrap();
        assert!(matches!(
            driver
                .state_mut()
                .ptk
                .as_mut()
                .unwrap()
                .authorize_unicast_management(&copied, LOCAL),
            Err(wifi::security::Error::NoInstalledKey)
        ));
        drop(driver);
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
        assert!(!model.memory.lock().unwrap().mappings.is_empty());
    }
}
