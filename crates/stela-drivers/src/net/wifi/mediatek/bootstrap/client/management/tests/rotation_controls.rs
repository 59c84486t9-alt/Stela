// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! Native completed RX/DMA, exact private sessions and live firmware update peers.
use super::*;
use crate::net::wifi::mediatek::mailbox::key::bip::rotation_tests::frame;

fn group_received(driver: &mut Native, model: &Model, index: u8, key: u8, pn: u64) -> Received {
    let mut raw = incoming_bytes(&frame(index, key, pn), None, false);
    raw[4] = 1; // actual source peer WCID → retained VIF GTK, never the BCMC WCID
    let mut events = completed(driver, model, &raw).unwrap();
    assert_eq!(events.len(), 1);
    match events.pop().unwrap() {
        Event::ProtectedManagement(rx) => rx,
        _ => panic!("original authenticated OS observation"),
    }
}

#[test]
fn native_live_igtk_update_revokes_old_envelopes_and_retains_both_real_rx_windows() {
    let (mut driver, model) = setup();
    associated(&mut driver, &model, 0);
    let (epoch, ptk, gtk) = keys(&mut driver);
    let first = attach(&mut driver, epoch);
    let delayed = group_received(&mut driver, &model, 4, 0x55, 101);
    let unicast_delayed = received(&mut driver, &model, 9);
    let before = model.response.lock().unwrap().client_commands.len();
    // SAFETY: genuine modeled OS exchange, empty native queues and independent RX/IRQ/user drain.
    let second = unsafe {
        driver.rotate_management_key(&first, 5, &[0x66; 16], PacketNumber::new(200).unwrap())
    }
    .unwrap();
    assert!(!Arc::ptr_eq(&first, &second));
    assert_eq!(second.pairwise_key(), ptk);
    assert_eq!(second.group_key(), gtk);
    assert_eq!(
        second.receive_management_keys()[0],
        Some(first.management_key())
    );
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        before + 1
    );
    assert!(
        driver
            .with_management(delayed, |_, _, _| panic!(
                "old BIP proof inherited a new transport"
            ))
            .is_err()
    );
    assert!(
        driver
            .with_management(unicast_delayed, |_, _, _| panic!(
                "old PTK proof inherited a new transport"
            ))
            .is_err()
    );
    for (index, key, pn) in [(4, 0x55, 102), (5, 0x66, 201)] {
        let rx = group_received(&mut driver, &model, index, key, pn);
        assert!(Arc::ptr_eq(rx.session(), &second));
        assert_eq!(
            driver
                .with_management(rx, |_, body, pn| {
                    assert_eq!(body, [7, 0]);
                    pn.value()
                })
                .unwrap(),
            pn
        );
        let mut raw = incoming_bytes(&frame(index, key, pn), None, false);
        raw[4] = 1;
        assert!(completed(&mut driver, &model, &raw).is_err());
    }
    // The protected-unicast management PN belongs to the unchanged PTK; rotating
    // IGTK must not reset its independent replay counter to accept an old frame.
    assert!(completed(&mut driver, &model, &unicast(9)).is_err());
    let rx = received(&mut driver, &model, 10);
    assert_eq!(
        driver.with_management(rx, |_, _, pn| pn.value()).unwrap(),
        10
    );
    let before = model.response.lock().unwrap().client_commands.len();
    // SAFETY: exact retry of the retained other index; independent model users drained.
    let retry = unsafe {
        driver.rotate_management_key(&second, 4, &[0x55; 16], PacketNumber::new(0).unwrap())
    }
    .unwrap();
    assert!(Arc::ptr_eq(&second, &retry));
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    assert!(!driver.station().port_open(
        Some(driver.state().ptk.as_ref().unwrap().slot()),
        Some(driver.state().gtk.as_ref().unwrap().slot())
    ));
    stop(&mut driver, &model);
    drop(driver);
    drop(first);
    drop(second);
    drop(retry);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn native_live_igtk_overlap_never_clears_actual_hardware_integrity_failures() {
    let (mut driver, model) = setup();
    associated(&mut driver, &model, 0);
    let (epoch, _, _) = keys(&mut driver);
    let first = attach(&mut driver, epoch);
    // SAFETY: authentic model key exchange and independently drained actual model users.
    let second = unsafe {
        driver.rotate_management_key(&first, 5, &[0x66; 16], PacketNumber::new(200).unwrap())
    }
    .unwrap();
    for (index, key, pn) in [(4, 0x55, 101), (5, 0x66, 201)] {
        let mut raw = incoming_bytes(&frame(index, key, pn), None, false);
        raw[4] = 1;
        // Source RXD1 ICV error means CCMP/BIP/WPI MIC error and ONLY_MONITOR.
        let flags = u32::from_le_bytes(raw[4..8].try_into().unwrap()) | (1 << 25);
        raw[4..8].copy_from_slice(&flags.to_le_bytes());
        assert!(completed(&mut driver, &model, &raw).is_err());
        let rx = group_received(&mut driver, &model, index, key, pn);
        assert_eq!(
            driver.with_management(rx, |_, _, pn| pn.value()).unwrap(),
            pn
        );
    }
    stop(&mut driver, &model);
    drop(driver);
    drop(first);
    drop(second);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn native_live_igtk_requires_actual_tx_descriptor_free_and_unmap_drain() {
    let (mut driver, model) = setup();
    associated(&mut driver, &model, 0);
    let (epoch, _, _) = keys(&mut driver);
    let first = attach(&mut driver, epoch);
    driver
        .transmit_management(
            &first,
            Transmit::SaQueryRequest([1, 2]),
            &Source,
            &mut Policy(true),
        )
        .unwrap();
    let before = model.response.lock().unwrap().client_commands.len();
    // SAFETY: deliberately incomplete model native drain must refuse before firmware effects.
    assert!(matches!(
        unsafe {
            driver.rotate_management_key(&first, 5, &[0x66; 16], PacketNumber::new(200).unwrap())
        },
        Err(Error::NeedsDrain)
    ));
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    assert_eq!(finish_tx(&model).len(), 1);
    assert!(driver.poll_released().unwrap().is_empty());
    // SAFETY: descriptor consumption alone is insufficient while TX-free/token remains.
    assert!(matches!(
        unsafe {
            driver.rotate_management_key(&first, 5, &[0x66; 16], PacketNumber::new(200).unwrap())
        },
        Err(Error::NeedsDrain)
    ));
    driver.poll(1_000_001, &Source, &mut Policy(true)).unwrap();
    let released = driver.poll_released().unwrap();
    assert_eq!(released.len(), 1);
    assert!(Arc::ptr_eq(
        released[0].context.management_session().unwrap(),
        &first
    ));
    drop(released);
    // SAFETY: matching actual TX-free, descriptor and unmap complete; independent model RX/IRQ/users drained.
    let second = unsafe {
        driver.rotate_management_key(&first, 5, &[0x66; 16], PacketNumber::new(200).unwrap())
    }
    .unwrap();
    let before = model.response.lock().unwrap().client_commands.len();
    assert!(
        driver
            .transmit_management(
                &first,
                Transmit::SaQueryResponse([1, 2]),
                &Source,
                &mut Policy(true)
            )
            .is_err()
    );
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    stop(&mut driver, &model);
    drop(driver);
    drop(first);
    drop(second);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
}

#[test]
fn native_live_igtk_uncertain_firmware_quarantines_old_new_keys_and_requester() {
    for fault in 0..3 {
        let (mut driver, model) = setup();
        associated(&mut driver, &model, 0);
        let (epoch, _, _) = keys(&mut driver);
        let first = attach(&mut driver, epoch);
        let delayed = received(&mut driver, &model, 9);
        match fault {
            0 => model.response.lock().unwrap().status = 9,
            1 => model.response.lock().unwrap().command_delta = 1,
            _ => model.response.lock().unwrap().drop = true,
        }
        // SAFETY: native and independent actual model users drained; inject real peer ACK failure.
        assert!(
            unsafe {
                driver.rotate_management_key(
                    &first,
                    5,
                    &[0x66; 16],
                    PacketNumber::new(200).unwrap(),
                )
            }
            .is_err()
        );
        assert_eq!(driver.phase(), Phase::Quarantined);
        assert!(driver.state().gtk.as_ref().unwrap().is_quarantined());
        assert!(
            driver
                .with_management(delayed, |_, _, _| panic!("uncertain key namespace effect"))
                .is_err()
        );
        let before = model.response.lock().unwrap().client_commands.len();
        // SAFETY: quarantine must remain closed to retries regardless of input.
        assert!(
            unsafe {
                driver.rotate_management_key(
                    &first,
                    5,
                    &[0x66; 16],
                    PacketNumber::new(200).unwrap(),
                )
            }
            .is_err()
        );
        assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
        drop(driver);
        drop(first);
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
    }
}
