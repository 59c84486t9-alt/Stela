use super::*;
use crate::net::wifi::station::phy::{Mode, Width};
mod authority;
use authority::*;

fn append_ie(out: &mut Vec<u8>, id: u8, bytes: &[u8]) {
    out.extend_from_slice(&[id, bytes.len() as u8]);
    out.extend_from_slice(bytes);
}
fn append_extension(out: &mut Vec<u8>, id: u8, bytes: &[u8]) {
    let mut data = vec![id];
    data.extend_from_slice(bytes);
    append_ie(out, 255, &data);
}
fn modern_inputs(driver: &Client<Bar, Q, NativeGuard>) -> (Join, scan::result::Bss) {
    modern_inputs_cipher(driver, 4)
}
fn modern_inputs_cipher(
    driver: &Client<Bar, Q, NativeGuard>,
    suite: u8,
) -> (Join, scan::result::Bss) {
    let actual = driver.local_advertisement(Band::Ghz5).unwrap();
    let mut local = vec![0, 1, b'x'];
    local.extend_from_slice(actual.elements());
    // Real OS-controlled WPA2 exchange remains outside this software AP.
    append_ie(
        &mut local,
        48,
        &[
            1, 0, 0, 15, 172, suite, 1, 0, 0, 15, 172, suite, 1, 0, 0, 15, 172, 2,
        ],
    );
    let mut join = join();
    join.request = AssociationRequest::new_modern_with_local(
        0x11,
        10,
        local.clone(),
        actual.capabilities().clone(),
        Mode::Eht,
        Width::Mhz80,
    )
    .unwrap();
    let mut ap = Vec::new();
    let mut at = 0;
    while at < local.len() {
        let n = usize::from(local[at + 1]);
        let bytes = &local[at + 2..at + 2 + n];
        if local[at] == 221 {
            append_ie(
                &mut ap,
                221,
                &[
                    0, 0x50, 0xf2, 2, 1, 1, 0x80, 0, 3, 0xa4, 0, 0, 0x27, 0xa4, 0, 0, 0x42, 0x43,
                    94, 0, 0x62, 0x32, 47, 0,
                ],
            );
        } else if local[at] == 1 {
            append_ie(&mut ap, 1, &[0x8c, 18, 0x98, 36, 0xb0, 72, 96, 108]);
        } else {
            append_ie(&mut ap, local[at], bytes);
        }
        at += 2 + n;
    }
    let mut ht = [0; 22];
    ht[0] = 36;
    ht[1] = 5;
    append_ie(&mut ap, 61, &ht);
    append_ie(&mut ap, 192, &[1, 42, 0, 0xff, 0xff]);
    append_extension(&mut ap, 36, &[3, 0x20, 0, 0x2a, 0xff, 0xff]);
    append_extension(&mut ap, 106, &[1, 0, 0, 0, 0, 2, 42, 0]);
    append_ie(&mut ap, 5, &[0, 2, 0, 0]);
    let mut scanner = scan::Scanner::new(LOCAL).unwrap();
    let ticket = scanner
        .begin(
            scan::Request::new(vec![CHANNEL], vec![], vec![]).unwrap(),
            0,
            100,
            &mut Policy(true),
        )
        .unwrap();
    let bss = scan::result::Bss {
        ticket,
        kind: scan::result::Kind::Beacon,
        bssid: AP,
        transmitter: AP,
        timestamp: 42,
        beacon_interval: 100,
        capabilities: 0x11,
        channel: CHANNEL,
        observed: wifi::RadioStatus {
            band: Band::Ghz5,
            channel: 36,
            frequency_mhz: 5180,
            signal_dbm: Some(-40),
            chain_signal_dbm: [None; 4],
            rate: wifi::RawRate {
                layout: 0x7925,
                words: [0; 4],
            },
            tsf: None,
        },
        signal_dbm: Some(-40),
        ssid: Some(vec![b'x']),
        elements: ap,
    };
    (join, bss)
}

fn awaiting() -> (Client<Bar, Q, NativeGuard>, Model, usize) {
    awaiting_cipher(4)
}
fn awaiting_cipher(suite: u8) -> (Client<Bar, Q, NativeGuard>, Model, usize) {
    let (mut driver, model) = setup();
    let (join, beacon) = modern_inputs_cipher(&driver, suite);
    let response_elements = beacon.elements.clone();
    driver
        .join_modern(join, beacon, profile(), 100, &Source, &mut Policy(true))
        .unwrap();
    assert_eq!(finish_tx(&model)[0][..2], [0xb0, 0]);
    driver.poll(101, &Source, &mut Policy(true)).unwrap();
    driver.poll_released().unwrap();
    incoming(&model, &response(0xb0, &[0, 0, 2, 0, 0, 0]), None, false);
    driver.poll(102, &Source, &mut Policy(true)).unwrap();
    let assoc = finish_tx(&model);
    assert_eq!(assoc[0][..2], [0, 0]);
    driver.poll(103, &Source, &mut Policy(true)).unwrap();
    driver.poll_released().unwrap();
    let commands_before = model.response.lock().unwrap().client_commands.len();
    let mut assoc_body = vec![0x11, 0, 0, 0, 1, 0xc0];
    assoc_body.extend_from_slice(&response_elements);
    incoming(&model, &response(0x10, &assoc_body), None, false);
    driver.poll(104, &Source, &mut Policy(true)).unwrap();
    (driver, model, commands_before)
}

#[test]
fn modern_current_context_waits_for_real_admission_without_legacy_configuration_ack() {
    let (mut driver, model, commands_before) = awaiting();
    assert_eq!(driver.phase(), ClientPhase::AwaitingModernAdmission);
    assert_eq!(driver.station().phase(), station::Phase::Configuring);
    assert_eq!(
        driver.modern_context().unwrap().definition().width,
        Width::Mhz80
    );
    assert_eq!(driver.pending_modern_requests(), 7);
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        commands_before
    );
    assert!(matches!(
        driver.install_key(true, 0, &[4; 16], ReplaySeed::ZERO),
        Err(ClientError::WrongPhase)
    ));
    assert!(
        driver
            .authorize_port(driver.station().association_epoch().unwrap())
            .is_err()
    );
    // Drop preserves the real current context, original peer and all DMA.
    drop(driver);
    assert_eq!(model.drops.load(Ordering::Relaxed), 0);
    assert!(!model.memory.lock().unwrap().mappings.is_empty());
}

#[test]
fn modern_actual_configuration_and_secure_qos_publication_hold_both_authorities() {
    use wifi::regulatory::AssociationUse;
    let (mut driver, model, before) = awaiting();
    let context = driver.modern_context().unwrap().clone();
    let (mut authority, state) = authority(&driver, &model);
    let revoked = admit(&mut authority, &driver, AssociationUse::Configure);
    state.allowed.set(false);
    assert!(matches!(
        unsafe { driver.configure_modern(&mut authority, revoked, 105) },
        Err(ClientError::Regulatory(_))
    ));
    assert_eq!(driver.phase(), ClientPhase::AwaitingModernAdmission);
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    state.allowed.set(true);
    let permit = admit(&mut authority, &driver, AssociationUse::Configure);
    unsafe { driver.configure_modern(&mut authority, permit, 106) }.unwrap();
    assert_eq!(driver.phase(), ClientPhase::Associated);
    assert_eq!(driver.station().phase(), station::Phase::Associated);
    assert_eq!(driver.completed_modern_requests(), 7);
    assert_eq!(driver.pending_modern_requests(), 0);
    assert!(state.windows.borrow().iter().any(|(a, b)| b - a == 7));
    let epoch = driver.station().association_epoch().unwrap();
    modern_keys(&mut driver, &mut authority);
    driver.authorize_port(epoch).unwrap();
    assert!(matches!(
        driver.transmit(
            epoch,
            &eth(0x0800),
            TxClass::Data,
            &Source,
            &mut Policy(true)
        ),
        Err(ClientError::ModernAdmissionRequired)
    ));

    let stale = admit(&mut authority, &driver, AssociationUse::Data);
    state.revision.set(2);
    let head = model.queues[&0xd4300].lock().unwrap().head;
    let allocations = state.allocations.get();
    assert!(matches!(
        unsafe {
            driver.transmit_modern(
                &mut authority,
                stale,
                epoch,
                &eth(0x0800),
                TxClass::Data,
                Some(6),
                &GuardedSource(state.clone()),
                &mut Policy(true),
            )
        },
        Err(ClientError::Regulatory(_))
    ));
    assert_eq!(state.allocations.get(), allocations);
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, head);
    let permit = admit(&mut authority, &driver, AssociationUse::Data);
    let receipt = unsafe {
        driver.transmit_modern(
            &mut authority,
            permit,
            epoch,
            &eth(0x0800),
            TxClass::Data,
            Some(6),
            &GuardedSource(state.clone()),
            &mut Policy(true),
        )
    }
    .unwrap();
    assert_eq!(state.allocations.get() - allocations, 2);
    assert!(driver.poll_released().unwrap().is_empty());
    let transmitted = finish_tx(&model);
    assert_eq!(transmitted.len(), 1);
    assert_eq!(&transmitted[0][..2], &[0x88, 0x41]);
    assert_eq!(&transmitted[0][24..28], &[6, 0, 0xaa, 0xaa]);
    driver
        .poll(1_000_000 + 110, &Source, &mut Policy(true))
        .unwrap();
    let released = driver.poll_released().unwrap();
    assert_eq!(released.len(), 1);
    assert_eq!(released[0].receipt, receipt);
    assert!(core::ptr::eq(
        released[0].context.association_context().unwrap(),
        context.as_ref()
    ));
    drop(released);
    let mut packet = data(false);
    packet[0] |= 0x80;
    packet.splice(24..24, [6, 0]);
    incoming(&model, &packet, Some((1, 0, 9)), false);
    assert!(matches!(
        driver
            .poll(1_000_000 + 111, &Source, &mut Policy(true))
            .unwrap()
            .as_slice(),
        [Event::Ingress(station::data::Ingress::Data(_))]
    ));
    incoming(&model, &packet, Some((1, 0, 9)), false);
    assert!(matches!(
        driver.poll(1_000_000 + 112, &Source, &mut Policy(true)),
        Err(ClientError::Aggregate(
            wifi::security::aggregate::Error::Security(wifi::security::Error::Replay)
        ))
    ));
    // A separate TID starts from its actual original slot's independent floor.
    packet[24] = 5;
    incoming(&model, &packet, Some((1, 0, 1)), false);
    driver
        .poll(1_000_000 + 113, &Source, &mut Policy(true))
        .unwrap();
    driver.disconnect().unwrap();
    assert_eq!(driver.phase(), ClientPhase::NeedsDrain);
    assert!(Arc::ptr_eq(driver.modern_context().unwrap(), &context));
    unsafe { driver.retire_peer_after_drain() }.unwrap();
    assert!(driver.modern_context().is_none());
    driver.stop().unwrap();
    model.response.lock().unwrap().clc_processing = false;
    model.bar.0.lock().unwrap().values.insert(0xd4208, 0);
    unsafe { driver.stop_after_quiesce() }.unwrap();
    drop(driver);
    assert_eq!(model.drops.load(Ordering::Relaxed), 1);
    assert!(model.memory.lock().unwrap().mappings.is_empty());
}

fn secure_modern() -> (
    Client<Bar, Q, NativeGuard>,
    Model,
    Owner,
    alloc::rc::Rc<AuthorityState>,
) {
    let (mut driver, model, _) = awaiting();
    let (mut authority, state) = authority(&driver, &model);
    let permit = admit(
        &mut authority,
        &driver,
        wifi::regulatory::AssociationUse::Configure,
    );
    unsafe { driver.configure_modern(&mut authority, permit, 105) }.unwrap();
    modern_keys(&mut driver, &mut authority);
    driver
        .authorize_port(driver.station().association_epoch().unwrap())
        .unwrap();
    (driver, model, authority, state)
}

fn modern_keys(driver: &mut Client<Bar, Q, NativeGuard>, authority: &mut Owner) {
    for (pairwise, index, material) in [(true, 0, 1), (false, 2, 2)] {
        let permit = admit(
            authority,
            driver,
            wifi::regulatory::AssociationUse::Management,
        );
        unsafe {
            driver.install_key_modern(
                authority,
                permit,
                pairwise,
                index,
                &[material; 16],
                ReplaySeed::ZERO,
            )
        }
        .unwrap();
    }
}

fn split_bytes(format: u8, pn: Option<u64>, source: u8) -> Vec<u8> {
    let mut payload = Vec::new();
    payload.extend_from_slice(&LOCAL.0);
    payload.extend_from_slice(&[4, source, 2, 3, 4, 5]);
    payload.extend_from_slice(&11u16.to_be_bytes());
    payload.extend_from_slice(&[0xaa, 0xaa, 3, 0, 0, 0, 8, 0, 1, 2, 3]);
    let mut frame = response(0x4288, &[]);
    frame[16..22].copy_from_slice(&[4, source, 2, 3, 4, 5]);
    frame[22..24].copy_from_slice(&(17u16 << 4).to_le_bytes());
    frame.extend_from_slice(&[6 | 0x80, 0]);
    frame.extend_from_slice(&payload);
    let mut bytes = incoming_bytes(&frame, Some((1, 0, pn.unwrap_or(0))), false);
    // Actual split RXD carries the source two-byte pad after the MAC header.
    bytes.splice(48 + 26..48 + 26, [0, 0]);
    bytes[16..20].copy_from_slice(&u32::from(format).to_le_bytes());
    if pn.is_none() {
        let mut r1 = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        r1 &= !(1 << 16);
        bytes[4..8].copy_from_slice(&r1.to_le_bytes());
        bytes.drain(32..48);
    }
    let len = bytes.len() as u32;
    bytes[..4].copy_from_slice(&((2 << 27) | len).to_le_bytes());
    bytes
}

#[test]
fn actual_queue_bound_split_parent_uses_one_replay_commit_and_original_member_sources() {
    let (mut driver, model, _, _) = secure_modern();
    let head = split_bytes(3, Some(20), 1);
    let tail = split_bytes(1, None, 2);
    device_receive(&model.queues[&0xd4500], &head, true, 0);
    assert!(
        driver
            .poll(1_000_000 + 110, &Source, &mut Policy(true))
            .unwrap()
            .is_empty()
    );
    // The same apparent SSN/TID on another actual queue cannot complete it or
    // inherit its PN. A genuine one-record parent needs its own observed PN.
    device_receive(&model.queues[&0xd4520], &tail, true, 0);
    assert!(matches!(
        driver.poll(1_000_000 + 111, &Source, &mut Policy(true)),
        Err(ClientError::Aggregate(
            wifi::security::aggregate::Error::Security(wifi::security::Error::MissingPacketNumber)
        ))
    ));
    device_receive(&model.queues[&0xd4500], &tail, true, 0);
    let events = driver
        .poll(1_000_000 + 112, &Source, &mut Policy(true))
        .unwrap();
    assert_eq!(events.len(), 2);
    for (index, event) in events.iter().enumerate() {
        let Event::Ingress(station::data::Ingress::Data(frame)) = event else {
            panic!("actual split data");
        };
        assert_eq!(&frame[..6], &LOCAL.0);
        assert_eq!(frame[7], index as u8 + 1);
        assert_eq!(&frame[12..], &[8, 0, 1, 2, 3]);
    }
    // Delivering two authenticated constituents consumed only the parent PN.
    device_receive(&model.queues[&0xd4500], &head, true, 0);
    driver
        .poll(1_000_000 + 113, &Source, &mut Policy(true))
        .unwrap();
    device_receive(&model.queues[&0xd4500], &tail, true, 0);
    assert!(matches!(
        driver.poll(1_000_000 + 114, &Source, &mut Policy(true)),
        Err(ClientError::Aggregate(
            wifi::security::aggregate::Error::Security(wifi::security::Error::Replay)
        ))
    ));
    // A malformed later constituent refuses the whole group before replay;
    // the same actual parent PN remains available for a valid replacement.
    let head = split_bytes(3, Some(21), 1);
    let mut bad = split_bytes(1, Some(22), 2);
    device_receive(&model.queues[&0xd4500], &head, true, 0);
    driver
        .poll(1_000_000 + 115, &Source, &mut Policy(true))
        .unwrap();
    device_receive(&model.queues[&0xd4500], &bad, true, 0);
    assert!(matches!(
        driver.poll(1_000_000 + 116, &Source, &mut Policy(true)),
        Err(ClientError::IncompleteParent)
    ));
    bad = split_bytes(1, None, 2);
    device_receive(&model.queues[&0xd4500], &head, true, 0);
    driver
        .poll(1_000_000 + 117, &Source, &mut Policy(true))
        .unwrap();
    device_receive(&model.queues[&0xd4500], &bad, true, 0);
    assert_eq!(
        driver
            .poll(1_000_000 + 118, &Source, &mut Policy(true))
            .unwrap()
            .len(),
        2
    );
}

fn qos_packet(sequence: u16) -> Vec<u8> {
    let mut packet = data(false);
    packet[0] |= 0x80;
    packet[22..24].copy_from_slice(&(sequence << 4).to_le_bytes());
    packet.splice(24..24, [6, 0]);
    packet
}

#[test]
fn actual_ba_ack_and_response_enable_sequence_then_one_parent_replay_and_timeout() {
    use wifi::regulatory::AssociationUse;
    let (mut driver, model, mut authority, state) = secure_modern();
    let parameters: u16 = 1 | 2 | (6 << 2) | (8 << 6);
    let mut body = vec![3, 0, 7];
    body.extend_from_slice(&parameters.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&(17u16 << 4).to_le_bytes());
    incoming(&model, &response(0xd0, &body), None, false);
    driver
        .poll(1_000_000 + 110, &Source, &mut Policy(true))
        .unwrap();
    assert!(driver.pending_block_ack());
    assert!(driver.station().active_rx_block_ack(6).is_none());
    assert!(
        !model
            .response
            .lock()
            .unwrap()
            .receive_ba
            .contains_key(&(1, 6))
    );
    let permit = admit(&mut authority, &driver, AssociationUse::Management);
    unsafe {
        driver.progress_block_ack(
            &mut authority,
            permit,
            &GuardedSource(state.clone()),
            1_000_111,
        )
    }
    .unwrap();
    let session = driver.station().active_rx_block_ack(6).unwrap().clone();
    assert_eq!(session.start_sequence(), 17);
    assert!(
        model
            .response
            .lock()
            .unwrap()
            .receive_ba
            .contains_key(&(1, 6))
    );
    assert!(driver.pending_block_ack());
    let permit = admit(&mut authority, &driver, AssociationUse::Management);
    unsafe {
        driver.progress_block_ack(
            &mut authority,
            permit,
            &GuardedSource(state.clone()),
            1_000_112,
        )
    }
    .unwrap();
    let sent = finish_tx(&model);
    assert_eq!(&sent[0][24..29], &[3, 1, 7, 0, 0]);
    assert!(!driver.pending_block_ack());
    driver
        .poll(1_000_000 + 113, &Source, &mut Policy(true))
        .unwrap();
    driver.poll_released().unwrap();
    // Deliver SSN17 to start; receiving19 before18 must not consume PN3 yet.
    incoming(&model, &qos_packet(17), Some((1, 0, 1)), false);
    assert_eq!(
        driver
            .poll(1_000_000 + 114, &Source, &mut Policy(true))
            .unwrap()
            .len(),
        1
    );
    incoming(&model, &qos_packet(19), Some((1, 0, 3)), false);
    assert!(
        driver
            .poll(1_000_000 + 115, &Source, &mut Policy(true))
            .unwrap()
            .is_empty()
    );
    assert_eq!(driver.next_receive_deadline(), Some(1_040_115));
    incoming(&model, &qos_packet(18), Some((1, 0, 2)), false);
    assert_eq!(
        driver
            .poll(1_000_000 + 116, &Source, &mut Policy(true))
            .unwrap()
            .len(),
        2
    );
    assert_eq!(driver.next_receive_deadline(), None);
    incoming(&model, &qos_packet(21), Some((1, 0, 5)), false);
    assert!(
        driver
            .poll(1_000_000 + 117, &Source, &mut Policy(true))
            .unwrap()
            .is_empty()
    );
    assert!(
        driver
            .poll(1_040_117, &Source, &mut Policy(true))
            .unwrap()
            .is_empty()
    );
    // Exact source timeout is strict after, and release then advances replay.
    assert_eq!(
        driver
            .poll(1_080_118, &Source, &mut Policy(true))
            .unwrap()
            .len(),
        1
    );
    // Peer DELBA invalidates before actual firmware stop; stop never needs a
    // new transmit permission even after genuine model policy revocation.
    let mut delete = vec![3, 2];
    delete.extend_from_slice(&((6u16 << 12) | 0x0800).to_le_bytes());
    delete.extend_from_slice(&37u16.to_le_bytes());
    incoming(&model, &response(0xd0, &delete), None, false);
    driver.poll(1_080_119, &Source, &mut Policy(true)).unwrap();
    assert!(driver.station().validate_rx_block_ack(&session).is_err());
    state.allowed.set(false);
    driver.progress_block_ack_stop().unwrap();
    assert!(!driver.pending_block_ack());
    assert!(
        !model
            .response
            .lock()
            .unwrap()
            .receive_ba
            .contains_key(&(1, 6))
    );
    assert_eq!(driver.next_receive_deadline(), None);
}

#[test]
fn negotiated_ccmp_and_gcmp_ciphers_bind_real_key_bytes_and_receive_layouts() {
    use wifi::regulatory::AssociationUse;
    for (suite, firmware, length) in [(4, 4u32, 16), (10, 10, 32), (8, 11, 16), (9, 12, 32)] {
        let (mut driver, model, _) = awaiting_cipher(suite);
        let (mut authority, state) = authority(&driver, &model);
        let permit = admit(&mut authority, &driver, AssociationUse::Configure);
        unsafe { driver.configure_modern(&mut authority, permit, 105) }.unwrap();
        assert!(matches!(
            driver.install_key(true, 0, &[1; 16], ReplaySeed::ZERO),
            Err(ClientError::ModernAdmissionRequired)
        ));
        for (pairwise, index, value) in [(true, 0, 1), (false, 2, 2)] {
            let material = vec![value; length];
            let permit = admit(&mut authority, &driver, AssociationUse::Management);
            let key = unsafe {
                driver.install_key_modern(
                    &mut authority,
                    permit,
                    pairwise,
                    index,
                    &material,
                    ReplaySeed::ZERO,
                )
            }
            .unwrap();
            assert_eq!(key.index(), index);
        }
        driver
            .authorize_port(driver.station().association_epoch().unwrap())
            .unwrap();
        let permit = admit(&mut authority, &driver, AssociationUse::Data);
        let epoch = driver.station().association_epoch().unwrap();
        unsafe {
            driver.transmit_modern(
                &mut authority,
                permit,
                epoch,
                &eth(0x0800),
                TxClass::Data,
                Some(6),
                &GuardedSource(state.clone()),
                &mut Policy(true),
            )
        }
        .unwrap();
        let packet = finish_tx(&model);
        assert_eq!(&packet[0][24..28], &[6, 0, 0xaa, 0xaa]);
        driver
            .poll(1_000_000 + 110, &Source, &mut Policy(true))
            .unwrap();
        driver.poll_released().unwrap();
        let mut raw = incoming_bytes(&qos_packet(1), Some((1, 0, 1)), false);
        let r2 = u32::from_le_bytes(raw[8..12].try_into().unwrap());
        raw[8..12].copy_from_slice(&((r2 & !(31 << 16)) | (firmware << 16)).to_le_bytes());
        device_receive(&model.queues[&0xd4520], &raw, true, 0);
        assert_eq!(
            driver
                .poll(1_000_000 + 111, &Source, &mut Policy(true))
                .unwrap()
                .len(),
            1
        );
        // A valid descriptor layout for another cipher cannot inherit this
        // actual key identity merely because WCID/index/PN look plausible.
        let wrong = if firmware == 4 { 11 } else { 4 };
        raw[8..12].copy_from_slice(&((r2 & !(31 << 16)) | (wrong << 16)).to_le_bytes());
        device_receive(&model.queues[&0xd4520], &raw, true, 0);
        assert!(matches!(
            driver.poll(1_000_000 + 112, &Source, &mut Policy(true)),
            Err(ClientError::WrongProfile)
        ));
    }
}

#[test]
fn peer_delba_before_native_start_cannot_publish_or_resurrect_the_agreement() {
    let (mut driver, model, _, _) = secure_modern();
    let parameters: u16 = 2 | (6 << 2) | (8 << 6);
    let mut request = vec![3, 0, 7];
    request.extend_from_slice(&parameters.to_le_bytes());
    request.extend_from_slice(&[0, 0, 0, 0]);
    incoming(&model, &response(0xd0, &request), None, false);
    driver
        .poll(1_000_000 + 110, &Source, &mut Policy(true))
        .unwrap();
    assert!(driver.pending_block_ack());
    let commands = model.response.lock().unwrap().client_commands.len();
    let mut delete = vec![3, 2];
    delete.extend_from_slice(&((6u16 << 12) | 0x0800).to_le_bytes());
    delete.extend_from_slice(&37u16.to_le_bytes());
    incoming(&model, &response(0xd0, &delete), None, false);
    driver
        .poll(1_000_000 + 111, &Source, &mut Policy(true))
        .unwrap();
    assert!(!driver.pending_block_ack());
    assert!(driver.station().active_rx_block_ack(6).is_none());
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        commands
    );
    assert!(
        !model
            .response
            .lock()
            .unwrap()
            .receive_ba
            .contains_key(&(1, 6))
    );
    assert_eq!(driver.next_receive_deadline(), None);
}

#[test]
fn modern_failed_real_configuration_retains_current_context_and_peer() {
    use wifi::regulatory::AssociationUse;
    let (mut driver, model, before) = awaiting();
    let context = driver.modern_context().unwrap().clone();
    let (mut authority, _) = authority(&driver, &model);
    let permit = admit(&mut authority, &driver, AssociationUse::Configure);
    model.response.lock().unwrap().bss_status = 0xdead;
    assert!(unsafe { driver.configure_modern(&mut authority, permit, 105) }.is_err());
    assert_eq!(driver.phase(), ClientPhase::Quarantined);
    assert_eq!(driver.station().phase(), station::Phase::Configuring);
    assert_eq!(driver.completed_modern_requests(), 0);
    assert_eq!(
        model.response.lock().unwrap().client_commands.len(),
        before + 1
    );
    assert!(Arc::ptr_eq(driver.modern_context().unwrap(), &context));
    assert!(
        driver
            .join_modern(
                modern_inputs(&driver).0,
                modern_inputs(&driver).1,
                profile(),
                106,
                &Source,
                &mut Policy(true)
            )
            .is_err()
    );
    drop(driver);
    assert_eq!(model.drops.load(Ordering::Relaxed), 0);
    assert!(!model.memory.lock().unwrap().mappings.is_empty());
}

#[test]
fn actual_late_firmware_completion_cannot_reuse_precommand_configuration_time() {
    use wifi::regulatory::AssociationUse;
    let (mut driver, model, _) = awaiting();
    let (mut authority, _) = authority(&driver, &model);
    let permit = admit(&mut authority, &driver, AssociationUse::Configure);
    // Real publication/ACK remains within PCI3s. Its actual elapsed time must
    // nevertheless exceed the independent canonical500ms Configure lifetime.
    model.response.lock().unwrap().pause_next_index_us = 600_000;
    assert!(matches!(
        unsafe { driver.configure_modern(&mut authority, permit, 105) },
        Err(ClientError::Station(station::Error::Timeout))
    ));
    assert_eq!(driver.phase(), ClientPhase::Quarantined);
    assert_eq!(driver.station().phase(), station::Phase::Quarantined);
    assert_eq!(driver.completed_modern_requests(), 7);
    assert!(
        driver
            .authorize_port(driver.station().association_epoch().unwrap())
            .is_err()
    );
    drop(driver);
    assert_eq!(model.drops.load(Ordering::Relaxed), 0);
    assert!(!model.memory.lock().unwrap().mappings.is_empty());
}

#[test]
fn copied_modern_local_streams_refuse_before_any_peer_or_packet_publication() {
    let (mut driver, model) = setup();
    let (mut join, beacon) = modern_inputs(&driver);
    let mut elements = join.request.elements().to_vec();
    let mut at = 0;
    while elements[at] != 45 {
        at += 2 + usize::from(elements[at + 1]);
    }
    elements[at + 2 + 5] = 0xff; // Add an unobserved third HT RX stream.
    let local =
        station::phy::Capabilities::parse(Band::Ghz5, station::phy::Role::Station, &elements)
            .unwrap()
            .with_local_he_source_maps(
                *driver
                    .local_advertisement(Band::Ghz5)
                    .unwrap()
                    .he_source_maps(),
            )
            .unwrap();
    join.request = AssociationRequest::new_modern_with_local(
        0x11,
        10,
        elements,
        local,
        Mode::Eht,
        Width::Mhz80,
    )
    .unwrap();
    let before = model.response.lock().unwrap().client_commands.len();
    assert!(matches!(
        driver.join_modern(join, beacon, profile(), 100, &Source, &mut Policy(true)),
        Err(ClientError::WrongProfile)
    ));
    assert_eq!(driver.phase(), ClientPhase::Idle);
    assert_eq!(model.response.lock().unwrap().client_commands.len(), before);
    assert_eq!(model.queues[&0xd4300].lock().unwrap().head, 0);
}
