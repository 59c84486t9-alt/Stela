// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
// Actual completed RX and native EDCA command peers; no physical-radio grant.
use super::*;
use crate::net::wifi::regulatory::database::{Wmm, WmmAc};

type Native = Client<Bar, Q, NativeGuard>;
const NOW: u64 = 1_000_210;

fn beacon(driver: &Native, count: u8, edit: impl FnOnce(&mut [u8])) -> Vec<u8> {
    let mut elements = driver.modern_context().unwrap().beacon().elements.clone();
    let mut at = 0;
    loop {
        let n = usize::from(elements[at + 1]);
        if elements[at] == 221 && elements[at + 2..at + 6] == [0, 0x50, 0xf2, 2] {
            let wmm = &mut elements[at + 2..at + 2 + n];
            wmm[6] = (wmm[6] & 0xf0) | (count & 15);
            edit(wmm);
            break;
        }
        at += 2 + n;
    }
    let mut fixed = vec![0; 8];
    fixed.extend_from_slice(&100u16.to_le_bytes());
    fixed.extend_from_slice(&0x11u16.to_le_bytes());
    fixed.extend_from_slice(&elements);
    let mut frame = response(0x80, &fixed);
    frame[4..10].copy_from_slice(&crate::net::Mac::BROADCAST.0);
    frame
}
fn observe(driver: &mut Native, model: &Model, frame: &[u8]) -> Result<Vec<Event>, ClientError> {
    incoming(model, frame, None, false);
    driver.poll(NOW, &Source, &mut Policy(true))
}
fn update(driver: &mut Native, owner: &mut Owner, limit: Option<&Wmm>) -> Result<(), ClientError> {
    let permit = admit(owner, driver, AssociationUse::Management);
    // SAFETY: actual same modeled requester; held guards serialize publication,
    // native queue drain and fixed model OS country/queue rule are explicit.
    unsafe { driver.update_edca_modern(owner, permit, limit) }
}
fn commands(model: &Model) -> usize {
    model.response.lock().unwrap().client_commands.len()
}
fn bytes(model: &Model) -> Vec<u8> {
    model
        .response
        .lock()
        .unwrap()
        .client_commands
        .last()
        .unwrap()[48..]
        .to_vec()
}

#[test]
fn associated_native_beacon_applies_new_baseline_only_after_actual_ack_and_dma() {
    let (mut driver, model, mut owner, state) = secure_modern();
    let context = driver.modern_context().unwrap().clone();
    let original = context.negotiated().clone();
    let old = *driver.applied_edca().unwrap();
    let frame = beacon(&driver, 1, |w| {
        // A valid later AP may relax earlier queues; original negotiation is
        // not the baseline against which a current regulatory clamp is checked.
        w[8] = 2;
        w[9] = 0x52;
        w[10..12].copy_from_slice(&100u16.to_le_bytes());
    });
    let before = commands(&model);
    let events = observe(&mut driver, &model, &frame).unwrap();
    assert!(matches!(events.as_slice(), [Event::Raw(_)]));
    assert!(driver.pending_edca());
    assert_eq!(*driver.applied_edca().unwrap(), old);
    assert_eq!(commands(&model), before);
    update(&mut driver, &mut owner, None).unwrap();
    assert_eq!(commands(&model), before + 1);
    let mut expected = vec![0, 0, 4, 0];
    for record in [
        [0, 0, 12, 0, 0, 15, 2, 3, 47, 0, 2, 0],
        [0, 0, 12, 0, 1, 15, 3, 4, 94, 0, 2, 0],
        [0, 0, 12, 0, 2, 15, 2, 5, 100, 0, 2, 0],
        [0, 0, 12, 0, 3, 15, 4, 10, 0, 0, 7, 0],
    ] {
        expected.extend_from_slice(&record);
    }
    assert_eq!(bytes(&model), expected);
    assert_eq!(driver.phase(), ClientPhase::Associated);
    assert!(!driver.pending_edca());
    assert_eq!(driver.applied_edca().unwrap().parameter_set_count, 1);
    assert_eq!(
        driver.applied_edca().unwrap().access_categories[0].txop_32us,
        100
    );
    assert!(Arc::ptr_eq(driver.modern_context().unwrap(), &context));
    assert_eq!(context.negotiated(), &original);
    assert!(
        state
            .windows
            .borrow()
            .iter()
            .any(|&(a, b)| a == before && b == before + 1)
    );
    let reply = driver.replies().last().unwrap();
    assert_eq!(reply.status, 0);
    assert!(reply.dma_released);
    assert!(
        driver
            .state()
            .controller
            .state()
            .mailbox
            .as_ref()
            .unwrap()
            .receive_idle()
    );
}

#[test]
fn unchanged_count_and_four_bit_wrap_use_source_equality_not_ordering() {
    let (mut driver, model, mut owner, _) = secure_modern();
    let before = commands(&model);
    let frame = beacon(&driver, 0, |w| w[9] = 0x52);
    observe(&mut driver, &model, &frame).unwrap();
    assert!(!driver.pending_edca());
    assert_eq!(commands(&model), before);
    for count in [15, 0, 7, 2] {
        let frame = beacon(&driver, count, |_| {});
        observe(&mut driver, &model, &frame).unwrap();
        assert!(driver.pending_edca());
        update(&mut driver, &mut owner, None).unwrap();
        assert_eq!(driver.applied_edca().unwrap().parameter_set_count, count);
    }
    let frame = beacon(&driver, 2, |_| {});
    observe(&mut driver, &model, &frame).unwrap();
    assert!(!driver.pending_edca());
    assert_eq!(commands(&model), before + 4);
}

#[test]
fn latest_completed_native_observation_replaces_only_unpublished_cpu_update() {
    let (mut driver, model, mut owner, _) = secure_modern();
    let before = commands(&model);
    for count in [1, 2] {
        let frame = beacon(&driver, count, |w| {
            w[10..12].copy_from_slice(&(u16::from(count) * 10).to_le_bytes())
        });
        observe(&mut driver, &model, &frame).unwrap();
    }
    assert_eq!(commands(&model), before);
    update(&mut driver, &mut owner, None).unwrap();
    assert_eq!(commands(&model), before + 1);
    assert_eq!(driver.applied_edca().unwrap().parameter_set_count, 2);
    assert_eq!(
        driver.applied_edca().unwrap().access_categories[0].txop_32us,
        20
    );
}

#[test]
fn current_regulatory_queue_limits_clamp_actual_dynamic_edca_bytes() {
    let (mut driver, model, mut owner, state) = secure_modern();
    let frame = beacon(&driver, 1, |_| {});
    observe(&mut driver, &model, &frame).unwrap();
    let rules = core::array::from_fn(|index| WmmAc {
        cw_min: (1 << (5 + index)) - 1,
        cw_max: (1 << (8 + index)) - 1,
        aifsn: 7 + index as u8,
        cot_us: (31 + 31 * index as u16) * 32,
    });
    let limit = Wmm {
        client: rules,
        ap: rules,
    };
    update(&mut driver, &mut owner, Some(&limit)).unwrap();
    let mut expected = vec![0, 0, 4, 0];
    for record in [
        [0, 0, 12, 0, 0, 15, 5, 8, 31, 0, 7, 0],
        [0, 0, 12, 0, 1, 15, 6, 9, 62, 0, 8, 0],
        [0, 0, 12, 0, 2, 15, 7, 10, 0, 0, 9, 0],
        [0, 0, 12, 0, 3, 15, 8, 11, 0, 0, 10, 0],
    ] {
        expected.extend_from_slice(&record);
    }
    assert_eq!(bytes(&model), expected);
    assert_eq!(
        driver.applied_edca().unwrap().access_categories[3].txop_32us,
        31
    );
    let inspections = state.edca_inspections.borrow();
    assert_eq!(inspections.len(), 2);
    assert!(inspections[0].hardware);
    assert!(!inspections[1].hardware);
    for inspection in inspections.iter() {
        assert_eq!(inspection.count, 1);
        assert_eq!(
            inspection.observed,
            driver
                .modern_context()
                .unwrap()
                .negotiated()
                .wmm
                .as_ref()
                .unwrap()
                .access_categories
        );
        assert_eq!(
            inspection.effective,
            driver.applied_edca().unwrap().access_categories
        );
        assert_ne!(inspection.observed, inspection.effective);
    }
}

#[test]
fn revoked_policy_and_foreign_context_cannot_publish_observed_update() {
    let (mut driver, model, mut owner, state) = secure_modern();
    let frame = beacon(&driver, 1, |_| {});
    observe(&mut driver, &model, &frame).unwrap();
    let before = commands(&model);
    let old = *driver.applied_edca().unwrap();
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    state.allowed.set(false);
    assert!(unsafe { driver.update_edca_modern(&mut owner, permit, None) }.is_err());
    assert_eq!(commands(&model), before);
    assert_eq!(*driver.applied_edca().unwrap(), old);
    assert_eq!(driver.phase(), ClientPhase::Associated);
    assert!(driver.pending_edca());
    state.allowed.set(true);
    let (other, _other_model, mut other_owner, _) = secure_modern();
    let permit = admit(&mut other_owner, &other, AssociationUse::Management);
    assert!(unsafe { driver.update_edca_modern(&mut other_owner, permit, None) }.is_err());
    assert_eq!(commands(&model), before);
    assert_eq!(*driver.applied_edca().unwrap(), old);
    update(&mut driver, &mut owner, None).unwrap();
}

#[test]
fn wrong_peer_channel_and_receiver_never_create_current_edca_authority() {
    let (mut driver, model, _, _) = secure_modern();
    let before = commands(&model);
    for field in [4, 10, 16] {
        let mut frame = beacon(&driver, 1, |_| {});
        frame[field] ^= 2;
        assert!(observe(&mut driver, &model, &frame).is_err());
        assert!(!driver.pending_edca());
    }
    struct Channels;
    impl station::RegulatoryPolicy for Channels {
        fn allow_management_tx(&mut self, _: wifi::Channel) -> bool {
            true
        }
        fn allow_data_tx(&mut self, _: wifi::Channel) -> bool {
            true
        }
    }
    impl scan::Policy for Channels {
        fn allow_receive(&mut self, _: wifi::Channel) -> bool {
            true
        }
        fn allow_probe(&mut self, _: wifi::Channel) -> bool {
            true
        }
        fn lookup_channel(&mut self, band: Band, number: u16) -> Option<wifi::Channel> {
            (band == Band::Ghz5 && matches!(number, 36 | 40)).then_some(wifi::Channel {
                band,
                number,
                frequency_mhz: 5000 + number * 5,
            })
        }
    }
    let frame = beacon(&driver, 1, |_| {});
    let mut raw = incoming_bytes(&frame, None, false);
    raw[13] = 40; // Actual RXD3 CH_FREQ, independently accepted by source policy.
    device_receive(&model.queues[&0xd4520], &raw, true, 0);
    assert!(matches!(
        driver.poll(NOW, &Source, &mut Channels),
        Err(ClientError::WrongProfile)
    ));
    assert!(!driver.pending_edca());
    let mut corrupt = frame;
    corrupt[1] |= 0x04; // More fragments: no dynamic observation authority.
    assert!(observe(&mut driver, &model, &corrupt).is_err());
    assert_eq!(commands(&model), before);
}

#[test]
fn malformed_or_unsupported_current_wmm_cancels_unpublished_relaxation() {
    let (mut driver, model, _, _) = secure_modern();
    let before = commands(&model);
    for change in 0..6 {
        let valid = beacon(&driver, 1, |_| {});
        observe(&mut driver, &model, &valid).unwrap();
        assert!(driver.pending_edca());
        let mut invalid = beacon(&driver, 2, |w| match change {
            0 => w[12] = w[8], // Duplicate ACI.
            1 => w[9] = 0x20,  // Source dynamic CWmin0 invalid.
            2 => w[8] |= 0x10, // ACM change has no canonical admission update.
            3 => w[6] ^= 0x80, // U-APSD renegotiation is separate.
            4 => w[8] = 1,
            _ => {} // Explicit strict parser AIFSN limit.
        });
        if change == 5 {
            invalid.extend_from_slice(&[255, 1, 38]);
        }
        assert!(observe(&mut driver, &model, &invalid).is_err());
        assert!(!driver.pending_edca());
        assert_eq!(commands(&model), before);
        assert_eq!(driver.applied_edca().unwrap().parameter_set_count, 0);
    }
}

#[test]
fn outstanding_actual_packet_owner_blocks_edca_until_txfree_descriptor_retirement() {
    let (mut driver, model, mut owner, state) = secure_modern();
    let permit = admit(&mut owner, &driver, AssociationUse::Data);
    let epoch = driver.station().association_epoch().unwrap();
    unsafe {
        driver.transmit_modern(
            &mut owner,
            permit,
            epoch,
            &eth(0x0800),
            TxClass::Data,
            Some(6),
            &GuardedSource(state),
            &mut Policy(true),
        )
    }
    .unwrap();
    let frame = beacon(&driver, 1, |_| {});
    observe(&mut driver, &model, &frame).unwrap();
    let before = commands(&model);
    assert!(matches!(
        update(&mut driver, &mut owner, None),
        Err(ClientError::NeedsDrain)
    ));
    assert_eq!(commands(&model), before);
    assert_eq!(driver.phase(), ClientPhase::Associated);
    assert_eq!(finish_tx(&model).len(), 1);
    driver.poll(NOW + 1, &Source, &mut Policy(true)).unwrap();
    let released = driver.poll_released().unwrap();
    assert_eq!(released.len(), 1);
    update(&mut driver, &mut owner, None).unwrap();
    assert_eq!(driver.applied_edca().unwrap().parameter_set_count, 1);
    assert_eq!(released[0].context.association_epoch(), epoch);
}

#[test]
fn actual_initial_key_installation_makes_pending_native_observation_stale_without_publication() {
    let (mut driver, model, _) = awaiting();
    let (mut owner, _) = authority(&driver, &model);
    let permit = admit(&mut owner, &driver, AssociationUse::Configure);
    unsafe { driver.configure_modern(&mut owner, permit, 105) }.unwrap();
    let frame = beacon(&driver, 1, |_| {});
    observe(&mut driver, &model, &frame).unwrap();
    let permit = admit(&mut owner, &driver, AssociationUse::Management);
    unsafe {
        driver.install_key_modern(&mut owner, permit, true, 0, &[0x77; 16], ReplaySeed::ZERO)
    }
    .unwrap();
    let before = commands(&model);
    assert!(matches!(
        update(&mut driver, &mut owner, None),
        Err(ClientError::Station(station::Error::Stale))
    ));
    assert_eq!(commands(&model), before);
    assert_eq!(driver.applied_edca().unwrap().parameter_set_count, 0);
    assert_eq!(driver.phase(), ClientPhase::Associated);
    let frame = beacon(&driver, 2, |_| {});
    observe(&mut driver, &model, &frame).unwrap();
    update(&mut driver, &mut owner, None).unwrap();
}

#[test]
fn negative_late_and_unmatched_actual_edca_ack_quarantine_original_owner_without_fake_rollback() {
    for failure in 0..3 {
        let (mut driver, model, mut owner, _) = secure_modern();
        let context = driver.modern_context().unwrap().clone();
        let old = *driver.applied_edca().unwrap();
        let frame = beacon(&driver, 1, |_| {});
        observe(&mut driver, &model, &frame).unwrap();
        let before = commands(&model);
        match failure {
            0 => model.response.lock().unwrap().edca_status = Some(0xbad),
            1 => model.response.lock().unwrap().pause_next_index_us = 3_100_000,
            _ => model.response.lock().unwrap().command_delta = 1, // Actual unmatched ACK.
        }
        assert!(update(&mut driver, &mut owner, None).is_err());
        assert_eq!(commands(&model), before + 1);
        assert_eq!(driver.phase(), ClientPhase::Quarantined);
        assert_eq!(*driver.applied_edca().unwrap(), old);
        assert!(driver.pending_edca());
        assert!(Arc::ptr_eq(driver.modern_context().unwrap(), &context));
        let count = commands(&model);
        assert!(update(&mut driver, &mut owner, None).is_err());
        assert_eq!(commands(&model), count);
        drop(driver);
        assert_eq!(model.drops.load(Ordering::Relaxed), 0);
        assert!(!model.memory.lock().unwrap().mappings.is_empty());
    }
}

#[test]
fn independently_denied_hardware_and_os_current_queue_guards_preserve_pending_owner() {
    let (mut driver, model, mut owner, state) = secure_modern();
    let frame = beacon(&driver, 1, |_| {});
    observe(&mut driver, &model, &frame).unwrap();
    let before = commands(&model);
    let old = *driver.applied_edca().unwrap();
    for hardware in [true, false] {
        state.edca_hardware.set(!hardware);
        state.edca_os.set(hardware);
        // Original context admission still succeeds. Only the exact new queue
        // operation is denied by the independently held dynamic provider.
        let permit = admit(&mut owner, &driver, AssociationUse::Management);
        let result = unsafe { driver.update_edca_modern(&mut owner, permit, None) };
        match result {
            Err(ClientError::Regulatory(reg::Error::HardwareDenied)) if hardware => {}
            Err(ClientError::Regulatory(reg::Error::OsDenied)) if !hardware => {}
            other => panic!("exact current provider denial expected: {other:?}"),
        }
        assert_eq!(commands(&model), before);
        assert_eq!(driver.phase(), ClientPhase::Associated);
        assert_eq!(*driver.applied_edca().unwrap(), old);
        assert!(driver.pending_edca());
    }
    state.edca_hardware.set(true);
    state.edca_os.set(true);
    update(&mut driver, &mut owner, None).unwrap();
}

#[test]
fn original_association_only_provider_cannot_implicitly_authorize_dynamic_queues() {
    struct OriginalOnly(Hardware);
    struct Guard(HardwareGuard);
    impl reg::HardwareLease for Guard {
        fn context(&self) -> reg::NativeContext {
            reg::HardwareLease::context(&self.0)
        }
        fn lookup_channel(&mut self, band: Band, number: u16) -> Option<wifi::Channel> {
            reg::HardwareLease::lookup_channel(&mut self.0, band, number)
        }
        fn allows(&mut self, operation: reg::Operation) -> bool {
            reg::HardwareLease::allows(&mut self.0, operation)
        }
        fn allows_association(&mut self, operation: &reg::AssociationOperation<'_>) -> bool {
            reg::HardwareLease::allows_association(&mut self.0, operation)
        }
        // Deliberately uses the actual default-deny dynamic provider hook.
    }
    // SAFETY: delegates this exact retained model policy/guard without extending
    // its accepted operations; original context permission never grants EDCA.
    unsafe impl reg::HardwarePolicy for OriginalOnly {
        type Lease<'a> = Guard;
        fn acquire(&mut self) -> Option<Self::Lease<'_>> {
            reg::HardwarePolicy::acquire(&mut self.0).map(Guard)
        }
    }
    let (mut driver, model, _, state) = secure_modern();
    let mut owner = reg::Owner::new(OriginalOnly(Hardware(state.clone())), Os(state)).unwrap();
    let frame = beacon(&driver, 1, |_| {});
    observe(&mut driver, &model, &frame).unwrap();
    let before = commands(&model);
    let permit = owner
        .admit_association(
            driver.station(),
            driver.modern_context().unwrap().clone(),
            AssociationUse::Management,
        )
        .unwrap();
    assert!(matches!(
        unsafe { driver.update_edca_modern(&mut owner, permit, None) },
        Err(ClientError::Regulatory(reg::Error::HardwareDenied))
    ));
    assert_eq!(commands(&model), before);
    assert!(driver.pending_edca());
    assert_eq!(driver.phase(), ClientPhase::Associated);
    assert_eq!(driver.applied_edca().unwrap().parameter_set_count, 0);
}

#[test]
fn current_canonical_block_ack_work_must_drain_before_native_queue_reconfiguration() {
    let (mut driver, model, mut owner, _) = secure_modern();
    let parameters: u16 = 1 | 2 | (6 << 2) | (8 << 6);
    let mut body = vec![3, 0, 7];
    body.extend_from_slice(&parameters.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body.extend_from_slice(&(17u16 << 4).to_le_bytes());
    incoming(&model, &response(0xd0, &body), None, false);
    driver.poll(NOW - 1, &Source, &mut Policy(true)).unwrap();
    assert!(driver.pending_block_ack());
    let frame = beacon(&driver, 1, |_| {});
    observe(&mut driver, &model, &frame).unwrap();
    let before = commands(&model);
    assert!(matches!(
        update(&mut driver, &mut owner, None),
        Err(ClientError::NeedsDrain)
    ));
    assert_eq!(commands(&model), before);
    assert_eq!(driver.applied_edca().unwrap().parameter_set_count, 0);
    assert!(driver.pending_edca());
    assert!(driver.pending_block_ack());
    assert_eq!(driver.phase(), ClientPhase::Associated);
}
