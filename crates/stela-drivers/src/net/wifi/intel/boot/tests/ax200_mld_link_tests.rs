// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2026 Intel Corporation
//! Selected MLD PHY assignment, active response admission and full unassign.
use super::*;
fn image() -> Vec<u8> {
    let mut bytes = binding_bytes(true);
    for (index, mask) in [(2u32, 1u32 << 4), (3, 1 << 14)] {
        bytes.extend(30u32.to_le_bytes());
        bytes.extend(8u32.to_le_bytes());
        bytes.extend(index.to_le_bytes());
        bytes.extend(mask.to_le_bytes());
    }
    bytes
}
fn complete_link(
    binding: &Ax200Binding<'_, Model, ClockBios, ScanOs>,
    native: &Native,
    command: &BindingCommand,
) {
    let boot = boot(&binding.power.phy.scan);
    let slot = boot.read;
    assert!(boot.credits > 0);
    let raw = device_read(
        &native.domain,
        boot.free.region().address,
        usize::from(slot) * 8,
        8,
    );
    let vid = (u64::from_le_bytes(raw.try_into().unwrap()) & 0xfff) as u16;
    assert!(vid > 0 && boot.buffers[usize::from(vid - 1)].device_owned);
    complete_from_free_slot(
        boot,
        &native.domain,
        slot,
        vid,
        slot,
        &command_packet(
            command.id().wire(),
            binding.ticket().unwrap().sequence(),
            &[],
        ),
    );
}
fn exercise(bytes: &[u8]) {
    let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), bytes);
    let empty = resources::Catalog::from_handoff(vec![]).unwrap();
    let native = Native::default();
    let source = Source::default();
    let policy = Arc::new(PolicyState::default());
    let (power, _, _) = powered(&catalog, &empty, &source, &native, &policy, false);
    assert!(power.phy.scan.mac.is_mld());
    authorize(&policy);
    // SAFETY: this same-device model retains every source basic response rate
    // and actual programmed ceiling through native deactivation/reset or stop.
    let mut link = unsafe { power.begin_mld_link() }.unwrap_or_else(|_| panic!("MLD link"));
    let at_sync = policy.clone();
    native.domain.records.lock().unwrap().device_sync_hook = Some(Arc::new(move || {
        assert_eq!(at_sync.held.load(Ordering::SeqCst), 1);
        assert_eq!(
            at_sync.transmit_rates.load(Ordering::SeqCst),
            ALL_COLD_RATES
        );
    }));
    assert_eq!(
        // SAFETY: Source allocates exclusive model RAM for this retained
        // requester/domain; its policy guard remains held through publication.
        unsafe { link.advance(&source) }.unwrap(),
        Ax200BindingPhase::Waiting(BindingCommandKind::AttachPhy)
    );
    native.domain.records.lock().unwrap().device_sync_hook = None;
    assert_eq!(
        link.commands()
            .iter()
            .map(BindingCommand::kind)
            .collect::<Vec<_>>(),
        [
            BindingCommandKind::AttachPhy,
            BindingCommandKind::ActivateLink,
            BindingCommandKind::Power
        ]
    );
    assert_eq!(
        link.commands()[0].id(),
        Id {
            group: 3,
            opcode: 9,
            version: 0
        }
    );
    assert_eq!(link.commands()[0].bytes().len(), 208);
    assert_eq!(&link.commands()[0].bytes()[12..16], &[0; 4]);
    assert_eq!(
        &link.commands()[1].bytes()[24..32],
        &[3, 0, 0, 0, 1, 0, 0, 0]
    );
    for command in link.commands().to_vec() {
        emitted_binding(&link, &native);
        complete_link(&link, &native, &command);
        let mut records = native.domain.records.lock().unwrap();
        records.cpu_sync_fail = Some(records.cpu_syncs + 1);
        drop(records);
        assert!(matches!(
            // SAFETY: completion was synchronous; injected CPU-sync failure
            // retains the same mapped command and receive buffers for retry.
            unsafe { link.advance(&source) },
            Err(Ax200BindingError::Boot(Error::CommandReclaim(_)))
        ));
        assert!(link.first_error().is_none());
        native.domain.records.lock().unwrap().cpu_sync_fail = None;
        // SAFETY: the failed reclaim retained the live mappings, same source
        // and requester; clearing the injection adds no device or worker.
        unsafe { link.advance(&source) }.unwrap();
        link.replenish_completed_receive().unwrap();
    }
    assert_eq!(link.phase(), Ax200BindingPhase::AuthenticationRequired);
    native.revoked.store(true, Ordering::SeqCst);
    let acquired = policy.acquired.load(Ordering::SeqCst);
    link.begin_remove().unwrap();
    // SAFETY: revocation starts ordered removal in the same no-device model;
    // the link still retains all DMA mappings and the source owner.
    unsafe { link.advance(&source) }.unwrap();
    let commands = link.commands()[3..].to_vec();
    assert_eq!(
        commands
            .iter()
            .map(BindingCommand::kind)
            .collect::<Vec<_>>(),
        [
            BindingCommandKind::DeactivateLink,
            BindingCommandKind::Power,
            BindingCommandKind::RemoveLink,
            BindingCommandKind::RestoreInactiveLink
        ]
    );
    for (index, command) in commands.into_iter().enumerate() {
        assert_ne!(link.phase(), Ax200BindingPhase::Unbound);
        link = match link.into_transmit_power() {
            Err(owner) => *owner,
            Ok(_) => panic!("parent escaped before complete unassign"),
        };
        emitted_binding(&link, &native);
        complete_link(&link, &native, &command);
        // SAFETY: this synchronous model completed the current removal ACK;
        // the retained domain/source still own every pending DMA allocation.
        unsafe { link.advance(&source) }.unwrap();
        link.replenish_completed_receive().unwrap();
        if index < 3 {
            assert_ne!(link.phase(), Ax200BindingPhase::Unbound);
        }
    }
    assert_eq!(link.phase(), Ax200BindingPhase::Unbound);
    assert_eq!(policy.acquired.load(Ordering::SeqCst), acquired);
    let power = link
        .into_transmit_power()
        .unwrap_or_else(|_| panic!("original PHY parent"));
    assert_eq!(power.phy.scan.mac.inactive_link_id(), Some(0));
    let mut phy = power
        .into_phy_context()
        .unwrap_or_else(|_| panic!("unique channel context"));
    phy.begin_remove().unwrap();
    // SAFETY: complete link unassignment returned this original PHY owner;
    // its source/domain remain live with no asynchronous model DMA user.
    unsafe { phy.advance(&source) }.unwrap();
    let command = phy.commands().last().unwrap().clone();
    assert_eq!(command.kind(), PhyCommandKind::Remove);
    assert_eq!(&command.bytes()[4..8], &3u32.to_le_bytes());
    let boot = boot(&phy.scan);
    let slot = boot.read;
    let raw = device_read(
        &native.domain,
        boot.free.region().address,
        usize::from(slot) * 8,
        8,
    );
    let vid = (u64::from_le_bytes(raw.try_into().unwrap()) & 0xfff) as u16;
    assert!(vid > 0 && boot.buffers[usize::from(vid - 1)].device_owned);
    complete_from_free_slot(
        boot,
        &native.domain,
        slot,
        vid,
        slot,
        &command_packet(command.id().wire(), phy.ticket().unwrap().sequence(), &[]),
    );
    assert_eq!(
        // SAFETY: the PHY removal ACK was published synchronously above; the
        // same owner retains its checked receive buffers through reclamation.
        unsafe { phy.advance(&source) }.unwrap(),
        Ax200PhyPhase::Removed
    );
    phy.stop().unwrap();
    drop(phy);
    assert!(native.domain.records.lock().unwrap().live.is_empty());
}

mod cases;
