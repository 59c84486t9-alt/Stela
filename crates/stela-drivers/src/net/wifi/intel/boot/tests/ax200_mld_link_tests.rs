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
#[test]
fn mld_active_link_and_unassign_require_every_ack_reclaim_and_real_link_reset_before_parent() {
    exercise(&image());
}
#[test]
fn mld_activation_refuses_missing_rate_or_ceiling_before_native_publication() {
    for deny_rate in [false, true] {
        let bytes = image();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (power, _, _) = powered(&catalog, &empty, &source, &native, &policy, false);
        authorize(&policy);
        if deny_rate {
            policy
                .deny_rate
                .store(LegacyRate::Ofdm24 as usize + 1, Ordering::SeqCst);
        } else {
            policy.transmit_ceiling_mbm.store(1999, Ordering::SeqCst);
        }
        // SAFETY: authored same-device service explicitly denies this envelope.
        let mut link = unsafe { power.begin_mld_link() }.unwrap_or_else(|_| panic!("MLD link"));
        let calls = source.calls.load(Ordering::Relaxed);
        let ops = native.state.lock().unwrap().ops.len();
        let causes = native
            .state
            .lock()
            .unwrap()
            .registers
            .get(&8)
            .copied()
            .unwrap_or(0);
        let syncs = native.domain.records.lock().unwrap().syncs;
        assert_eq!(
            unsafe { link.advance(&source) },
            Err(Ax200BindingError::Regulatory(regulatory::Error::OsDenied))
        );
        assert!(link.ticket().is_none());
        assert_eq!(source.calls.load(Ordering::Relaxed), calls);
        // The original idle RX check precedes admission: reading/acknowledging
        // interrupt causes is required, while no HCMD publication is allowed.
        assert_eq!(
            &native.state.lock().unwrap().ops[ops..],
            &[
                Op::Read(8),
                Op::Write(8, causes | !(1 | (1 << 31))),
                Op::Read(0x24)
            ]
        );
        assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        link.stop().unwrap();
    }
}
#[test]
fn missing_mld_activation_or_unassign_ack_never_releases_parent_or_rearms_after_failure() {
    for target in [0, 1, 3, 5, 6] {
        let bytes = image();
        let catalog = catalog_for(&profile(), Family::Ax200.firmware_name(), &bytes);
        let empty = resources::Catalog::from_handoff(vec![]).unwrap();
        let native = Native::default();
        let source = Source::default();
        let policy = Arc::new(PolicyState::default());
        let (power, _, _) = powered(&catalog, &empty, &source, &native, &policy, true);
        authorize(&policy);
        // SAFETY: same retained finite source response/revocation model.
        let mut link = unsafe { power.begin_mld_link() }.unwrap_or_else(|_| panic!("MLD link"));
        unsafe { link.advance(&source) }.unwrap();
        for index in 0..target {
            let command = link.commands()[index].clone();
            complete_link(&link, &native, &command);
            unsafe { link.advance(&source) }.unwrap();
            link.replenish_completed_receive().unwrap();
            if index == 2 {
                assert_eq!(link.phase(), Ax200BindingPhase::AuthenticationRequired);
                native.revoked.store(true, Ordering::SeqCst);
                link.begin_remove().unwrap();
                unsafe { link.advance(&source) }.unwrap();
            }
        }
        let kind = link.commands()[target].kind();
        Clock {
            ticks_per_microsecond: 1,
        }
        .delay(20);
        let error = Ax200BindingError::Deadline(kind);
        assert_eq!(unsafe { link.advance(&source) }, Err(error.clone()));
        assert_eq!(link.phase(), Ax200BindingPhase::Failed);
        assert_eq!(link.first_error(), Some(&error));
        link = match link.into_transmit_power() {
            Err(owner) => *owner,
            Ok(_) => panic!("incomplete source unassign released PHY parent"),
        };
        let ops = native.state.lock().unwrap().ops.len();
        let syncs = native.domain.records.lock().unwrap().syncs;
        assert_eq!(unsafe { link.advance(&source) }, Err(error.clone()));
        assert_eq!(link.replenish_completed_receive(), Err(error));
        assert_eq!(native.state.lock().unwrap().ops.len(), ops);
        assert_eq!(native.domain.records.lock().unwrap().syncs, syncs);
        if target == 6 {
            native.state.lock().unwrap().fail = Some(ops + 1);
            assert!(link.stop().is_err());
            let live = native.domain.records.lock().unwrap().live.len();
            drop(link);
            assert_eq!(native.domain.records.lock().unwrap().live.len(), live);
            assert_eq!(native.os_drops.load(Ordering::Relaxed), 0);
        } else {
            link.stop().unwrap();
            drop(link);
            assert!(native.domain.records.lock().unwrap().live.is_empty());
        }
    }
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
            unsafe { link.advance(&source) },
            Err(Ax200BindingError::Boot(Error::CommandReclaim(_)))
        ));
        assert!(link.first_error().is_none());
        native.domain.records.lock().unwrap().cpu_sync_fail = None;
        unsafe { link.advance(&source) }.unwrap();
        link.replenish_completed_receive().unwrap();
    }
    assert_eq!(link.phase(), Ax200BindingPhase::AuthenticationRequired);
    native.revoked.store(true, Ordering::SeqCst);
    let acquired = policy.acquired.load(Ordering::SeqCst);
    link.begin_remove().unwrap();
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
        unsafe { phy.advance(&source) }.unwrap(),
        Ax200PhyPhase::Removed
    );
    phy.stop().unwrap();
    drop(phy);
    assert!(native.domain.records.lock().unwrap().live.is_empty());
}
#[test]
#[ignore = "requires unchanged pinned AX200 firmware"]
fn actual_ax200_mld_default_link1_activation_and_full_unassign_are_selected_commands() {
    use sha2::{Digest, Sha256};
    let root = std::env::var("STELA_IWLWIFI_IMAGES").unwrap();
    let bytes =
        std::fs::read(std::path::Path::new(&root).join(Family::Ax200.firmware_name())).unwrap();
    assert_eq!(
        std::format!("{:x}", Sha256::digest(&bytes)),
        "1866a58a1daee56b120362122d5f7548b443b53d33f2558a7e4407d58fd27dab"
    );
    let fw = crate::net::wifi::intel::firmware::Firmware::parse(&bytes).unwrap();
    assert!(fw.supports_capability(110));
    assert!(fw.command_version(3, 9).is_none());
    exercise(&bytes);
}
