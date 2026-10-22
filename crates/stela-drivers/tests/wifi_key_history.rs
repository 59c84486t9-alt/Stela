// SPDX-License-Identifier: GPL-2.0-only
//! Exercise nonce-history ownership through the public key-control boundary.

use stela_drivers::net::{
    Mac,
    wifi::security::{
        Cipher, Error, InstallOutcome, InstallTicket, KeyScope, KeySlot, PacketNumber, ReplaySeed,
        TransmitSeed,
    },
};

fn begin(slot: &mut KeySlot, material: u8, seed: TransmitSeed) -> Result<InstallTicket, Error> {
    slot.begin_install(
        0,
        Cipher::Ccmp128,
        &[material; 16],
        ReplaySeed::ZERO,
        KeyScope::Pairwise(Mac([2, 0, 0, 0, 0, 1])),
        seed,
    )
}

fn retire_model(slot: &mut KeySlot) {
    slot.invalidate();
    // SAFETY: this pure model has no physical table, DMA or deferred users.
    // A real backend must independently establish acknowledged removal/drain.
    unsafe { slot.retire_after_drain() };
}

#[test]
fn public_boundary_confirmed_a_b_a_cannot_restart_firmware_nonce() {
    // SAFETY: no physical slot or old hardware users exist in this model.
    let mut slot = unsafe { KeySlot::new(11) }.unwrap();
    for material in [0x71, 0x72] {
        let ticket = begin(&mut slot, material, TransmitSeed::FIRMWARE_FRESH).unwrap();
        slot.complete_install(ticket, InstallOutcome::Accepted)
            .unwrap();
        retire_model(&mut slot);
    }
    assert_eq!(
        begin(&mut slot, 0x71, TransmitSeed::FIRMWARE_FRESH),
        Err(Error::Reinstallation)
    );
    assert_eq!(slot.installed(), None);
}

#[test]
fn mixed_history_preserves_all_used_keys_and_only_retries_unused_rejection() {
    // SAFETY: no physical slot or old hardware users exist in this model.
    let mut slot = unsafe { KeySlot::new(12) }.unwrap();
    for (material, outcome) in [
        (0xa1, InstallOutcome::Accepted),
        (0xb2, InstallOutcome::Uncertain),
        (0xc3, InstallOutcome::RejectedAndEmpty),
        (0xd4, InstallOutcome::Accepted),
        (0xe5, InstallOutcome::Uncertain),
    ] {
        let ticket = begin(&mut slot, material, TransmitSeed::FIRMWARE_FRESH).unwrap();
        slot.complete_install(ticket, outcome).unwrap();
        retire_model(&mut slot);
    }
    for material in [0xa1, 0xb2, 0xd4, 0xe5] {
        for seed in [
            TransmitSeed::FIRMWARE_FRESH,
            TransmitSeed::host(PacketNumber::new(400).unwrap()),
            TransmitSeed::RECEIVE_ONLY,
        ] {
            assert_eq!(begin(&mut slot, material, seed), Err(Error::Reinstallation));
        }
    }
    // The original rejection proved this candidate unused, so it can proceed.
    let host_seed = TransmitSeed::host(PacketNumber::new(0).unwrap());
    let ticket = begin(&mut slot, 0xc3, host_seed).unwrap();
    slot.complete_install(ticket, InstallOutcome::Accepted)
        .unwrap();
    let key = ticket.identity();
    assert_eq!(
        slot.reserve_host_tx_nonce(key)
            .unwrap()
            .packet_number()
            .value(),
        1
    );
    // An idempotent retry returns the current identity without resetting PN.
    assert_eq!(
        begin(&mut slot, 0xc3, host_seed),
        Err(Error::AlreadyInstalled(key))
    );
    assert_eq!(slot.installed(), Some(key));
    assert_eq!(
        slot.reserve_host_tx_nonce(key)
            .unwrap()
            .packet_number()
            .value(),
        2
    );
    retire_model(&mut slot);
    for material in [0xa1, 0xb2, 0xc3, 0xd4, 0xe5] {
        assert_eq!(
            begin(&mut slot, material, TransmitSeed::FIRMWARE_FRESH),
            Err(Error::Reinstallation)
        );
    }
    let fresh = begin(&mut slot, 0xf6, TransmitSeed::FIRMWARE_FRESH).unwrap();
    slot.complete_install(fresh, InstallOutcome::Accepted)
        .unwrap();
    assert_eq!(slot.installed(), Some(fresh.identity()));
}
