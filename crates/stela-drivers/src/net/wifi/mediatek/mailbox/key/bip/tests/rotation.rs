// SPDX-License-Identifier: BSD-3-Clause-Clear AND GPL-2.0-only
//! Source-modeled MCU/DMA and software receive peers. These tests are authored
//! controls, not physical firmware dual-key delivery or a negotiated PMF claim.
extern crate std;
use super::super::super::super::tests::*;
use super::super::*;
use aes::{
    Aes128,
    cipher::{BlockEncrypt, KeyInit},
};
use alloc::{sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

// Independent bounded test peer: ordinary AES-CMAC blocks over the source BIP
// AAD/body/MMIE. It never invokes production Cmac/BipKey to invent a proof.
fn cmac(material: &[u8; 16], bytes: &[u8]) -> [u8; 16] {
    let aes = Aes128::new_from_slice(material).unwrap();
    let block = |bytes: &mut [u8; 16]| aes.encrypt_block(aes::Block::from_mut_slice(bytes));
    let double = |mut bytes: [u8; 16]| {
        let carry = bytes[0] >> 7;
        for i in 0..15 {
            bytes[i] = (bytes[i] << 1) | (bytes[i + 1] >> 7);
        }
        bytes[15] = (bytes[15] << 1) ^ (carry * 0x87);
        bytes
    };
    let mut zero = [0; 16];
    block(&mut zero);
    let first = double(zero);
    let last = if !bytes.is_empty() && bytes.len().is_multiple_of(16) {
        first
    } else {
        double(first)
    };
    let chunks = bytes.len().max(1).div_ceil(16);
    let mut state = [0; 16];
    for chunk in 0..chunks {
        let start = chunk * 16;
        let count = bytes.len().saturating_sub(start).min(16);
        for i in 0..count {
            state[i] ^= bytes[start + i];
        }
        if chunk + 1 == chunks {
            if count != 16 {
                state[count] ^= 0x80;
            }
            for i in 0..16 {
                state[i] ^= last[i];
            }
        }
        block(&mut state);
    }
    state
}

pub(crate) fn frame(index: u8, material: u8, pn: u64) -> Vec<u8> {
    let mut bytes = vec![
        0xc0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 2, 6, 7, 8, 9, 10, 2, 6, 7, 8, 9, 10, 0, 0, 7,
        0, 76, 16, index, 0,
    ];
    bytes.extend_from_slice(&pn.to_le_bytes()[..6]);
    bytes.extend_from_slice(&[0; 8]);
    let mut authenticated = bytes[..2].to_vec();
    authenticated.extend_from_slice(&bytes[4..22]);
    authenticated.extend_from_slice(&bytes[24..]);
    let mic = cmac(&[material; 16], &authenticated);
    bytes[36..44].copy_from_slice(&mic[..8]);
    bytes
}
fn packet(gtk: KeyIdentity, index: u8, material: u8, pn: u64) -> crate::net::wifi::frame::Mpdu {
    crate::net::wifi::frame::Mpdu::new(
        frame(index, material, pn),
        key_packet(gtk, 1).radio,
        security::SecurityStatus::default(),
    )
    .unwrap()
}
type Fixture = (
    TestMailbox,
    HardwareKey<KeyResource>,
    Arc<Mutex<Response>>,
    ModelState,
    Arc<AtomicUsize>,
    KeyIdentity,
);
fn fixture() -> Fixture {
    let response = Arc::new(Mutex::new(Response {
        key_execution: true,
        ..Response::default()
    }));
    let (mut mailbox, wm, _, _) = setup_controlled(Chip::Mt7925, true, false, 0, response.clone());
    let drops = Arc::new(AtomicUsize::new(0));
    // SAFETY: exclusive modeled WCID/BSS and independently empty users.
    let mut key = unsafe {
        HardwareKey::claim(
            &mailbox,
            7,
            key_context(),
            key_scope(true),
            KeyResource(drops.clone()),
        )
    }
    .unwrap();
    let gtk = key
        .install(
            &mut mailbox,
            2,
            Cipher::Ccmp128,
            &[0x44; 16],
            ReplaySeed::ZERO,
        )
        .unwrap();
    // SAFETY: model command/RX/TX/IRQ users drained; authenticated model key exchange.
    unsafe {
        key.install_igtk(
            &mut mailbox,
            ManagementCipher::Cmac128,
            4,
            &[0x55; 16],
            PacketNumber::new(100).unwrap(),
        )
    }
    .unwrap();
    (mailbox, key, response, wm, drops, gtk)
}

#[test]
fn live_igtk_independent_peer_matches_nist_and_unchanged_source_mic() {
    assert_eq!(
        cmac(
            &[
                0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
                0x4f, 0x3c
            ],
            &[]
        ),
        [
            0xbb, 0x1d, 0x69, 0x29, 0xe9, 0x59, 0x37, 0x28, 0x7f, 0xa3, 0x7d, 0x12, 0x9b, 0x75,
            0x67, 0x46
        ]
    );
    // Same source helper trace as the preexisting immutable BIP controls.
    assert_eq!(
        &frame(4, 0x55, 101)[36..],
        &[0xc4, 0x80, 0xa2, 0x3a, 0x2c, 0x44, 0x77, 0x70]
    );
}

#[test]
fn live_igtk_ack_keeps_both_index_windows_without_data_pn_reset() {
    let (mut mailbox, mut key, response, wm, drops, gtk) = fixture();
    let old = key.installed_igtk().unwrap();
    key.authorize(&key_packet(gtk, 9)).unwrap();
    key.authenticate_bip(&packet(gtk, 4, 0x55, 101)).unwrap();
    let before = wm.lock().unwrap().completed.len();
    // SAFETY: authentic model key exchange; combined-batch users drained.
    let new = unsafe {
        key.rotate_igtk(
            &mut mailbox,
            5,
            &[0x66; 16],
            PacketNumber::new(200).unwrap(),
        )
    }
    .unwrap();
    assert_eq!(key.installed_igtks(), [Some(old), Some(new)]);
    assert_eq!(wm.lock().unwrap().completed.len(), before + 1);
    assert_eq!(
        response.lock().unwrap().keys[&7],
        [vec![0x44; 16], vec![0x66; 16]].concat()
    );
    let commands = wm.lock().unwrap();
    let body = &commands.completed.last().unwrap()[48..];
    assert_eq!(&body[23..26], &[6, 2, 32]); // source GTK index, never invented IGTK wire index
    drop(commands);
    for (index, material, pn) in [(4, 0x55, 102), (5, 0x66, 201)] {
        key.authenticate_bip(&packet(gtk, index, material, pn))
            .unwrap();
        assert!(matches!(
            key.authenticate_bip(&packet(gtk, index, material, pn)),
            Err(super::super::super::Error::Bip(Error::Authentication(
                management::Error::Replay
            )))
        ));
    }
    assert_eq!(key.retained_igtk_receive_floor(old).unwrap().value(), 102);
    assert_eq!(key.retained_igtk_receive_floor(new).unwrap().value(), 201);
    assert!(matches!(
        key.authorize(&key_packet(gtk, 9)),
        Err(security::Error::Replay)
    ));
    key.authorize(&key_packet(gtk, 10)).unwrap();
    for (index, material, identity) in [(4, 0x55, old), (5, 0x66, new)] {
        assert_eq!(
            // SAFETY: no model old users; exact retries cannot reset either IPN.
            unsafe {
                key.rotate_igtk(
                    &mut mailbox,
                    index,
                    &[material; 16],
                    PacketNumber::new(0).unwrap(),
                )
            }
            .unwrap(),
            identity
        );
    }
    assert_eq!(wm.lock().unwrap().completed.len(), before + 1);
    // SAFETY: model OS has retired old index4 at the peer; all old users drained.
    let third = unsafe {
        key.rotate_igtk(
            &mut mailbox,
            4,
            &[0x77; 16],
            PacketNumber::new(300).unwrap(),
        )
    }
    .unwrap();
    assert_eq!(key.installed_igtks(), [Some(third), Some(new)]);
    assert!(key.retained_igtk_receive_floor(old).is_none());
    assert_eq!(key.retained_igtk_receive_floor(new).unwrap().value(), 201);
    assert!(key.authenticate_bip(&packet(gtk, 4, 0x55, 301)).is_err());
    key.authenticate_bip(&packet(gtk, 4, 0x77, 301)).unwrap();
    // SAFETY: authenticated model peer has retired current index4 material;
    // old users drained. Same-index replacement must keep other index5.
    let fourth = unsafe {
        key.rotate_igtk(
            &mut mailbox,
            4,
            &[0x88; 16],
            PacketNumber::new(400).unwrap(),
        )
    }
    .unwrap();
    assert_eq!(key.installed_igtks(), [Some(fourth), Some(new)]);
    assert!(key.retained_igtk_receive_floor(third).is_none());
    assert_eq!(key.retained_igtk_receive_floor(new).unwrap().value(), 201);
    assert!(key.authenticate_bip(&packet(gtk, 4, 0x77, 401)).is_err());
    key.authenticate_bip(&packet(gtk, 4, 0x88, 401)).unwrap();
    assert!(matches!(
        key.authorize(&key_packet(gtk, 10)),
        Err(security::Error::Replay)
    ));
    key.authorize(&key_packet(gtk, 11)).unwrap();
    let removed = key.remove(&mut mailbox).unwrap();
    // SAFETY: whole-batch removal ACK and independent model old-user drain.
    unsafe { key.retire_after_drain(removed) }.unwrap();
    drop(key);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
}

#[test]
fn live_igtk_retired_material_and_invalid_requests_refuse_before_publication() {
    let (mut mailbox, mut key, _, wm, _, gtk) = fixture();
    // SAFETY: source-modeled command/key/IRQ users drained and authentic new key.
    unsafe { key.rotate_igtk(&mut mailbox, 4, &[0x66; 16], PacketNumber::new(5).unwrap()) }
        .unwrap();
    let identity = key.installed_igtk().unwrap();
    let before = wm.lock().unwrap().completed.len();
    for (index, material, len, expected) in [
        (
            4,
            0x55,
            16,
            super::super::super::Error::Bip(Error::RetiredMaterial),
        ),
        (
            5,
            0x66,
            16,
            super::super::super::Error::Bip(Error::RetiredMaterial),
        ),
        (
            3,
            0x77,
            16,
            super::super::super::Error::Request(
                crate::net::wifi::mediatek::mcu::key::Error::InvalidBipIndex,
            ),
        ),
        (
            5,
            0x77,
            15,
            super::super::super::Error::Request(
                crate::net::wifi::mediatek::mcu::key::Error::InvalidKeyLength,
            ),
        ),
    ] {
        assert_eq!(
            // SAFETY: no model users; invalid input must not publish.
            unsafe {
                key.rotate_igtk(
                    &mut mailbox,
                    index,
                    &vec![material; len],
                    PacketNumber::new(0).unwrap(),
                )
            },
            Err(expected)
        );
    }
    assert_eq!(wm.lock().unwrap().completed.len(), before);
    assert_eq!(key.installed_igtk(), Some(identity));
    key.authenticate_bip(&packet(gtk, 4, 0x66, 6)).unwrap();
    let removed = key.remove(&mut mailbox).unwrap();
    // SAFETY: model whole-key removal and old-user drain; history must survive.
    unsafe { key.retire_after_drain(removed) }.unwrap();
    key.install(
        &mut mailbox,
        2,
        Cipher::Ccmp128,
        &[0x45; 16],
        ReplaySeed::ZERO,
    )
    .unwrap();
    let before = wm.lock().unwrap().completed.len();
    assert_eq!(
        // SAFETY: new authentic model GTK namespace with no old users; reuse must still refuse.
        unsafe {
            key.install_igtk(
                &mut mailbox,
                ManagementCipher::Cmac128,
                4,
                &[0x55; 16],
                PacketNumber::new(0).unwrap(),
            )
        },
        Err(super::super::super::Error::Bip(Error::RetiredMaterial))
    );
    assert_eq!(wm.lock().unwrap().completed.len(), before);
}

#[test]
fn live_igtk_history_exhaustion_preserves_current_and_other_receive_windows() {
    let (mut mailbox, mut key, _, wm, _, _) = fixture();
    for material in 1..HISTORY_CAPACITY as u8 {
        // SAFETY: modeled old users drained; source peer retired overwritten index.
        unsafe {
            key.rotate_igtk(
                &mut mailbox,
                4 + material % 2,
                &[material; 16],
                PacketNumber::new(material.into()).unwrap(),
            )
        }
        .unwrap();
    }
    let windows = key.installed_igtks();
    let before = wm.lock().unwrap().completed.len();
    assert_eq!(
        // SAFETY: same fully drained model namespace; capacity refusal must be effect-free.
        unsafe { key.rotate_igtk(&mut mailbox, 5, &[0xfe; 16], PacketNumber::new(0).unwrap()) },
        Err(super::super::super::Error::Bip(Error::HistoryExhausted))
    );
    assert_eq!(key.installed_igtks(), windows);
    assert_eq!(wm.lock().unwrap().completed.len(), before);
}

#[test]
fn negative_late_or_missing_live_igtk_ack_quarantines_every_key_owner() {
    for fault in 0..4 {
        let (mut mailbox, mut key, response, wm, drops, gtk) = fixture();
        let old = key.installed_igtk().unwrap();
        // SAFETY: real modeled peer exchange, empty queues and independent users drained.
        let current = unsafe {
            key.rotate_igtk(
                &mut mailbox,
                5,
                &[0x66; 16],
                PacketNumber::new(200).unwrap(),
            )
        }
        .unwrap();
        match fault {
            0 => response.lock().unwrap().status = 9,
            1 => response.lock().unwrap().command_delta = 1,
            2 => response.lock().unwrap().unsolicited = true,
            _ => response.lock().unwrap().drop = true,
        }
        assert!(
            // SAFETY: no modeled old users; firmware/ACK faults are real peer
            // outcomes.
            unsafe {
                key.rotate_igtk(
                    &mut mailbox,
                    4,
                    &[0x77; 16],
                    PacketNumber::new(300).unwrap(),
                )
            }
            .is_err()
        );
        assert!(key.is_quarantined());
        assert!(key.slot().installed().is_none());
        assert_eq!(key.installed_igtks(), [None; 2]);
        assert!(key.authenticate_bip(&packet(gtk, 4, 0x55, 101)).is_err());
        assert_eq!(key.owned().igtk.as_ref().unwrap().identity, current);
        assert_eq!(key.owned().other_igtk.as_ref().unwrap().identity, old);
        assert_eq!(
            key.owned().pending_igtk.as_ref().unwrap().identity.index(),
            4
        );
        assert_eq!(wm.lock().unwrap().completed.last().unwrap()[48 + 44], 0x77);
        drop(key);
        drop(mailbox);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
    }
}
