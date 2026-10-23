// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2020-2023 MediaTek Inc.
//! Initial source GTK/IGTK batch ownership and bound group BIP authentication.
//! This grants no PMF negotiation, MMIE generation or current-association RX
//! delivery authority; station/key-generation checks remain mandatory.
use super::*;
use crate::net::wifi::{
    mediatek::{identity::Chip, mcu::key::bip as wire},
    security::{PacketNumber, management},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    DataKeyRequired,
    GenerationExhausted,
    AlreadyInstalled,
    Authentication(management::Error),
}

/// One acknowledged management-key batch, bound to the exact installed GTK,
/// native mailbox owner and monotonically increasing management generation.
/// This is never a data KeyIdentity or a MIC/association/port authorization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Identity {
    gtk: KeyIdentity,
    owner: u64,
    generation: u64,
    index: u8,
}
impl Identity {
    pub const fn gtk(self) -> KeyIdentity {
        self.gtk
    }
    pub const fn index(self) -> u8 {
        self.index
    }
    pub const fn generation(self) -> u64 {
        self.generation
    }
}
pub(super) struct GtkCache {
    identity: KeyIdentity,
    material: Zeroizing<[u8; 16]>,
}
pub(super) struct Installed {
    identity: Identity,
    digest: [u8; 32],
    key: management::BipKey,
}

pub(super) fn remember<C>(state: &mut Owned<C>, key: KeyIdentity, material: &[u8]) {
    if key.cipher() == Cipher::Ccmp128 && matches!(key.scope(), KeyScope::Group(_)) {
        let mut bytes = Zeroizing::new([0; 16]);
        bytes.copy_from_slice(material);
        state.gtk = Some(GtkCache {
            identity: key,
            material: bytes,
        });
    }
}
impl<C: 'static> HardwareKey<C> {
    /// Actual successful initial IGTK batch, valid only while its original GTK
    /// and this native owner remain installed. Copies grant no RX authority.
    pub fn installed_igtk(&self) -> Option<Identity> {
        let s = self.owned();
        let bip = s.igtk.as_ref()?;
        (s.phase == Phase::Installed
            && bip.identity.owner == s.owner
            && s.slot.installed() == Some(bip.identity.gtk)
            && s.pending_igtk.is_none())
        .then_some(bip.identity)
    }
    pub fn igtk_receive_floor(&self) -> Option<PacketNumber> {
        self.installed_igtk()?;
        Some(self.owned().igtk.as_ref()?.key.receive_floor())
    }
    pub fn igtk_statistics(&self) -> Option<management::Statistics> {
        self.installed_igtk()?;
        Some(self.owned().igtk.as_ref()?.key.statistics())
    }
    /// Authenticate a complete group robust-management frame under this actual
    /// acknowledged IGTK and original still-installed GTK. Software CMAC and IPN
    /// checks always run, independently of copied hardware integrity flags.
    /// The returned frame proof grants no current association/port authority;
    /// its eventual consuming station must recheck the exact retained association
    /// and still-current GTK/IGTK before acting on a deferred frame.
    pub fn authenticate_bip<'a>(
        &mut self,
        frame: &'a crate::net::wifi::frame::Mpdu,
    ) -> Result<management::Authenticated<'a>, super::Error> {
        self.installed_igtk()
            .ok_or(super::Error::Bip(Error::DataKeyRequired))?;
        self.owned_mut()
            .igtk
            .as_mut()
            .unwrap()
            .key
            .authenticate(frame)
            .map_err(|error| super::Error::Bip(Error::Authentication(error)))
    }

    /// Program the source CCMP128 GTK || BIP-CMAC128 IGTK batch. The firmware
    /// batch repeats the same GTK, while its canonical data identity and replay
    /// floors remain unchanged. Exact identical retries publish no command and
    /// do not replace the original authenticated management floor.
    ///
    /// # Safety
    /// The caller owns this actual GTK/WCID/BSS namespace and has independently
    /// drained all old GTK hardware RX/TX, DMA/IRQ/work and delayed key users.
    /// No data or management publication may use the namespace until this call
    /// returns successfully; uncertain outcomes require the actual removal/reset
    /// and drain path. `material` and `receive` come from the genuine authenticated
    /// OS key exchange. This initial-batch API does not implement live IGTK rekey.
    pub unsafe fn install_igtk<W: QueueIo, F: QueueIo, R: QueueIo>(
        &mut self,
        mailbox: &mut Mailbox<W, F, R>,
        index: u8,
        material: &[u8],
        receive: PacketNumber,
    ) -> Result<Identity, super::Error> {
        self.check(mailbox)?;
        if mailbox.identity.chip != Chip::Mt7925 {
            return Err(super::Error::Request(
                crate::net::wifi::mediatek::mcu::key::Error::UnsupportedBip,
            ));
        }
        let s = self.owned_mut();
        if s.phase != Phase::Installed {
            return Err(super::Error::Bip(Error::DataKeyRequired));
        }
        let gtk = s.slot.installed().ok_or(super::Error::NoKey)?;
        let cache = s
            .gtk
            .as_ref()
            .filter(|cache| cache.identity == gtk)
            .ok_or(super::Error::Bip(Error::DataKeyRequired))?;
        // Complete scope/index/length/codec validation before changing ownership.
        let request = wire::Request::install(
            mailbox.identity.chip,
            s.context,
            gtk,
            cache.material.as_ref(),
            index,
            material,
        )
        .map_err(super::Error::Request)?;
        let digest: [u8; 32] = Sha256::digest(material).into();
        if let Some(old) = &s.igtk {
            let same = old
                .digest
                .iter()
                .zip(digest)
                .fold(0u8, |difference, (a, b)| difference | (*a ^ b))
                == 0;
            if old.identity.gtk == gtk && old.identity.index == index && same {
                return Ok(old.identity);
            }
            return Err(super::Error::Bip(Error::AlreadyInstalled));
        }
        let generation = s
            .igtk_generation
            .checked_add(1)
            .ok_or(super::Error::Bip(Error::GenerationExhausted))?;
        let identity = Identity {
            gtk,
            owner: s.owner,
            generation,
            index,
        };
        let key = management::BipKey::new(gtk, index, material, receive)
            .map_err(|error| super::Error::Bip(Error::Authentication(error)))?;
        s.igtk_generation = generation;
        s.pending_igtk = Some(Installed {
            identity,
            digest,
            key,
        });
        s.phase = Phase::Quarantined;
        s.reply = None;
        let outcome = mailbox.unified(Command::StationRecord, request.bytes());
        let accepted = outcome
            .as_ref()
            .is_ok_and(|r| r.status == 0 && r.dma_released);
        if accepted {
            s.igtk = s.pending_igtk.take();
            s.phase = Phase::Installed;
        } else {
            // The device may already have installed the combined key record.
            // Neither data nor management may inherit an uncertain batch.
            s.slot.invalidate();
        }
        match outcome {
            Ok(reply) => {
                let status = reply.status;
                s.reply = Some(reply);
                if accepted {
                    Ok(identity)
                } else {
                    Err(super::Error::Firmware(status))
                }
            }
            Err(error) => {
                s.reply = mailbox.interrupted_unified_reply().cloned();
                Err(super::Error::Transport(error))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::super::tests::*;
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    fn source_bip_packet(gtk: KeyIdentity) -> crate::net::wifi::frame::Mpdu {
        // Complete pinned CMAC helper native.trace, SHA256 3bbe84f7780d5cc948d8a6a0c9fff42a891370c7ecadfb650c2c1baf3119fe40.
        // Expected MIC comes from independent CommonCrypto-AES + unchanged Linux CMAC/BIP bodies.
        let bytes = vec![
            0xc0, 0, 0, 0, 255, 255, 255, 255, 255, 255, 2, 6, 7, 8, 9, 10, 2, 6, 7, 8, 9, 10, 0,
            0, 7, 0, 76, 16, 4, 0, 101, 0, 0, 0, 0, 0, 0xc4, 0x80, 0xa2, 0x3a, 0x2c, 0x44, 0x77,
            0x70,
        ];
        crate::net::wifi::frame::Mpdu::new(
            bytes,
            key_packet(gtk, 1).radio,
            security::SecurityStatus::default(),
        )
        .unwrap()
    }

    #[test]
    fn actual_acknowledged_igtk_authenticates_source_mic_without_hardware_flag_bypass() {
        let response = Arc::new(Mutex::new(Response {
            key_execution: true,
            ..Response::default()
        }));
        let (mut mailbox, wm, _, _) =
            setup_controlled(Chip::Mt7925, true, false, 0, response.clone());
        let drops = Arc::new(AtomicUsize::new(0));
        // SAFETY: exclusive empty source-modeled actual WCID and drained old users.
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
        key.authorize(&key_packet(gtk, 9)).unwrap();
        let frame = source_bip_packet(gtk);
        assert!(matches!(
            key.authenticate_bip(&frame),
            Err(super::super::Error::Bip(Error::DataKeyRequired))
        ));
        // SAFETY: actual initial modeled GTK request/ACK drained; no other key users exist.
        let identity = unsafe {
            key.install_igtk(
                &mut mailbox,
                4,
                &[0x55; 16],
                PacketNumber::new(100).unwrap(),
            )
        }
        .unwrap();
        let commands = wm.lock().unwrap().completed.len();
        let authenticated = key.authenticate_bip(&frame).unwrap();
        assert_eq!(authenticated.body(), &[7, 0]);
        assert_eq!(authenticated.gtk(), gtk);
        assert_eq!(authenticated.index(), 4);
        assert_eq!(authenticated.packet_number().value(), 101);
        assert_eq!(key.igtk_receive_floor().unwrap().value(), 101);
        assert!(matches!(
            key.authenticate_bip(&frame),
            Err(super::super::Error::Bip(Error::Authentication(
                management::Error::Replay
            )))
        ));
        // Fake copied hardware integrity must not bypass the actual software MIC.
        let mut bytes = frame.bytes().to_vec();
        bytes[30] = 102;
        let mut forged = crate::net::wifi::frame::Mpdu::new(
            bytes,
            frame.radio.clone(),
            security::SecurityStatus::default(),
        )
        .unwrap();
        forged.security.decrypted = true;
        forged.security.integrity = security::Integrity::Verified;
        assert!(matches!(
            key.authenticate_bip(&forged),
            Err(super::super::Error::Bip(Error::Authentication(
                management::Error::Integrity
            )))
        ));
        assert_eq!(key.igtk_receive_floor().unwrap().value(), 101);
        assert_eq!(
            key.igtk_statistics(),
            Some(management::Statistics {
                replays: 1,
                mic_failures: 1
            })
        );
        // Authenticated management replay never consumes a canonical GTK data PN.
        assert!(matches!(
            key.authorize(&key_packet(gtk, 9)),
            Err(security::Error::Replay)
        ));
        key.authorize(&key_packet(gtk, 10)).unwrap();
        // SAFETY: unchanged actual drained namespace; identical retry must preserve advanced management IPN.
        assert_eq!(
            unsafe {
                key.install_igtk(&mut mailbox, 4, &[0x55; 16], PacketNumber::new(0).unwrap())
            }
            .unwrap(),
            identity
        );
        assert_eq!(key.igtk_receive_floor().unwrap().value(), 101);
        assert_eq!(wm.lock().unwrap().completed.len(), commands);
        let removed = key.remove(&mut mailbox).unwrap();
        assert!(matches!(
            key.authenticate_bip(&frame),
            Err(super::super::Error::Bip(Error::DataKeyRequired))
        ));
        // SAFETY: successful actual whole-batch removal and complete old model user drain.
        unsafe { key.retire_after_drain(removed) }.unwrap();
        assert!(key.igtk_statistics().is_none());
        assert!(key.igtk_receive_floor().is_none());
        assert!(!response.lock().unwrap().keys.contains_key(&7));
        drop(key);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn actual_owned_gtk_igtk_batch_preserves_original_data_key_replay_and_exact_retry() {
        let response = Arc::new(Mutex::new(Response {
            key_execution: true,
            ..Response::default()
        }));
        let (mut mailbox, wm, _, _) =
            setup_controlled(Chip::Mt7925, true, false, 0, response.clone());
        let drops = Arc::new(AtomicUsize::new(0));
        // SAFETY: genuine exclusive empty source-modeled WCID/BSS and old-user drain.
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
                ReplaySeed::uniform(PacketNumber::new(7).unwrap()),
            )
            .unwrap();
        key.authorize(&key_packet(gtk, 9)).unwrap();
        let before = wm.lock().unwrap().completed.len();
        // SAFETY: every actual model GTK descriptor/ACK was consumed; no old key users remain.
        let installed = unsafe {
            key.install_igtk(
                &mut mailbox,
                5,
                &[0x55; 16],
                PacketNumber::new(100).unwrap(),
            )
        }
        .unwrap();
        assert_eq!(installed.gtk(), gtk);
        assert_eq!(installed.index(), 5);
        assert_eq!(key.installed_igtk(), Some(installed));
        assert_eq!(key.igtk_receive_floor().unwrap().value(), 100);
        assert_eq!(wm.lock().unwrap().completed.len(), before + 1);
        assert_eq!(
            response.lock().unwrap().keys[&7],
            [vec![0x44; 16], vec![0x55; 16]].concat()
        );
        let packets = wm.lock().unwrap();
        let body = &packets.completed.last().unwrap()[48..];
        assert_eq!(&body[23..26], &[6, 2, 32]);
        drop(packets);
        assert_eq!(key.slot().installed(), Some(gtk));
        assert!(matches!(
            key.authorize(&key_packet(gtk, 9)),
            Err(security::Error::Replay)
        ));
        key.authorize(&key_packet(gtk, 10)).unwrap();
        // SAFETY: same actual drained namespace; this exact retry must not publish.
        let retry = unsafe {
            key.install_igtk(&mut mailbox, 5, &[0x55; 16], PacketNumber::new(0).unwrap())
        }
        .unwrap();
        assert_eq!(retry, installed);
        assert_eq!(key.igtk_receive_floor().unwrap().value(), 100);
        // SAFETY: no external model key users; different live initial-batch material is refused.
        assert!(matches!(
            unsafe {
                key.install_igtk(&mut mailbox, 4, &[0x66; 16], PacketNumber::new(0).unwrap())
            },
            Err(super::super::Error::Bip(Error::AlreadyInstalled))
        ));
        assert_eq!(wm.lock().unwrap().completed.len(), before + 1);
        let removed = key.remove(&mut mailbox).unwrap();
        assert!(key.installed_igtk().is_none());
        assert!(!response.lock().unwrap().keys.contains_key(&7));
        // SAFETY: whole source batch removal ACK and complete actual modeled-user drain.
        unsafe { key.retire_after_drain(removed) }.unwrap();
        drop(key);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn invalid_igtk_admission_never_publishes_or_changes_the_original_key() {
        for (chip, group, cipher) in [
            (Chip::Mt7921, true, Cipher::Ccmp128),
            (Chip::Mt7922, true, Cipher::Ccmp128),
            (Chip::Mt7925, false, Cipher::Ccmp128),
            (Chip::Mt7925, true, Cipher::Gcmp128),
            (Chip::Mt7925, true, Cipher::Ccmp128),
        ] {
            let response = Arc::new(Mutex::new(Response {
                key_execution: true,
                ..Response::default()
            }));
            let (mut mailbox, wm, _, _) = setup_controlled(chip, true, false, 0, response.clone());
            let drops = Arc::new(AtomicUsize::new(0));
            // SAFETY: exclusive empty/drained actual model WCID and peer context.
            let mut key = unsafe {
                HardwareKey::claim(
                    &mailbox,
                    7,
                    key_context(),
                    key_scope(group),
                    KeyResource(drops.clone()),
                )
            }
            .unwrap();
            let empty = wm.lock().unwrap().completed.len();
            // SAFETY: no model key users; absence of a GTK must fail before publication.
            assert!(
                unsafe {
                    key.install_igtk(&mut mailbox, 4, &[0x55; 16], PacketNumber::new(1).unwrap())
                }
                .is_err()
            );
            assert_eq!(wm.lock().unwrap().completed.len(), empty);
            let gtk = key
                .install(
                    &mut mailbox,
                    if group { 2 } else { 0 },
                    cipher,
                    &[0x44; 16],
                    ReplaySeed::ZERO,
                )
                .unwrap();
            let before = wm.lock().unwrap().completed.len();
            for (index, length) in [(3, 16), (6, 16), (4, 15), (5, 17)] {
                let expected = if chip != Chip::Mt7925 {
                    super::super::Error::Request(
                        crate::net::wifi::mediatek::mcu::key::Error::UnsupportedBip,
                    )
                } else if !group || cipher != Cipher::Ccmp128 {
                    super::super::Error::Bip(Error::DataKeyRequired)
                } else if !(4..=5).contains(&index) {
                    super::super::Error::Request(
                        crate::net::wifi::mediatek::mcu::key::Error::InvalidBipIndex,
                    )
                } else {
                    super::super::Error::Request(
                        crate::net::wifi::mediatek::mcu::key::Error::InvalidKeyLength,
                    )
                };
                // SAFETY: every actual initial descriptor/ACK drained, no external model users.
                assert_eq!(
                    unsafe {
                        key.install_igtk(
                            &mut mailbox,
                            index,
                            &vec![0x55; length],
                            PacketNumber::new(1).unwrap(),
                        )
                    },
                    Err(expected)
                );
                assert_eq!(wm.lock().unwrap().completed.len(), before);
                assert_eq!(key.slot().installed(), Some(gtk));
                assert!(key.installed_igtk().is_none());
                assert!(!key.is_quarantined());
            }
            if chip != Chip::Mt7925 || !group || cipher != Cipher::Ccmp128 {
                let expected = if chip != Chip::Mt7925 {
                    super::super::Error::Request(
                        crate::net::wifi::mediatek::mcu::key::Error::UnsupportedBip,
                    )
                } else {
                    super::super::Error::Bip(Error::DataKeyRequired)
                };
                // SAFETY: actual model namespace is drained; unsupported scope/chip stays explicit.
                assert_eq!(
                    unsafe {
                        key.install_igtk(
                            &mut mailbox,
                            4,
                            &[0x55; 16],
                            PacketNumber::new(1).unwrap(),
                        )
                    },
                    Err(expected)
                );
                assert_eq!(wm.lock().unwrap().completed.len(), before);
                assert_eq!(key.slot().installed(), Some(gtk));
            }
            let removed = key.remove(&mut mailbox).unwrap();
            // SAFETY: actual removal ACK and complete model key/user drain.
            unsafe { key.retire_after_drain(removed) }.unwrap();
            drop(key);
            assert_eq!(drops.load(Ordering::Relaxed), 1);
        }
    }

    #[test]
    fn uncertain_igtk_batch_revokes_data_and_retains_actual_namespace() {
        for fault in 0..4 {
            let response = Arc::new(Mutex::new(Response {
                key_execution: true,
                ..Response::default()
            }));
            let (mut mailbox, _, _, _) =
                setup_controlled(Chip::Mt7925, true, false, 0, response.clone());
            let drops = Arc::new(AtomicUsize::new(0));
            // SAFETY: genuine exclusive empty source-modeled WCID/BSS, with no old key users.
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
            match fault {
                0 => response.lock().unwrap().status = 9,
                1 => response.lock().unwrap().command_delta = 1,
                2 => response.lock().unwrap().unsolicited = true,
                _ => response.lock().unwrap().drop = true,
            }
            // SAFETY: actual model initial key request is drained; late/invalid ACK must quarantine.
            assert!(
                unsafe {
                    key.install_igtk(&mut mailbox, 4, &[0x55; 16], PacketNumber::new(1).unwrap())
                }
                .is_err()
            );
            assert!(key.is_quarantined());
            assert!(key.slot().installed().is_none());
            assert!(key.installed_igtk().is_none());
            assert!(matches!(
                key.authenticate_bip(&source_bip_packet(gtk)),
                Err(super::super::Error::Bip(Error::DataKeyRequired))
            ));
            assert!(matches!(
                key.authorize(&key_packet(gtk, 2)),
                Err(security::Error::NoInstalledKey)
            ));
            assert_eq!(
                response.lock().unwrap().keys[&7],
                [vec![0x44; 16], vec![0x55; 16]].concat()
            );
            drop(key);
            drop(mailbox);
            assert_eq!(drops.load(Ordering::Relaxed), 0);
        }
    }
}
