// SPDX-License-Identifier: GPL-2.0-only
// CCMP/GCMP replay and PN layout adapted from Linux net/mac80211/wpa.c.
// Copyright 2002-2004 Instant802 Networks, Inc.
// Copyright 2008 Jouni Malinen <j@w1.fi>
// Copyright (C) 2016-2017 Intel Deutschland GmbH
// Copyright (C) 2020-2023 Intel Corporation
// Key-reinstallation guard also adapts Linux net/mac80211/key.c:
// Copyright 2002-2005 Instant802 Networks, Inc.;
// 2005-2006 Devicescape Software, Inc.; 2006-2007 Jiri Benc;
// 2007-2008 Johannes Berg; 2013-2014 Intel Mobile Communications GmbH;
// 2015-2017 Intel Deutschland GmbH; 2018-2020, 2022-2026 Intel Corporation.
//! Hardware-key acknowledgements and software replay checks.
//!
//! This layer does not implement a WPA handshake or software encryption. A
//! vendor must report successful hardware key installation only after its real
//! firmware acknowledgement, and verified integrity only from the applicable
//! negotiated RX status. Unknown evidence is refused. No hardware replay flag
//! bypasses the software check. Reordering, fragmentation, shared-PN A-MSDUs and
//! protected management frames are explicitly unsupported by this first path.

use super::{Aggregation, frame::Mpdu};
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cipher {
    Ccmp128,
    Ccmp256,
    Gcmp128,
    Gcmp256,
}

impl Cipher {
    const fn mic_length(self) -> usize {
        match self {
            Self::Ccmp128 => 8,
            _ => 16,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PacketNumber(u64);

impl PacketNumber {
    pub const fn new(value: u64) -> Option<Self> {
        if value < (1_u64 << 48) {
            Some(Self(value))
        } else {
            None
        }
    }
    pub const fn value(self) -> u64 {
        self.0
    }

    /// CCMP and GCMP share this eight-byte ExtIV header layout.
    pub fn from_header(header: &[u8]) -> Result<(Self, u8), Error> {
        let h: &[u8; 8] = header.get(..8).ok_or(Error::Truncated)?.try_into().unwrap();
        if h[2] != 0 || h[3] & 0x3f != 0x20 {
            return Err(Error::CryptoHeader);
        }
        let value = u64::from_le_bytes([h[0], h[1], h[4], h[5], h[6], h[7], 0, 0]);
        Ok((Self(value), h[3] >> 6))
    }
}

/// Binding to one acknowledged installation, not merely a reusable HW slot.
/// Copy this identity from `KeySlot::installed()` into the vendor key table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyIdentity {
    slot: u16,
    index: u8,
    generation: u64,
    cipher: Cipher,
}

impl KeyIdentity {
    pub const fn slot(self) -> u16 {
        self.slot
    }
    pub const fn index(self) -> u8 {
        self.index
    }
    pub const fn generation(self) -> u64 {
        self.generation
    }
    pub const fn cipher(self) -> Cipher {
        self.cipher
    }
}

/// Actual hardware observation, distinct from stripped MIC bytes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Integrity {
    #[default]
    Unknown,
    Verified,
    Failed,
}

/// A device replay result is meaningful only under its negotiated RX layout.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HardwareReplay {
    #[default]
    Unknown,
    Validated {
        layout: u16,
    },
    Failed {
        layout: u16,
    },
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SecurityStatus {
    pub key: Option<KeyIdentity>,
    pub pn: Option<PacketNumber>,
    pub decrypted: bool,
    pub integrity: Integrity,
    pub iv_stripped: bool,
    pub mic_stripped: bool,
    pub icv_error: bool,
    pub tkip_mic_error: bool,
    /// Retained observation only; never substitutes for checking a PN.
    pub hardware_replay: HardwareReplay,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidKeyIndex,
    InvalidKeyLength,
    AlreadyInstalled(KeyIdentity),
    Reinstallation,
    KeyStillInstalled,
    Busy,
    Quarantined,
    GenerationExhausted,
    StaleAcknowledgement,
    NoInstalledKey,
    WrongKey,
    NotProtected,
    Integrity,
    MissingPacketNumber,
    CryptoHeader,
    InconsistentPacketNumber,
    Replay,
    Truncated,
    Unsupported(&'static str),
}

/// A command ticket stays unusable until an actual successful acknowledgement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstallTicket(KeyIdentity);

impl InstallTicket {
    pub const fn identity(self) -> KeyIdentity {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallOutcome {
    /// Firmware explicitly accepted this exact key command.
    Accepted,
    /// Firmware rejected it and the vendor established that the slot is empty.
    RejectedAndEmpty,
    /// Timeout, bad response, or any uncertain key/command ownership.
    Uncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Empty,
    Pending(KeyIdentity),
    Installed(KeyIdentity),
    Quarantined,
}

/// Serialized key slot and its per-TID replay state (queue16 is non-QoS).
/// Keep this object for the lifetime of the physical slot; recreating it while
/// old RX/completions can still arrive would invalidate generation isolation.
#[derive(Debug)]
pub struct KeySlot {
    slot: u16,
    generation: u64,
    state: State,
    rx_pn: [u64; 17],
    material_digest: Option<[u8; 32]>,
    pending_digest: Option<[u8; 32]>,
}

impl KeySlot {
    pub const fn new(slot: u16) -> Self {
        Self {
            slot,
            generation: 0,
            state: State::Empty,
            rx_pn: [0; 17],
            material_digest: None,
            pending_digest: None,
        }
    }

    pub fn begin_install(
        &mut self,
        index: u8,
        cipher: Cipher,
        material: &[u8],
    ) -> Result<InstallTicket, Error> {
        if index > 3 {
            return Err(Error::InvalidKeyIndex);
        }
        let length = match cipher {
            Cipher::Ccmp128 | Cipher::Gcmp128 => 16,
            _ => 32,
        };
        if material.len() != length {
            return Err(Error::InvalidKeyLength);
        }
        let digest: [u8; 32] = Sha256::digest(material).into();
        // Linux key.c::ieee80211_key_identical prevents reinstalling an
        // identical temporal key. Do not reset nonce/replay state on a retry.
        if self.material_digest.is_some_and(|old| {
            digest
                .iter()
                .zip(old)
                .fold(0_u8, |difference, (a, b)| difference | (*a ^ b))
                == 0
        }) {
            if let State::Installed(key) = self.state
                && key.index == index
                && key.cipher == cipher
            {
                return Err(Error::AlreadyInstalled(key));
            }
            return Err(Error::Reinstallation);
        }
        match self.state {
            State::Installed(_) => return Err(Error::KeyStillInstalled),
            State::Pending(_) => return Err(Error::Busy),
            State::Quarantined => return Err(Error::Quarantined),
            _ => (),
        }
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(Error::GenerationExhausted)?;
        self.generation = generation;
        let key = KeyIdentity {
            slot: self.slot,
            index,
            generation,
            cipher,
        };
        // Invalidate the old binding before a command can change hardware state.
        self.state = State::Pending(key);
        self.pending_digest = Some(digest);
        Ok(InstallTicket(key))
    }

    /// Call only after matching the device command identity and real status.
    /// `Accepted` must never be inferred from DMA completion or a timeout.
    pub fn complete_install(
        &mut self,
        ticket: InstallTicket,
        outcome: InstallOutcome,
    ) -> Result<(), Error> {
        if self.state != State::Pending(ticket.0) {
            return Err(Error::StaleAcknowledgement);
        }
        self.state = match outcome {
            InstallOutcome::Accepted => {
                self.rx_pn = [0; 17];
                self.material_digest = self.pending_digest.take();
                State::Installed(ticket.0)
            }
            InstallOutcome::RejectedAndEmpty => State::Empty,
            InstallOutcome::Uncertain => State::Quarantined,
        };
        Ok(())
    }

    pub const fn installed(&self) -> Option<KeyIdentity> {
        if let State::Installed(key) = self.state {
            Some(key)
        } else {
            None
        }
    }

    /// Invalidate before sending a remove command. RX is no longer authorized.
    /// Use `retire_after_drain` after acknowledgement and old RX/work retirement.
    pub fn invalidate(&mut self) {
        self.state = State::Quarantined;
    }

    /// # Safety
    /// Hardware key removal/reset must be acknowledged and all old RX,
    /// completions and deferred key users drained. The caller retains this
    /// slot's monotonically increasing generation across subsequent installs.
    pub unsafe fn retire_after_drain(&mut self) {
        self.state = State::Empty;
        self.pending_digest = None;
        // Retain the last material identity: device reset is not permission to
        // reinstall an identical key with reset transmit/replay counters.
    }

    /// Validate one non-aggregated, non-fragmented protected data MPDU and
    /// consume its PN only after framing, key and integrity checks succeed.
    pub fn authorize<'a>(&mut self, mpdu: &'a Mpdu) -> Result<AuthenticatedData<'a>, Error> {
        let key = self.installed().ok_or(Error::NoInstalledKey)?;
        let header = mpdu.header();
        if !header.protected() {
            return Err(Error::NotProtected);
        }
        if !header.data_present() {
            return Err(Error::Unsupported("protected management/null/control"));
        }
        if header.fragmented() {
            return Err(Error::Unsupported("fragment replay/assembly"));
        }
        if header.amsdu || mpdu.aggregation != Aggregation::default() {
            return Err(Error::Unsupported("aggregate replay/reordering"));
        }
        let status = mpdu.security;
        if mpdu.monitor_only
            || mpdu.fcs_error
            || status.icv_error
            || status.tkip_mic_error
            || !status.decrypted
            || status.integrity != Integrity::Verified
            || matches!(status.hardware_replay, HardwareReplay::Failed { .. })
        {
            return Err(Error::Integrity);
        }
        if status.key != Some(key) {
            return Err(Error::WrongKey);
        }
        let mut start = header.length;
        let pn = if status.iv_stripped {
            status.pn.ok_or(Error::MissingPacketNumber)?
        } else {
            let (pn, index) =
                PacketNumber::from_header(mpdu.bytes().get(start..).ok_or(Error::Truncated)?)?;
            if index != key.index {
                return Err(Error::WrongKey);
            }
            if status.pn.is_some_and(|observed| observed != pn) {
                return Err(Error::InconsistentPacketNumber);
            }
            start += 8;
            pn
        };
        let mic = if status.mic_stripped {
            0
        } else {
            key.cipher.mic_length()
        };
        let end = mpdu
            .bytes()
            .len()
            .checked_sub(mic)
            .filter(|end| *end >= start)
            .ok_or(Error::Truncated)?;
        let queue = header.tid.map_or(16, usize::from);
        if pn.0 <= self.rx_pn[queue] {
            return Err(Error::Replay);
        }
        self.rx_pn[queue] = pn.0;
        Ok(AuthenticatedData {
            mpdu,
            start,
            end,
            key,
            pn,
        })
    }
}

/// Integrity-checked plaintext for this key/PN. Station/BSSID/port policy must
/// still be checked before delivering its MSDU to an Ethernet interface.
#[derive(Debug)]
pub struct AuthenticatedData<'a> {
    mpdu: &'a Mpdu,
    start: usize,
    end: usize,
    key: KeyIdentity,
    pn: PacketNumber,
}

impl<'a> AuthenticatedData<'a> {
    pub fn payload(&self) -> &'a [u8] {
        &self.mpdu.bytes()[self.start..self.end]
    }
    pub const fn mpdu(&self) -> &'a Mpdu {
        self.mpdu
    }
    pub const fn key(&self) -> KeyIdentity {
        self.key
    }
    pub const fn packet_number(&self) -> PacketNumber {
        self.pn
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::wifi::{Band, RadioStatus, RawRate};
    use alloc::vec;

    fn install(slot: &mut KeySlot) -> KeyIdentity {
        let ticket = slot.begin_install(2, Cipher::Ccmp128, &[0x42; 16]).unwrap();
        assert_eq!(slot.installed(), None);
        slot.complete_install(ticket, InstallOutcome::Accepted)
            .unwrap();
        slot.installed().unwrap()
    }

    fn packet(key: KeyIdentity, pn: u64, tid: Option<u8>) -> Mpdu {
        let len = if tid.is_some() { 26 } else { 24 };
        let mut bytes = vec![0; len + 3];
        bytes[..2].copy_from_slice(
            &(if tid.is_some() {
                0x4088_u16
            } else {
                0x4008_u16
            })
            .to_le_bytes(),
        );
        if let Some(tid) = tid {
            bytes[24] = tid;
        }
        bytes[len..].copy_from_slice(&[1, 2, 3]);
        Mpdu::new(
            bytes,
            RadioStatus {
                band: Band::Ghz5,
                channel: 36,
                frequency_mhz: 5180,
                signal_dbm: Some(-40),
                chain_signal_dbm: [None; 4],
                rate: RawRate {
                    layout: 1,
                    words: [0; 4],
                },
                tsf: None,
            },
            SecurityStatus {
                key: Some(key),
                pn: PacketNumber::new(pn),
                decrypted: true,
                integrity: Integrity::Verified,
                iv_stripped: true,
                mic_stripped: true,
                ..SecurityStatus::default()
            },
        )
        .unwrap()
    }

    #[test]
    fn key_acknowledgement_rekey_and_stale_rx() {
        let mut slot = KeySlot::new(7);
        let old = install(&mut slot);
        assert_eq!(
            slot.authorize(&packet(old, 8, None)).unwrap().payload(),
            &[1, 2, 3]
        );
        assert_eq!(
            slot.begin_install(2, Cipher::Ccmp128, &[0x43; 16]),
            Err(Error::KeyStillInstalled)
        );
        slot.invalidate();
        // Fixture has no physical key, RX or deferred users.
        unsafe {
            slot.retire_after_drain();
        }
        let ticket = slot.begin_install(2, Cipher::Ccmp128, &[0x43; 16]).unwrap();
        assert!(matches!(
            slot.authorize(&packet(old, 9, None)),
            Err(Error::NoInstalledKey)
        ));
        assert_eq!(
            slot.begin_install(2, Cipher::Ccmp128, &[0x43; 16]),
            Err(Error::Busy)
        );
        slot.complete_install(ticket, InstallOutcome::Accepted)
            .unwrap();
        let new = slot.installed().unwrap();
        assert_ne!(old.generation(), new.generation());
        assert!(matches!(
            slot.authorize(&packet(old, 9, None)),
            Err(Error::WrongKey)
        ));
        assert!(slot.authorize(&packet(new, 1, None)).is_ok());
        assert_eq!(
            slot.complete_install(ticket, InstallOutcome::Accepted),
            Err(Error::StaleAcknowledgement)
        );
    }

    #[test]
    fn uncertain_install_requires_real_retirement() {
        let mut slot = KeySlot::new(3);
        let ticket = slot.begin_install(0, Cipher::Gcmp128, &[0x43; 16]).unwrap();
        slot.complete_install(ticket, InstallOutcome::Uncertain)
            .unwrap();
        assert_eq!(
            slot.begin_install(0, Cipher::Ccmp128, &[0x44; 16]),
            Err(Error::Quarantined)
        );
        // Fixture has no hardware or queued RX users.
        unsafe {
            slot.retire_after_drain();
        }
        assert!(
            slot.begin_install(0, Cipher::Ccmp128, &[0x44; 16])
                .unwrap()
                .identity()
                .generation()
                > ticket.identity().generation()
        );
    }

    #[test]
    fn replay_is_per_tid_and_non_qos_and_zero_is_not_new() {
        let mut slot = KeySlot::new(1);
        let key = install(&mut slot);
        for tid in (0..16).map(Some).chain([None]) {
            assert!(matches!(
                slot.authorize(&packet(key, 0, tid)),
                Err(Error::Replay)
            ));
            assert!(slot.authorize(&packet(key, 5, tid)).is_ok());
            for pn in [1, 4, 5] {
                assert!(matches!(
                    slot.authorize(&packet(key, pn, tid)),
                    Err(Error::Replay)
                ));
            }
            assert!(slot.authorize(&packet(key, 6, tid)).is_ok());
        }
    }

    #[test]
    fn decryption_and_hardware_replay_claim_do_not_authorize() {
        let mut slot = KeySlot::new(1);
        let key = install(&mut slot);
        let mut frame = packet(key, 10, Some(0));
        frame.security.integrity = Integrity::Unknown;
        assert!(matches!(slot.authorize(&frame), Err(Error::Integrity)));
        frame.security.integrity = Integrity::Verified;
        frame.security.pn = None;
        frame.security.hardware_replay = HardwareReplay::Validated { layout: 1 };
        assert!(matches!(
            slot.authorize(&frame),
            Err(Error::MissingPacketNumber)
        ));
        frame.security.pn = PacketNumber::new(10);
        assert!(slot.authorize(&frame).is_ok());
    }

    #[test]
    fn failed_packet_does_not_advance_replay_state() {
        let mut slot = KeySlot::new(1);
        let key = install(&mut slot);
        let mut frame = packet(key, 99, None);
        frame.fcs_error = true;
        assert!(matches!(slot.authorize(&frame), Err(Error::Integrity)));
        assert!(slot.authorize(&packet(key, 3, None)).is_ok());
        frame.fcs_error = false;
        frame.security.mic_stripped = false;
        assert!(matches!(slot.authorize(&frame), Err(Error::Truncated)));
        assert!(slot.authorize(&packet(key, 4, None)).is_ok());
    }

    #[test]
    fn aggregates_fragments_and_non_data_are_explicit() {
        let mut slot = KeySlot::new(1);
        let key = install(&mut slot);
        let mut frame = packet(key, 1, None);
        frame.aggregation.ampdu = Some(2);
        assert!(matches!(slot.authorize(&frame), Err(Error::Unsupported(_))));
        for control in [0x4408_u16, 0x4000, 0x4048] {
            let mut bytes = vec![0; 24];
            bytes[..2].copy_from_slice(&control.to_le_bytes());
            let bad = Mpdu::new(bytes, frame.radio.clone(), frame.security).unwrap();
            assert!(matches!(slot.authorize(&bad), Err(Error::Unsupported(_))));
        }
        assert!(slot.authorize(&packet(key, 1, None)).is_ok());
    }

    #[test]
    fn identical_key_retry_does_not_reset_nonce_or_replay_state() {
        let mut slot = KeySlot::new(1);
        let key = install(&mut slot);
        assert!(slot.authorize(&packet(key, 10, None)).is_ok());
        assert_eq!(
            slot.begin_install(2, Cipher::Ccmp128, &[0x42; 16]),
            Err(Error::AlreadyInstalled(key))
        );
        assert!(matches!(
            slot.authorize(&packet(key, 10, None)),
            Err(Error::Replay)
        ));
        slot.invalidate();
        // Explicit quiescence does not grant permission for counter reset.
        unsafe {
            slot.retire_after_drain();
        }
        assert_eq!(
            slot.begin_install(2, Cipher::Ccmp128, &[0x42; 16]),
            Err(Error::Reinstallation)
        );
    }

    #[test]
    fn retained_crypto_header_and_mic_match_all_declared_ciphers() {
        for cipher in [
            Cipher::Ccmp128,
            Cipher::Ccmp256,
            Cipher::Gcmp128,
            Cipher::Gcmp256,
        ] {
            for index in 0..4 {
                let mut slot = KeySlot::new(5);
                let length = if matches!(cipher, Cipher::Ccmp128 | Cipher::Gcmp128) {
                    16
                } else {
                    32
                };
                let material = [0x42; 32];
                let ticket = slot
                    .begin_install(index, cipher, &material[..length])
                    .unwrap();
                slot.complete_install(ticket, InstallOutcome::Accepted)
                    .unwrap();
                let key = slot.installed().unwrap();
                let base = packet(key, 0x112233445566, Some(15));
                let mut bytes = base.bytes()[..26].to_vec();
                bytes.extend_from_slice(&[
                    0x66,
                    0x55,
                    0,
                    0x20 | index << 6,
                    0x44,
                    0x33,
                    0x22,
                    0x11,
                ]);
                bytes.extend_from_slice(&[1, 2, 3]);
                bytes.resize(bytes.len() + cipher.mic_length(), 0xcc);
                let mut status = base.security;
                status.iv_stripped = false;
                status.mic_stripped = false;
                let mut frame = Mpdu::new(bytes, base.radio.clone(), status).unwrap();
                frame.security.pn = PacketNumber::new(0x112233445567);
                assert!(matches!(
                    slot.authorize(&frame),
                    Err(Error::InconsistentPacketNumber)
                ));
                frame.security.pn = None;
                let authorized = slot.authorize(&frame).unwrap();
                assert_eq!(authorized.payload(), &[1, 2, 3]);
                assert_eq!(authorized.packet_number().value(), 0x112233445566);
            }
        }
    }

    #[test]
    fn every_bad_security_observation_preserves_replay_floor() {
        let mut slot = KeySlot::new(1);
        let key = install(&mut slot);
        for case in 0..7 {
            let mut frame = packet(key, 99, None);
            match case {
                0 => frame.security.icv_error = true,
                1 => frame.security.tkip_mic_error = true,
                2 => frame.security.decrypted = false,
                3 => frame.security.integrity = Integrity::Failed,
                4 => frame.security.hardware_replay = HardwareReplay::Failed { layout: 2 },
                5 => frame.monitor_only = true,
                _ => frame.fcs_error = true,
            }
            assert!(matches!(slot.authorize(&frame), Err(Error::Integrity)));
        }
        assert!(slot.authorize(&packet(key, 1, None)).is_ok());
    }

    #[test]
    fn ccmp_header_layout_bounds_and_reserved_bits() {
        assert_eq!(
            PacketNumber::from_header(&[0x66, 0x55, 0, 0xa0, 0x44, 0x33, 0x22, 0x11]),
            Ok((PacketNumber(0x112233445566), 2))
        );
        assert_eq!(PacketNumber::new(1 << 48), None);
        for n in 0..8 {
            assert_eq!(
                PacketNumber::from_header(&[0; 8][..n]),
                Err(Error::Truncated)
            );
        }
        for (offset, value) in [(2, 1), (3, 0), (3, 0x21)] {
            let mut hdr = [0; 8];
            hdr[3] = 0x20;
            hdr[offset] = value;
            assert_eq!(PacketNumber::from_header(&hdr), Err(Error::CryptoHeader));
        }
    }
}
