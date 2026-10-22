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
//! bypasses the software check. The separate complete-owned post-order group
//! gate authenticates all constituents before one parent replay update. This
//! does not implement grouping, BA/reordering, fragmentation, deaggregation or
//! protected management frames; those boundaries remain explicit.

use super::{Aggregation, frame::Mpdu};
use crate::net::Mac;
use core::sync::atomic::{AtomicU64, Ordering};
use sha2::{Digest, Sha256};

pub mod aggregate;
pub mod tx;
pub use tx::{HostTxNonce, NonceOwner, TransmitSeed};

static NEXT_NATIVE_EPOCH: AtomicU64 = AtomicU64::new(1);

fn allocate_epoch(counter: &AtomicU64) -> Result<u64, Error> {
    counter
        .try_update(Ordering::Relaxed, Ordering::Relaxed, |epoch| {
            epoch.checked_add(1).filter(|_| epoch != 0)
        })
        .map_err(|_| Error::EpochExhausted)
}

fn same_digest(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter()
        .zip(b)
        .fold(0_u8, |difference, (a, b)| difference | (*a ^ *b))
        == 0
}

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
        // Like Linux `ccmp_hdr2pn` and `ieee80211_get_keyid`, only the PN
        // bytes and the key ID are read.
        let value = u64::from_le_bytes([h[0], h[1], h[4], h[5], h[6], h[7], 0, 0]);
        Ok((Self(value), h[3] >> 6))
    }
}

/// Actual firmware key purpose and peer/BSS, independent of a reusable slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyScope {
    Pairwise(Mac),
    Group(Mac),
}

impl KeyScope {
    pub const fn peer(self) -> Mac {
        match self {
            Self::Pairwise(peer) | Self::Group(peer) => peer,
        }
    }
}

/// Binding to one acknowledged installation, not merely a reusable HW slot.
/// Copy this identity from `KeySlot::installed()` into the vendor key table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeyIdentity {
    slot: u16,
    index: u8,
    generation: u64,
    native_epoch: u64,
    cipher: Cipher,
    scope: KeyScope,
    nonce_owner: NonceOwner,
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
    pub const fn native_epoch(self) -> u64 {
        self.native_epoch
    }
    pub const fn scope(self) -> KeyScope {
        self.scope
    }
    pub const fn nonce_owner(self) -> NonceOwner {
        self.nonce_owner
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
    InvalidPeer,
    WrongNonceOwner,
    PacketNumberExhausted,
    InvalidKeyLength,
    AlreadyInstalled(KeyIdentity),
    KeyStillInstalled,
    Busy,
    Quarantined,
    GenerationExhausted,
    EpochExhausted,
    NoMemory,
    StaleAcknowledgement,
    NoInstalledKey,
    WrongKey,
    NotProtected,
    Integrity,
    MissingPacketNumber,
    InconsistentPacketNumber,
    Replay,
    Truncated,
    Unsupported(&'static str),
}

/// Authenticated initial receive counters from the actual key exchange or
/// device handoff. Queue0..15 correspond to TIDs; queue16 is non-QoS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplaySeed([u64; 17]);

impl ReplaySeed {
    /// Use only where the protocol specifies fresh-key initial counters of zero.
    pub const ZERO: Self = Self([0; 17]);

    /// E.g. an authenticated GTK Key RSC applied to all receive queues.
    pub const fn uniform(pn: PacketNumber) -> Self {
        Self([pn.0; 17])
    }

    pub fn per_queue(pn: [PacketNumber; 17]) -> Self {
        Self(pn.map(|pn| pn.0))
    }

    pub const fn counters(self) -> [u64; 17] {
        self.0
    }
}

/// A command ticket stays unusable until an actual successful acknowledgement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InstallTicket {
    key: KeyIdentity,
    receive: ReplaySeed,
    transmit: TransmitSeed,
}

impl InstallTicket {
    pub const fn identity(self) -> KeyIdentity {
        self.key
    }
    /// Program these same initial counters into firmware/hardware when required.
    pub const fn receive_seed(self) -> ReplaySeed {
        self.receive
    }
    /// Initial programming values, never a snapshot of a running firmware PN.
    pub const fn transmit_seed(self) -> TransmitSeed {
        self.transmit
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InstallOutcome {
    /// Firmware explicitly accepted this exact key command.
    Accepted,
    /// Firmware rejected this command without using its material, and the
    /// vendor established that the slot is empty. Removal after a possibly
    /// successful installation is not this outcome; report Uncertain instead.
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
    native_epoch: u64,
    generation: u64,
    state: State,
    rx_pn: [u64; 17],
    tx_pn: u64,
    /// The digest of the pending or installed key's material.
    material_digest: Option<[u8; 32]>,
}

impl KeySlot {
    /// Claim one actual hardware key slot, initially empty.
    ///
    /// # Safety
    /// The caller must exclusively own this physical slot and its associated
    /// vendor key table. Removal/reset of any previous key must be acknowledged;
    /// all previous DMA RX, completions and deferred key users must be drained.
    /// No other `KeySlot` may control the same physical slot concurrently.
    /// Preserve this object for retries, so an identical reinstall is seen.
    ///
    /// ```compile_fail
    /// use stela_drivers::net::wifi::security::KeySlot;
    /// let slot = KeySlot::new(7); // Physical ownership requires unsafe proof.
    /// ```
    pub unsafe fn new(slot: u16) -> Result<Self, Error> {
        let native_epoch = allocate_epoch(&NEXT_NATIVE_EPOCH)?;
        Ok(Self {
            slot,
            native_epoch,
            generation: 0,
            state: State::Empty,
            rx_pn: [0; 17],
            tx_pn: 0,
            material_digest: None,
        })
    }

    /// Begin installing a key. A group key is receive-only and takes the RSC
    /// the OS learned in its authenticated key exchange, including when the
    /// same GTK is installed again after a reconnect.
    pub fn begin_install(
        &mut self,
        index: u8,
        cipher: Cipher,
        material: &[u8],
        receive: ReplaySeed,
        scope: KeyScope,
        transmit: TransmitSeed,
    ) -> Result<InstallTicket, Error> {
        if index > 3 || (matches!(scope, KeyScope::Pairwise(_)) && index > 1) {
            return Err(Error::InvalidKeyIndex);
        }
        if scope.peer().is_multicast() || scope.peer().0 == [0; 6] {
            return Err(Error::InvalidPeer);
        }
        if matches!(scope, KeyScope::Group(_)) && transmit.owner() != NonceOwner::ReceiveOnly {
            return Err(Error::WrongNonceOwner);
        }
        let length = match cipher {
            Cipher::Ccmp128 | Cipher::Gcmp128 => 16,
            _ => 32,
        };
        if material.len() != length {
            return Err(Error::InvalidKeyLength);
        }
        let digest: [u8; 32] = Sha256::digest(material).into();
        match self.state {
            // Linux `ieee80211_key_link`: reinstalling the identical key
            // changes nothing, so its nonce and replay state never reset.
            State::Installed(key)
                if key.index == index
                    && key.cipher == cipher
                    && key.scope == scope
                    && self
                        .material_digest
                        .is_some_and(|old| same_digest(&digest, &old)) =>
            {
                return Err(Error::AlreadyInstalled(key));
            }
            State::Installed(_) => return Err(Error::KeyStillInstalled),
            State::Pending(_) => return Err(Error::Busy),
            State::Quarantined => return Err(Error::Quarantined),
            State::Empty => (),
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
            native_epoch: self.native_epoch,
            cipher,
            scope,
            nonce_owner: transmit.owner(),
        };
        // Invalidate the old binding before a command can change hardware state.
        self.state = State::Pending(key);
        self.material_digest = Some(digest);
        Ok(InstallTicket {
            key,
            receive,
            transmit,
        })
    }

    /// Call only after matching the device command identity and real status.
    /// `Accepted` must never be inferred from DMA completion or a timeout.
    pub fn complete_install(
        &mut self,
        ticket: InstallTicket,
        outcome: InstallOutcome,
    ) -> Result<(), Error> {
        if self.state != State::Pending(ticket.key) {
            return Err(Error::StaleAcknowledgement);
        }
        self.state = match outcome {
            InstallOutcome::Accepted => {
                self.rx_pn = ticket.receive.0;
                self.tx_pn = ticket.transmit.initial_counter().value();
                State::Installed(ticket.key)
            }
            InstallOutcome::RejectedAndEmpty => {
                self.material_digest = None;
                State::Empty
            }
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
        self.material_digest = None;
    }

    /// # Safety
    /// Hardware key removal/reset must be acknowledged and all old RX,
    /// completions and deferred key users drained. The caller retains this
    /// slot's monotonically increasing generation across subsequent installs.
    pub unsafe fn retire_after_drain(&mut self) {
        self.state = State::Empty;
        self.material_digest = None;
    }

    /// Validate one non-aggregated, non-fragmented protected data MPDU and
    /// consume its PN only after framing, key and integrity checks succeed.
    pub fn authorize<'a>(&mut self, mpdu: &'a Mpdu) -> Result<AuthenticatedData<'a>, Error> {
        let checked = self.checked_mpdu(mpdu, false, None)?;
        self.commit_receive(mpdu.header().tid.map_or(16, usize::from), checked.pn)?;
        Ok(checked)
    }

    // Only the complete-owned group gate may permit aggregate framing or
    // supply an actual authenticated parent's PN for an absent member group1.
    fn checked_mpdu<'a>(
        &self,
        mpdu: &'a Mpdu,
        aggregate: bool,
        parent_pn: Option<PacketNumber>,
    ) -> Result<AuthenticatedData<'a>, Error> {
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
        if !aggregate && (header.amsdu || mpdu.aggregation != Aggregation::default()) {
            return Err(Error::Unsupported("aggregate replay/reordering"));
        }
        let status = mpdu.security;
        if !valid_receive_observations(mpdu)
            || !status.decrypted
            || status.integrity != Integrity::Verified
        {
            return Err(Error::Integrity);
        }
        if status.key != Some(key) {
            return Err(Error::WrongKey);
        }
        let mut start = header.length;
        let pn = if status.iv_stripped {
            status.pn.or(parent_pn).ok_or(Error::MissingPacketNumber)?
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
        Ok(AuthenticatedData {
            mpdu,
            start,
            end,
            key,
            pn,
        })
    }
    fn commit_receive(&mut self, queue: usize, pn: PacketNumber) -> Result<(), Error> {
        if pn.0 <= self.rx_pn[queue] {
            return Err(Error::Replay);
        }
        self.rx_pn[queue] = pn.0;
        Ok(())
    }
}

fn valid_receive_observations(mpdu: &Mpdu) -> bool {
    !mpdu.monitor_only
        && !mpdu.fcs_error
        && !mpdu.security.icv_error
        && !mpdu.security.tkip_mic_error
        && !matches!(mpdu.security.hardware_replay, HardwareReplay::Failed { .. })
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

    fn slot(number: u16) -> KeySlot {
        // Independent pure model: no physical slot, DMA or deferred users exist.
        unsafe { KeySlot::new(number).unwrap() }
    }

    fn install(slot: &mut KeySlot) -> KeyIdentity {
        let ticket = slot
            .begin_install(
                2,
                Cipher::Ccmp128,
                &[0x42; 16],
                ReplaySeed::ZERO,
                KeyScope::Group(Mac([2, 0, 0, 0, 0, 1])),
                TransmitSeed::RECEIVE_ONLY,
            )
            .unwrap();
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
        let mut slot = slot(7);
        let old = install(&mut slot);
        assert_eq!(
            slot.authorize(&packet(old, 8, None)).unwrap().payload(),
            &[1, 2, 3]
        );
        assert_eq!(
            slot.begin_install(
                2,
                Cipher::Ccmp128,
                &[0x43; 16],
                ReplaySeed::ZERO,
                KeyScope::Group(Mac([2, 0, 0, 0, 0, 1])),
                TransmitSeed::RECEIVE_ONLY
            ),
            Err(Error::KeyStillInstalled)
        );
        slot.invalidate();
        // Fixture has no physical key, RX or deferred users.
        unsafe {
            slot.retire_after_drain();
        }
        let ticket = slot
            .begin_install(
                2,
                Cipher::Ccmp128,
                &[0x43; 16],
                ReplaySeed::ZERO,
                KeyScope::Group(Mac([2, 0, 0, 0, 0, 1])),
                TransmitSeed::RECEIVE_ONLY,
            )
            .unwrap();
        assert!(matches!(
            slot.authorize(&packet(old, 9, None)),
            Err(Error::NoInstalledKey)
        ));
        assert_eq!(
            slot.begin_install(
                2,
                Cipher::Ccmp128,
                &[0x43; 16],
                ReplaySeed::ZERO,
                KeyScope::Group(Mac([2, 0, 0, 0, 0, 1])),
                TransmitSeed::RECEIVE_ONLY
            ),
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
        let mut slot = slot(3);
        let ticket = slot
            .begin_install(
                0,
                Cipher::Gcmp128,
                &[0x43; 16],
                ReplaySeed::ZERO,
                KeyScope::Group(Mac([2, 0, 0, 0, 0, 1])),
                TransmitSeed::RECEIVE_ONLY,
            )
            .unwrap();
        slot.complete_install(ticket, InstallOutcome::Uncertain)
            .unwrap();
        assert_eq!(
            slot.begin_install(
                0,
                Cipher::Ccmp128,
                &[0x44; 16],
                ReplaySeed::ZERO,
                KeyScope::Group(Mac([2, 0, 0, 0, 0, 1])),
                TransmitSeed::RECEIVE_ONLY
            ),
            Err(Error::Quarantined)
        );
        // Fixture has no hardware or queued RX users.
        unsafe {
            slot.retire_after_drain();
        }
        assert!(
            slot.begin_install(
                0,
                Cipher::Ccmp128,
                &[0x44; 16],
                ReplaySeed::ZERO,
                KeyScope::Group(Mac([2, 0, 0, 0, 0, 1])),
                TransmitSeed::RECEIVE_ONLY
            )
            .unwrap()
            .identity()
            .generation()
                > ticket.identity().generation()
        );
    }

    fn begin_firmware_key(slot: &mut KeySlot, byte: u8) -> Result<InstallTicket, Error> {
        slot.begin_install(
            0,
            Cipher::Ccmp128,
            &[byte; 16],
            ReplaySeed::ZERO,
            KeyScope::Pairwise(Mac([2, 0, 0, 0, 0, 1])),
            TransmitSeed::FIRMWARE_FRESH,
        )
    }

    fn drain_model(slot: &mut KeySlot) {
        // Pure slot fixture has no physical key, DMA or old deferred users.
        // A real caller must prove the documented independent remove/drain.
        unsafe {
            slot.retire_after_drain();
        }
    }

    #[test]
    fn only_the_installed_key_is_compared_for_reinstallation() {
        let mut slot = slot(7);
        let first = begin_firmware_key(&mut slot, 0xa0).unwrap();
        slot.complete_install(first, InstallOutcome::Accepted)
            .unwrap();
        // An identical install changes nothing; another key needs removal first.
        assert_eq!(
            begin_firmware_key(&mut slot, 0xa0),
            Err(Error::AlreadyInstalled(first.identity()))
        );
        assert_eq!(
            begin_firmware_key(&mut slot, 0xb1),
            Err(Error::KeyStillInstalled)
        );
        slot.invalidate();
        drain_model(&mut slot);
        // After removal, as in Linux, any key installs with fresh counters.
        let again = begin_firmware_key(&mut slot, 0xa0).unwrap();
        assert!(again.identity().generation() > first.identity().generation());
        slot.complete_install(again, InstallOutcome::Uncertain)
            .unwrap();
        assert_eq!(begin_firmware_key(&mut slot, 0xc2), Err(Error::Quarantined));
        drain_model(&mut slot);
        let rejected = begin_firmware_key(&mut slot, 0xc2).unwrap();
        slot.complete_install(rejected, InstallOutcome::RejectedAndEmpty)
            .unwrap();
        let fresh = begin_firmware_key(&mut slot, 0xc2).unwrap();
        slot.complete_install(fresh, InstallOutcome::Accepted)
            .unwrap();
        assert_eq!(slot.installed(), Some(fresh.identity()));
    }

    #[test]
    fn invalidating_a_pending_install_refuses_its_late_acknowledgement() {
        for invalidate_first in [false, true] {
            let mut slot = slot(7);
            let pending = begin_firmware_key(&mut slot, 0xb1).unwrap();
            if invalidate_first {
                slot.invalidate();
            }
            drain_model(&mut slot);
            assert_eq!(
                slot.complete_install(pending, InstallOutcome::Accepted),
                Err(Error::StaleAcknowledgement)
            );
            assert!(begin_firmware_key(&mut slot, 0xb1).is_ok());
        }
    }

    #[test]
    fn replay_is_per_tid_and_non_qos_and_zero_is_not_new() {
        let mut slot = slot(1);
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
        let mut slot = slot(1);
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
        let mut slot = slot(1);
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
        let mut slot = slot(1);
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
        let mut slot = slot(1);
        let key = install(&mut slot);
        assert!(slot.authorize(&packet(key, 10, None)).is_ok());
        assert_eq!(
            slot.begin_install(
                2,
                Cipher::Ccmp128,
                &[0x42; 16],
                ReplaySeed::ZERO,
                KeyScope::Group(Mac([2, 0, 0, 0, 0, 1])),
                TransmitSeed::RECEIVE_ONLY
            ),
            Err(Error::AlreadyInstalled(key))
        );
        assert!(matches!(
            slot.authorize(&packet(key, 10, None)),
            Err(Error::Replay)
        ));
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
                let mut slot = slot(5);
                let length = if matches!(cipher, Cipher::Ccmp128 | Cipher::Gcmp128) {
                    16
                } else {
                    32
                };
                let material = [0x42; 32];
                let ticket = slot
                    .begin_install(
                        index,
                        cipher,
                        &material[..length],
                        ReplaySeed::ZERO,
                        KeyScope::Group(Mac([2, 0, 0, 0, 0, 1])),
                        TransmitSeed::RECEIVE_ONLY,
                    )
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
        let mut slot = slot(1);
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
    fn authenticated_initial_rsc_is_committed_only_with_key_ack() {
        let mut slot = slot(7);
        let seed = ReplaySeed::uniform(PacketNumber::new(100).unwrap());
        let ticket = slot
            .begin_install(
                2,
                Cipher::Ccmp128,
                &[0x42; 16],
                seed,
                KeyScope::Group(Mac([2, 0, 0, 0, 0, 1])),
                TransmitSeed::RECEIVE_ONLY,
            )
            .unwrap();
        assert_eq!(ticket.receive_seed().counters(), [100; 17]);
        assert_eq!(slot.installed(), None);
        slot.complete_install(ticket, InstallOutcome::Accepted)
            .unwrap();
        let key = slot.installed().unwrap();
        for tid in (0..16).map(Some).chain([None]) {
            assert!(matches!(
                slot.authorize(&packet(key, 100, tid)),
                Err(Error::Replay)
            ));
            assert!(slot.authorize(&packet(key, 101, tid)).is_ok());
        }
    }

    #[test]
    fn native_epoch_exhaustion_never_wraps_to_a_previous_identity() {
        let counter = AtomicU64::new(u64::MAX - 1);
        assert_eq!(allocate_epoch(&counter), Ok(u64::MAX - 1));
        assert_eq!(allocate_epoch(&counter), Err(Error::EpochExhausted));
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }

    #[test]
    fn key_purpose_has_a_real_peer_and_legal_on_air_index() {
        let mut key = slot(7);
        let peer = Mac([2, 0, 0, 0, 0, 1]);
        assert_eq!(
            key.begin_install(
                2,
                Cipher::Ccmp128,
                &[1; 16],
                ReplaySeed::ZERO,
                KeyScope::Pairwise(peer),
                TransmitSeed::RECEIVE_ONLY
            ),
            Err(Error::InvalidKeyIndex)
        );
        for peer in [Mac([0; 6]), Mac::BROADCAST] {
            assert_eq!(
                key.begin_install(
                    0,
                    Cipher::Ccmp128,
                    &[1; 16],
                    ReplaySeed::ZERO,
                    KeyScope::Pairwise(peer),
                    TransmitSeed::RECEIVE_ONLY
                ),
                Err(Error::InvalidPeer)
            );
            assert_eq!(
                key.begin_install(
                    2,
                    Cipher::Ccmp128,
                    &[1; 16],
                    ReplaySeed::ZERO,
                    KeyScope::Group(peer),
                    TransmitSeed::RECEIVE_ONLY
                ),
                Err(Error::InvalidPeer)
            );
        }
        assert!(key.installed().is_none());
    }

    #[test]
    fn recreated_hardware_slot_cannot_accept_old_native_epoch() {
        let old = {
            let mut previous = slot(7);
            let old = install(&mut previous);
            assert!(previous.authorize(&packet(old, 10, None)).is_ok());
            previous.invalidate();
            // Pure model has no hardware, queued RX, or outstanding key users.
            unsafe {
                previous.retire_after_drain();
            }
            old
        };
        let mut current = slot(7);
        let ticket = current
            .begin_install(
                2,
                Cipher::Ccmp128,
                &[0x43; 16],
                ReplaySeed::ZERO,
                KeyScope::Group(Mac([2, 0, 0, 0, 0, 1])),
                TransmitSeed::RECEIVE_ONLY,
            )
            .unwrap();
        current
            .complete_install(ticket, InstallOutcome::Accepted)
            .unwrap();
        let new = current.installed().unwrap();
        assert_eq!(old.slot(), new.slot());
        assert_eq!(old.generation(), new.generation());
        assert_ne!(old.native_epoch(), new.native_epoch());
        assert!(matches!(
            current.authorize(&packet(old, 10, None)),
            Err(Error::WrongKey)
        ));
        assert!(current.authorize(&packet(new, 1, None)).is_ok());
    }

    #[test]
    fn ccmp_header_layout_and_bounds() {
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
        // Linux reads only the PN bytes and key ID; reserved bits are ignored.
        assert_eq!(
            PacketNumber::from_header(&[1, 0, 0xff, 0x5f, 0, 0, 0, 0]),
            Ok((PacketNumber(1), 1))
        );
    }
}
