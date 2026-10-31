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
//! This layer does not implement a WPA handshake or software data encryption;
//! `wep` encrypts only the shared-key authentication challenge response. A
//! vendor must report successful hardware key installation only after its real
//! firmware acknowledgement, and verified integrity only from the applicable
//! negotiated RX status. Unknown evidence is refused. No hardware replay flag
//! bypasses the software check. The separate complete-owned post-order group
//! gate authenticates all constituents before one parent replay update. This
//! does not implement grouping, BA/reordering, fragmentation, deaggregation or
//! PMF association negotiation. The unicast management boundary authenticates
//! hardware-verified CCMP128 under the installed PTK and separate counter16;
//! it grants no current-association or station-delivery permission. The separate
//! management module authenticates group BIP-CMAC128 under a kept
//! IGTK; this grants no current-association or controlled-port permission.

use super::{Aggregation, frame::Mpdu};
use crate::Mac;
use stela_crypto::{Sha256, digest::Digest};

pub mod aggregate;
pub mod management;
pub mod tx;
pub mod unicast_management;
pub mod wep;
pub use tx::{HostTxNonce, NonceOwner, TransmitSeed};

static NEXT_NATIVE_EPOCH: super::Identities = super::Identities::new();

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
    /// TKIP: a 16-byte temporal key with the 8-byte TX and RX Michael keys.
    Tkip,
    /// Static WEP default keys, which carry no packet number.
    Wep40,
    Wep104,
}

impl Cipher {
    /// The trailer after the payload: TKIP's Michael MIC and ICV, the WEP
    /// ICV, or the CCMP/GCMP MIC.
    const fn mic_length(self) -> usize {
        match self {
            Self::Wep40 | Self::Wep104 => 4,
            Self::Ccmp128 => 8,
            Self::Tkip => 12,
            _ => 16,
        }
    }
    /// `struct ieee80211_key_conf`'s keylen for the suite.
    pub const fn key_length(self) -> usize {
        match self {
            Self::Wep40 => 5,
            Self::Wep104 => 13,
            Self::Ccmp128 | Self::Gcmp128 => 16,
            Self::Ccmp256 | Self::Gcmp256 | Self::Tkip => 32,
        }
    }
    /// mac80211 checks no replay counter for WEP.
    pub const fn is_wep(self) -> bool {
        matches!(self, Self::Wep40 | Self::Wep104)
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
    /// The TSC of a TKIP IV/EIV, as `ieee80211_tkip_decrypt_data` reads
    /// TSC0 at byte 2 and TSC1 at byte 0 ahead of the 32-bit IV32.
    pub fn from_tkip_header(header: &[u8]) -> Result<(Self, u8), Error> {
        let h: &[u8; 8] = header.get(..8).ok_or(Error::Truncated)?.try_into().unwrap();
        if h[3] & 0x20 == 0 {
            return Err(Error::Unsupported("TKIP without Extended IV"));
        }
        let value = u64::from_le_bytes([h[2], h[0], h[4], h[5], h[6], h[7], 0, 0]);
        Ok((Self(value), h[3] >> 6))
    }
}

/// Firmware key purpose and peer/BSS, independent of a reusable slot.
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

/// Binding to one acknowledged installation, not a reusable HW slot.
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

/// Hardware observation, distinct from stripped MIC bytes.
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
    /// Observation only; never substitutes for checking a PN.
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

/// Authenticated initial receive counters from the key exchange or
/// device handoff. Queues 0..15 correspond to TIDs; non-QoS data shares queue 0.
/// Queue 16 is the separate unicast protected-management receive counter.
/// Data authorization never reads or advances that counter.
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

/// A command ticket stays unusable until a successful acknowledgement.
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

/// Serialized key slot and source receive replay queues. Non-QoS data shares
/// TID0; queue 16 is the separate source protected-management counter.
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
    /// Claim one hardware key slot, initially empty.
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
        let native_epoch = NEXT_NATIVE_EPOCH.next().ok_or(Error::EpochExhausted)?;
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
        // A static WEP default key may sit at any index, also on the AP's
        // station record, as mt7925_set_key installs it to both.
        if index > 3 || (matches!(scope, KeyScope::Pairwise(_)) && index > 1 && !cipher.is_wep()) {
            return Err(Error::InvalidKeyIndex);
        }
        if scope.peer().is_multicast() || scope.peer().0 == [0; 6] {
            return Err(Error::InvalidPeer);
        }
        if matches!(scope, KeyScope::Group(_)) && transmit.owner() != NonceOwner::ReceiveOnly {
            return Err(Error::WrongNonceOwner);
        }
        if material.len() != cipher.key_length() {
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
    /// completions and deferred key users drained. The caller keeps this
    /// slot's monotonically increasing generation across subsequent installs.
    pub unsafe fn retire_after_drain(&mut self) {
        self.state = State::Empty;
        self.material_digest = None;
    }

    /// Validate one non-aggregated, non-fragmented protected data MPDU and
    /// consume its PN only after framing, key and integrity checks succeed.
    pub fn authorize<'a>(&mut self, mpdu: &'a Mpdu) -> Result<AuthenticatedData<'a>, Error> {
        let checked = self.checked_mpdu(mpdu, false, None)?;
        self.commit_receive(data_replay_queue(mpdu), checked.pn)?;
        Ok(checked)
    }

    /// One verified fragment's plaintext and packet number, for
    /// `station::fragments`. Each fragment before the last spends its packet
    /// number here, as mac80211's per-fragment decryption does. The last spends
    /// its own with the whole MSDU, which `authorize` then checks.
    pub(in crate::wifi) fn fragment_payload<'a>(
        &mut self,
        mpdu: &'a Mpdu,
        last: bool,
    ) -> Result<(&'a [u8], PacketNumber), Error> {
        let key = self.installed().ok_or(Error::NoInstalledKey)?;
        if !mpdu.header().protected() {
            return Err(Error::NotProtected);
        }
        let (start, end, pn) = self.checked_payload(mpdu, key, None)?;
        if !last {
            self.commit_receive(data_replay_queue(mpdu), pn)?;
        }
        Ok((&mpdu.bytes()[start..end], pn))
    }

    // Only the complete-owned group gate may permit aggregate framing or
    // supply an authenticated parent's PN for an absent member group1.
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
        let (start, end, pn) = self.checked_payload(mpdu, key, parent_pn)?;
        Ok(AuthenticatedData {
            mpdu,
            start,
            end,
            key,
            pn,
        })
    }
    // Shared hardware-verified plaintext extraction. Callers first establish
    // their own frame class, peer, aggregate and key-scope constraints.
    fn checked_payload(
        &self,
        mpdu: &Mpdu,
        key: KeyIdentity,
        parent_pn: Option<PacketNumber>,
    ) -> Result<(usize, usize, PacketNumber), Error> {
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
        let mut start = mpdu.header().length;
        let pn = if key.cipher.is_wep() {
            // ieee80211_crypto_wep_decrypt removes the IV and ICV; no packet
            // number exists to check.
            if !status.iv_stripped {
                let iv = mpdu.bytes().get(start..start + 4).ok_or(Error::Truncated)?;
                if iv[3] >> 6 != key.index {
                    return Err(Error::WrongKey);
                }
                start += 4;
            }
            PacketNumber(0)
        } else if status.iv_stripped {
            status.pn.or(parent_pn).ok_or(Error::MissingPacketNumber)?
        } else {
            let header = mpdu.bytes().get(start..).ok_or(Error::Truncated)?;
            let (pn, index) = if key.cipher == Cipher::Tkip {
                PacketNumber::from_tkip_header(header)?
            } else {
                PacketNumber::from_header(header)?
            };
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
        Ok((start, end, pn))
    }
    /// Whether `mpdu`'s packet number is one this key already took, which
    /// `ieee80211_tkip_decrypt_data` drops before Michael's verdict counts.
    pub fn replays(&self, mpdu: &Mpdu) -> bool {
        let queue = data_replay_queue(mpdu);
        mpdu.security.pn.is_some_and(|pn| pn.0 <= self.rx_pn[queue])
    }
    fn commit_receive(&mut self, queue: usize, pn: PacketNumber) -> Result<(), Error> {
        if self.installed().is_some_and(|key| key.cipher.is_wep()) {
            return Ok(());
        }
        if pn.0 <= self.rx_pn[queue] {
            return Err(Error::Replay);
        }
        self.rx_pn[queue] = pn.0;
        Ok(())
    }
}

/// mac80211 ieee80211_parse_qos and mt76_check_ccmp_pn agree: ordinary
/// non-QoS data uses security index 0, independently of sequence queue 16.
fn data_replay_queue(mpdu: &Mpdu) -> usize {
    mpdu.header().tid.map_or(0, usize::from)
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
mod tests;
