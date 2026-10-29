// SPDX-License-Identifier: GPL-2.0-only
// Packet-number increment and CCMP/GCMP header layout adapt Linux
// net/mac80211/wpa.c, Copyright 2002-2004 Instant802 Networks, Inc.;
// 2008 Jouni Malinen; 2016-2017 Intel Deutschland GmbH;
// 2020-2023 Intel Corporation. See THIRD_PARTY.md.
//! Explicit transmit PN ownership. Cipher/MIC execution remains in hardware.

use super::{Error, KeyIdentity, KeySlot, PacketNumber, State};

const PACKET_NUMBER_LIMIT: u64 = 1 << 48;

fn crypto_header(pn: PacketNumber, index: u8) -> [u8; 8] {
    let [p0, p1, p2, p3, p4, p5, _, _] = pn.value().to_le_bytes();
    [p0, p1, 0, 0x20 | index << 6, p2, p3, p4, p5]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NonceOwner {
    /// Driver needs a filled CCMP/GCMP header (`GENERATE_IV`).
    Host,
    /// Firmware/hardware inserts PN/IV and computes the cipher/MIC.
    Firmware,
    /// Station GTK or a key not enabled for transmission.
    ReceiveOnly,
}

/// Initial counter programming for a new temporal-key epoch.
/// Does not authorize reinstalling a previous key or invent a recovery counter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TransmitSeed {
    owner: NonceOwner,
    counter: PacketNumber,
}

impl TransmitSeed {
    /// Hardware-managed PN is admitted only for a fresh key. Running firmware
    /// PN recovery requires vendor proof and is not supplied here.
    pub const FIRMWARE_FRESH: Self = Self {
        owner: NonceOwner::Firmware,
        counter: PacketNumber(0),
    };
    pub const RECEIVE_ONLY: Self = Self {
        owner: NonceOwner::ReceiveOnly,
        counter: PacketNumber(0),
    };

    /// The highest already reserved host PN for this new key. Future allocations
    /// start strictly above it. A fresh key normally starts at zero.
    pub const fn host(counter: PacketNumber) -> Self {
        Self {
            owner: NonceOwner::Host,
            counter,
        }
    }
    pub const fn owner(self) -> NonceOwner {
        self.owner
    }
    /// Initialization input only; never evidence of running firmware state.
    pub const fn initial_counter(self) -> PacketNumber {
        self.counter
    }
}

/// One reserved host PN. Not Clone/Copy: consume it once when
/// building this MPDU's crypto header. Failed TX consumes/skips the reservation;
/// it must never be rolled back or reused for a different plaintext MPDU.
#[derive(Debug)]
pub struct HostTxNonce {
    key: KeyIdentity,
    pn: PacketNumber,
}

impl HostTxNonce {
    pub const fn key(&self) -> KeyIdentity {
        self.key
    }
    pub const fn packet_number(&self) -> PacketNumber {
        self.pn
    }

    pub fn into_header(self) -> [u8; 8] {
        crypto_header(self.pn, self.key.index())
    }
}

impl KeySlot {
    /// Reserve a monotonically increasing PN for one host-IV MPDU. The caller
    /// serializes this with the physical key's TX queue publication.
    /// Hardware retries of the same MPDU keep its PN and payload; a new MPDU
    /// must obtain a new reservation. Hold the key/counter context through real
    /// hardware completion and deferred-work drain before slot retirement.
    pub fn reserve_host_tx_nonce(&mut self, expected: KeyIdentity) -> Result<HostTxNonce, Error> {
        let key = self.installed().ok_or(Error::NoInstalledKey)?;
        if key != expected {
            return Err(Error::WrongKey);
        }
        if key.nonce_owner() != NonceOwner::Host {
            return Err(Error::WrongNonceOwner);
        }
        let Some(next) = self
            .tx_pn
            .checked_add(1)
            .filter(|next| *next < PACKET_NUMBER_LIMIT)
        else {
            self.state = State::Quarantined;
            return Err(Error::PacketNumberExhausted);
        };
        self.tx_pn = next;
        Ok(HostTxNonce {
            key,
            pn: PacketNumber(next),
        })
    }

    /// Highest reserved host PN, including reservations whose TX failed. This
    /// is not a TX completion receipt. Firmware/receive-only counters cannot be
    /// observed through this API; returning zero for them would invent state.
    pub fn host_tx_counter(&self, expected: KeyIdentity) -> Result<PacketNumber, Error> {
        let key = self.installed().ok_or(Error::NoInstalledKey)?;
        if key != expected {
            return Err(Error::WrongKey);
        }
        if key.nonce_owner() != NonceOwner::Host {
            return Err(Error::WrongNonceOwner);
        }
        Ok(PacketNumber(self.tx_pn))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{
        Mac,
        wifi::security::{Cipher, InstallOutcome, KeyScope, ReplaySeed},
    };

    fn installed(seed: TransmitSeed) -> (KeySlot, KeyIdentity) {
        // Pure model: no physical slot, DMA or deferred users exist.
        // SAFETY: this test owns the key slot number alone.
        let mut slot = unsafe { KeySlot::new(7).unwrap() };
        let ticket = slot
            .begin_install(
                0,
                Cipher::Ccmp128,
                &[0x42; 16],
                ReplaySeed::ZERO,
                KeyScope::Pairwise(Mac([2, 0, 0, 0, 0, 1])),
                seed,
            )
            .unwrap();
        assert_eq!(ticket.transmit_seed(), seed);
        slot.complete_install(ticket, InstallOutcome::Accepted)
            .unwrap();
        let identity = slot.installed().unwrap();
        (slot, identity)
    }

    #[test]
    fn host_reservations_skip_failed_tx_and_same_key_reinstall_does_not_reset() {
        let (mut slot, key) = installed(TransmitSeed::host(PacketNumber(0)));
        let first = slot.reserve_host_tx_nonce(key).unwrap();
        assert_eq!(first.packet_number().value(), 1);
        // This packet was not queued. Dropping it still consumes the PN.
        let _unused = first;
        assert_eq!(
            slot.reserve_host_tx_nonce(key)
                .unwrap()
                .packet_number()
                .value(),
            2
        );
        assert_eq!(slot.host_tx_counter(key).unwrap().value(), 2);
        assert_eq!(
            slot.begin_install(
                0,
                Cipher::Ccmp128,
                &[0x42; 16],
                ReplaySeed::ZERO,
                key.scope(),
                TransmitSeed::host(PacketNumber(0))
            ),
            Err(Error::AlreadyInstalled(key))
        );
        assert_eq!(
            slot.reserve_host_tx_nonce(key)
                .unwrap()
                .packet_number()
                .value(),
            3
        );
    }

    #[test]
    fn last_legal_nonce_is_followed_by_quarantine_not_wrap() {
        let (mut slot, key) = installed(TransmitSeed::host(PacketNumber(PACKET_NUMBER_LIMIT - 2)));
        let last = slot.reserve_host_tx_nonce(key).unwrap();
        assert_eq!(last.packet_number().value(), PACKET_NUMBER_LIMIT - 1);
        assert_eq!(
            last.into_header(),
            [0xff, 0xff, 0, 0x20, 0xff, 0xff, 0xff, 0xff]
        );
        assert!(matches!(
            slot.reserve_host_tx_nonce(key),
            Err(Error::PacketNumberExhausted)
        ));
        assert!(slot.installed().is_none());
        assert!(matches!(
            slot.reserve_host_tx_nonce(key),
            Err(Error::NoInstalledKey)
        ));
    }

    #[test]
    fn firmware_nonce_has_no_invented_host_counter_or_header() {
        let (mut slot, key) = installed(TransmitSeed::FIRMWARE_FRESH);
        assert_eq!(slot.host_tx_counter(key), Err(Error::WrongNonceOwner));
        assert!(matches!(
            slot.reserve_host_tx_nonce(key),
            Err(Error::WrongNonceOwner)
        ));
        assert_eq!(slot.installed(), Some(key));
    }

    #[test]
    fn reinstalling_an_identical_key_keeps_its_nonce_owner() {
        let (mut slot, key) = installed(TransmitSeed::host(PacketNumber(100)));
        assert_eq!(
            slot.begin_install(
                0,
                Cipher::Ccmp128,
                &[0x42; 16],
                ReplaySeed::ZERO,
                key.scope(),
                TransmitSeed::FIRMWARE_FRESH
            ),
            Err(Error::AlreadyInstalled(key))
        );
        assert_eq!(slot.host_tx_counter(key).unwrap().value(), 100);
        slot.invalidate();
        assert!(matches!(
            slot.reserve_host_tx_nonce(key),
            Err(Error::NoInstalledKey)
        ));
    }

    #[test]
    fn unchanged_linux_pn_encoder_matches_all_fixture_key_ids_and_bytes() {
        use sha2::{Digest, Sha256};
        let mut digest = Sha256::new();
        for i in 0_u16..=u16::MAX {
            let pn = PacketNumber(u64::from_be_bytes([
                0,
                0,
                (i >> 8) as u8,
                i as u8,
                i.wrapping_mul(13) as u8,
                (i >> 3) as u8,
                i.wrapping_mul(7) as u8,
                i.wrapping_mul(5) as u8,
            ]));
            for index in 0..4 {
                digest.update(crypto_header(pn, index));
            }
        }
        // Exact complete output from the unchanged C helper, ASan/UBSan;
        // reproduce with tests/reference/wifi_tx_pn_oracle.py.
        assert_eq!(
            digest.finalize().as_slice(),
            &[
                0x70, 0x62, 0xe7, 0x56, 0xdf, 0x2e, 0xfe, 0x98, 0xa3, 0xfe, 0x9b, 0x6a, 0xe4, 0xdc,
                0x60, 0xb3, 0x61, 0x46, 0xa1, 0xee, 0x98, 0x15, 0xcf, 0xc5, 0x5d, 0x6f, 0x20, 0xa6,
                0x24, 0xed, 0x56, 0xd1
            ]
        );
    }

    #[test]
    fn unacknowledged_key_cannot_reserve_a_nonce() {
        // SAFETY: this test owns the key slot number alone.
        let mut slot = unsafe { KeySlot::new(7).unwrap() };
        let ticket = slot
            .begin_install(
                0,
                Cipher::Ccmp128,
                &[0x42; 16],
                ReplaySeed::ZERO,
                KeyScope::Pairwise(Mac([2, 0, 0, 0, 0, 1])),
                TransmitSeed::host(PacketNumber(0)),
            )
            .unwrap();
        let key = ticket.identity();
        assert!(matches!(
            slot.reserve_host_tx_nonce(key),
            Err(Error::NoInstalledKey)
        ));
        slot.complete_install(ticket, InstallOutcome::Uncertain)
            .unwrap();
        assert!(matches!(
            slot.reserve_host_tx_nonce(key),
            Err(Error::NoInstalledKey)
        ));
    }
}
