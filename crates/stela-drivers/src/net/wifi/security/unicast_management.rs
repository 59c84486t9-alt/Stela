// SPDX-License-Identifier: GPL-2.0-only
// CCMP receive replay follows Linux net/mac80211/{rx,wpa}.c and mt76/mac80211.c.
// Copyright 2002-2004 Instant802 Networks, Inc.; 2008 Jouni Malinen;
// Copyright (C) 2016-2017 Intel Deutschland GmbH;
// Copyright (C) 2020-2023 Intel Corporation. See THIRD_PARTY.md.
//! Hardware-verified unicast robust-management CCMP/GCMP receive authentication.
//! This is a selected-key crypto boundary, not PMF negotiation, software CCMP
//! decryption or current-station delivery. Vendor status must come from
//! completed RX under its peer/key owner, exactly as for data.

use super::{Error, KeyIdentity, KeyScope, KeySlot, PacketNumber, management};
use crate::net::{
    Mac,
    wifi::{
        Aggregation,
        frame::{self, Mpdu},
    },
};

const MANAGEMENT_REPLAY_QUEUE: usize = 16;
const MANAGEMENT_HEADER: usize = 24;

/// One original integrity-checked frame and consumed PTK management PN. No
/// public constructor or Clone. A delayed station consumer must consume this
/// and separately recheck its association and still-installed PTK.
#[derive(Debug)]
pub struct Authenticated<'a> {
    mpdu: &'a Mpdu,
    key: KeyIdentity,
    pn: PacketNumber,
    start: usize,
    end: usize,
}
impl<'a> Authenticated<'a> {
    pub const fn frame(&self) -> &'a Mpdu {
        self.mpdu
    }
    pub const fn key(&self) -> KeyIdentity {
        self.key
    }
    pub const fn packet_number(&self) -> PacketNumber {
        self.pn
    }
    pub fn body(&self) -> &'a [u8] {
        &self.mpdu.bytes()[self.start..self.end]
    }
}

impl KeySlot {
    /// Authenticate one ordinary unicast robust-management frame for `local`.
    /// Peer transmitter and BSSID must match this exact acknowledged PTK. Data
    /// counters 0..15 are independent; copied hardware replay flags never skip
    /// counter16. This grants no permission to change a station's association.
    pub fn authorize_unicast_management<'a>(
        &mut self,
        mpdu: &'a Mpdu,
        local: Mac,
    ) -> Result<Authenticated<'a>, Error> {
        let key = self.installed().ok_or(Error::NoInstalledKey)?;
        if !matches!(key.scope(), KeyScope::Pairwise(_)) {
            return Err(Error::Unsupported("unicast management requires a PTK"));
        }
        let h = mpdu.header();
        if !h.protected() {
            return Err(Error::NotProtected);
        }
        if h.length != MANAGEMENT_HEADER
            || !management::robust(mpdu)
            || h.fragmented()
            || h.control & (frame::TO_DS | frame::FROM_DS) != 0
            || mpdu.aggregation != Aggregation::default()
        {
            return Err(Error::Unsupported("management framing/fragment/aggregate"));
        }
        let peer = key.scope().peer();
        if local.is_multicast()
            || local.0 == [0; 6]
            || h.receiver != local
            || h.transmitter != Some(peer)
            || mpdu.bytes()[16..22] != peer.0
        {
            return Err(Error::InvalidPeer);
        }
        let (start, end, pn) = self.checked_payload(mpdu, key, None)?;
        let minimum = if h.control & frame::TYPE_SUBTYPE == frame::ACTION {
            1
        } else {
            2
        };
        if end - start < minimum {
            return Err(Error::Truncated);
        }
        self.commit_receive(MANAGEMENT_REPLAY_QUEUE, pn)?;
        Ok(Authenticated {
            mpdu,
            key,
            pn,
            start,
            end,
        })
    }
}

#[cfg(test)]
mod tests;
