// SPDX-License-Identifier: GPL-2.0-only AND BSD-3-Clause-Clear
// Parent-group PN/injection behavior adapts mt76/mac80211.c,
// Copyright (C) 2016 Felix Fietkau <nbd@nbd.name> (BSD-3-Clause-Clear).
// Common protected-data replay uses the GPL2 Linux-derived implementation in
// security.rs; its original copyright notices remain there and in THIRD_PARTY.
//! One post-order replay decision for a complete MPDU.
//! Source ownership, grouping and BA/reorder execution remain with the backend.

use super::{Error as SecurityError, KeyIdentity, KeySlot, PacketNumber};
use crate::net::wifi::{
    frame::Mpdu,
    station::{self, AssociationContext},
};
use alloc::{sync::Arc, vec::Vec};

/// An original whole A-MSDU can arrive in one record, including a real single
/// subframe. A hardware split parent has multiple raw 802.11 records. Neither
/// shape is already Ethernet, or permission inferred from a first/last flag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    WholeMpdu,
    HardwareSplitAmsdu,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Security(SecurityError),
    Station(station::Error),
    Invalid(&'static str),
}
impl From<SecurityError> for Error {
    fn from(error: SecurityError) -> Self {
        Self::Security(error)
    }
}
impl From<station::Error> for Error {
    fn from(error: station::Error) -> Self {
        Self::Station(error)
    }
}

/// Complete, post-reorder source ownership. `C` keeps the
/// queue/peer/device resources, not a number or newly looked-up current epoch.
/// Authentication borrows this owner; failure cannot silently drop resources.
#[derive(Debug)]
pub struct OrderedGroup<C> {
    context: Arc<AssociationContext>,
    members: Vec<Mpdu>,
    shape: Shape,
    source_owner: C,
}
impl<C> OrderedGroup<C> {
    /// # Safety
    /// All members must come from one complete hardware parent in
    /// original source queue order, bound to this exact association,
    /// peer/WCID, physical key generation, device/firmware/reset and RX queue.
    /// Keep those resources in `source_owner` through all users.
    /// The backend must check real split completion or a whole
    /// one-record parent. Do not promote a partial flush, gap/loss, raw AMPDU
    /// or first/last flag, or caller-copied epoch into complete ownership.
    /// Current BA namespace/reorder release, if applicable, must precede
    /// this call; a raw BAID or transport ACK cannot establish that proof.
    /// For protected traffic, per-member integrity/key observations must derive
    /// from the native installation and negotiated receive layout.
    /// Missing optional member PN observations stay absent, never copied.
    /// Reset/removal must invalidate the current association before further
    /// authorization, while keeping old queue/key resources through
    /// drain and deferred users. Group creation does not authorize delivery or
    /// replace current station/key/controlled-port checks at that boundary.
    pub unsafe fn new(
        context: Arc<AssociationContext>,
        members: Vec<Mpdu>,
        shape: Shape,
        source_owner: C,
    ) -> Self {
        Self {
            context,
            members,
            shape,
            source_owner,
        }
    }
    pub fn context(&self) -> &AssociationContext {
        &self.context
    }
    pub fn members(&self) -> &[Mpdu] {
        &self.members
    }
    pub const fn shape(&self) -> Shape {
        self.shape
    }
    pub const fn source_owner(&self) -> &C {
        &self.source_owner
    }

    pub(crate) fn checked(&self) -> Result<Candidate<'_, C>, Error> {
        // Zero-payload A-MSDU subframes still require14-byte subheaders. This
        // bounds memory; it is not a claimed effective AMPDU byte exponent.
        if self.members.is_empty() || self.members.len() > super::super::frame::MAX_MPDU / 14 {
            return Err(Error::Invalid("aggregate member bound"));
        }
        if self.shape == Shape::WholeMpdu && self.members.len() != 1 {
            return Err(Error::Invalid("whole MPDU member count"));
        }
        if self.shape == Shape::HardwareSplitAmsdu && self.members.len() < 2 {
            return Err(Error::Invalid("split shape requires multiple records"));
        }
        let head = self.members[0].header();
        for (index, member) in self.members.iter().enumerate() {
            let h = member.header();
            if !h.data_present() || h.fragmented() {
                return Err(Error::Invalid("fragment/null/management aggregate"));
            }
            if h.control & 0x0300 != head.control & 0x0300
                || h.protected() != head.protected()
                || h.receiver != head.receiver
                || h.transmitter != head.transmitter
                || h.sequence != head.sequence
                || h.tid != head.tid
                || h.amsdu != head.amsdu
            {
                return Err(Error::Invalid("different MPDU parent"));
            }
            if self.shape == Shape::HardwareSplitAmsdu {
                let Some(a) = member.aggregation.amsdu else {
                    return Err(Error::Invalid("missing split observation"));
                };
                if !h.amsdu
                    || a.index != index as u16
                    || a.first != (index == 0)
                    || a.last != (index + 1 == self.members.len())
                {
                    return Err(Error::Invalid("incomplete split parent"));
                }
            } else if member.aggregation.amsdu.is_some() && !h.amsdu {
                return Err(Error::Invalid("split observation without actual QoS bit"));
            }
            if !super::valid_receive_observations(member) {
                return Err(SecurityError::Integrity.into());
            }
        }
        Ok(Candidate { group: self })
    }
}

/// Security of this original parent. Open reception creates no key or PN.
/// Protected PN is the parent's proof, not a claim that every raw member
/// descriptor independently reported that value; original facts stay intact.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupSecurity {
    Open,
    Protected { key: KeyIdentity, pn: PacketNumber },
}

/// Validated plaintext, still requiring current port/key/association
/// checks and the shared raw A-MSDU deaggregator before Ethernet delivery.
#[derive(Debug)]
pub struct ReceivedGroup<'a, C> {
    group: &'a OrderedGroup<C>,
    spans: Vec<(usize, usize)>,
    security: GroupSecurity,
}
#[derive(Debug)]
pub struct ReceivedMember<'a> {
    mpdu: &'a Mpdu,
    start: usize,
    end: usize,
    security: GroupSecurity,
}
impl<'a> ReceivedMember<'a> {
    pub const fn mpdu(&self) -> &'a Mpdu {
        self.mpdu
    }
    pub fn payload(&self) -> &'a [u8] {
        &self.mpdu.bytes()[self.start..self.end]
    }
    pub const fn security(&self) -> GroupSecurity {
        self.security
    }
}
impl<'a, C> ReceivedGroup<'a, C> {
    pub fn group(&self) -> &'a OrderedGroup<C> {
        self.group
    }
    pub const fn security(&self) -> GroupSecurity {
        self.security
    }
    pub fn members(&self) -> impl ExactSizeIterator<Item = ReceivedMember<'a>> + '_ {
        self.group
            .members
            .iter()
            .zip(&self.spans)
            .map(|(mpdu, &(start, end))| ReceivedMember {
                mpdu,
                start,
                end,
                security: self.security,
            })
    }
}

pub(crate) struct Candidate<'a, C> {
    group: &'a OrderedGroup<C>,
}
impl<'a, C> Candidate<'a, C> {
    fn spans(&self) -> Result<Vec<(usize, usize)>, Error> {
        let mut spans = Vec::new();
        spans
            .try_reserve_exact(self.group.members.len())
            .map_err(|_| SecurityError::NoMemory)?;
        Ok(spans)
    }
    fn payloads(&self, spans: &[(usize, usize)]) -> Result<(), Error> {
        let head = &self.group.members[0];
        if !head.header().amsdu {
            return Ok(());
        }
        if head.header().receiver.is_multicast() {
            return Err(Error::Invalid("multicast A-MSDU receiver"));
        }
        let length = spans
            .iter()
            .try_fold(0usize, |sum, &(start, end)| sum.checked_add(end - start))
            .ok_or(Error::Invalid("aggregate length overflow"))?;
        if length > usize::from(self.group.context.negotiated().max_rx_amsdu) {
            return Err(Error::Invalid("local A-MSDU receive bound"));
        }
        let (start, end) = spans[0];
        if head.bytes()[start..end].get(..6) == Some(&[0xaa, 0xaa, 3, 0, 0, 0]) {
            return Err(Error::Invalid("A-MSDU first-subframe injection"));
        }
        Ok(())
    }
    pub(crate) fn open(self) -> Result<ReceivedGroup<'a, C>, Error> {
        let mut spans = self.spans()?;
        for frame in &self.group.members {
            if frame.header().protected() || frame.security.key.is_some() {
                return Err(SecurityError::WrongKey.into());
            }
            spans.push((frame.header().length, frame.bytes().len()));
        }
        self.payloads(&spans)?;
        Ok(ReceivedGroup {
            group: self.group,
            spans,
            security: GroupSecurity::Open,
        })
    }
    pub(crate) fn protected(self, slot: &mut KeySlot) -> Result<ReceivedGroup<'a, C>, Error> {
        let head = &self.group.members[0];
        let first = slot.checked_mpdu(head, true, None)?;
        let mut spans = self.spans()?;
        spans.push((first.start, first.end));
        for member in self.group.members.iter().skip(1) {
            // Optional non-head group1 stays absent. The complete
            // source owner, not a same-PN flag, binds that member to its parent.
            let checked = slot.checked_mpdu(member, true, Some(first.pn))?;
            if checked.key != first.key || checked.pn != first.pn {
                return Err(SecurityError::InconsistentPacketNumber.into());
            }
            spans.push((checked.start, checked.end));
        }
        self.payloads(&spans)?;
        slot.commit_receive(super::data_replay_queue(head), first.pn)?;
        Ok(ReceivedGroup {
            group: self.group,
            spans,
            security: GroupSecurity::Protected {
                key: first.key,
                pn: first.pn,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Error, KeySlot, PacketNumber};
    use sha2::{Digest, Sha256};

    fn value(i: u64) -> u64 {
        match i {
            0 => 0,
            1 => 1,
            2 => (1 << 48) - 1,
            3 => (1 << 48) - 2,
            _ => (i * 0x0102_0304_0507) & ((1 << 48) - 1),
        }
    }

    #[test]
    fn parent_replay_counter_projection_matches_complete_mt76_qos_helper() {
        // Counter-primitive model only: no installed physical key, DMA or RX users.
        // Full unchanged C helper/flags are emitted by wifi_group_replay_oracle.py.
        // The complete unchanged helper ASan/UBSan trace covers 1,048,576 cases.
        // This does not establish grouping, BA, integrity or hardware permission.
        // SAFETY: this test owns the key slot number alone.
        let mut slot = unsafe { KeySlot::new(8).unwrap() };
        let mut digest = Sha256::new();
        for tid in 0..16 {
            for i in 0..256 {
                for j in 0..256 {
                    slot.rx_pn = [0; 17];
                    slot.rx_pn[tid] = value(i);
                    let result = slot.commit_receive(tid, PacketNumber::new(value(j)).unwrap());
                    assert!(result.is_ok() || result == Err(Error::Replay));
                    digest.update([u8::from(result.is_ok())]);
                    digest.update(&slot.rx_pn[tid].to_be_bytes()[2..]);
                    digest.update([u8::from(result.is_ok())]);
                }
            }
        }
        assert_eq!(
            digest.finalize().as_slice(),
            &[
                0x93, 0x9a, 0xfb, 0xc6, 0x62, 0x90, 0x0e, 0x35, 0x27, 0x7d, 0x94, 0x59, 0x73, 0x87,
                0xd2, 0xf5, 0x58, 0xd5, 0xcb, 0x6a, 0x58, 0xd0, 0xba, 0x41, 0x83, 0x3d, 0x05, 0x0a,
                0xcb, 0x6a, 0xa7, 0xc3,
            ]
        );
    }
}
