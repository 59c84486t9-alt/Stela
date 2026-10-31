// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2015-2017 Intel Deutschland GmbH
//! What happens to data between the firmware and the station, as rxmq.c: the
//! records of an A-MSDU gather into their MPDU, a retransmission of a TID's
//! last frame goes, and a Block Ack session's frames wait for their turn.
//!
//! mvm admits each later A-MSDU record to mac80211 with `RX_FLAG_ALLOW_SAME_PN`.
//! Gathering them first lets the shared aggregate gate make that one replay
//! decision for the MPDU, so no raw same-PN frame is ever admitted.
use crate::wifi::{
    frame::Mpdu,
    intel::{
        receive::mpdu::Metadata,
        receive::reorder::{Arrival, Buffer},
    },
    security::aggregate::Shape,
    station::ba::RxSession,
};
use alloc::{sync::Arc, vec, vec::Vec};

/// `IWL_MAX_BAID`.
pub(super) const MAX_SESSIONS: u32 = 32;
const RETRY: u16 = 0x0800;
/// `IWL_MAX_TID_COUNT`, which also names the slot of non-QoS frames.
const QOS_TIDS: u8 = 8;
const TU_US: u64 = 1024;

/// One whole MPDU: a frame, or every record of an A-MSDU.
#[derive(Debug)]
pub(super) struct Parent {
    pub(super) members: Vec<Mpdu>,
    pub(super) shape: Shape,
}

/// `iwl_mvm_baid_data`.
struct Session {
    id: u8,
    agreement: Arc<RxSession>,
    buffer: Buffer<Parent>,
    last: u64,
}

pub(super) struct Reception {
    partial: Vec<Mpdu>,
    /// `iwl_mvm_rxq_dup_data`, by TID.
    seen: [Option<u16>; QOS_TIDS as usize + 1],
    sessions: Vec<Session>,
}

/// Whether an agreement of `timeout` TU has heard nothing for too long.
fn quiet(timeout: u16, last: u64, now: u64) -> bool {
    timeout != 0 && now.saturating_sub(last) >= u64::from(timeout) * 2 * TU_US
}

impl Reception {
    pub(super) fn new() -> Self {
        Self {
            partial: Vec::new(),
            seen: [None; QOS_TIDS as usize + 1],
            sessions: Vec::new(),
        }
    }

    pub(super) fn clear(&mut self) {
        *self = Self::new();
    }

    /// The MPDU `frame` finishes, if it does. A record out of its place loses
    /// the MPDU, which the shared gate could not accept incomplete anyway.
    pub(super) fn gather(&mut self, frame: Mpdu) -> Option<Parent> {
        let Some(record) = frame.aggregation.amsdu else {
            self.partial.clear();
            return Some(Parent {
                members: vec![frame],
                shape: Shape::WholeMpdu,
            });
        };
        if record.first {
            self.partial.clear();
        }
        if usize::from(record.index) != self.partial.len() {
            self.partial.clear();
            return None;
        }
        self.partial.push(frame);
        record.last.then(|| Parent {
            members: core::mem::take(&mut self.partial),
            shape: Shape::DeaggregatedAmsdu,
        })
    }

    /// `iwl_mvm_is_dup`, for a whole MPDU.
    pub(super) fn repeats(&mut self, parent: &Parent) -> bool {
        let header = parent.members[0].header();
        if header.receiver.is_multicast() {
            return false;
        }
        let slot = match header.tid {
            Some(tid) if tid >= QOS_TIDS => return true,
            Some(tid) => usize::from(tid),
            None => usize::from(QOS_TIDS),
        };
        let repeated = header.control & RETRY != 0 && self.seen[slot] == header.sequence;
        self.seen[slot] = header.sequence;
        repeated
    }

    /// `iwl_mvm_reorder`: add to `ready` what may go on, `parent` or not.
    pub(super) fn order(
        &mut self,
        parent: Parent,
        metadata: &Metadata,
        now: u64,
        ready: &mut Vec<Parent>,
    ) {
        let header = parent.members[0].header();
        let session = metadata
            .reorder
            .ba_id
            .and_then(|id| self.sessions.iter_mut().find(|session| session.id == id))
            .filter(|session| {
                header.tid == Some(session.agreement.tid()) && !header.receiver.is_multicast()
            });
        let Some(session) = session else {
            ready.push(parent);
            return;
        };
        session.last = now;
        let arrival = Arrival {
            sequence: metadata.reorder.sequence,
            next: metadata.reorder.next_sequence,
            old: metadata.reorder.old_sequence,
            duplicate: metadata.status.duplicate_bit(),
        };
        session.buffer.arrive(arrival, parent, ready);
    }

    /// The firmware took `agreement` as session `id`.
    pub(super) fn open(&mut self, id: u8, agreement: Arc<RxSession>, now: u64) -> bool {
        if self.sessions.iter().any(|session| session.id == id) {
            return false;
        }
        let Some(buffer) = Buffer::new(agreement.start_sequence(), agreement.window()) else {
            return false;
        };
        self.sessions.push(Session {
            id,
            agreement,
            buffer,
            last: now,
        });
        true
    }

    pub(super) fn session(&self, tid: u8) -> Option<u8> {
        self.sessions
            .iter()
            .find(|session| session.agreement.tid() == tid)
            .map(|session| session.id)
    }

    /// Session `tid` ended: what it held goes on.
    pub(super) fn close(&mut self, tid: u8, ready: &mut Vec<Parent>) {
        if let Some(at) = self
            .sessions
            .iter()
            .position(|session| session.agreement.tid() == tid)
        {
            self.sessions.swap_remove(at).buffer.flush(ready);
        }
    }

    /// The firmware moved session `id`'s window, for a timed-out hole or for a
    /// Block Ack Request on `tid`.
    pub(super) fn release(
        &mut self,
        id: u8,
        tid: Option<u8>,
        through: u16,
        ready: &mut Vec<Parent>,
    ) {
        if let Some(session) = self.sessions.iter_mut().find(|session| {
            session.id == id && tid.is_none_or(|tid| tid == session.agreement.tid())
        }) {
            session.buffer.release(through, ready);
        }
    }

    /// The TIDs whose peer went quiet: `iwl_rx_agg_session_expired` allows
    /// twice the agreed timeout.
    pub(super) fn expired(&self, now: u64) -> Vec<u8> {
        self.sessions
            .iter()
            .filter(|session| quiet(session.agreement.timeout_tu(), session.last, now))
            .map(|session| session.agreement.tid())
            .collect()
    }

    /// Every session, each as its firmware identity and TID, gone.
    pub(super) fn take_sessions(&mut self) -> Vec<(u8, u8)> {
        self.sessions
            .drain(..)
            .map(|session| (session.id, session.agreement.tid()))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::quiet;

    #[test]
    fn a_session_expires_after_twice_its_timeout_and_never_without_one() {
        assert!(!quiet(10, 1000, 1000 + 20 * 1024 - 1));
        assert!(quiet(10, 1000, 1000 + 20 * 1024));
        assert!(!quiet(0, 0, u64::MAX));
    }
}
