// SPDX-License-Identifier: BSD-3-Clause-Clear
// Copyright (C) 2018 Felix Fietkau <nbd@nbd.name>
//! Serialized receive BA reorder queue, adapted from pinned mt76/agg-rx.c.
//!
//! A queue belongs to one actual peer/association/TID BA session. The caller
//! selects it only after checking that identity, the real RX aggregate status
//! and ACK policy. Non-aggregate/no-ACK traffic bypasses the source queue. A BAR
//! must likewise name this actual peer and TID. This module does not authorize
//! a session, install firmware BA state, authenticate a frame or advance PN.
//!
//! Payloads are completed host-owned RX packets, not outstanding DMA owners.
//! Releases must pass through canonical integrity/replay/data validation in the
//! emitted order. Poll with the same wrapping 32-bit clock used by push, at the
//! requested timeout while buffered packets remain. Arm the first pending poll;
//! later pushes must not postpone it. After polling, rearm while needs_timer is
//! true. The clock must not skip a
//! signed half-range. The caller serializes RX, BAR, timer and teardown; there
//! is no scheduler, lock or concurrent callback hidden in this queue.

use crate::net::wifi::frame::{MAX_AMPDU_BUF_EHT, SEQUENCE_MASK, next_sequence as next};
use alloc::vec::Vec;

const SEQUENCE_HALF: u16 = 0x0800;
/// EHT's maximum BA window; negotiation and actual firmware may limit it further.
pub const MAX_WINDOW: u16 = MAX_AMPDU_BUF_EHT;

fn before(a: u16, b: u16) -> bool {
    a.wrapping_sub(b) & SEQUENCE_MASK > SEQUENCE_HALF
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    InvalidTid,
    InvalidSequence,
    InvalidWindow,
    InvalidClock,
    NoMemory,
    Stopped,
}

/// Rejected input is returned intact; neither an invalid sequence nor a stopped
/// session can silently release it through this queue.
#[derive(Debug)]
pub struct Rejected<T> {
    pub error: Error,
    pub frame: T,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Disposition {
    Released,
    Buffered,
    Duplicate,
}

struct Buffered<T> {
    frame: T,
    sequence: u16,
    received: u32,
}

/// Owned CPU receive storage only. Stopping or dropping discards buffered
/// packets; it does not prove firmware, DMA, key or radio retirement.
pub struct Reorder<T> {
    tid: u8,
    head: u16,
    buffered: usize,
    started: bool,
    stopped: bool,
    timeout: u32,
    slots: Vec<Option<Buffered<T>>>,
}

impl<T> Reorder<T> {
    /// `window` is the already negotiated nonzero actual BA size, not its wire
    /// encoding (whose zero has a separate negotiated default). `start` is the
    /// actual SSN. Source timing is ticks_per_second / (TID >= 4 ? 25 : 10).
    /// TID8..15 are representable here; current station BA negotiation must
    /// separately reject unsupported TSPEC TIDs, as mac80211 does.
    pub fn new(tid: u8, start: u16, window: u16, ticks_per_second: u32) -> Result<Self, Error> {
        if tid >= 16 {
            return Err(Error::InvalidTid);
        }
        if start > SEQUENCE_MASK {
            return Err(Error::InvalidSequence);
        }
        if window == 0 || window > MAX_WINDOW {
            return Err(Error::InvalidWindow);
        }
        let timeout = ticks_per_second / if tid >= 4 { 25 } else { 10 };
        if timeout == 0 {
            return Err(Error::InvalidClock);
        }
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(usize::from(window))
            .map_err(|_| Error::NoMemory)?;
        slots.resize_with(usize::from(window), || None);
        Ok(Self {
            tid,
            head: start,
            buffered: 0,
            started: false,
            stopped: false,
            timeout,
            slots,
        })
    }

    pub const fn tid(&self) -> u8 {
        self.tid
    }
    pub const fn head(&self) -> u16 {
        self.head
    }
    pub const fn buffered(&self) -> usize {
        self.buffered
    }
    pub const fn started(&self) -> bool {
        self.started
    }
    pub const fn stopped(&self) -> bool {
        self.stopped
    }
    pub const fn timeout_ticks(&self) -> u32 {
        self.timeout
    }
    /// Poll again after timeout_ticks while true. A return from the release
    /// callback is not firmware ACK, data authentication or DMA retirement.
    pub const fn needs_timer(&self) -> bool {
        self.buffered != 0 && !self.stopped
    }

    fn release_one(&mut self, index: usize, release: &mut impl FnMut(T)) {
        self.head = next(self.head);
        if let Some(packet) = self.slots[index].take() {
            self.buffered -= 1;
            release(packet.frame);
        }
    }

    fn release_before(&mut self, head: u16, release: &mut impl FnMut(T)) {
        while before(self.head, head) {
            self.release_one(usize::from(self.head) % self.slots.len(), release);
        }
    }

    fn release_head(&mut self, release: &mut impl FnMut(T)) {
        let mut index = usize::from(self.head) % self.slots.len();
        while self.slots[index].is_some() {
            self.release_one(index, release);
            index = usize::from(self.head) % self.slots.len();
        }
    }

    /// Consume one eligible MPDU. Source behavior deliberately passes an old
    /// sequence before the first in-window packet starts the queue. Once
    /// started, old sequences and occupied slots are duplicates and discarded.
    /// This sequencing decision alone is never proof of frame authenticity.
    pub fn push(
        &mut self,
        sequence: u16,
        now: u32,
        frame: T,
        mut release: impl FnMut(T),
    ) -> Result<Disposition, Rejected<T>> {
        let error = if self.stopped {
            Some(Error::Stopped)
        } else if sequence > SEQUENCE_MASK {
            Some(Error::InvalidSequence)
        } else {
            None
        };
        if let Some(error) = error {
            return Err(Rejected { error, frame });
        }
        let old = before(sequence, self.head);
        if !self.started {
            if old {
                release(frame);
                return Ok(Disposition::Released);
            }
            self.started = true;
        }
        if old {
            return Ok(Disposition::Duplicate);
        }
        if sequence == self.head {
            self.head = next(self.head);
            release(frame);
            if self.buffered != 0 {
                self.release_head(&mut release);
            }
            return Ok(Disposition::Released);
        }
        let size = self.slots.len() as u16;
        // Keep source's unmasked head+size input to ieee80211_sn_less. The
        // comparison itself masks the subtraction to twelve bits.
        if !before(sequence, self.head + size) {
            self.release_before(
                next(sequence.wrapping_sub(size) & SEQUENCE_MASK),
                &mut release,
            );
        }
        let index = usize::from(sequence) % self.slots.len();
        if self.slots[index].is_some() {
            return Ok(Disposition::Duplicate);
        }
        self.slots[index] = Some(Buffered {
            frame,
            sequence,
            received: now,
        });
        self.buffered += 1;
        self.release_head(&mut release);
        Ok(if self.slots[index].is_some() {
            Disposition::Buffered
        } else {
            Disposition::Released
        })
    }

    /// Apply the SSN of an already validated single-TID BAR to this session.
    /// The caller retains/handles the BAR itself; only buffered data is emitted.
    pub fn bar(&mut self, sequence: u16, mut release: impl FnMut(T)) -> Result<(), Error> {
        if self.stopped {
            return Err(Error::Stopped);
        }
        if sequence > SEQUENCE_MASK {
            return Err(Error::InvalidSequence);
        }
        self.release_before(sequence, &mut release);
        self.release_head(&mut release);
        Ok(())
    }

    /// Source time_after32 is strictly after the deadline, including rollover;
    /// a packet exactly timeout_ticks old does not yet expire.
    pub fn poll(&mut self, now: u32, mut release: impl FnMut(T)) -> Result<(), Error> {
        if self.stopped {
            return Err(Error::Stopped);
        }
        if self.buffered == 0 {
            return Ok(());
        }
        self.release_head(&mut release);
        let start = usize::from(self.head) % self.slots.len();
        let mut remaining = self.buffered;
        let mut index = (usize::from(self.head) + 1) % self.slots.len();
        while index != start && remaining != 0 {
            if let Some(packet) = &self.slots[index] {
                remaining -= 1;
                let expired =
                    (packet.received.wrapping_add(self.timeout).wrapping_sub(now) as i32) < 0;
                if expired {
                    self.release_before(packet.sequence, &mut release);
                }
            }
            index = (index + 1) % self.slots.len();
        }
        self.release_head(&mut release);
        Ok(())
    }

    /// Terminal host-queue shutdown. Discard buffered CPU packets and disable
    /// further timer/BAR/RX use. The native session must separately stop actual
    /// firmware BA work and retain uncertain peer/key/DMA owners on failure.
    pub fn stop(&mut self) -> usize {
        self.stopped = true;
        let discarded = self.buffered;
        for slot in &mut self.slots {
            *slot = None;
        }
        self.buffered = 0;
        discarded
    }
}

#[cfg(test)]
mod tests;
