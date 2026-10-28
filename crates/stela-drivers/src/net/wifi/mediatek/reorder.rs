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
mod tests {
    // SPDX-License-Identifier: BSD-3-Clause-Clear
    use super::*;
    use alloc::{rc::Rc, vec, vec::Vec};
    use core::cell::Cell;

    #[test]
    fn missing_head_holds_successors_and_releases_in_sequence_once() {
        let mut q = Reorder::new(0, 10, 64, 1000).unwrap();
        let mut out = Vec::new();
        assert_eq!(
            q.push(12, 0, 12, |v| out.push(v)).unwrap(),
            Disposition::Buffered
        );
        q.push(11, 1, 11, |v| out.push(v)).unwrap();
        assert!(out.is_empty());
        assert!(q.needs_timer());
        q.push(10, 2, 10, |v| out.push(v)).unwrap();
        assert_eq!(out, [10, 11, 12]);
        assert_eq!(q.head(), 13);
        assert_eq!(
            q.push(12, 3, 999, |v| out.push(v)).unwrap(),
            Disposition::Duplicate
        );
        assert_eq!(out, [10, 11, 12]);
        assert!(!q.needs_timer());
    }

    #[test]
    fn old_sequence_before_start_is_passed_without_starting_the_queue() {
        let mut q = Reorder::new(0, 10, 64, 1000).unwrap();
        let mut out = Vec::new();
        q.push(9, 0, 9, |v| out.push(v)).unwrap();
        q.push(8, 0, 8, |v| out.push(v)).unwrap();
        assert_eq!(out, [9, 8]);
        assert!(!q.started());
        assert_eq!(q.head(), 10);
        q.push(11, 0, 11, |v| out.push(v)).unwrap();
        assert!(q.started());
        assert_eq!(
            q.push(9, 0, 9, |v| out.push(v)).unwrap(),
            Disposition::Duplicate
        );
        assert_eq!(out, [9, 8]);
    }

    #[test]
    fn window_advance_releases_old_entries_and_occupied_slots_discard_duplicates() {
        let mut q = Reorder::new(0, 10, 4, 1000).unwrap();
        let mut out = Vec::new();
        q.push(11, 0, 11, |v| out.push(v)).unwrap();
        assert_eq!(
            q.push(11, 1, 999, |v| out.push(v)).unwrap(),
            Disposition::Duplicate
        );
        q.push(15, 2, 15, |v| out.push(v)).unwrap();
        assert_eq!(out, [11]);
        assert_eq!(q.head(), 12);
        q.push(12, 3, 12, |v| out.push(v)).unwrap();
        q.push(14, 4, 14, |v| out.push(v)).unwrap();
        q.push(13, 5, 13, |v| out.push(v)).unwrap();
        assert_eq!(out, [11, 12, 13, 14, 15]);
    }

    #[test]
    fn sequence_wrap_preserves_order_and_old_duplicate_decisions() {
        let mut q = Reorder::new(0, 4094, 64, 1000).unwrap();
        let mut out = Vec::new();
        q.push(1, 0, 1, |v| out.push(v)).unwrap();
        q.push(4095, 0, 4095, |v| out.push(v)).unwrap();
        q.push(0, 0, 0, |v| out.push(v)).unwrap();
        q.push(4094, 0, 4094, |v| out.push(v)).unwrap();
        assert_eq!(out, [4094, 4095, 0, 1]);
        assert_eq!(q.head(), 2);
        assert_eq!(
            q.push(4095, 0, 99, |v| out.push(v)).unwrap(),
            Disposition::Duplicate
        );
    }

    #[test]
    fn bar_skips_holes_releases_successors_and_does_not_mark_initial_queue_started() {
        let mut q = Reorder::new(3, 0, 64, 1000).unwrap();
        let mut out = Vec::new();
        q.bar(9, |v| out.push(v)).unwrap();
        assert!(!q.started());
        q.push(12, 0, 12, |v| out.push(v)).unwrap();
        q.push(11, 0, 11, |v| out.push(v)).unwrap();
        q.bar(11, |v| out.push(v)).unwrap();
        assert_eq!(out, [11, 12]);
        assert_eq!(q.head(), 13);
        q.bar(10, |v| out.push(v)).unwrap();
        assert_eq!(q.head(), 13);
    }

    #[test]
    fn timeout_is_strict_and_wraps_for_both_source_access_category_intervals() {
        for (tid, timeout) in [(0, 100), (3, 100), (4, 40), (7, 40)] {
            let mut q = Reorder::new(tid, 10, 64, 1000).unwrap();
            let mut out = Vec::new();
            assert_eq!(q.timeout_ticks(), timeout);
            let received = u32::MAX - 20;
            q.push(12, received, 12, |v| out.push(v)).unwrap();
            q.poll(received.wrapping_add(timeout), |v| out.push(v))
                .unwrap();
            assert!(out.is_empty());
            q.poll(received.wrapping_add(timeout + 1), |v| out.push(v))
                .unwrap();
            assert_eq!(out, [12]);
            assert_eq!(q.head(), 13);
            assert!(!q.needs_timer());
        }
    }

    #[test]
    fn later_expired_packet_can_release_an_earlier_unexpired_packet() {
        let mut q = Reorder::new(0, 10, 64, 1000).unwrap();
        let mut out = Vec::new();
        q.push(13, 0, 13, |v| out.push(v)).unwrap();
        q.push(12, 90, 12, |v| out.push(v)).unwrap();
        q.poll(101, |v| out.push(v)).unwrap();
        assert_eq!(out, [12, 13]);
        assert_eq!(q.head(), 14);
    }

    #[test]
    fn invalid_inputs_return_owned_frame_without_mutation_and_stop_is_terminal() {
        let mut q = Reorder::new(0, 0, 64, 1000).unwrap();
        let error = q
            .push(4096, 0, 19, |_| panic!("invalid release"))
            .unwrap_err();
        assert_eq!(error.error, Error::InvalidSequence);
        assert_eq!(error.frame, 19);
        assert_eq!(q.head(), 0);
        assert!(!q.started());
        assert_eq!(q.bar(4096, |_| {}), Err(Error::InvalidSequence));
        q.push(3, 0, 3, |_| {}).unwrap();
        assert_eq!(q.stop(), 1);
        assert_eq!(q.stop(), 0);
        assert!(q.stopped());
        assert!(!q.needs_timer());
        let error = q.push(0, 0, 20, |_| panic!("stopped release")).unwrap_err();
        assert_eq!(error.error, Error::Stopped);
        assert_eq!(error.frame, 20);
        assert_eq!(q.bar(1, |_| {}), Err(Error::Stopped));
        assert_eq!(q.poll(200, |_| {}), Err(Error::Stopped));
    }

    #[test]
    fn constructor_rejects_wire_defaults_and_out_of_range_parameters() {
        for (tid, ssn, window, hz, error) in [
            (16, 0, 64, 1000, Error::InvalidTid),
            (0, 4096, 64, 1000, Error::InvalidSequence),
            (0, 0, 0, 1000, Error::InvalidWindow),
            (0, 0, 1025, 1000, Error::InvalidWindow),
            (4, 0, 64, 24, Error::InvalidClock),
        ] {
            assert!(matches!(Reorder::<u32>::new(tid, ssn, window, hz), Err(e) if e == error));
        }
    }

    #[test]
    fn one_slot_window_reports_immediate_release_after_advancing_past_a_hole() {
        let mut q = Reorder::new(0, 10, 1, 1000).unwrap();
        let mut out = Vec::new();
        assert_eq!(
            q.push(15, 0, 15, |v| out.push(v)).unwrap(),
            Disposition::Released
        );
        assert_eq!(out, [15]);
        assert_eq!(q.head(), 16);
        assert!(!q.needs_timer());
    }

    #[test]
    fn terminal_shutdown_drops_each_buffered_host_packet_once() {
        #[derive(Debug)]
        struct Packet(Rc<Cell<usize>>);
        impl Drop for Packet {
            fn drop(&mut self) {
                self.0.set(self.0.get() + 1);
            }
        }
        let dropped = Rc::new(Cell::new(0));
        let mut q = Reorder::new(0, 10, 64, 1000).unwrap();
        for seq in [11, 13] {
            q.push(seq, 0, Packet(dropped.clone()), |_| {
                panic!("unexpected release")
            })
            .unwrap();
        }
        assert_eq!(dropped.get(), 0);
        q.stop();
        assert_eq!(dropped.get(), 2);
        drop(q);
        assert_eq!(dropped.get(), 2);
    }

    #[test]
    #[ignore = "oracle: STELA_MT76_REORDER_ORACLE"]
    fn complete_unchanged_source_matches_each_release_and_retained_queue() {
        use sha2::{Digest, Sha256};
        let path = std::env::var_os("STELA_MT76_REORDER_ORACLE").expect("unchanged C output");
        let bytes = std::fs::read(path).unwrap();
        assert_eq!(
            format!("{:x}", Sha256::digest(&bytes)),
            "b1abc4c89e6bdd75f6277961adf5e6fcb5e4618d10c9376f6d138c26e4b392e6"
        );
        struct Read<'a>(&'a [u8]);
        impl Read<'_> {
            fn byte(&mut self) -> u8 {
                let value = self.0[0];
                self.0 = &self.0[1..];
                value
            }
            fn word(&mut self) -> u16 {
                u16::from(self.byte()) | u16::from(self.byte()) << 8
            }
            fn dword(&mut self) -> u32 {
                u32::from(self.word()) | u32::from(self.word()) << 16
            }
        }
        let mut r = Read(&bytes);
        let cases = r.dword();
        assert_eq!(cases, 1920);
        let mut operations = 0;
        for case in 0..cases {
            let tid = r.byte();
            let ssn = r.word();
            let window = r.word();
            let hz = r.dword();
            let count = r.word();
            let mut q = Reorder::new(tid, ssn, window, hz).unwrap();
            for op in 0..count {
                let kind = r.byte();
                let sequence = r.word();
                let now = r.dword();
                let id = r.dword();
                let mut released = Vec::new();
                match kind {
                    0 => {
                        q.push(sequence, now, id, |v| released.push(v)).unwrap();
                    }
                    1 => q.poll(now, |v| released.push(v)).unwrap(),
                    2 => q.bar(sequence, |v| released.push(v)).unwrap(),
                    3 => {
                        q.stop();
                    }
                    _ => panic!("unknown source operation"),
                }
                let head = r.word();
                let buffered = r.word();
                let started = r.byte() != 0;
                let stopped = r.byte() != 0;
                let n = r.word();
                let expected: Vec<_> = (0..n).map(|_| r.dword()).collect();
                assert_eq!(released, expected, "case {case},operation {op}");
                assert_eq!(
                    (q.head(), q.buffered(), q.started(), q.stopped()),
                    (head, usize::from(buffered), started, stopped),
                    "case {case},operation {op}"
                );
                let mut expected = vec![];
                for _ in 0..buffered {
                    expected.push((r.word(), r.dword(), r.word(), r.dword()));
                }
                let actual: Vec<_> = q
                    .slots
                    .iter()
                    .enumerate()
                    .filter_map(|(i, slot)| {
                        slot.as_ref()
                            .map(|p| (i as u16, p.frame, p.sequence, p.received))
                    })
                    .collect();
                assert_eq!(actual, expected, "case {case},operation {op}");
                operations += 1;
            }
        }
        assert_eq!(operations, 124800);
        assert!(r.0.is_empty());
    }
    extern crate std;
}
