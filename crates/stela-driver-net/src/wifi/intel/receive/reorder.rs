// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
// Copyright (C) 2012-2014, 2018-2026 Intel Corporation
// Copyright (C) 2013-2015 Intel Mobile Communications GmbH
// Copyright (C) 2015-2017 Intel Deutschland GmbH
//! One Block Ack session's reorder buffer, as `iwl_mvm_reorder`. The firmware
//! keeps the window: each frame carries how far it has moved (the NSSN), and
//! a frame release notification moves it when frames stop coming. The host only
//! holds frames until the window passes them, so there is no reorder timer.
//!
//! One receive queue serves the function, so frames need no queue sync. An
//! entry is a whole MPDU: the records of an A-MSDU are gathered before this.
use alloc::vec::Vec;

const SEQUENCE_MASK: u16 = 0xfff;

/// `ieee80211_sn_less`.
fn before(first: u16, second: u16) -> bool {
    first.wrapping_sub(second) & SEQUENCE_MASK > 2048
}

/// `ieee80211_sn_inc`.
fn next(sequence: u16) -> u16 {
    sequence.wrapping_add(1) & SEQUENCE_MASK
}

/// What the firmware reports with a frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Arrival {
    pub sequence: u16,
    /// The NSSN: everything before it may go.
    pub next: u16,
    /// The frame is behind the window.
    pub old: bool,
    pub duplicate: bool,
}

/// `iwl_mvm_reorder_buffer` and its entries.
#[derive(Debug)]
pub struct Buffer<T> {
    head: u16,
    /// Until a frame fits the window, old ones pass: the firmware's window
    /// may have opened before the sequence number the agreement named.
    valid: bool,
    stored: usize,
    entries: Vec<Option<T>>,
}

impl<T> Buffer<T> {
    /// A buffer from `head` of `window` entries, or `None` without the memory.
    pub fn new(head: u16, window: u16) -> Option<Self> {
        let window = usize::from(window);
        let mut entries = Vec::new();
        entries.try_reserve_exact(window).ok()?;
        entries.resize_with(window, || None);
        Some(Self {
            head: head & SEQUENCE_MASK,
            valid: false,
            stored: 0,
            entries,
        })
    }

    fn slot(&self, sequence: u16) -> usize {
        usize::from(sequence) % self.entries.len()
    }

    /// Take `item`, adding to `ready` all that may go, in order.
    pub fn arrive(&mut self, arrival: Arrival, item: T, ready: &mut Vec<T>) {
        if !self.valid {
            if arrival.old {
                ready.push(item);
                return;
            }
            self.valid = true;
        }
        if arrival.duplicate || arrival.old {
            return;
        }
        if self.stored == 0 && before(arrival.sequence, arrival.next) {
            self.head = arrival.next;
            ready.push(item);
            return;
        }
        if self.stored == 0 && arrival.sequence == self.head {
            self.head = next(self.head);
            ready.push(item);
            return;
        }
        let slot = self.slot(arrival.sequence);
        if self.entries[slot].is_none() {
            self.entries[slot] = Some(item);
            self.stored += 1;
        }
        self.release(arrival.next, ready);
    }

    /// `iwl_mvm_release_frames`. Unlike there a notification can follow frames
    /// that came after it, so a window behind the head moves nothing.
    pub fn release(&mut self, through: u16, ready: &mut Vec<T>) {
        if !before(self.head, through) {
            return;
        }
        let mut sequence = self.head;
        while before(sequence, through) {
            let slot = self.slot(sequence);
            if let Some(item) = self.entries[slot].take() {
                ready.push(item);
                self.stored -= 1;
            }
            sequence = next(sequence);
        }
        self.head = through;
    }

    /// Everything held, in order, as `iwl_mvm_del_ba` releases it.
    pub fn flush(&mut self, ready: &mut Vec<T>) {
        let end = (self.head + self.entries.len() as u16) & SEQUENCE_MASK;
        self.release(end, ready);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn arrival(sequence: u16, next: u16) -> Arrival {
        Arrival {
            sequence,
            next,
            old: false,
            duplicate: false,
        }
    }

    #[test]
    fn frames_in_order_pass_through() {
        let mut buffer = Buffer::new(10, 8).unwrap();
        let mut ready = Vec::new();
        buffer.arrive(arrival(10, 11), 'a', &mut ready);
        buffer.arrive(arrival(11, 12), 'b', &mut ready);
        assert_eq!(ready, ['a', 'b']);
    }

    #[test]
    fn a_hole_holds_what_follows_until_it_fills() {
        let mut buffer = Buffer::new(10, 8).unwrap();
        let mut ready = Vec::new();
        buffer.arrive(arrival(11, 10), 'b', &mut ready);
        buffer.arrive(arrival(12, 10), 'c', &mut ready);
        assert!(ready.is_empty());
        buffer.arrive(arrival(10, 13), 'a', &mut ready);
        assert_eq!(ready, ['a', 'b', 'c']);
        buffer.arrive(arrival(13, 14), 'd', &mut ready);
        assert_eq!(ready, ['a', 'b', 'c', 'd']);
    }

    #[test]
    fn the_firmware_gives_up_on_a_hole() {
        let mut buffer = Buffer::new(10, 8).unwrap();
        let mut ready = Vec::new();
        buffer.arrive(arrival(12, 10), 'c', &mut ready);
        buffer.release(13, &mut ready);
        assert_eq!(ready, ['c']);
        // A late notification cannot take the window back.
        buffer.release(11, &mut ready);
        buffer.arrive(arrival(13, 14), 'd', &mut ready);
        assert_eq!(ready, ['c', 'd']);
    }

    #[test]
    fn old_frames_pass_only_until_the_window_is_found() {
        let mut buffer = Buffer::new(10, 8).unwrap();
        let mut ready = Vec::new();
        let old = Arrival {
            old: true,
            ..arrival(9, 10)
        };
        buffer.arrive(old, 'a', &mut ready);
        buffer.arrive(arrival(10, 11), 'b', &mut ready);
        buffer.arrive(old, 'c', &mut ready);
        let duplicate = Arrival {
            duplicate: true,
            ..arrival(11, 12)
        };
        buffer.arrive(duplicate, 'd', &mut ready);
        assert_eq!(ready, ['a', 'b']);
    }

    #[test]
    fn a_session_ending_releases_what_it_held_in_order() {
        let mut buffer = Buffer::new(4094, 8).unwrap();
        let mut ready = Vec::new();
        buffer.arrive(arrival(1, 4094), 'c', &mut ready);
        buffer.arrive(arrival(4095, 4094), 'b', &mut ready);
        buffer.arrive(arrival(3, 4094), 'd', &mut ready);
        assert!(ready.is_empty());
        buffer.flush(&mut ready);
        assert_eq!(ready, ['b', 'c', 'd']);
    }

    #[test]
    fn a_second_frame_for_an_occupied_slot_is_dropped() {
        let mut buffer = Buffer::new(10, 8).unwrap();
        let mut ready = vec![];
        buffer.arrive(arrival(12, 10), 'a', &mut ready);
        buffer.arrive(arrival(12, 10), 'b', &mut ready);
        buffer.flush(&mut ready);
        assert_eq!(ready, ['a']);
    }
}
