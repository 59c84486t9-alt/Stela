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
#[ignore = "requires STELA_MT76_REORDER_ORACLE from complete unchanged pinned C implementation"]
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
