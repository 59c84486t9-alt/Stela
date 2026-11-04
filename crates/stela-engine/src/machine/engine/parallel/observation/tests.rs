use super::*;
use alloc::sync::Arc;

fn state(value: u64) -> MaterializedSource {
    MaterializedSource {
        host_counter: value,
        phase: SourcePhase::BroadcastEnter,
        pc: value * 4,
        sp: !value,
        fp: value << 4,
        lr: value ^ 0x1234_5678,
        el: (value % 3) as u8,
        daif: (value & 15) as u8,
    }
}

#[test]
fn observations_remain_stale_until_the_owner_publishes_again() {
    let slot = Slot::default();
    assert_eq!(slot.read(1), None);
    slot.publish(1, state(7));
    let observed = slot.read(1).unwrap();
    assert_eq!(observed.sequence, 2);
    assert_eq!(observed.source, state(7));
    assert_eq!(slot.read(2), None, "copy belongs to another owner");
    let newer_materialized_state = state(8);
    assert_eq!(slot.read(1), Some(observed));
    slot.publish(1, newer_materialized_state);
    assert_eq!(slot.read(1).unwrap().sequence, 4);
    assert_eq!(slot.read(1).unwrap().source, newer_materialized_state);
}

#[test]
fn unfinished_or_invalid_publications_are_unavailable() {
    let slot = Slot::default();
    slot.sequence.store(1, SeqCst);
    slot.publish(1, state(7));
    assert_eq!(
        slot.sequence.load(SeqCst),
        1,
        "busy publisher does not wait or overwrite"
    );
    assert_eq!(
        slot.read(1),
        None,
        "bounded reader does not wait for a writer"
    );
    slot.sequence.store(0, SeqCst);
    slot.publish(1, state(1));
    slot.mode.store(99 << 16, SeqCst);
    assert_eq!(slot.read(1), None, "unknown phase is not an invented state");
}

#[test]
fn exhausted_sequence_keeps_the_last_copy_without_wrapping() {
    let slot = Slot::default();
    slot.sequence.store(u64::MAX - 3, SeqCst);
    slot.publish(1, state(1));
    let last = slot.read(1).unwrap();
    assert_eq!(last.sequence, u64::MAX - 1);
    slot.publish(1, state(2));
    assert_eq!(slot.read(1), Some(last));
}

#[test]
fn concurrent_reader_never_accepts_fields_from_different_publications() {
    let slot = Arc::new(Slot::default());
    let writer = Arc::clone(&slot);
    let ready = Arc::new(std::sync::Barrier::new(2));
    let writer_ready = Arc::clone(&ready);
    let thread = std::thread::spawn(move || {
        writer_ready.wait();
        for value in 1..=10_000 {
            writer.publish(1, state(value));
        }
    });
    ready.wait();
    for _ in 0..10_000 {
        if let Some(observed) = slot.read(1) {
            assert_eq!(observed.source, state(observed.source.host_counter));
            assert_eq!(observed.sequence, observed.source.host_counter * 2);
        }
    }
    thread.join().unwrap();
    assert_eq!(slot.read(1).unwrap().source, state(10_000));
}

#[test]
fn accidental_duplicate_publishers_cannot_mix_their_payloads() {
    let slot = Arc::new(Slot::default());
    let ready = Arc::new(std::sync::Barrier::new(3));
    let publisher = |start| {
        let writer = Arc::clone(&slot);
        let ready = Arc::clone(&ready);
        std::thread::spawn(move || {
            ready.wait();
            for value in start..start + 10_000 {
                writer.publish(1, state(value));
            }
        })
    };
    let first = publisher(1);
    let second = publisher(10_001);
    ready.wait();
    for _ in 0..10_000 {
        if let Some(observed) = slot.read(1) {
            assert_eq!(observed.sequence & 1, 0);
            assert_eq!(observed.source, state(observed.source.host_counter));
        }
    }
    first.join().unwrap();
    second.join().unwrap();
    let last = slot.read(1).unwrap();
    assert_eq!(last.sequence & 1, 0);
    assert_eq!(last.source, state(last.source.host_counter));
}
