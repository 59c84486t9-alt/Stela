//! Several threads, each a PE, take away and reuse what the others read,
//! under [`Grace`]: no reader ever sees what it holds change.

use super::*;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU32, AtomicUsize},
    },
    thread,
    time::{Duration, Instant},
};

/// A deadline for every wait: a stuck grace period fails the test.
fn give_up(started: Instant) -> impl FnMut() -> bool {
    move || started.elapsed() > Duration::from_secs(20)
}

/// A small pseudo-random step, so each thread reads its own pattern.
fn next(seed: &mut u64) -> u64 {
    *seed ^= *seed << 13;
    *seed ^= *seed >> 7;
    *seed ^= *seed << 17;
    *seed
}

#[test]
fn grace_waits_for_readers_and_not_for_outside_pes() {
    let grace = Grace::new(3);
    grace.enter(0);
    let snapshot = grace.snapshot();
    // PE 0 is inside since before; PEs 1 and 2 are outside.
    assert!(!grace.passed(&snapshot, None));
    assert!(grace.passed(&snapshot, Some(0)));
    grace.pass(0);
    assert!(grace.passed(&snapshot, None));
    // A PE that enters after the snapshot holds nothing of before.
    grace.enter(1);
    assert!(grace.passed(&snapshot, None));
    let later = grace.snapshot();
    assert!(!grace.passed(&later, None));
    grace.leave(1);
    grace.leave(0);
    assert!(grace.passed(&later, None));
    assert!(!grace.inside(0) && !grace.inside(1));
}

/// Readers hold one of a few buffers inside a section; a writer replaces
/// it, waits the grace period, then poisons and reuses the old one.
#[test]
fn grace_keeps_buffers_until_readers_left() {
    const READERS: usize = 4;
    const BUFFERS: usize = 4;
    const WORDS: usize = 8;
    let grace = Arc::new(Grace::new(READERS + 2));
    let buffers: Arc<Vec<[AtomicU64; WORDS]>> = Arc::new(
        (0..BUFFERS)
            .map(|_| core::array::from_fn(|_| AtomicU64::new(1)))
            .collect(),
    );
    let current = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicBool::new(false));
    let started = Instant::now();
    let readers: Vec<_> = (0..READERS)
        .map(|pe| {
            let (grace, buffers, current, done) = (
                grace.clone(),
                buffers.clone(),
                current.clone(),
                done.clone(),
            );
            thread::spawn(move || {
                let mut reads = 0u64;
                while !done.load(Ordering::Relaxed) {
                    grace.enter(pe);
                    for _ in 0..16 {
                        let held = &buffers[current.load(Ordering::Acquire)];
                        let value = held[0].load(Ordering::Relaxed);
                        assert_ne!(value, u64::MAX, "a reader saw a poisoned buffer");
                        for _ in 0..4 {
                            for word in held {
                                assert_eq!(
                                    word.load(Ordering::Relaxed),
                                    value,
                                    "reused under a reader"
                                );
                            }
                        }
                        reads += 1;
                    }
                    // Readers alternate between leaving and passing a point.
                    if reads.is_multiple_of(64) {
                        grace.pass(pe);
                    }
                    grace.leave(pe);
                }
                reads
            })
        })
        .collect();
    // The last PE is parked throughout: it never holds anything up.
    let writer = READERS;
    grace.enter(writer);
    let mut value = 1;
    for _ in 0..20_000 {
        let old = current.load(Ordering::Relaxed);
        let new = (old + 1) % BUFFERS;
        value += 1;
        for word in &buffers[new] {
            word.store(value, Ordering::Relaxed);
        }
        current.store(new, Ordering::Release);
        let snapshot = grace.snapshot();
        assert!(
            grace.wait(writer, &snapshot, give_up(started)),
            "a grace period never passed"
        );
        for word in &buffers[old] {
            word.store(u64::MAX, Ordering::Relaxed);
        }
    }
    grace.leave(writer);
    done.store(true, Ordering::Relaxed);
    for reader in readers {
        assert!(reader.join().unwrap() > 0);
    }
}

#[test]
fn ring_moves_on_and_retires_one_ahead() {
    let grace = Grace::new(1);
    let ring = Ring::new(3, 256);
    grace.enter(0);
    let first = ring.take(200, 16).unwrap();
    assert_eq!(
        first,
        Place {
            generation: 0,
            offset: 0
        }
    );
    assert_eq!(ring.take(100, 16), Err(0));
    // Parts 1 and 2 never held code: nothing to retire yet.
    assert_eq!(ring.advance(0, &grace, Some(0)), Advance::Moved);
    assert_eq!(
        ring.take(64, 16).unwrap(),
        Place {
            generation: 1,
            offset: 0
        }
    );
    assert!(ring.live(first));
    // Moving to generation 2 retires generation 0, the oldest.
    assert_eq!(ring.advance(1, &grace, Some(0)), Advance::Retire(0));
    assert!(!ring.live(first));
    // Until it is retired another advance waits for the retirer.
    assert_eq!(ring.advance(2, &grace, Some(0)), Advance::Busy);
    ring.retired(0, grace.snapshot());
    // PE 0 was inside at the snapshot: it waits unless it holds nothing.
    assert!(matches!(ring.advance(2, &grace, None), Advance::Wait(_)));
    grace.pass(0);
    assert_eq!(ring.advance(2, &grace, None), Advance::Retire(1));
    // Generation 1 is not retired yet: the ring cannot reach its part.
    assert_eq!(
        ring.take(256, 16).unwrap(),
        Place {
            generation: 3,
            offset: 0
        }
    );
    assert_eq!(ring.take(16, 16), Err(3));
    assert_eq!(ring.advance(3, &grace, Some(0)), Advance::Busy);
    ring.retired(1, grace.snapshot());
    assert_eq!(ring.advance(3, &grace, Some(0)), Advance::Retire(2));
    assert_eq!(
        ring.take(16, 16).unwrap(),
        Place {
            generation: 4,
            offset: 0
        }
    );
    // An older caller's full generation is stale: the ring moved already.
    assert_eq!(ring.advance(3, &grace, None), Advance::Moved);
    grace.leave(0);
}

/// PEs install records into a small ring and publish them in a table;
/// the others read published records, as cores run code, and check they
/// stay whole while held. Parts turn over thousands of times, so PEs meet
/// full parts, retire the oldest and wait for grace periods all at once.
#[test]
fn ring_reuses_parts_only_after_readers_left() {
    const PES: usize = 6;
    const PARTS: usize = 3;
    const PART: usize = 512;
    const RECORD: usize = 64;
    const PUBLISHED: usize = 32;
    let grace = Arc::new(Grace::new(PES));
    let ring = Arc::new(Ring::new(PARTS, PART));
    let arena: Arc<Vec<AtomicU64>> =
        Arc::new((0..PARTS * PART / 8).map(|_| AtomicU64::new(0)).collect());
    // Published places plus one; the lock is the retirer's and installers'.
    let table: Arc<Vec<AtomicU64>> = Arc::new((0..PUBLISHED).map(|_| AtomicU64::new(0)).collect());
    let lock = Arc::new(std::sync::Mutex::new(()));
    let waits = Arc::new(AtomicU32::new(0));
    let started = Instant::now();
    let threads: Vec<_> = (0..PES)
        .map(|pe| {
            let (grace, ring, arena, table, lock, waits) = (
                grace.clone(),
                ring.clone(),
                arena.clone(),
                table.clone(),
                lock.clone(),
                waits.clone(),
            );
            thread::spawn(move || {
                let word =
                    |place: Place| (ring.part(place.generation) * PART + place.offset as usize) / 8;
                let mut seed = pe as u64 * 0x9e37_79b9 + 1;
                let mut installed = 0u64;
                grace.enter(pe);
                for sequence in 1..=20_000u64 {
                    // Install a record.
                    let place = loop {
                        match ring.take(RECORD, 16) {
                            Ok(place) => break place,
                            Err(full) => match ring.advance(full, &grace, Some(pe)) {
                                Advance::Moved | Advance::Busy => {}
                                Advance::Retire(generation) => {
                                    {
                                        let _held = lock.lock().unwrap();
                                        for entry in table.iter() {
                                            let held = entry.load(Ordering::Relaxed);
                                            if held != 0 && split(held - 1).0 == generation {
                                                entry.store(0, Ordering::Relaxed);
                                            }
                                        }
                                    }
                                    ring.retired(generation, grace.snapshot());
                                }
                                Advance::Wait(snapshot) => {
                                    waits.fetch_add(1, Ordering::Relaxed);
                                    assert!(
                                        grace.wait(pe, &snapshot, give_up(started)),
                                        "a part's grace never passed"
                                    );
                                }
                            },
                        }
                    };
                    let tag = (pe as u64) << 48 | sequence;
                    let first = word(place);
                    for index in first..first + RECORD / 8 {
                        arena[index].store(tag, Ordering::Relaxed);
                    }
                    {
                        let _held = lock.lock().unwrap();
                        if ring.live(place) {
                            let slot = next(&mut seed) as usize % PUBLISHED;
                            let packed = cursor(place.generation, place.offset) + 1;
                            table[slot].store(packed, Ordering::Release);
                            installed += 1;
                        }
                    }
                    // Run a few published records.
                    for _ in 0..4 {
                        let held =
                            table[next(&mut seed) as usize % PUBLISHED].load(Ordering::Acquire);
                        if held == 0 {
                            continue;
                        }
                        let (generation, offset) = split(held - 1);
                        let first = word(Place { generation, offset });
                        let tag = arena[first].load(Ordering::Relaxed);
                        assert_ne!(tag, 0);
                        for _ in 0..256 {
                            for index in first..first + RECORD / 8 {
                                assert_eq!(
                                    arena[index].load(Ordering::Relaxed),
                                    tag,
                                    "code reused under a reader"
                                );
                            }
                        }
                    }
                    if sequence.is_multiple_of(8) {
                        grace.leave(pe);
                        grace.enter(pe);
                    }
                }
                grace.leave(pe);
                installed
            })
        })
        .collect();
    let installed: u64 = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .sum();
    assert!(installed > 0);
    // Six PEs over three parts of 8 records each turn the ring constantly.
    assert!(ring.generation() as usize > 10 * PARTS);
    std::eprintln!(
        "ring: {} generations, {installed} installs, {} waits",
        ring.generation(),
        waits.load(Ordering::Relaxed)
    );
}

#[test]
fn slots_wait_in_limbo_and_never_block() {
    let grace = Grace::new(2);
    let slots = Slots::new(4);
    grace.enter(0);
    grace.enter(1);
    let taken: Vec<u32> = (0..2)
        .map(|_| slots.take(&grace, Some(0)).unwrap())
        .collect();
    assert_eq!(taken, [0, 1]);
    slots.release(taken, grace.snapshot());
    // PE 1 stays inside: new numbers are given instead, up to the capacity.
    assert_eq!(slots.take(&grace, Some(0)), Some(2));
    assert_eq!(slots.take(&grace, Some(0)), Some(3));
    assert_eq!(slots.take(&grace, Some(0)), None);
    assert_eq!(slots.issued(), 4);
    grace.pass(1);
    let mut again = [slots.take(&grace, Some(0)), slots.take(&grace, Some(0))];
    again.sort();
    assert_eq!(again, [Some(0), Some(1)]);
    grace.leave(1);
    grace.leave(0);
}

/// PEs take slots, write their records, publish them and later release
/// them; the others read published slots' records and check they stay
/// unchanged while held.
#[test]
fn slots_reused_only_after_readers_left() {
    const PES: usize = 6;
    const CAPACITY: u32 = 256;
    const PUBLISHED: usize = 16;
    let grace = Arc::new(Grace::new(PES + 1));
    let slots = Arc::new(Slots::new(CAPACITY));
    let records: Arc<Vec<AtomicU64>> = Arc::new((0..CAPACITY).map(|_| AtomicU64::new(0)).collect());
    let table: Arc<Vec<AtomicU32>> = Arc::new((0..PUBLISHED).map(|_| AtomicU32::new(0)).collect());
    let threads: Vec<_> = (0..PES)
        .map(|pe| {
            let (grace, slots, records, table) =
                (grace.clone(), slots.clone(), records.clone(), table.clone());
            thread::spawn(move || {
                let mut seed = pe as u64 * 0x2545_f491 + 7;
                let mut full = 0;
                grace.enter(pe);
                for sequence in 1..=20_000u64 {
                    if let Some(slot) = slots.take(&grace, Some(pe)) {
                        records[slot as usize]
                            .store((pe as u64) << 48 | sequence, Ordering::Relaxed);
                        let old = table[next(&mut seed) as usize % PUBLISHED]
                            .swap(slot + 1, Ordering::AcqRel);
                        if old != 0 {
                            slots.release(alloc::vec![old - 1], grace.snapshot());
                        }
                    } else {
                        full += 1;
                    }
                    for _ in 0..2 {
                        let held =
                            table[next(&mut seed) as usize % PUBLISHED].load(Ordering::Acquire);
                        if held == 0 {
                            continue;
                        }
                        let record = &records[held as usize - 1];
                        let value = record.load(Ordering::Relaxed);
                        for _ in 0..256 {
                            assert_eq!(
                                record.load(Ordering::Relaxed),
                                value,
                                "a slot reused under a reader"
                            );
                        }
                    }
                    if sequence.is_multiple_of(16) {
                        grace.pass(pe);
                    }
                }
                grace.leave(pe);
                full
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    // The published slots and those in limbo stay within the capacity.
    assert!(slots.issued() <= CAPACITY);
}

/// PEs take slots, fill their records and publish them; readers on other
/// threads find records whole as chunks are allocated beside them.
#[test]
fn records_are_read_without_locks_while_others_grow() {
    #[derive(Default)]
    struct Record {
        tag: AtomicU64,
        check: AtomicU64,
    }
    const PES: usize = 4;
    const CAPACITY: u32 = 64 * 1024;
    let grace = Arc::new(Grace::new(PES));
    let slots = Arc::new(Slots::new(CAPACITY));
    let records = Arc::new(Records::<Record>::new(CAPACITY));
    let published: Arc<Vec<AtomicU32>> = Arc::new((0..256).map(|_| AtomicU32::new(0)).collect());
    assert!(records.get(0).is_none());
    let threads: Vec<_> = (0..PES)
        .map(|pe| {
            let (grace, slots, records, published) = (
                grace.clone(),
                slots.clone(),
                records.clone(),
                published.clone(),
            );
            thread::spawn(move || {
                let mut seed = pe as u64 + 11;
                grace.enter(pe);
                for sequence in 1..=12_000u64 {
                    let Some(slot) = slots.take(&grace, Some(pe)) else {
                        break;
                    };
                    let record = records.reserve(slot);
                    let tag = (pe as u64) << 48 | sequence;
                    record.tag.store(tag, Ordering::Relaxed);
                    record.check.store(!tag, Ordering::Relaxed);
                    published[next(&mut seed) as usize % 256].store(slot + 1, Ordering::Release);
                    let held = published[next(&mut seed) as usize % 256].load(Ordering::Acquire);
                    if held != 0 {
                        let record = records.get(held - 1).expect("a published slot's chunk");
                        let tag = record.tag.load(Ordering::Relaxed);
                        assert_eq!(record.check.load(Ordering::Relaxed), !tag);
                    }
                }
                grace.leave(pe);
            })
        })
        .collect();
    for thread in threads {
        thread.join().unwrap();
    }
    // Nothing was released: every slot is new, 48,000 of them.
    assert_eq!(slots.issued(), 48_000);
    assert!(records.heap_bytes() >= 48_000 * size_of::<Record>());
}

#[test]
fn the_code_lock_counts_its_waits_and_the_report_starts_the_longest_over() {
    let code = Arc::new(Code::new(1 << 16, 1 << 16, None));
    let held = code.cache();
    let waiting = Arc::clone(&code);
    let started = Arc::new(AtomicBool::new(false));
    let seen = Arc::clone(&started);
    let waiter = thread::spawn(move || {
        seen.store(true, Ordering::Release);
        drop(waiting.cache());
    });
    while !started.load(Ordering::Acquire) {
        thread::yield_now();
    }
    thread::sleep(Duration::from_millis(20));
    drop(held);
    waiter.join().unwrap();
    let report = code.report();
    // The holder, the waiter and the report's own.
    assert_eq!(report.lock.acquired, 3);
    assert_eq!(report.lock.contended, 1);
    assert!(report.lock.longest > 0 && report.lock.longest == report.lock.waited);
    let again = code.report();
    assert_eq!(again.lock.acquired, 4);
    assert_eq!(again.lock.longest, 0, "the longest wait is per report");
    assert_eq!(again.lock.waited, report.lock.waited);
}
