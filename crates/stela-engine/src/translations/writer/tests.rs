use super::*;
use crate::translations::translator_id;
use alloc::collections::BTreeSet;
use stela_formats::journal::Target;

/// Counter ticks per second, and the steps a second of a boot gives.
const HZ: u64 = 1000;
const STEPS_PER_SECOND: u64 = 10;

/// A pack file in memory whose writes may be cut after a number of bytes,
/// as a power loss cuts a disk's: the cut write lands only partly.
struct Disk {
    bytes: Vec<u8>,
    /// Bytes still written before the cut; `None` for no cut.
    left: Option<u64>,
    cut: bool,
    written: u64,
    /// A commit slot was written since the last flush, and the page keys
    /// each commit left, once durable.
    slot: bool,
    contents: Vec<BTreeSet<Digest>>,
}

impl Disk {
    fn new(size: u64) -> Self {
        Self {
            bytes: vec![0; size as usize],
            left: None,
            cut: false,
            written: 0,
            slot: false,
            contents: Vec::new(),
        }
    }
}

impl Target for Disk {
    type Error = String;
    fn write_at(&mut self, offset: u64, bytes: &[u8]) -> Result<bool, String> {
        let take = match self.left {
            Some(left) => (left as usize).min(bytes.len()),
            None => bytes.len(),
        };
        let at = offset as usize;
        self.bytes[at..at + take].copy_from_slice(&bytes[..take]);
        self.written += take as u64;
        self.slot |= offset < DATA_START;
        if let Some(left) = &mut self.left {
            *left -= take as u64;
            if take < bytes.len() {
                self.cut = true;
                return Err(String::from("cut"));
            }
        }
        Ok(true)
    }
    fn flush(&mut self) -> Result<bool, String> {
        if self.cut {
            return Err(String::from("cut"));
        }
        if core::mem::take(&mut self.slot) {
            let found = keys(&self.bytes);
            self.contents.push(found);
        }
        Ok(true)
    }
}

/// What a boot's store hands the writer: entries added, keys found. Like
/// the store, it keeps at most `bound` entries between takes and counts
/// those it refused, and those it shed. Its heap, when measured, holds
/// `heap_total` bytes, of which the rest of the boot takes `filler` and
/// the writer's segments `resident`.
struct Boot {
    added: BTreeMap<Digest, Record>,
    found: Vec<Digest>,
    next: u32,
    total: u64,
    bound: usize,
    unkept: u64,
    heap_total: u64,
    filler: u64,
    resident: u64,
    shedding: bool,
    shed: u64,
}

impl Boot {
    /// A boot whose pages are numbered from `seed` millions, that found
    /// every record in `found`.
    fn new(seed: u32, found: Vec<Digest>) -> Self {
        Self {
            added: BTreeMap::new(),
            found,
            next: seed * 1_000_000,
            total: 0,
            bound: usize::MAX,
            unkept: 0,
            heap_total: 0,
            filler: 0,
            resident: 0,
            shedding: false,
            shed: 0,
        }
    }

    /// The heap's room the boot measures: what the rest, the writer's
    /// segments and the entries added leave.
    fn room(&self) -> u64 {
        let added = self.added.len() as u64 * ENTRY_HEAP_BYTES;
        self.heap_total
            .saturating_sub(self.filler + self.resident + added)
    }

    /// Add `count` entries of new pages: the keys of those kept.
    fn add(&mut self, count: u32) -> Vec<Digest> {
        let translator = translator_id();
        let mut kept = Vec::new();
        for _ in 0..count {
            self.next += 1;
            if self.shedding {
                self.shed += 1;
                continue;
            }
            if self.added.len() >= self.bound {
                self.unkept += 1;
                continue;
            }
            let key = Digest::of(&self.next.to_le_bytes());
            self.added.insert(key, Record::new(translator, key));
            self.total += 1;
            kept.push(key);
        }
        kept
    }
}

impl Entries for Boot {
    fn take_added(&mut self) -> BTreeMap<Digest, Record> {
        core::mem::take(&mut self.added)
    }
    fn found_keys(&mut self) -> Vec<Digest> {
        self.found.clone()
    }
    fn added(&mut self) -> u64 {
        self.total
    }
    fn pressed(&mut self) -> bool {
        !self.added.is_empty() && self.added.len().saturating_mul(2) >= self.bound
    }
    fn heap(&mut self) -> Option<Heap> {
        (self.heap_total != 0).then(|| Heap {
            total: self.heap_total,
            room: self.room(),
        })
    }
    fn shed(&mut self, shed: bool) {
        self.shedding = shed;
    }
}

/// The heap bytes an added entry of [`Boot::add`] takes.
const ENTRY_HEAP_BYTES: u64 = 256;

/// The pack file as a boot's loader reads it: the newest commit, whose
/// blobs must read back whole, and its segments and lists.
fn load(disk: &[u8], limit: u64) -> File<'static> {
    let translator = translator_id();
    let size = disk.len() as u64;
    let committed = journal::candidates(&disk[..DATA_START as usize], JOURNAL_DOMAIN, size)
        .into_iter()
        .next();
    let mut segments = Vec::new();
    let mut used = Vec::new();
    if let Some(commit) = &committed {
        let blobs = journal::read_entries(commit, |offset, into| {
            let at = offset as usize;
            into.copy_from_slice(disk.get(at..at + into.len())?);
            Some(())
        })
        .expect("the newest commit's blobs read back whole");
        for (kind, bytes) in blobs {
            let bytes: &'static [u8] = Vec::leak(bytes);
            match kind {
                SEGMENT_BLOB => segments.push(Pack::parse(bytes, &translator).unwrap()),
                USED_BLOB => used.push(UsedKeys::parse(bytes, &translator).unwrap()),
                _ => panic!("an unknown blob"),
            }
        }
    }
    File {
        translator,
        limit,
        file_bytes: size,
        committed,
        segments,
        used,
        partial: false,
    }
}

/// The page keys the file's newest commit holds.
fn keys(disk: &[u8]) -> BTreeSet<Digest> {
    load(disk, u64::MAX)
        .segments
        .iter()
        .flat_map(|pack| pack.iter().map(|(key, _)| key).collect::<Vec<_>>())
        .collect()
}

/// A writer's boot: its clock, the store and the disk.
struct Run<'a> {
    writer: Writer<'a>,
    boot: Boot,
    now: u64,
    events: Vec<Event>,
}

impl<'a> Run<'a> {
    /// A boot over `file` whose pages are numbered from `seed` millions,
    /// that uses every record the file holds.
    fn new(file: File<'a>, seed: u32) -> Self {
        let found = file
            .segments
            .iter()
            .flat_map(|pack| pack.iter().map(|(key, _)| key).collect::<Vec<_>>())
            .collect();
        Self {
            writer: Writer::new(file, HZ),
            boot: Boot::new(seed, found),
            now: 0,
            events: Vec::new(),
        }
    }

    /// Step for `seconds` of the guest's time.
    fn run(&mut self, disk: &mut Disk, seconds: u64) -> Result<(), String> {
        for _ in 0..seconds * STEPS_PER_SECOND {
            let now = self.now;
            self.boot.resident = self.writer.resident();
            let events =
                self.writer
                    .step(&mut || now, now + 1, &mut self.boot, &mut |execution| {
                        Some(execution.advance(disk, PIECE_BYTES))
                    })?;
            self.events.extend(events);
            self.now += HZ / STEPS_PER_SECOND;
        }
        Ok(())
    }

    /// Step for `seconds` while the device takes no write.
    fn stall(&mut self, seconds: u64) {
        for _ in 0..seconds * STEPS_PER_SECOND {
            let now = self.now;
            let events = self
                .writer
                .step(&mut || now, now + 1, &mut self.boot, &mut |_| None)
                .unwrap();
            self.events.extend(events);
            self.now += HZ / STEPS_PER_SECOND;
        }
    }

    /// The triggers of the segments committed so far.
    fn triggers(&self) -> Vec<Trigger> {
        self.events
            .iter()
            .filter_map(|event| match event {
                Event::Segment { trigger, .. } => Some(*trigger),
                _ => None,
            })
            .collect()
    }

    fn stop(&mut self, disk: &mut Disk) -> Result<Stopped, String> {
        self.writer.stop(&mut self.boot, &mut |execution| {
            while !execution.advance(disk, PIECE_BYTES)? {}
            Ok(())
        })
    }
}

const FILE_BYTES: u64 = DATA_START + 4096 * journal::ALIGN;

/// A boot `seed` of entries added in bursts, each followed by its
/// seconds, and stopped: the keys it added.
fn boot_of(
    disk: &mut Disk,
    seed: u32,
    bursts: &[(u64, u32)],
) -> Result<(BTreeSet<Digest>, Stopped), String> {
    let file = load(&disk.bytes.clone(), u64::MAX);
    let mut run = Run::new(file, seed);
    let mut added = BTreeSet::new();
    for &(seconds, count) in bursts {
        added.extend(run.boot.add(count));
        run.run(disk, seconds)?;
    }
    let stopped = run.stop(disk)?;
    Ok((added, stopped))
}

#[test]
fn boots_commit_their_segments_and_lists_and_a_later_boot_merges_them() {
    let mut disk = Disk::new(FILE_BYTES);
    let mut all = BTreeSet::new();
    for boot in 0..5 {
        let bursts = [(30, 200), (100, 50), (200, 10)];
        let (added, stopped) = boot_of(&mut disk, boot + 1, &bursts).unwrap();
        all.extend(added);
        assert_eq!(keys(&disk.bytes), all, "boot {boot}");
        assert!(stopped.segments < MAX_SEGMENTS && stopped.lists <= MAX_USED_LISTS);
        assert!(!stopped.merge_left);
    }
    // A merge ran once segments or lists reached MERGE_AT: the file holds
    // fewer than five boots wrote.
    let file = load(&disk.bytes, u64::MAX);
    assert!(file.segments.len() < 5 * 3, "{}", file.segments.len());
    assert!(file.used.len() < 5);
}

#[test]
fn a_long_session_keeps_a_free_slot_and_commits_every_entry_in_bounded_time() {
    let mut disk = Disk::new(FILE_BYTES);
    let mut run = Run::new(load(&disk.bytes.clone(), u64::MAX), 1);
    let mut pending: Vec<(u64, Vec<Digest>)> = Vec::new();
    // Three days of a burst every ten minutes.
    for _ in 0..3 * 24 * 6 {
        pending.push((run.now, run.boot.add(20)));
        run.run(&mut disk, 600).unwrap();
        let committed = keys(&disk.bytes);
        let file = load(&disk.bytes, u64::MAX);
        assert!(
            file.segments.len() < MAX_SEGMENTS,
            "{}",
            file.segments.len()
        );
        // Whatever was added a last delay and a merge ago is in the file.
        let bound = run.now.saturating_sub(HZ * (LAST_DELTA_SECONDS + 600));
        for (at, added) in &pending {
            if *at < bound {
                assert!(
                    added.iter().all(|key| committed.contains(key)),
                    "added at {at}"
                );
            }
        }
    }
    let stats = run.writer.stats();
    assert!(stats.pairs + stats.merges > 3, "{stats:?}");
    run.stop(&mut disk).unwrap();
    let committed = keys(&disk.bytes);
    assert!(
        pending
            .iter()
            .all(|(_, added)| added.iter().all(|key| committed.contains(key)))
    );
}

#[test]
fn a_stop_finishes_a_segment_in_flight_and_leaves_a_merge() {
    // A segment's write queued and not yet done: the stop finishes it.
    let mut disk = Disk::new(FILE_BYTES);
    let mut run = Run::new(load(&disk.bytes.clone(), u64::MAX), 1);
    let added = run.boot.add(5000);
    run.stall(FIRST_DELTA_SECONDS);
    assert!(!run.writer.idle());
    assert!(keys(&disk.bytes).is_empty());
    let stopped = run.stop(&mut disk).unwrap();
    assert!(!stopped.merge_left);
    assert_eq!(keys(&disk.bytes), added.into_iter().collect());
    assert_eq!(stopped.segments, 1);

    // A merge in progress at the stop: the file keeps its segments, and
    // the stop adds its own beside them.
    let mut disk = Disk::new(FILE_BYTES);
    let mut all = BTreeSet::new();
    for seed in 0..MERGE_AT as u32 {
        all.extend(boot_of(&mut disk, seed + 1, &[(1, 100)]).unwrap().0);
    }
    // The boot's merge waits for its first segment's delay; then its write
    // never lands.
    let mut run = Run::new(load(&disk.bytes.clone(), u64::MAX), 9);
    run.stall(FIRST_DELTA_SECONDS + 1);
    assert!(!run.writer.idle());
    assert!(
        run.events
            .iter()
            .any(|event| matches!(event, Event::Merged { full: true, .. })),
        "{:?}",
        run.events
    );
    all.extend(run.boot.add(30));
    let before = load(&disk.bytes, u64::MAX).segments.len();
    let stopped = run.stop(&mut disk).unwrap();
    assert!(stopped.merge_left);
    assert_eq!(stopped.segments, before + 1);
    assert_eq!(keys(&disk.bytes), all);
}

/// Records whose segment takes about `blocks` journal blocks.
fn records_for(blocks: u64) -> u32 {
    let translator = translator_id();
    let sample: Vec<(Digest, crate::translations::pack::Piece)> = (0u32..100)
        .map(|n| {
            let key = Digest::of(&n.to_le_bytes());
            let piece =
                crate::translations::pack::Piece::New(Record::new(translator, key).encode());
            (key, piece)
        })
        .collect();
    let per_record = Layout::new(&translator, sample).bytes() / 100;
    (blocks * journal::ALIGN / per_record) as u32
}

#[test]
fn a_segment_without_room_waits_for_a_merge_and_one_larger_than_the_file_is_left_out() {
    let mut disk = Disk::new(DATA_START + 64 * journal::ALIGN);
    let mut run = Run::new(load(&disk.bytes.clone(), u64::MAX), 1);
    let first: BTreeSet<Digest> = run.boot.add(records_for(10)).into_iter().collect();
    run.run(&mut disk, FIRST_DELTA_SECONDS + 1).unwrap();
    assert_eq!(keys(&disk.bytes), first);
    // More than the room beside the first, and than any room a merge
    // leaves beside its segment.
    let second = run.boot.add(records_for(60));
    run.run(&mut disk, 2 * FIRST_DELTA_SECONDS + 10).unwrap();
    let position = |wanted: fn(&Event) -> bool| run.events.iter().position(wanted);
    let waiting = position(|event| matches!(event, Event::Waiting { .. })).unwrap();
    let merged = position(|event| *event == Event::MergeCommitted { full: true }).unwrap();
    let lost = position(|event| matches!(event, Event::Lost { .. })).unwrap();
    assert!(waiting < merged && merged < lost, "{:?}", run.events);
    // The writer goes on: the next segment commits.
    let third: BTreeSet<Digest> = run.boot.add(20).into_iter().collect();
    run.run(&mut disk, 4 * FIRST_DELTA_SECONDS + 10).unwrap();
    let committed = keys(&disk.bytes);
    assert!(committed.is_superset(&first) && committed.is_superset(&third));
    assert!(second.iter().all(|key| !committed.contains(key)));
    run.stop(&mut disk).unwrap();
}

/// Boots of a writer, the same each run: a first with two segments, three
/// short ones whose lists bring a merge, and one more.
fn scenario(disk: &mut Disk) -> Result<(), String> {
    let boots: [&[(u64, u32)]; 5] = [
        &[(70, 300), (130, 40)],
        &[(5, 20)],
        &[(5, 20)],
        &[(5, 20)],
        &[(90, 50)],
    ];
    for (seed, bursts) in boots.into_iter().enumerate() {
        boot_of(disk, seed as u32 + 1, bursts)?;
    }
    Ok(())
}

#[test]
fn a_cut_at_any_write_leaves_the_content_of_a_whole_commit() {
    const SIZE: u64 = DATA_START + 512 * journal::ALIGN;
    let mut disk = Disk::new(SIZE);
    scenario(&mut disk).unwrap();
    let contents = core::mem::take(&mut disk.contents);
    assert!(contents.len() > 8, "{}", contents.len());
    assert!(
        contents
            .iter()
            .any(|content| content.len() < contents.last().unwrap().len()),
        "commits before the last hold less"
    );
    let total = disk.written;
    let step = (total / 250).max(1);
    let mut cut = 0;
    while cut <= total {
        let mut disk = Disk::new(SIZE);
        disk.left = Some(cut);
        let _ = scenario(&mut disk);
        // The newest commit reads back whole (`load` checks it) and holds
        // what one of the uncut run's commits held.
        let found = keys(&disk.bytes);
        assert!(
            found.is_empty() || contents.contains(&found),
            "a cut after {cut} of {total} bytes left content no commit held"
        );
        cut += step;
    }
}

#[test]
fn entries_added_faster_than_their_bound_go_to_segments_before_any_is_refused() {
    // A boot's kernel adds entries for its first seconds far faster than the
    // bound the store keeps between segments: the writer takes them once
    // they reach half of it, so the store refuses none, and the next boot
    // finds all of them.
    let mut disk = Disk::new(FILE_BYTES);
    let mut run = Run::new(load(&disk.bytes.clone(), u64::MAX), 1);
    run.boot.bound = 1000;
    let mut added = BTreeSet::new();
    for _ in 0..FIRST_DELTA_SECONDS {
        added.extend(run.boot.add(400));
        run.run(&mut disk, 1).unwrap();
    }
    assert_eq!(run.boot.unkept, 0);
    assert!(run.writer.stats().pressed >= 5, "{:?}", run.writer.stats());
    assert!(run.triggers().contains(&Trigger::Pressed));
    run.stop(&mut disk).unwrap();
    assert_eq!(keys(&disk.bytes), added);
    assert_eq!(added.len() as u64, 400 * FIRST_DELTA_SECONDS);
    // The pressed segments were merged as they came: fewer than the slots.
    assert!(load(&disk.bytes, u64::MAX).segments.len() < MAX_SEGMENTS);
}

#[test]
fn the_first_segment_comes_when_translation_goes_quiet_or_at_its_delay() {
    // A burst, then quiet: the first segment commits a few seconds after.
    let mut disk = Disk::new(FILE_BYTES);
    let mut run = Run::new(load(&disk.bytes.clone(), u64::MAX), 1);
    let burst: BTreeSet<Digest> = run.boot.add(3000).into_iter().collect();
    run.run(&mut disk, QUIET_SECONDS + 2).unwrap();
    assert_eq!(run.triggers(), [Trigger::Quiet]);
    assert_eq!(keys(&disk.bytes), burst);
    run.stop(&mut disk).unwrap();

    // Translation that never goes quiet: the first segment at its delay.
    let mut disk = Disk::new(FILE_BYTES);
    let mut run = Run::new(load(&disk.bytes.clone(), u64::MAX), 1);
    for second in 0..FIRST_DELTA_SECONDS + 2 {
        run.boot.add(2 * QUIET_RATE as u32);
        run.run(&mut disk, 1).unwrap();
        if second + 1 < FIRST_DELTA_SECONDS {
            assert!(run.triggers().is_empty(), "at {second} s");
        }
    }
    assert_eq!(run.triggers(), [Trigger::Due]);
    run.stop(&mut disk).unwrap();
}

#[test]
fn entries_that_press_while_a_write_waits_are_held_for_the_next_segment() {
    let mut disk = Disk::new(FILE_BYTES);
    let mut run = Run::new(load(&disk.bytes.clone(), u64::MAX), 1);
    run.boot.bound = 1000;
    let mut added: BTreeSet<Digest> = run.boot.add(400).into_iter().collect();
    // The first segment starts once translation is quiet; its write waits.
    run.stall(QUIET_SECONDS + 2);
    assert!(!run.writer.idle());
    // More than the bound arrives while it waits: the writer takes a batch
    // once it presses, and the store refuses none.
    for _ in 0..3 {
        added.extend(run.boot.add(400));
        run.stall(1);
    }
    assert_eq!(run.boot.unkept, 0);
    assert_eq!(run.writer.stats().held, 1);
    run.run(&mut disk, 5).unwrap();
    run.stop(&mut disk).unwrap();
    assert_eq!(keys(&disk.bytes), added);
}

#[test]
fn a_filling_heap_sheds_the_stores_entries_and_then_lets_the_segments_go() {
    const HEAP: u64 = 8 << 20;
    let mut disk = Disk::new(FILE_BYTES);
    let mut run = Run::new(load(&disk.bytes.clone(), u64::MAX), 1);
    run.boot.heap_total = HEAP;
    run.boot.filler = HEAP / 4;
    run.boot.bound = 2000;
    let shed = |run: &Run| {
        run.events
            .iter()
            .filter(|event| matches!(event, Event::Shed { .. }))
            .count()
    };

    // The heap's room dips under its shed share: the store keeps no entry
    // until the room is back a release share above it.
    let mut committed: BTreeSet<Digest> = run.boot.add(2000).into_iter().collect();
    run.run(&mut disk, QUIET_SECONDS + 2).unwrap();
    assert_eq!(keys(&disk.bytes), committed);
    run.boot.filler = HEAP - HEAP / SHED_SHARE - run.writer.resident() + 1;
    run.run(&mut disk, 1).unwrap();
    assert!(run.boot.shedding);
    assert_eq!(shed(&run), 1, "{:?}", run.events);
    assert!(run.boot.add(100).is_empty());
    run.boot.filler =
        HEAP - HEAP / SHED_SHARE - HEAP / RELEASE_SHARE - run.writer.resident() - (1 << 20);
    run.run(&mut disk, 1).unwrap();
    assert!(!run.boot.shedding);

    // Entries keep coming with room to spare: the segments laid out grow to
    // their share of the heap, then the store sheds; they never pass it by
    // more than the segment that reached it.
    run.boot.filler = HEAP / 4;
    let cap = HEAP / RESIDENT_SHARE;
    let mut most = 0;
    for _ in 0..4 * FIRST_DELTA_SECONDS {
        committed.extend(run.boot.add(3000));
        run.run(&mut disk, 1).unwrap();
        most = most.max(run.writer.resident());
    }
    assert!(run.boot.shedding && run.boot.shed > 100);
    assert!(most >= cap / 2 && most < cap * 2, "{most} of {cap}");
    assert_eq!(shed(&run), 1, "reported once: {:?}", run.events);
    assert!(run.writer.stats().sheds >= 2);
    let written = keys(&disk.bytes);
    assert!(!written.is_empty());

    // The rest of the boot fills the heap: the writer lets its segments go
    // and the store sheds for the rest of the boot, room or not.
    run.boot.filler = HEAP - HEAP / RELEASE_SHARE + 1;
    run.run(&mut disk, 1).unwrap();
    assert_eq!(run.writer.resident(), 0);
    assert!(
        run.events
            .iter()
            .any(|event| matches!(event, Event::Released { .. })),
        "{:?}",
        run.events
    );
    run.boot.filler = 0;
    run.run(&mut disk, 2 * FIRST_DELTA_SECONDS).unwrap();
    assert_eq!(run.writer.shedding(), (true, true));
    assert!(run.boot.add(100).is_empty());
    assert_eq!(run.writer.resident(), 0);

    // What the file held stays whole; the stop writes the boot's list.
    let stopped = run.stop(&mut disk).unwrap();
    assert!(keys(&disk.bytes).is_superset(&written));
    assert_eq!(stopped.lists, 1);
}
