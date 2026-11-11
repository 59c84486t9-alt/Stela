//! The parts of the board's code arena and which of them goes next.
//!
//! Every PE installs into the open part of one of two generations: young
//! code (compiled for the first time, or long after its block went) and
//! tenured code (compiled again soon after the ring took its block away:
//! code the guest keeps running). Each generation has its own bump cursor,
//! a part and an offset in one word that a compare-exchange advances, so
//! an install takes no lock. When an open part is full its generation
//! opens a free part, under the ring's plan lock (once per part), and when
//! that leaves no free part the plan chooses the part to take away next,
//! one ahead of its reuse, so no PE waits in the usual case. Of the full
//! parts that fit (free of references, filled at least a quarter turn ago,
//! and written by no install), it chooses:
//!
//! - a part whose blocks mostly left the index already (IC IVAU holes);
//! - else the oldest tenured part once it outlived [`AGE_TURNS`] turns
//!   since it opened;
//! - else the oldest young part while young code holds more than its share
//!   ([`Ring::young_parts`]) or no tenured part is full: young code goes
//!   first in first out, as all code did before;
//! - else the tenured part entered least since the last such choice: a
//!   fetch the engine makes counts its block's part ([`Ring::entered_by`],
//!   in batches per PE), which chained native code never does;
//! - else, when none fits, the oldest settled part free of references, or
//!   the oldest part.
//!
//! A part code of another part jumps into (a thunk or a tail, which go in
//! the part the referring block's generation fills) is never chosen while
//! that part is live: [`Ring::refer`] notes the reference before the jump
//! is written, and refuses one into a part already chosen. References go
//! from older parts to newer ones of one generation, so the oldest full
//! part is always free to go, and of the parts that filled a quarter turn
//! ago (at least one, as at most a quarter turn of parts filled since) the
//! oldest is too.
//!
//! The margins keep installs from meeting a retirement; what makes one
//! harmless is two rules. A place a take hands out counts as a writer of
//! its part until its install gives it back ([`Ring::release`]), and a part
//! with writers is not opened again, so no install writes into a part's
//! next code. And a block is published only while its part still holds
//! the generation its place was taken in ([`Ring::live`], checked under the
//! board's code lock, under which a retirement lists the part's blocks
//! after choosing it), so every published block is one its part's
//! retirement takes away; an install that finds its part gone is done
//! again.
use super::{Grace, Snapshot};
use crate::platform::sync::Mutex;
use alloc::{boxed::Box, collections::VecDeque, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// The fewest parts a [`Ring`] has: the current one, the one being retired
/// ahead of it, and at least one that keeps code.
pub(in crate::machine::engine) const MIN_PARTS: usize = 3;
/// The generation of first-time code.
pub(in crate::machine::engine) const YOUNG: usize = 0;
/// The generation of code compiled again soon after its part went.
pub(in crate::machine::engine) const TENURED: usize = 1;
/// The fewest parts a ring keeps a tenured generation in.
const TENURE_PARTS: usize = 8;
/// Turns of the ring a tenured part lives at most.
pub(in crate::machine::engine) const AGE_TURNS: u32 = 4;
/// A part whose blocks left the index for at least this share (in
/// quarters) of those it took goes first, once it took [`HOLE_BLOCKS`].
const HOLE_QUARTERS: u32 = 3;
const HOLE_BLOCKS: u32 = 64;

const PART_BITS: u32 = 6;
const MAX_PARTS: usize = 1 << PART_BITS;
/// A cursor's head with no part: its generation never opened one.
const NONE: u32 = u32::MAX;

const fn head(generation: u32, part: u32) -> u32 {
    generation << PART_BITS | part
}

const fn cursor(head: u32, offset: u32) -> u64 {
    (head as u64) << 32 | offset as u64
}

/// Where [`Ring::take`] put something: the generation of the part's
/// opening, the part, and the offset in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::machine::engine) struct Place {
    pub(in crate::machine::engine) generation: u32,
    pub(in crate::machine::engine) part: u32,
    pub(in crate::machine::engine) offset: u32,
}

/// Why the plan chose a part to take away.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::machine::engine) enum Why {
    /// The oldest young part.
    Young = 0,
    /// The tenured part entered least.
    Cold = 1,
    /// A tenured part past [`AGE_TURNS`].
    Aged = 2,
    /// Most of its blocks had left the index.
    Holes = 3,
}

/// What [`Ring::advance`] asks of its caller.
#[derive(Debug, PartialEq, Eq)]
pub(in crate::machine::engine) enum Advance {
    /// The generation moved on, by this caller or another: take again.
    Moved,
    /// This caller must take away the code of this part (unlink every exit
    /// into it, forget its blocks, cells and table entries), then call
    /// [`Ring::retired`].
    Retire(u32, Why),
    /// The next part's code is still being taken away by another PE: take
    /// again soon.
    Busy,
    /// The next part's grace has not passed: [`Grace::wait`] for it outside
    /// the section, then take again.
    Wait(Snapshot),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Free,
    Open,
    Full,
    Retiring,
}

/// What changes once per part, under the ring's lock.
struct Plan {
    state: Vec<State>,
    /// Parts taken away, oldest first: each is reused once its grace passed.
    free: VecDeque<u32>,
    /// Each generation's full parts, oldest first.
    full: [VecDeque<u32>; 2],
    retiring: Option<u32>,
}

/// A part's count of fetches, on a cache line of its own.
#[repr(align(64))]
#[derive(Default)]
struct Entered(AtomicU32);

/// A part's count of unfinished installs, on a cache line of its own.
#[repr(align(64))]
#[derive(Default)]
struct Writers(AtomicU32);

pub(in crate::machine::engine) struct Ring {
    part_bytes: u32,
    pub(in crate::machine::engine) parts: u32,
    /// The parts young code keeps when tenured code wants room; 0 for a
    /// ring too small for a tenured generation, whose code is all young.
    pub(in crate::machine::engine) young_parts: u32,
    /// Each generation's open part's head above, its bytes taken below.
    cursors: [AtomicU64; 2],
    /// Generations given: each opening of a part takes the next.
    opened: AtomicU32,
    plan: Mutex<Plan>,
    /// Per part: the generation of its last opening, and whether it holds
    /// that generation's code (open or full, not chosen to go).
    holds: Box<[AtomicU32]>,
    live: Box<[AtomicBool]>,
    /// Per part: the generation of code it took ([`YOUNG`], [`TENURED`]).
    kind: Box<[AtomicU32]>,
    /// Per part: one more than the generation it last went in; 0 for none.
    retired: Box<[AtomicU32]>,
    /// The snapshot each part's last retirement waits on.
    snapshots: Box<[Mutex<Option<Snapshot>>]>,
    entered: Box<[Entered]>,
    /// Per part: blocks it took and of those, blocks that left the index
    /// before it went (under the board's code lock).
    installed: Box<[AtomicU32]>,
    dropped: Box<[AtomicU32]>,
    /// Per part: a bit per part whose code jumps into it.
    refs: Box<[AtomicU64]>,
    /// Per part: the generation given when it filled (its next part's).
    filled: Box<[AtomicU32]>,
    /// Per part: places taken in it whose installs are not published yet
    /// ([`Ring::take`], [`Ring::release`]).
    writers: Box<[Writers]>,
    /// Parts chosen to go, by [`Why`].
    outs: [AtomicU64; 4],
}

fn atomics<T: Default>(parts: usize) -> Box<[T]> {
    (0..parts).map(|_| T::default()).collect()
}

impl Ring {
    /// `parts` parts of `part_bytes` each; young code takes the first.
    pub(in crate::machine::engine) fn new(parts: usize, part_bytes: usize) -> Self {
        assert!(
            (MIN_PARTS..=MAX_PARTS).contains(&parts),
            "a ring of three to 64 parts"
        );
        let part_bytes = u32::try_from(part_bytes).expect("a part below 4 GiB");
        let young_parts = if parts >= TENURE_PARTS {
            (parts as u32 / 4).max(2)
        } else {
            0
        };
        let mut state = alloc::vec![State::Free; parts];
        state[0] = State::Open;
        let ring = Self {
            part_bytes,
            parts: parts as u32,
            young_parts,
            cursors: [
                AtomicU64::new(cursor(head(0, 0), 0)),
                AtomicU64::new(cursor(NONE, part_bytes)),
            ],
            opened: AtomicU32::new(1),
            plan: Mutex::new(Plan {
                state,
                free: (1..parts as u32).collect(),
                full: [VecDeque::new(), VecDeque::new()],
                retiring: None,
            }),
            holds: atomics(parts),
            live: atomics(parts),
            kind: atomics(parts),
            retired: atomics(parts),
            snapshots: (0..parts).map(|_| Mutex::new(None)).collect(),
            entered: atomics(parts),
            installed: atomics(parts),
            dropped: atomics(parts),
            refs: atomics(parts),
            filled: atomics(parts),
            writers: atomics(parts),
            outs: Default::default(),
        };
        ring.live[0].store(true, Ordering::Relaxed);
        ring
    }

    /// The generation `stream` installs into: a ring without a tenured
    /// generation puts all code in the young one.
    fn stream(&self, stream: usize) -> usize {
        if self.young_parts == 0 { YOUNG } else { stream }
    }

    /// The latest generation given.
    pub(in crate::machine::engine) fn generation(&self) -> u32 {
        self.opened.load(Ordering::Acquire) - 1
    }

    /// The head [`Self::take`] refuses with while `stream`'s part is full.
    pub(in crate::machine::engine) fn head(&self, stream: usize) -> u32 {
        (self.cursors[self.stream(stream)].load(Ordering::Acquire) >> 32) as u32
    }

    /// `bytes` at `align` (a power of two) in `stream`'s open part, or the
    /// head of its full part, which [`Self::advance`] takes. The place
    /// counts as a writer of its part until the caller gives it back
    /// ([`Self::release`]): the part is not opened again meanwhile.
    pub(in crate::machine::engine) fn take(
        &self,
        stream: usize,
        bytes: usize,
        align: usize,
    ) -> Result<Place, u32> {
        debug_assert!(align.is_power_of_two());
        let at = &self.cursors[self.stream(stream)];
        let mut current = at.load(Ordering::Acquire);
        loop {
            let (top, offset) = ((current >> 32) as u32, current as u32);
            let start = (offset as usize).next_multiple_of(align);
            let end = start + bytes;
            if top == NONE || end > self.part_bytes as usize {
                return Err(top);
            }
            let part = top & (MAX_PARTS as u32 - 1);
            // A writer before the take: the advance that closes the part
            // swaps the cursor after this compare-exchange, so whatever
            // reopens the part later sees the count.
            let writers = &self.writers[part as usize].0;
            writers.fetch_add(1, Ordering::SeqCst);
            match at.compare_exchange_weak(
                current,
                cursor(top, end as u32),
                Ordering::SeqCst,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(Place {
                        generation: top >> PART_BITS,
                        part,
                        offset: start as u32,
                    });
                }
                Err(now) => {
                    writers.fetch_sub(1, Ordering::Release);
                    current = now;
                }
            }
        }
    }

    /// Open a free part for `stream`, whose part of head `full` is full,
    /// once one is ready; and when none is left free, choose the part to
    /// go next. `skip` is as for [`Grace::passed`].
    pub(in crate::machine::engine) fn advance(
        &self,
        stream: usize,
        full: u32,
        grace: &Grace,
        skip: Option<usize>,
    ) -> Advance {
        let stream = self.stream(stream);
        let mut plan = self.plan.lock().unwrap_or_else(|error| error.into_inner());
        if self.head(stream) != full {
            return Advance::Moved;
        }
        let Some(&next) = plan.free.front() else {
            if plan.retiring.is_some() {
                return Advance::Busy;
            }
            return match self.choose(&mut plan) {
                Some((part, why)) => Advance::Retire(part, why),
                None => Advance::Busy,
            };
        };
        {
            let snapshot = self.snapshots[next as usize]
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some(snapshot) = snapshot.as_ref()
                && !grace.passed(snapshot, skip)
            {
                return Advance::Wait(snapshot.clone());
            }
        }
        // An install that took its place in the part before it went has
        // not given it back: its writes would land in the part's next code.
        if self.writers[next as usize].0.load(Ordering::SeqCst) != 0 {
            return Advance::Busy;
        }
        plan.free.pop_front();
        let generation = self.opened.fetch_add(1, Ordering::AcqRel);
        if full != NONE {
            let old = full & (MAX_PARTS as u32 - 1);
            plan.state[old as usize] = State::Full;
            plan.full[stream].push_back(old);
            self.filled[old as usize].store(generation, Ordering::Relaxed);
        }
        assert!(generation < NONE >> PART_BITS, "ring generations exhausted");
        let part = next as usize;
        self.holds[part].store(generation, Ordering::Release);
        self.kind[part].store(stream as u32, Ordering::Relaxed);
        self.entered[part].0.store(0, Ordering::Relaxed);
        self.installed[part].store(0, Ordering::Relaxed);
        self.dropped[part].store(0, Ordering::Relaxed);
        self.refs[part].store(0, Ordering::Relaxed);
        self.live[part].store(true, Ordering::Release);
        plan.state[part] = State::Open;
        // A swap, not a store: it reads the last take's compare-exchange,
        // and with it every writer counted before one.
        self.cursors[stream].swap(cursor(head(generation, next), 0), Ordering::SeqCst);
        if plan.free.is_empty()
            && plan.retiring.is_none()
            && let Some((part, why)) = self.choose(&mut plan)
        {
            return Advance::Retire(part, why);
        }
        Advance::Moved
    }

    /// The part to take away next, marked going (see the module's rules).
    fn choose(&self, plan: &mut Plan) -> Option<(u32, Why)> {
        let latest = self.generation();
        let parts = self.parts;
        let live: u64 = (0..parts)
            .filter(|&part| plan.state[part as usize] != State::Free)
            .fold(0, |bits, part| bits | 1 << part);
        let free =
            |part: u32| self.refs[part as usize].load(Ordering::Acquire) & live & !(1 << part) == 0;
        let settled = |part: u32| self.settled(part, latest);
        // Free of references, filled a while ago, and written by no
        // install: what every choice but the last resort takes.
        let fit = |part: u32| {
            free(part) && settled(part) && self.writers[part as usize].0.load(Ordering::SeqCst) == 0
        };
        let holey = |part: u32| {
            let (installed, dropped) = (
                self.installed[part as usize].load(Ordering::Relaxed),
                self.dropped[part as usize].load(Ordering::Relaxed),
            );
            installed >= HOLE_BLOCKS && dropped * 4 >= installed * HOLE_QUARTERS
        };
        let [young, tenured] = &plan.full;
        let young_owned = young.len() as u32 + u32::from(self.head(YOUNG) != NONE);
        let chosen = young
            .iter()
            .chain(tenured)
            .copied()
            .find(|&part| holey(part) && fit(part))
            .map(|part| (part, Why::Holes))
            .or_else(|| {
                let &oldest = tenured.front()?;
                let aged = self.holds[oldest as usize].load(Ordering::Acquire) + AGE_TURNS * parts
                    <= latest;
                (aged && fit(oldest)).then_some((oldest, Why::Aged))
            })
            .or_else(|| {
                let first =
                    self.young_parts == 0 || tenured.is_empty() || young_owned > self.young_parts;
                // The oldest that fits: first in, first out.
                let oldest = young.iter().copied().find(|&part| first && fit(part))?;
                Some((oldest, Why::Young))
            })
            .or_else(|| {
                let coldest = tenured
                    .iter()
                    .copied()
                    .filter(|&part| fit(part))
                    .min_by_key(|&part| self.entered[part as usize].0.load(Ordering::Relaxed))?;
                // The counts start over: the next choice weighs what the
                // parts are entered from now on.
                for part in tenured.iter() {
                    self.entered[*part as usize].0.store(0, Ordering::Relaxed);
                }
                Some((coldest, Why::Cold))
            })
            .or_else(|| {
                // Nothing else fits: the oldest settled full part free of
                // references (one always is, as references go from older
                // parts to newer ones and a quarter turn of parts at most
                // filled recently), else the oldest, which no live part
                // refers to. An install still writing into it finds its
                // part gone when it publishes, and installs again.
                let oldest = |settled: bool| {
                    young
                        .iter()
                        .chain(tenured)
                        .copied()
                        .filter(|&part| !settled || (self.settled(part, latest) && free(part)))
                        .min_by_key(|&part| self.holds[part as usize].load(Ordering::Acquire))
                };
                oldest(true).or_else(|| oldest(false)).map(|part| {
                    let why = match self.kind[part as usize].load(Ordering::Relaxed) {
                        0 => Why::Young,
                        _ => Why::Aged,
                    };
                    (part, why)
                })
            })?;
        let (part, why) = chosen;
        self.going(plan, part, why);
        Some((part, why))
    }

    /// Mark full `part` going for `why`.
    fn going(&self, plan: &mut Plan, part: u32, why: Why) {
        for list in &mut plan.full {
            list.retain(|&held| held != part);
        }
        plan.state[part as usize] = State::Retiring;
        plan.retiring = Some(part);
        self.live[part as usize].store(false, Ordering::Release);
        self.outs[why as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Choose `part` to go, as [`Advance::Retire`] would, if it is full and
    /// no part is going: what an install meets when another PE's advance
    /// chose its part between its take and its publish.
    #[cfg(test)]
    pub(in crate::machine::engine) fn choose_part(&self, part: u32) -> bool {
        let mut plan = self.plan.lock().unwrap_or_else(|error| error.into_inner());
        if plan.state[part as usize] != State::Full || plan.retiring.is_some() {
            return false;
        }
        self.going(&mut plan, part, Why::Aged);
        true
    }

    /// Whether `part` filled at least a quarter turn before generation
    /// `latest`: installs that took their places in it before it filled
    /// have had that long to publish.
    fn settled(&self, part: u32, latest: u32) -> bool {
        self.filled[part as usize].load(Ordering::Relaxed) + (self.parts / 4).max(1) <= latest
    }

    /// The install that took `place` published its code, or gave it up: the
    /// place no longer holds its part from being opened again.
    pub(in crate::machine::engine) fn release(&self, place: Place) {
        let before = self.writers[place.part as usize]
            .0
            .fetch_sub(1, Ordering::Release);
        debug_assert!(before != 0, "a place released once");
    }

    /// The caller of [`Advance::Retire`] took away `part`'s code, and
    /// `snapshot` was taken after: the part is reused once that passed.
    pub(in crate::machine::engine) fn retired(&self, part: u32, snapshot: Snapshot) {
        let mut plan = self.plan.lock().unwrap_or_else(|error| error.into_inner());
        *self.snapshots[part as usize]
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(snapshot);
        for refs in self.refs.iter() {
            refs.fetch_and(!(1 << part), Ordering::AcqRel);
        }
        self.retired[part as usize].store(
            self.holds[part as usize].load(Ordering::Acquire) + 1,
            Ordering::Release,
        );
        plan.state[part as usize] = State::Free;
        plan.free.push_back(part);
        if plan.retiring == Some(part) {
            plan.retiring = None;
        }
    }

    /// One more than the generation `part` last went in; 0 for none.
    pub(in crate::machine::engine) fn retired_through(&self, part: usize) -> u32 {
        self.retired[part].load(Ordering::Acquire)
    }

    /// The generation of `part`'s last opening.
    pub(in crate::machine::engine) fn holds(&self, part: usize) -> u32 {
        self.holds[part].load(Ordering::Acquire)
    }

    /// The generation `part` takes code of.
    pub(in crate::machine::engine) fn kind(&self, part: usize) -> usize {
        self.kind[part].load(Ordering::Relaxed) as usize
    }

    /// Whether `place`'s part still holds its generation's code: false from
    /// the choice that takes it away on. A publish checks it under the
    /// board's code lock: a retirement chooses its part before it lists the
    /// part's blocks under that lock, so a block it did not list sees it.
    pub(in crate::machine::engine) fn live(&self, place: Place) -> bool {
        let part = place.part as usize;
        self.live[part].load(Ordering::Acquire) && self.holds(part) == place.generation
    }

    /// A fetch found a block of `part`: one atomic add, no lock. PEs add
    /// their counts in batches ([`Self::entered_by`]); tests count one.
    #[cfg(test)]
    pub(in crate::machine::engine) fn entered(&self, part: usize) {
        self.entered_by(part, 1);
    }

    /// `count` fetches found blocks of `part`, which a PE kept and adds at
    /// once (`Machine::entered`).
    pub(in crate::machine::engine) fn entered_by(&self, part: usize, count: u32) {
        self.entered[part].0.fetch_add(count, Ordering::Relaxed);
    }

    /// `part` took a block; under the board's code lock.
    pub(in crate::machine::engine) fn installed(&self, part: usize) {
        self.installed[part].fetch_add(1, Ordering::Relaxed);
    }

    /// A block of `part` left the index before its part went; under the
    /// board's code lock.
    pub(in crate::machine::engine) fn dropped(&self, part: usize) {
        self.dropped[part].fetch_add(1, Ordering::Relaxed);
    }

    /// Code of part `from` is about to jump into part `to`: `to` does not go
    /// while `from` holds code. False, and nothing noted, when `to` was
    /// chosen to go already: the caller makes no such jump. Under the plan
    /// lock, which every choice holds, so no choice comes between the check
    /// and the note. The caller holds its place in `to` (or the code lock),
    /// so a live `to` is the generation it took its place in.
    pub(in crate::machine::engine) fn refer(&self, from: usize, to: usize) -> bool {
        if from == to {
            return true;
        }
        let plan = self.plan.lock().unwrap_or_else(|error| error.into_inner());
        if !matches!(plan.state[to], State::Open | State::Full) {
            return false;
        }
        self.refs[to].fetch_or(1 << from, Ordering::AcqRel);
        true
    }

    /// The parts each generation holds (open or full).
    pub(in crate::machine::engine) fn owned(&self) -> [u32; 2] {
        let plan = self.plan.lock().unwrap_or_else(|error| error.into_inner());
        core::array::from_fn(|stream| {
            let open = (self.cursors[stream].load(Ordering::Acquire) >> 32) as u32 != NONE;
            plan.full[stream].len() as u32 + u32::from(open)
        })
    }

    /// Parts chosen to go so far, by [`Why`].
    pub(in crate::machine::engine) fn outs(&self) -> [u64; 4] {
        core::array::from_fn(|why| self.outs[why].load(Ordering::Relaxed))
    }
}
