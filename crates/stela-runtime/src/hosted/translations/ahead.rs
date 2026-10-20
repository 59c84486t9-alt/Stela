//! Translation ahead of execution for a hosted process, on background
//! threads off the guest's path (the role Rosetta's AOT translation plays
//! for an image, `docs/research/rosetta.md`).
//!
//! The engine's compiled blocks seed it. Each one's static successors
//! (branch targets, fall-throughs and call continuations) are prepared
//! before the guest reaches them, and the first block compiled in an image
//! the process has not met yet makes the image's own metadata
//! (`super::image`) name every entry it has: those are prepared too, and
//! their successors inside the image. A prepared block is the block the
//! engine would compile at that PC from those page bytes in that context
//! (`machine::Preparation`), so a thread's engine installs it instead of
//! compiling, and the store's workers prove and persist it like any other.
//!
//! Nothing here executes guest code or changes guest state: a wrong entry
//! costs time only. Pages are read through `copy_in`, which refuses an
//! unmapped page instead of faulting, and are keyed by their bytes as read,
//! so a page the guest changes later simply misses.
use super::{
    Shared,
    image::{self, Memory},
    lock,
};
use crate::machine::{Offer, Preparation, Prepared, window};
use crate::translations::{self, Digest, PAGE_BYTES};
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    ops::Range,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

/// The environment variable that sets how far translation ahead of
/// execution reaches ([`Scope`]): `off` (the default), `successors` or
/// `images`.
pub const VARIABLE: &str = "STELA_AHEAD_TRANSLATION";
/// How many successor steps ahead of the engine's own blocks a process
/// prepares, outside whole images.
const SUCCESSOR_DEPTH: u8 = 2;
/// The most blocks one process prepares ahead.
const MAX_BLOCKS: u64 = 1 << 18;
/// The most entry PCs one process queues or has prepared.
const MAX_SEEN: usize = 1 << 20;
/// The most images one process reads.
const MAX_IMAGES: usize = 4096;
/// Host threads per worker: the guest's own threads come first.
const HOST_THREADS_PER_WORKER: usize = 4;
const MAX_WORKERS: usize = 4;

/// What ahead-of-time translation did, for `--statistics`.
#[derive(Debug, Default)]
pub struct Counters {
    pub images: AtomicU64,
    pub entries: AtomicU64,
    pub prepared: AtomicU64,
    pub already: AtomicU64,
    pub refused: AtomicU64,
}

pub static COUNTERS: Counters = Counters {
    images: AtomicU64::new(0),
    entries: AtomicU64::new(0),
    prepared: AtomicU64::new(0),
    already: AtomicU64::new(0),
    refused: AtomicU64::new(0),
};

/// How far translation ahead of execution reaches. A process translates
/// nothing ahead by default: on a busy host the blocks it prepares that
/// never run cost more than the compiles they save
/// (`docs/design/runtime.md#translation-ahead-of-execution`). Whole images
/// are translated once, for every later run, by `stelad`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    Off,
    /// The static successors of the engine's blocks, [`SUCCESSOR_DEPTH`]
    /// steps ahead.
    Successors,
    /// Also every entry each image the process runs names, and their
    /// successors inside the image.
    Images,
}

impl Scope {
    /// The scope the environment names.
    pub fn from_environment() -> Self {
        match std::env::var(VARIABLE).as_deref() {
            Ok("successors") => Self::Successors,
            Ok("images") => Self::Images,
            _ => Self::Off,
        }
    }
}

/// One piece of work.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Job {
    /// Find and read the image holding this address.
    Image(u64),
    /// Prepare the block at this PC, following successors inside `within`
    /// while `depth` lasts.
    Block {
        pc: u64,
        within: (u64, u64),
        depth: u8,
    },
}

/// Anywhere: a block outside every image read.
const ANYWHERE: (u64, u64) = (0, u64::MAX);

#[derive(Default)]
struct State {
    queue: VecDeque<Job>,
    /// Entry PCs queued or prepared.
    seen: HashSet<u64>,
    /// Pages the image search has covered.
    searched: HashSet<u64>,
    /// The `__TEXT` ranges of the images read.
    images: Vec<Range<u64>>,
    /// How the engine compiles, by address class: the last preparation an
    /// offer of that class carried.
    preparations: BTreeMap<u64, Arc<Preparation>>,
    blocks: u64,
    workers: usize,
    closed: bool,
}

#[derive(Default)]
pub(super) struct Ahead {
    state: Mutex<State>,
    changed: Condvar,
}

/// The process's memory, read without faulting.
struct Process;

impl Memory for Process {
    fn read(&self, address: u64, buffer: &mut [u8]) -> bool {
        crate::hosted::host::copy_in(address, buffer)
    }
}

static SCOPE: std::sync::OnceLock<Scope> = std::sync::OnceLock::new();

fn scope() -> Scope {
    *SCOPE.get_or_init(Scope::from_environment)
}

fn workers() -> usize {
    let threads = std::thread::available_parallelism().map_or(1, usize::from);
    (threads / HOST_THREADS_PER_WORKER).clamp(1, MAX_WORKERS)
}

impl State {
    fn image_of(&self, pc: u64) -> Option<(u64, u64)> {
        self.images
            .iter()
            .find(|range| range.contains(&pc))
            .map(|range| (range.start, range.end))
    }

    /// Queue the block at `pc` unless it was queued before or the budget
    /// is spent.
    fn queue_block(&mut self, pc: u64, within: (u64, u64), depth: u8) -> bool {
        if pc & 3 != 0
            || !(within.0..within.1).contains(&pc)
            || self.seen.len() >= MAX_SEEN
            || !self.seen.insert(pc)
        {
            return false;
        }
        self.queue.push_back(Job::Block { pc, within, depth });
        true
    }
}

impl Ahead {
    /// The engine compiled `offer`'s block: prepare its successors, and
    /// read its image if the process has not.
    pub(super) fn note(&self, shared: &'static Shared, offer: &Offer) {
        let scope = scope();
        if scope == Scope::Off {
            return;
        }
        let mut state = lock(&self.state);
        if state.closed {
            return;
        }
        let class = translations::address_class(offer.page);
        state.preparations.insert(class, offer.preparation.clone());
        state.seen.insert(offer.pc);
        let image = state.image_of(offer.pc);
        let (within, depth) = match image {
            Some(image) if scope == Scope::Images => (image, u8::MAX),
            _ => (ANYWHERE, SUCCESSOR_DEPTH),
        };
        let mut queued = false;
        for &successor in &offer.successors {
            queued |= state.queue_block(successor, within, depth - 1);
        }
        if scope == Scope::Images
            && image.is_none()
            && state.images.len() < MAX_IMAGES
            && !state.searched.contains(&offer.page)
        {
            state.searched.insert(offer.page);
            state.queue.push_front(Job::Image(offer.pc));
            queued = true;
        }
        if !queued {
            return;
        }
        if state.workers < workers() {
            state.workers += 1;
            drop(state);
            let spawned = std::thread::Builder::new()
                .name("stela-ahead".into())
                .spawn(move || shared.ahead.work(shared));
            if spawned.is_err() {
                lock(&self.state).workers -= 1;
            }
            return;
        }
        drop(state);
        self.changed.notify_one();
    }

    /// Stop: queued work is dropped, and workers end after their current
    /// job.
    pub(super) fn close(&self) {
        let mut state = lock(&self.state);
        state.closed = true;
        state.queue.clear();
        drop(state);
        self.changed.notify_all();
    }

    fn work(&self, shared: &'static Shared) {
        lower_priority();
        loop {
            let mut state = lock(&self.state);
            let job = loop {
                if state.closed {
                    state.workers -= 1;
                    return;
                }
                if let Some(job) = state.queue.pop_front() {
                    break job;
                }
                state = self
                    .changed
                    .wait(state)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            };
            drop(state);
            match job {
                Job::Image(address) => self.read_image(address),
                Job::Block { pc, within, depth } => self.prepare(shared, pc, within, depth),
            }
        }
    }

    /// Read the image holding `address` and queue its entries.
    fn read_image(&self, address: u64) {
        let mut searched = Vec::new();
        let header = image::find_header(&Process, address, |page| searched.push(page));
        let read = header.and_then(|header| image::read(&Process, header));
        let mut state = lock(&self.state);
        state.searched.extend(searched);
        let Some(read) = read else {
            return;
        };
        if state
            .images
            .iter()
            .any(|range| range.start == read.text.start)
        {
            return;
        }
        COUNTERS.images.fetch_add(1, Ordering::Relaxed);
        let within = (read.text.start, read.text.end);
        state.images.push(read.text);
        for entry in read.entries {
            if state.queue_block(entry, within, u8::MAX) {
                COUNTERS.entries.fetch_add(1, Ordering::Relaxed);
            }
        }
        drop(state);
        self.changed.notify_all();
    }

    /// Prepare the block at `pc` as the engine would, unless the process
    /// or its store already has it.
    fn prepare(&self, shared: &'static Shared, pc: u64, within: (u64, u64), depth: u8) {
        let page = pc & !(PAGE_BYTES as u64 - 1);
        let preparation = {
            let state = lock(&self.state);
            if state.blocks >= MAX_BLOCKS {
                return;
            }
            match state.preparations.get(&translations::address_class(page)) {
                Some(preparation) => preparation.clone(),
                None => return,
            }
        };
        let Some(successors) = prepare_at(shared, &Process, &preparation, pc) else {
            return;
        };
        let mut state = lock(&self.state);
        state.blocks += 1;
        if depth != 0 {
            for &successor in &successors {
                state.queue_block(successor, within, depth - 1);
            }
        }
        drop(state);
        self.changed.notify_all();
    }
}

/// Prepare the block at `pc` of `memory` through `preparation` and hand it
/// to the store, unless the process or the store has it: the successors of
/// a block prepared now.
pub(super) fn prepare_at(
    shared: &'static Shared,
    memory: &dyn Memory,
    preparation: &Arc<Preparation>,
    pc: u64,
) -> Option<Vec<u64>> {
    let page = pc & !(PAGE_BYTES as u64 - 1);
    let mut bytes = vec![0u8; PAGE_BYTES];
    if !memory.read(page, &mut bytes) {
        return None;
    }
    let key = Digest::of(&bytes);
    let context = preparation.context(page);
    let offset = (pc - page) as usize;
    let already = shared.has_prepared(&key, pc, &context)
        || shared
            .record(&key)
            .is_some_and(|record| record.find(offset as u16, &context).is_some());
    if already {
        COUNTERS.already.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let mut source = bytes[offset..offset + window(pc)].to_vec();
    preparation.admit(&mut source);
    let length = source.len();
    let Ok(Prepared::Block {
        compiled,
        input,
        successors,
    }) = preparation.prepare(&source, pc, length)
    else {
        COUNTERS.refused.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    COUNTERS.prepared.fetch_add(1, Ordering::Relaxed);
    shared.prepare(Offer {
        key,
        page,
        pc,
        context,
        input: source[..input].to_vec(),
        preparation: preparation.clone(),
        block: compiled,
        successors: successors.clone(),
    });
    Some(successors)
}

/// Run below the guest's threads: the host's utility QoS class.
fn lower_priority() {
    // SAFETY: changes only the calling thread's scheduling class.
    unsafe {
        libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_UTILITY, 0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_are_queued_once_word_aligned_within_the_budget() {
        let mut state = State::default();
        let within = (0x1000, 0x2000);
        assert!(state.queue_block(0x1000, within, 1));
        assert!(!state.queue_block(0x1000, within, 1));
        assert!(!state.queue_block(0x1002, within, 1));
        assert!(!state.queue_block(0x2000, within, 1));
        state.images.push(0x1000..0x2000);
        assert_eq!(state.image_of(0x1fff), Some(within));
        assert_eq!(state.image_of(0x2000), None);
        assert_eq!(state.queue.len(), 1);
    }
}
