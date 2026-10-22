//! Original fixed-family buffer-cache private allocation/reuse/release.
//!
//! These are the inner private phases after scheduler eligibility/context
//! override, plus retained physical selector publication through Access.
//! They acknowledge no AP command and establish no native quiescence: the
//! actual native owner must settle its flush/drain before private release.

use super::{
    Submission, cache_input::BufferCacheInput, ownership::Identity, render_context::Program,
    resources::Lease,
};

pub(crate) const RECORDS: usize = 8;
pub(crate) const CONFIGURATION: u32 = 0x11900;
pub(crate) const SELECTORS: [u32; 3] = [0x11860, 0x118a0, 0x118e0];
const PIPELINES: usize = 3;
const SLOTS: usize = 6;
const CAPACITY: u32 = 1024;
const POSITION_MASK: u32 = CAPACITY - 1;
const MATCH_MASK: u32 = 0x0fff_ffff;

/// Complete qword pair copied from the scheduler's descriptor +0x48. The
/// upper word is retained even though allocation/selector do not interpret it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Descriptor {
    address: u64,
    word: u32,
    tail: u32,
}
impl Descriptor {
    pub fn from_scheduler(input: &BufferCacheInput, old_word: u32, tail: u32) -> Self {
        Self {
            address: input.address(),
            word: input.descriptor_word(old_word),
            tail,
        }
    }
    fn units(self) -> u32 {
        (self.word >> 6) & 0x7ff
    }
    fn matches(self, other: Self) -> bool {
        self.address == other.address && (self.word ^ other.word) & MATCH_MASK == 0
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Record {
    descriptor: Descriptor,
    start: u32,
    references: u32,
}
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Range {
    start: u32,
    units: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Allocation {
    NoUnits,
    Assigned,
    Unavailable,
}

/// Values consumed by the following physical selector. Producing this
/// snapshot neither performs those stores nor grants execution/retirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Selection {
    pub configuration: Option<(u32, u64)>,
    pub selector: (u32, u64),
    pub first_reference: bool,
}

pub trait Access {
    fn check_available(&self) -> Result<(), &'static str>;
    fn check_owner(
        &self,
        program: Program,
        submission: &Submission,
        lease: Lease,
        pool: &Identity,
    ) -> Result<(), &'static str>;
    fn write_native(&mut self, offset: u32, value: u64) -> Result<(), &'static str>;
    fn owner_identity(&self) -> Result<Identity, &'static str>;
    fn check_quiesced(
        &self,
        program: Program,
        submission: &Submission,
        lease: Lease,
        pool: &Identity,
    ) -> Result<(), &'static str>;
}

#[derive(Debug)]
struct Pending {
    submission: Submission,
    lease: Lease,
    outcome: Allocation,
    selection: Option<Selection>,
    phase: Option<Identity>,
    next: u8,
    done: bool,
}

/// Fresh state only at the original cold initializer's private memset and
/// setup boundary. No Default/clear/reset API can discard live ownership.
#[derive(Debug)]
pub struct Pool {
    identity: Identity,
    program: Program,
    records: [Record; RECORDS],
    used: u8,
    free: [Range; RECORDS],
    free_mask: u8,
    lookup: [[Option<usize>; SLOTS]; PIPELINES],
    owners: [[Option<Submission>; SLOTS]; PIPELINES],
    phases: [[Option<Identity>; SLOTS]; PIPELINES],
    minimum: u32,
    wake: bool,
    activation: [u64; PIPELINES],
    pending: Option<Pending>,
}
impl Pool {
    pub fn after_cold_initialization(program: Program) -> Self {
        let mut free = [Range::default(); RECORDS];
        free[0].units = CAPACITY;
        Self {
            identity: Identity::new(),
            program,
            records: [Record::default(); RECORDS],
            used: 0,
            free,
            free_mask: 1,
            lookup: [[None; SLOTS]; PIPELINES],
            owners: core::array::from_fn(|_| core::array::from_fn(|_| None)),
            phases: core::array::from_fn(|_| core::array::from_fn(|_| None)),
            minimum: u32::MAX,
            wake: false,
            activation: [0; PIPELINES],
            pending: None,
        }
    }
    pub fn program(&self) -> Program {
        self.program
    }
    pub fn active(&self) -> bool {
        self.used != 0
            || self.pending.is_some()
            || self.owners.iter().flatten().any(Option::is_some)
    }
    pub fn wake_pending(&self) -> bool {
        self.wake
    }
    /// Only the actual scheduler's event-consumption phase may consume it.
    pub fn take_scheduler_wake(&mut self) -> bool {
        core::mem::take(&mut self.wake)
    }
    pub fn activation_mask(&self, pipe: u8) -> Result<u64, &'static str> {
        self.activation
            .get(usize::from(pipe))
            .copied()
            .ok_or("GFX buffer-cache activation pipeline is outside its table")
    }
    pub fn abort_pending(&mut self) -> Result<(), &'static str> {
        if self.pending.is_some() {
            return Err("GFX buffer-cache pending selector abort effects are not qualified");
        }
        Ok(())
    }
    fn slot(lease: Lease) -> Result<(usize, usize), &'static str> {
        let (pipe, slot) = (usize::from(lease.pipe), usize::from(lease.slot));
        if pipe >= PIPELINES || slot >= SLOTS {
            return Err("GFX buffer-cache lease exceeds the source pipeline/slot table");
        }
        Ok((pipe, slot))
    }
    /// Inner allocation only: earlier source eligibility, optional context
    /// override and scheduler-output publications remain the caller's phases.
    fn allocate_private(
        &mut self,
        lease: Lease,
        descriptor: Descriptor,
    ) -> Result<Allocation, &'static str> {
        let (pipe, slot) = Self::slot(lease)?;
        if self.lookup[pipe][slot].is_some() || self.owners[pipe][slot].is_some() {
            return Err("GFX buffer-cache execution slot still owns its previous allocation");
        }
        let units = descriptor.units();
        if units == 0 {
            return Ok(Allocation::NoUnits);
        }
        if let Some(index) = (0..RECORDS)
            .find(|&i| self.used & (1 << i) != 0 && self.records[i].descriptor.matches(descriptor))
        {
            self.records[index].references += 1; // at most eighteen source slots
            self.lookup[pipe][slot] = Some(index);
            self.minimum = u32::MAX;
            return Ok(Allocation::Assigned);
        }
        let best = (0..RECORDS)
            .filter(|&i| self.free_mask & (1 << i) != 0 && self.free[i].units >= units)
            .min_by_key(|&i| (self.free[i].units, i));
        let Some(free) = best else {
            self.minimum = self.minimum.min(units);
            return Ok(Allocation::Unavailable);
        };
        // The original no-free-record branch forms index0xff. Its out-of-
        // table private store is not a supported allocation or fake wait.
        let index = (0..RECORDS)
            .find(|&i| self.used & (1 << i) == 0)
            .ok_or("GFX buffer-cache allocation exhausts eight source records")?;
        let range = &mut self.free[free];
        self.records[index] = Record {
            descriptor,
            start: range.start,
            references: 1,
        };
        self.used |= 1 << index;
        range.start = (range.start + units) & POSITION_MASK;
        range.units -= units;
        if range.units == 0 {
            self.free_mask &= !(1 << free);
        }
        self.lookup[pipe][slot] = Some(index);
        self.minimum = u32::MAX;
        Ok(Allocation::Assigned)
    }
    pub fn allocate_eligible(
        &mut self,
        input: &BufferCacheInput,
        lease: Lease,
        old_word: u32,
        tail: u32,
    ) -> Result<(), &'static str> {
        if self.pending.is_some() {
            return Err("GFX buffer-cache still owns an unfinished allocation/selector phase");
        }
        if input.submission().encoding != super::Encoding::Fixed {
            return Err("GFX buffer-cache pool does not implement the newer native packet ABI");
        }
        let expected_pipe = match input.submission().command.kind {
            crate::platform::apple::agx::channel::Kind::Ta => 0,
            crate::platform::apple::agx::channel::Kind::ThreeD
            | crate::platform::apple::agx::channel::Kind::FastBlit => 1,
            crate::platform::apple::agx::channel::Kind::Cl => 2,
            _ => return Err("GFX buffer-cache descriptor does not own executable work"),
        };
        if lease.pipe != expected_pipe || input.submission().context >= 64 {
            return Err(
                "GFX buffer-cache execution pipeline/context differs from its accepted work",
            );
        }
        let descriptor = Descriptor::from_scheduler(input, old_word, tail);
        let outcome = self.allocate_private(lease, descriptor)?;
        if outcome != Allocation::Unavailable {
            self.owners[usize::from(lease.pipe)][usize::from(lease.slot)] =
                Some(input.submission().clone());
        }
        let selection = if outcome == Allocation::Unavailable {
            None
        } else {
            Some(self.selection(lease)?)
        };
        self.pending = Some(Pending {
            submission: input.submission().clone(),
            lease,
            outcome,
            selection,
            phase: None,
            next: 0,
            done: selection.is_none(),
        });
        Ok(())
    }
    /// The original native setup/resource phases occur between allocation
    /// and selector. The actual adapter must qualify that exact owner here.
    pub fn advance_selection(&mut self, access: &mut dyn Access) -> Result<(), &'static str> {
        let pending = self
            .pending
            .as_mut()
            .ok_or("GFX buffer-cache has no pending selector")?;
        if pending.done {
            return Ok(());
        }
        access.check_available()?;
        access.check_owner(
            self.program,
            &pending.submission,
            pending.lease,
            &self.identity,
        )?;
        let identity = access.owner_identity()?;
        if pending
            .phase
            .as_ref()
            .is_some_and(|old| !old.same(&identity))
        {
            return Err("GFX buffer-cache selector belongs to another accepted parameter helper");
        }
        pending.phase = Some(identity.clone());
        self.phases[usize::from(pending.lease.pipe)][usize::from(pending.lease.slot)] =
            Some(identity);
        let selection = pending.selection.unwrap();
        if pending.next == 0 {
            if let Some((offset, value)) = selection.configuration {
                access.write_native(offset, value)?;
                if self.program.policy() == super::resources::Policy::G13X {
                    self.activation[usize::from(pending.lease.pipe)] |= 1u64 << pending.lease.slot;
                }
            }
            pending.next = 1;
        }
        access.write_native(selection.selector.0, selection.selector.1)?;
        pending.next = 2;
        pending.done = true;
        Ok(())
    }
    pub fn finish(&mut self) -> Result<Allocation, &'static str> {
        if self.pending.as_ref().is_none_or(|p| !p.done) {
            return Err("GFX buffer-cache selector still owns unfinished native effects");
        }
        Ok(self.pending.take().unwrap().outcome)
    }
    pub fn selection(&self, lease: Lease) -> Result<Selection, &'static str> {
        let (pipe, slot) = Self::slot(lease)?;
        let native = SELECTORS[pipe];
        let Some(index) = self.lookup[pipe][slot] else {
            return Ok(Selection {
                configuration: None,
                selector: (native, 0),
                first_reference: false,
            });
        };
        let record = &self.records[index];
        let first = record.references == 1;
        let pointer = ((record.descriptor.address & !3) & 0x8fff_ffff_ffff_ffff) + 1;
        Ok(Selection {
            configuration: first.then_some((
                CONFIGURATION + index as u32 * 8,
                u64::from(record.start | record.descriptor.units() << 16),
            )),
            selector: (
                native,
                pointer | ((index as u64) << 60) | if first { 2 } else { 0 },
            ),
            first_reference: first,
        })
    }
    /// Original release's private part. This does not execute or replace
    /// the preceding physical invalidation/drain or clear its native owner.
    pub fn release_after_native_quiescence(
        &mut self,
        access: &mut dyn Access,
        lease: Lease,
    ) -> Result<(), &'static str> {
        if self.pending.is_some() {
            return Err("GFX buffer-cache release precedes selector settlement");
        }
        access.check_available()?;
        let (pipe, slot) = Self::slot(lease)?;
        if let Some(owner) = self.owners[pipe][slot].as_ref() {
            let identity = access.owner_identity()?;
            if self.phases[pipe][slot]
                .as_ref()
                .is_some_and(|old| !old.same(&identity))
            {
                return Err(
                    "GFX buffer-cache release belongs to another accepted parameter helper",
                );
            }
            access.check_quiesced(self.program, owner, lease, &self.identity)?;
        }
        let Some(index) = self.lookup[pipe][slot] else {
            self.owners[pipe][slot] = None;
            self.phases[pipe][slot] = None;
            self.activation[pipe] &= !(1 << slot);
            return Ok(());
        };
        let record = self.records[index];
        if record.references == 0 || self.used & (1 << index) == 0 {
            return Err("GFX buffer-cache lookup has no live source record");
        }
        // Preflight the independent free-table bound before private effects.
        // Every valid source free region is coalesced, including across1024.
        let mut next_free = self.free;
        let mut mask = self.free_mask;
        let mut start = record.start;
        let mut units = record.descriptor.units();
        let mut selected: Option<usize> = None;
        if record.references == 1 {
            for (i, next) in next_free.iter_mut().enumerate() {
                if self.free_mask & (1 << i) == 0 {
                    continue;
                }
                let range = self.free[i];
                let end = (start + units) & POSITION_MASK;
                if (range.start + range.units) & POSITION_MASK != start && end != range.start {
                    continue;
                }
                units += range.units;
                if end != range.start {
                    start = range.start;
                }
                *next = Range { start, units };
                if let Some(old) = selected {
                    mask &= !(1 << old);
                }
                selected = Some(i);
            }
            if selected.is_none() {
                let i = (0..RECORDS)
                    .find(|&i| mask & (1 << i) == 0)
                    .ok_or("GFX buffer-cache release exhausts eight free ranges")?;
                next_free[i] = Range { start, units };
                mask |= 1 << i;
                selected = Some(i);
            }
            if units > CAPACITY {
                return Err("GFX buffer-cache release overlaps its source capacity");
            }
        }
        self.lookup[pipe][slot] = None;
        self.owners[pipe][slot] = None;
        self.phases[pipe][slot] = None;
        self.activation[pipe] &= !(1 << slot);
        self.records[index].references -= 1;
        if record.references != 1 {
            return Ok(());
        }
        self.used &= !(1 << index);
        self.free = next_free;
        self.free_mask = mask;
        if self.free[selected.unwrap()].units >= self.minimum {
            self.wake = true;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::agx::{
        channel::{Command, Kind, Stamp},
        initdata::Root,
        ring::tests::Flat,
        work_decode::{Encoding, render_context::G13XVariant, resources::Policy},
    };
    use alloc::{format, vec::Vec};

    fn programs() -> Vec<Program> {
        let root = Root {
            rings: 0x100,
            page_1660: 1,
            object_358: 2,
            object_848: 3,
            object_928: 4,
            object_930: 5,
            object_368: 6,
            config: [0; 0x68],
        };
        let mut memory = Flat::new(0, 0x3000);
        memory.put_u64(0x100, 0x1000);
        let mut result = alloc::vec![
            Program::fixed(Policy::G13G, *b"b100").unwrap(),
            Program::fixed(Policy::G14G, *b"b000").unwrap()
        ];
        for (variant, mode) in [
            (G13XVariant::A000, 3),
            (G13XVariant::A000, 0),
            (G13XVariant::B000, 3),
            (G13XVariant::C000, 3),
        ] {
            memory.put_u32(0x20d4, mode);
            result.push(Program::g13x(variant, &root, &mut memory).unwrap());
        }
        result
    }
    fn input(
        lease: Lease,
        context: u32,
        address: u64,
        units: u32,
        policy: u32,
    ) -> BufferCacheInput {
        let (kind, field) = match lease.pipe {
            0 => (Kind::Ta, 0x558),
            1 => (Kind::ThreeD, 0x8bc),
            _ => (Kind::Cl, 0x284),
        };
        let sub = Submission {
            command: Command { va: 0x1000, kind },
            encoding: Encoding::Fixed,
            counter: address,
            context,
            stamp: Stamp {
                driver: 0,
                firmware: 0,
                value: 0,
                index: 0,
            },
            stream: 0x2000,
            stream_bytes: 0x400,
        };
        let mut memory = Flat::new(0x1000, 0x1000);
        memory.put_u64(0x1000 + field, address);
        memory.put_u32(0x1000 + field + 8, units);
        memory.put_u32(0x1000 + field + 12, policy);
        BufferCacheInput::read(&mut memory, &sub).unwrap()
    }
    struct Native {
        program: Program,
        identity: Identity,
        owner: Option<(Submission, Lease)>,
        available: bool,
        quiesced: bool,
        writes: Vec<(u32, u64)>,
        attempts: usize,
        fail: Option<usize>,
        cfg: [Option<u64>; 8],
        selector: [Option<u64>; 3],
    }
    impl Native {
        fn new(program: Program) -> Self {
            Self {
                program,
                identity: Identity::new(),
                owner: None,
                available: true,
                quiesced: true,
                writes: Vec::new(),
                attempts: 0,
                fail: None,
                cfg: [None; 8],
                selector: [None; 3],
            }
        }
        fn bind(&mut self, input: &BufferCacheInput, lease: Lease) {
            self.owner = Some((input.submission().clone(), lease));
        }
    }
    impl Access for Native {
        fn check_available(&self) -> Result<(), &'static str> {
            if self.available {
                Ok(())
            } else {
                Err("retained cache gate")
            }
        }
        fn check_owner(
            &self,
            program: Program,
            sub: &Submission,
            lease: Lease,
            _pool: &Identity,
        ) -> Result<(), &'static str> {
            if program == self.program
                && self
                    .owner
                    .as_ref()
                    .is_some_and(|(s, l)| s == sub && *l == lease)
            {
                Ok(())
            } else {
                Err("foreign cache owner")
            }
        }
        fn check_quiesced(
            &self,
            program: Program,
            sub: &Submission,
            lease: Lease,
            _pool: &Identity,
        ) -> Result<(), &'static str> {
            self.check_owner(program, sub, lease, _pool)?;
            if self.quiesced {
                Ok(())
            } else {
                Err("native cache not drained")
            }
        }
        fn owner_identity(&self) -> Result<Identity, &'static str> {
            Ok(self.identity.clone())
        }
        fn write_native(&mut self, offset: u32, value: u64) -> Result<(), &'static str> {
            let attempt = self.attempts;
            self.attempts += 1;
            if self.fail == Some(attempt) {
                self.fail = None;
                return Err("native cache write fault");
            }
            if (0x11900..0x11940).contains(&offset) && offset & 7 == 0 {
                self.cfg[((offset - 0x11900) / 8) as usize] = Some(value);
            } else if let Some(pipe) = [0x11860, 0x118a0, 0x118e0]
                .iter()
                .position(|&p| p == offset)
            {
                self.selector[pipe] = Some(value);
            } else {
                panic!("unknown native cache target");
            }
            self.writes.push((offset, value));
            Ok(())
        }
    }
    fn publish(
        pool: &mut Pool,
        native: &mut Native,
        lease: Lease,
        address: u64,
        units: u32,
    ) -> BufferCacheInput {
        let input = input(lease, 5, address, units, 9);
        native.bind(&input, lease);
        pool.allocate_eligible(&input, lease, 0xa0000000, 0x11223344)
            .unwrap();
        pool.advance_selection(native).unwrap();
        assert_eq!(
            pool.finish().unwrap(),
            if units == 0 {
                Allocation::NoUnits
            } else {
                Allocation::Assigned
            }
        );
        partition(pool);
        input
    }
    // Independent unit-occupancy/refcount invariant, rather than replaying
    // the source's best-fit/coalescing algorithm in the expected result.
    fn partition(pool: &Pool) {
        let mut counts = [0u8; 1024];
        for i in 0..RECORDS {
            let refs = pool
                .lookup
                .iter()
                .flatten()
                .filter(|slot| **slot == Some(i))
                .count();
            assert_eq!(pool.records[i].references as usize, refs);
            if pool.used & (1 << i) == 0 {
                assert_eq!(refs, 0);
                continue;
            }
            assert!(refs > 0);
            let r = pool.records[i];
            for n in 0..r.descriptor.units() {
                counts[((r.start + n) & 1023) as usize] += 1;
            }
        }
        for i in 0..RECORDS {
            if pool.free_mask & (1 << i) == 0 {
                continue;
            }
            let r = pool.free[i];
            for n in 0..r.units {
                counts[((r.start + n) & 1023) as usize] += 1;
            }
        }
        assert!(counts.iter().all(|&n| n == 1));
    }
    #[test]
    fn original_cache_reuse_preserves_descriptor_and_releases_only_last_reference() {
        for program in programs() {
            let mut pool = Pool::after_cold_initialization(program);
            let mut native = Native::new(program);
            let a = Lease { pipe: 0, slot: 0 };
            let b = Lease { pipe: 1, slot: 0 };
            let first = publish(&mut pool, &mut native, a, 0xffff123400000001, 256);
            assert_eq!(
                native.writes,
                [(0x11900, 0x01000000), (0x11860, 0x8fff123400000003)]
            );
            assert_eq!(pool.records[0].descriptor.tail, 0x11223344);
            assert_eq!(
                pool.activation_mask(0).unwrap(),
                if program.policy() == Policy::G13X {
                    1
                } else {
                    0
                }
            );
            let second = input(b, 5, 0xffff123400000001, 256, 9);
            native.bind(&second, b);
            pool.allocate_eligible(&second, b, 0xb0000000, 0x55667788)
                .unwrap();
            pool.advance_selection(&mut native).unwrap();
            assert_eq!(pool.finish(), Ok(Allocation::Assigned));
            assert_eq!(&native.writes[2..], [(0x118a0, 0x8fff123400000001)]);
            assert_eq!(pool.records[0].references, 2);
            assert_eq!(pool.records[0].descriptor.tail, 0x11223344);
            assert_eq!(pool.records[0].descriptor.word >> 28, 0xa);
            native.bind(&first, a);
            pool.release_after_native_quiescence(&mut native, a)
                .unwrap();
            partition(&pool);
            assert!(pool.active());
            assert_eq!(pool.records[0].references, 1);
            native.bind(&second, b);
            pool.release_after_native_quiescence(&mut native, b)
                .unwrap();
            partition(&pool);
            assert!(!pool.active());
            assert_eq!(pool.free_mask, 1);
            assert_eq!(
                pool.free[0],
                Range {
                    start: 0,
                    units: 1024
                }
            );
            assert_eq!(native.writes.len(), 3); // release cannot invent native clears
            let zero = publish(&mut pool, &mut native, a, 0, 0);
            assert_eq!(native.writes.last(), Some(&(0x11860, 0)));
            native.bind(&zero, a);
            pool.release_after_native_quiescence(&mut native, a)
                .unwrap();
            assert!(!pool.active());
        }
    }
    #[test]
    fn original_cache_circular_coalescing_and_capacity_wake_keep_exact_ranges() {
        for program in programs() {
            let mut pool = Pool::after_cold_initialization(program);
            let mut native = Native::new(program);
            let leases = core::array::from_fn::<_, 4, _>(|i| Lease {
                pipe: 0,
                slot: i as u8,
            });
            let inputs: Vec<_> = leases
                .iter()
                .enumerate()
                .map(|(i, &l)| publish(&mut pool, &mut native, l, 0x1000 + i as u64 * 0x1000, 256))
                .collect();
            assert_eq!(pool.free_mask, 0);
            let wait = Lease { pipe: 1, slot: 0 };
            let request = input(wait, 5, 0xdead, 300, 9);
            pool.allocate_eligible(&request, wait, 0, 0).unwrap();
            assert_eq!(pool.finish(), Ok(Allocation::Unavailable));
            assert_eq!(pool.minimum, 300);
            for i in [1, 3] {
                native.bind(&inputs[i], leases[i]);
                pool.release_after_native_quiescence(&mut native, leases[i])
                    .unwrap();
                partition(&pool);
                assert!(!pool.wake_pending());
            }
            assert_eq!(
                pool.free[0],
                Range {
                    start: 256,
                    units: 256
                }
            );
            assert_eq!(
                pool.free[1],
                Range {
                    start: 768,
                    units: 256
                }
            );
            native.bind(&inputs[2], leases[2]);
            pool.release_after_native_quiescence(&mut native, leases[2])
                .unwrap();
            partition(&pool);
            assert_eq!(pool.free_mask, 2);
            assert_eq!(
                pool.free[1],
                Range {
                    start: 256,
                    units: 768
                }
            );
            assert!(pool.take_scheduler_wake());
            assert!(!pool.take_scheduler_wake());
            let large = publish(&mut pool, &mut native, wait, 0xdead, 600);
            assert_eq!(native.cfg[1], Some(0x02580100));
            assert_eq!(pool.minimum, u32::MAX);
            assert_eq!(
                pool.free[1],
                Range {
                    start: 856,
                    units: 168
                }
            );
            native.bind(&inputs[0], leases[0]);
            pool.release_after_native_quiescence(&mut native, leases[0])
                .unwrap();
            partition(&pool);
            assert_eq!(
                pool.free[1],
                Range {
                    start: 856,
                    units: 424
                }
            );
            native.bind(&large, wait);
            pool.release_after_native_quiescence(&mut native, wait)
                .unwrap();
            partition(&pool);
            assert_eq!(
                pool.free[1],
                Range {
                    start: 256,
                    units: 1024
                }
            );
            assert!(!pool.active());
        }
    }
    #[test]
    fn native_cache_selector_faults_preserve_private_allocation_and_first_store() {
        for program in programs() {
            for fault in [0, 1] {
                let mut pool = Pool::after_cold_initialization(program);
                let mut native = Native::new(program);
                let lease = Lease { pipe: 2, slot: 5 };
                let input = input(lease, 7, 0x12340000, 33, 0xfedc);
                native.bind(&input, lease);
                pool.allocate_eligible(&input, lease, 0xf0000000, 0x98765432)
                    .unwrap();
                assert!(pool.finish().is_err());
                assert!(pool.abort_pending().is_err());
                let before = format!("{pool:?}");
                assert!(pool.allocate_eligible(&input, lease, 0, 0).is_err());
                assert_eq!(format!("{pool:?}"), before);
                native.fail = Some(fault);
                assert!(pool.advance_selection(&mut native).is_err());
                assert_eq!(pool.records[0].references, 1);
                assert_eq!(native.writes.len(), fault);
                if fault == 1 {
                    native.cfg[0] = Some(0xfeed);
                }
                let before = format!("{pool:?}");
                let count = native.writes.len();
                native.available = false;
                assert!(pool.advance_selection(&mut native).is_err());
                assert_eq!(format!("{pool:?}"), before);
                assert_eq!(native.writes.len(), count);
                native.available = true;
                native.owner.as_mut().unwrap().0.counter += 1;
                assert!(pool.advance_selection(&mut native).is_err());
                assert_eq!(format!("{pool:?}"), before);
                assert_eq!(native.writes.len(), count);
                native.bind(&input, lease);
                let identity = native.identity.clone();
                native.identity = Identity::new();
                assert!(pool.advance_selection(&mut native).is_err());
                assert_eq!(format!("{pool:?}"), before);
                assert_eq!(native.writes.len(), count);
                native.identity = identity;
                pool.advance_selection(&mut native).unwrap();
                let count = native.writes.len();
                pool.advance_selection(&mut native).unwrap();
                assert_eq!(native.writes.len(), count);
                assert_eq!(
                    native.cfg[0],
                    Some(if fault == 1 { 0xfeed } else { 33 << 16 })
                );
                assert_eq!(native.selector[2], Some(0x12340003));
                assert_eq!(pool.finish(), Ok(Allocation::Assigned));
                let before = format!("{pool:?}");
                native.quiesced = false;
                assert!(
                    pool.release_after_native_quiescence(&mut native, lease)
                        .is_err()
                );
                assert_eq!(format!("{pool:?}"), before);
                native.quiesced = true;
                native.available = false;
                assert!(
                    pool.release_after_native_quiescence(&mut native, lease)
                        .is_err()
                );
                assert_eq!(format!("{pool:?}"), before);
                native.available = true;
                pool.release_after_native_quiescence(&mut native, lease)
                    .unwrap();
                partition(&pool);
                assert!(!pool.active());
            }
        }
    }
    #[test]
    fn cache_record_and_slot_bounds_refuse_without_aliasing_private_tables() {
        let program = programs()[0];
        let mut pool = Pool::after_cold_initialization(program);
        let mut native = Native::new(program);
        for i in 0..8 {
            publish(
                &mut pool,
                &mut native,
                Lease {
                    pipe: (i / 6) as u8,
                    slot: (i % 6) as u8,
                },
                0x1000 + i as u64 * 4,
                1,
            );
        }
        assert_eq!(pool.used, 0xff);
        let before = format!("{pool:?}");
        let lease = Lease { pipe: 1, slot: 2 };
        let input = input(lease, 5, 0x8888, 1, 9);
        assert_eq!(
            pool.allocate_eligible(&input, lease, 0, 0),
            Err("GFX buffer-cache allocation exhausts eight source records")
        );
        assert_eq!(format!("{pool:?}"), before);
        assert!(
            pool.allocate_eligible(&input, Lease { pipe: 3, slot: 0 }, 0, 0)
                .is_err()
        );
        assert_eq!(format!("{pool:?}"), before);
        assert!(
            pool.allocate_eligible(&input, Lease { pipe: 1, slot: 6 }, 0, 0)
                .is_err()
        );
        assert_eq!(format!("{pool:?}"), before);
        let mut newer = input.submission().clone();
        newer.encoding = Encoding::G14X;
        let mut memory = Flat::new(0x1000, 0x1000);
        let newer = BufferCacheInput::read(&mut memory, &newer).unwrap();
        assert_eq!(
            pool.allocate_eligible(&newer, lease, 0, 0),
            Err("GFX buffer-cache pool does not implement the newer native packet ABI")
        );
        assert_eq!(format!("{pool:?}"), before);
        partition(&pool);
    }
}
