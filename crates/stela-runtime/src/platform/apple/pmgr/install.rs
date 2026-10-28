//! Ordered T8112 native program installation, from original J473 LLB
//! 0x142c0/0x4d1b4/0x4d2cc/0x4dcd8/0x4ec98/0x4f1b4.
//!
//! Supplied metadata, firmware history and native images are actual inputs.
//! This does not compile the source tables, supply their live AP effects,
//! reconstruct initial SRAM, qualify a hardware trigger or retire instructions.
//! Each effect goes through the owning controller's normal checked physical
//! route. Release controller/bus borrows before dispatch; never run two program
//! installations concurrently against the same physical controller/SRAM.
use super::sequencer::PhysicalWrite;
use alloc::{rc::Rc, vec::Vec};
use stela_contracts::bus::Width;

pub mod t6000;

const NUB_BASE: u64 = 0x23df00000;
const NUB_LIMIT: u64 = 0x23df3ffff;
const FIXED_CODE: u64 = 0x23df05200;
const FIXED_LIMIT: u64 = 0x23df2fa00;
const GROUP_CONTROL: [u64; 4] = [0x23d2d0200, 0x23d2d0300, 0x23b781000, 0x23b78d000];
const PA_LIMIT: u64 = 1 << 42;
const PAIRED_SLOTS: [u8; 12] = [3, 9, 4, 10, 5, 11, 0, 6, 1, 7, 2, 8];
const PAIRED_OFFSETS: [u64; 6] = [0x14, 0x10, 8, 4, 0xc, 0x18];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProgramKind {
    EarlyCpu,
    EarlyPeripheral,
    LateCpu,
    LatePeripheral,
}
impl ProgramKind {
    fn peripheral(self) -> bool {
        matches!(self, Self::EarlyPeripheral | Self::LatePeripheral)
    }
    fn sequences(self) -> Vec<u8> {
        match self {
            Self::EarlyCpu => (0..24).step_by(2).chain(28..30).collect(),
            Self::EarlyPeripheral | Self::LatePeripheral => {
                (1..24).step_by(2).chain(24..28).collect()
            }
            Self::LateCpu => (0..24).step_by(2).collect(),
        }
    }
    fn groups(self) -> [u8; 2] {
        // Kind3 shares both original group descriptors, even though it has no
        // group3 sequence. The constructor still publishes that group base.
        if self.peripheral() { [1, 2] } else { [0, 3] }
    }
}

impl TryFrom<u32> for ProgramKind {
    type Error = Error;
    fn try_from(value: u32) -> Result<Self, Error> {
        match value {
            0 => Ok(Self::EarlyCpu),
            1 => Ok(Self::EarlyPeripheral),
            2 => Err(Error::EmptyKind),
            3 => Ok(Self::LateCpu),
            4 => Ok(Self::LatePeripheral),
            other => Err(Error::UnqualifiedKind(other)),
        }
    }
}

/// Captured firmware bytes at context+0x248/249 and +0x24a/24b. Unknown is
/// distinct from zero; their source guards are not hardware capability flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct History {
    pub setup: [Option<u8>; 2],
    pub activation: [Option<u8>; 2],
}

/// Actual NUB metadata words at physical0x23d050000/4 when the native pool is
/// first initialized. Reuse the resulting pool if later firmware rewrites
/// those words; recomputing it would substitute a different allocation epoch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Metadata {
    pub first_page: u32,
    pub pages: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NubPool {
    tables: [u64; 2],
    code: u64,
    metadata: Metadata,
}
impl NubPool {
    pub fn from_metadata(metadata: Metadata) -> Result<Self, Error> {
        // Original W-register shift deliberately truncates the second term.
        let start = NUB_BASE
            + u64::from(metadata.first_page & 0xff) * 4096
            + u64::from(metadata.pages.wrapping_shl(12));
        if start > NUB_LIMIT {
            return Err(Error::PoolGeometry);
        }
        let first = align(start, 4096)?;
        let code = align(first.checked_add(512).ok_or(Error::PoolGeometry)?, 32)?;
        if code > NUB_LIMIT {
            return Err(Error::PoolGeometry);
        }
        Ok(Self {
            tables: [first, first + 256],
            code,
            metadata,
        })
    }
    pub fn tables(self) -> [u64; 2] {
        self.tables
    }
    pub fn code_start(self) -> u64 {
        self.code
    }
}

/// Already emitted native bytes and the separately counted words before the
/// source allocator reserves one terminating word. No tag is executed here.
pub struct NativeImage {
    pub sequence: u8,
    pub counted_words: u32,
    pub bytes: Vec<u8>,
}

pub struct Inputs {
    pub chip: u32,
    pub revision: u32,
    pub stage: u32,
    pub kind: ProgramKind,
    pub pool: Option<NubPool>,
    pub history: History,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Placement {
    pub sequence: u8,
    pub group: u8,
    pub slot: u8,
    pub table: u64,
    pub code: u64,
    pub bytes: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    UnqualifiedChip,
    UnqualifiedKind(u32),
    EmptyKind,
    UnqualifiedRevision,
    UnknownPool,
    PoolGeometry,
    MissingImage(u8),
    UnexpectedImage(u8),
    DuplicateImage(u8),
    ImageGeometry(u8),
    CodeExhausted(u8),
    UnknownHistory,
    AlreadyConfigured,
    InFlight,
    StaleClaim,
    NotDispatched,
    AlreadyDispatched,
    Suspended,
    TicketExhausted,
    Blocked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Original helper26634 branches to DMB SY at file4ac.
    DmbSy,
    Read {
        address: u64,
        width: Width,
    },
    Write(PhysicalWrite),
}

#[derive(Debug)]
pub struct Claim {
    owner: Rc<()>,
    ticket: u64,
    action: Action,
}
impl Claim {
    pub fn action(&self) -> Action {
        self.action
    }
}

/// The physical route must classify errors by effects, not their error name.
/// A normal MMIO/RAM error defaults to Uncertain unless no effect is proved.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome<E> {
    Read(u64),
    Written,
    Ordered,
    NoEffect(E),
    Uncertain(E),
}

#[derive(Debug, PartialEq, Eq)]
pub enum FinishError<E> {
    Ownership(Error, Outcome<E>),
    NoEffect(E),
    Uncertain(E),
    WrongResult(Outcome<E>),
    Readback {
        address: u64,
        expected: u32,
        actual: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Blockage {
    Uncertain(Action),
    WrongResult(Action),
    Readback {
        address: u64,
        expected: u32,
        actual: u64,
    },
}

enum Step {
    DmbSy,
    Write(PhysicalWrite),
    Modify {
        address: u64,
        clear: u32,
        set: u32,
        latched: Option<u32>,
    },
    Expect {
        address: u64,
        value: u32,
    },
    MarkSetup(usize),
    MarkActivation(usize),
}
struct Flight {
    ticket: u64,
    dispatched: bool,
}

/// Owns one immutable installation and its committed prefix. `published()`
/// means only that these configuration effects committed through actual routes;
/// it supplies no hardware trigger, instruction retirement or PS handoff value.
/// There is no reset/image replacement/uncertainty clearing API.
pub struct Installation {
    owner: Rc<()>,
    ticket: u64,
    flight: Option<Flight>,
    blocked: Option<Blockage>,
    suspended: bool,
    steps: Vec<Step>,
    step: usize,
    placements: Vec<Placement>,
    history: History,
    committed_reads: u64,
    committed_writes: u64,
}
impl Installation {
    pub fn new(inputs: Inputs, mut images: Vec<NativeImage>) -> Result<Self, Error> {
        if inputs.chip != 0x8112 {
            return Err(Error::UnqualifiedChip);
        }
        if !matches!(inputs.revision, 0 | 1 | 0x10 | 0x11) {
            return Err(Error::UnqualifiedRevision);
        }
        let family = usize::from(inputs.kind.peripheral());
        let setup = matches!(inputs.stage, 2 | 3);
        let activate = matches!(inputs.stage, 2 | 3 | 10);
        for (needed, flags) in [
            (setup, inputs.history.setup),
            (activate, inputs.history.activation),
        ] {
            if needed {
                let byte = flags[family].ok_or(Error::UnknownHistory)?;
                if if family == 0 {
                    byte & 1 != 0
                } else {
                    byte == 1
                } {
                    return Err(Error::AlreadyConfigured);
                }
            }
        }
        let (tables, mut code, limit) = if inputs.kind.peripheral() {
            let pool = inputs.pool.ok_or(Error::UnknownPool)?;
            ([0, pool.tables[0], pool.tables[1], 0], pool.code, NUB_LIMIT)
        } else {
            ([0x23df05000, 0, 0, 0x23df05100], FIXED_CODE, FIXED_LIMIT)
        };
        let ids = inputs.kind.sequences();
        images.sort_by_key(|image| image.sequence);
        for pair in images.windows(2) {
            if pair[0].sequence == pair[1].sequence {
                return Err(Error::DuplicateImage(pair[0].sequence));
            }
        }
        for image in &images {
            if !ids.contains(&image.sequence) {
                return Err(Error::UnexpectedImage(image.sequence));
            }
        }
        let mut placements = Vec::new();
        for id in ids {
            let image = images
                .iter()
                .find(|image| image.sequence == id)
                .ok_or(Error::MissingImage(id))?;
            let words = image
                .counted_words
                .checked_add(1)
                .ok_or(Error::ImageGeometry(id))?;
            if u64::from(words) * 4 != image.bytes.len() as u64
                || image.bytes.last_chunk::<4>() != Some(&[0; 4])
            {
                return Err(Error::ImageGeometry(id));
            }
            code = align(code, 32)?;
            let end = code
                .checked_add(image.bytes.len() as u64)
                .ok_or(Error::CodeExhausted(id))?;
            if end >= limit {
                return Err(Error::CodeExhausted(id));
            }
            let (group, slot) = group_slot(id);
            placements.push(Placement {
                sequence: id,
                group,
                slot,
                table: tables[usize::from(group)],
                code,
                bytes: words * 4,
            });
            code = end;
        }
        let mut steps = Vec::new();
        // Constructor: every active group base, then ascending sequence controls
        // and zero code pointers. These precede allocation/publication/emission.
        for group in inputs.kind.groups() {
            let table = tables[usize::from(group)];
            let value = if group < 2 {
                table & 0x3ff00
            } else {
                (table >> 8) & 0xfffffff
            };
            write(
                &mut steps,
                GROUP_CONTROL[usize::from(group)],
                Width::Word,
                value,
            );
        }
        for placement in &placements {
            bind(&mut steps, *placement, 0);
        }
        // Allocation publishes actual pointers before any native image bytes.
        for placement in &placements {
            bind(&mut steps, *placement, placement.code);
        }
        if setup {
            setup_steps(&mut steps, family);
        }
        for (placement, image) in placements.iter().zip(images) {
            for (index, bytes) in image.bytes.as_chunks::<4>().0.iter().enumerate() {
                write(
                    &mut steps,
                    placement.code + index as u64 * 4,
                    Width::Word,
                    u64::from(u32::from_le_bytes(*bytes)),
                );
            }
        }
        // Metadata publication is a physical effect, separate from activation.
        if family == 0 {
            write(&mut steps, 0x23d050000, Width::Word, 2);
            write(&mut steps, 0x23d050004, Width::Word, 0x2e);
        } else {
            let pool = inputs.pool.expect("checked peripheral pool");
            write(
                &mut steps,
                0x23d054000,
                Width::Word,
                (pool.tables[0] >> 12) & 0xff,
            );
            write(
                &mut steps,
                0x23d054004,
                Width::Word,
                (NUB_LIMIT - pool.tables[0]).div_ceil(4096),
            );
        }
        if activate {
            let address = if family == 0 {
                0x23d050008
            } else {
                0x23d054008
            };
            steps.push(Step::Expect { address, value: 0 });
            write(&mut steps, address, Width::Word, 3);
            steps.push(Step::DmbSy);
            steps.push(Step::Expect { address, value: 3 });
            steps.push(Step::MarkActivation(family));
        }
        Ok(Self {
            owner: Rc::new(()),
            ticket: 0,
            flight: None,
            blocked: None,
            suspended: false,
            steps,
            step: 0,
            placements,
            history: inputs.history,
            committed_reads: 0,
            committed_writes: 0,
        })
    }
    pub fn placements(&self) -> &[Placement] {
        &self.placements
    }
    pub fn history(&self) -> History {
        self.history
    }
    pub fn committed_reads(&self) -> u64 {
        self.committed_reads
    }
    pub fn committed_writes(&self) -> u64 {
        self.committed_writes
    }
    pub fn blockage(&self) -> Option<Blockage> {
        self.blocked
    }
    pub fn published(&self) -> bool {
        self.step == self.steps.len() && self.blocked.is_none()
    }
    pub fn set_suspended(&mut self, value: bool) {
        self.suspended = value;
    }

    pub fn begin(&mut self) -> Result<Option<Claim>, Error> {
        if self.blocked.is_some() {
            return Err(Error::Blocked);
        }
        if self.flight.is_some() {
            return Err(Error::InFlight);
        }
        if self.suspended {
            return Err(Error::Suspended);
        }
        while let Some(step) = self.steps.get(self.step) {
            match step {
                Step::MarkSetup(family) => self.history.setup[*family] = Some(1),
                Step::MarkActivation(family) => self.history.activation[*family] = Some(1),
                _ => break,
            }
            self.step += 1;
        }
        let Some(step) = self.steps.get(self.step) else {
            return Ok(None);
        };
        let action = match step {
            Step::DmbSy => Action::DmbSy,
            Step::Write(write) => Action::Write(*write),
            Step::Modify {
                address,
                latched: Some(value),
                ..
            } => Action::Write(PhysicalWrite {
                address: *address,
                width: Width::Word,
                value: u64::from(*value),
            }),
            Step::Modify {
                address,
                latched: None,
                ..
            }
            | Step::Expect { address, .. } => Action::Read {
                address: *address,
                width: Width::Word,
            },
            _ => unreachable!("history steps processed above"),
        };
        self.ticket = self.ticket.checked_add(1).ok_or(Error::TicketExhausted)?;
        self.flight = Some(Flight {
            ticket: self.ticket,
            dispatched: false,
        });
        Ok(Some(Claim {
            owner: self.owner.clone(),
            ticket: self.ticket,
            action,
        }))
    }
    fn check(&self, claim: &Claim) -> Result<(), Error> {
        if self.blocked.is_some() {
            return Err(Error::Blocked);
        }
        if Rc::ptr_eq(&self.owner, &claim.owner)
            && self
                .flight
                .as_ref()
                .is_some_and(|state| state.ticket == claim.ticket)
        {
            Ok(())
        } else {
            Err(Error::StaleClaim)
        }
    }
    pub fn dispatch(&mut self, claim: &Claim) -> Result<Action, Error> {
        self.check(claim)?;
        let state = self.flight.as_mut().expect("checked claim");
        if state.dispatched {
            return Err(Error::AlreadyDispatched);
        }
        if self.suspended {
            return Err(Error::Suspended);
        }
        state.dispatched = true;
        Ok(claim.action)
    }
    pub fn cancel(&mut self, claim: &Claim) -> Result<(), Error> {
        self.check(claim)?;
        if self.flight.as_ref().expect("checked claim").dispatched {
            return Err(Error::AlreadyDispatched);
        }
        self.flight = None;
        Ok(())
    }
    pub fn finish<E>(&mut self, claim: &Claim, outcome: Outcome<E>) -> Result<(), FinishError<E>> {
        if let Err(error) = self.check(claim) {
            return Err(FinishError::Ownership(error, outcome));
        }
        if !self.flight.as_ref().expect("checked claim").dispatched {
            return Err(FinishError::Ownership(Error::NotDispatched, outcome));
        }
        self.flight = None;
        match outcome {
            Outcome::NoEffect(error) => Err(FinishError::NoEffect(error)),
            Outcome::Uncertain(error) => {
                self.blocked = Some(Blockage::Uncertain(claim.action));
                Err(FinishError::Uncertain(error))
            }
            Outcome::Ordered if claim.action == Action::DmbSy => {
                self.step += 1;
                Ok(())
            }
            Outcome::Written if matches!(claim.action, Action::Write(_)) => {
                self.committed_writes += 1;
                self.step += 1;
                Ok(())
            }
            Outcome::Read(actual) if matches!(claim.action, Action::Read { .. }) => {
                self.committed_reads += 1;
                match &mut self.steps[self.step] {
                    Step::Modify {
                        clear,
                        set,
                        latched,
                        ..
                    } if actual <= u64::from(u32::MAX) => {
                        *latched = Some((actual as u32 & !*clear) | *set);
                        Ok(())
                    }
                    Step::Expect { address, value } if actual != u64::from(*value) => {
                        self.blocked = Some(Blockage::Readback {
                            address: *address,
                            expected: *value,
                            actual,
                        });
                        Err(FinishError::Readback {
                            address: *address,
                            expected: *value,
                            actual,
                        })
                    }
                    Step::Expect { .. } => {
                        self.step += 1;
                        Ok(())
                    }
                    _ => self.wrong_result(claim, Outcome::Read(actual)),
                }
            }
            other => self.wrong_result(claim, other),
        }
    }
    fn wrong_result<E>(
        &mut self,
        claim: &Claim,
        outcome: Outcome<E>,
    ) -> Result<(), FinishError<E>> {
        self.blocked = Some(Blockage::WrongResult(claim.action));
        Err(FinishError::WrongResult(outcome))
    }
}

fn align(value: u64, alignment: u64) -> Result<u64, Error> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
        .ok_or(Error::PoolGeometry)
}
fn group_slot(id: u8) -> (u8, u8) {
    if id < 24 {
        (id % 2, PAIRED_SLOTS[usize::from(id / 2)])
    } else if id < 28 {
        (2, id - 24)
    } else {
        (3, id - 28)
    }
}
fn write(steps: &mut Vec<Step>, address: u64, width: Width, value: u64) {
    debug_assert!(address + width.bytes() <= PA_LIMIT);
    steps.push(Step::Write(PhysicalWrite {
        address,
        width,
        value,
    }));
}
fn bind(steps: &mut Vec<Step>, placement: Placement, code: u64) {
    let id = placement.sequence;
    let (address, shift, clear, enable) = if id < 24 {
        let shift = u32::from(id / 2 % 2) * 16;
        (
            0x23d2d0200 + u64::from(id % 2) * 256 + PAIRED_OFFSETS[usize::from(id / 4)],
            shift,
            0x1f << shift,
            1 << (8 + shift),
        )
    } else {
        let address = if id < 26 {
            0x23b781004
        } else if id < 28 {
            0x23b781008
        } else {
            0x23b78d004
        };
        let shift = if id == 29 { 5 } else { u32::from(id % 2) * 16 };
        (address, shift, 0, 0)
    };
    steps.push(Step::Modify {
        address,
        clear,
        set: u32::from(placement.slot) << shift | enable,
        latched: None,
    });
    write(
        steps,
        placement.table + u64::from(placement.slot) * 8,
        Width::Double,
        (code >> 4) & ((1 << 38) - 1),
    );
}
fn setup_steps(steps: &mut Vec<Step>, family: usize) {
    if family == 0 {
        checked_write(steps, 0x23d2d021c, 1);
        checked_write(steps, 0x23b78d008, 1);
        // Source writes all three words, orders them, then checks all three.
        for (address, value) in [(0x23b78fff8, 15), (0x23b793ff8, 0), (0x23b797ff8, 0)] {
            write(steps, address, Width::Word, value);
        }
        steps.push(Step::DmbSy);
        for (address, value) in [(0x23b78fff8, 15), (0x23b793ff8, 0), (0x23b797ff8, 0)] {
            steps.push(Step::Expect { address, value });
        }
        for address in [0x23b78fffc, 0x23b793ffc, 0x23b797ffc] {
            write(steps, address, Width::Word, 1);
        }
        steps.push(Step::DmbSy);
        for address in [0x23b78fffc, 0x23b793ffc, 0x23b797ffc] {
            steps.push(Step::Expect { address, value: 1 });
        }
    } else {
        write(steps, 0x23d2d031c, Width::Word, 1);
        write(steps, 0x23d2d7ff8, Width::Word, 0x01c0200f);
        write(steps, 0x23d2d7ffc, Width::Word, 1);
        steps.push(Step::DmbSy);
        for address in [0x23d2d031c, 0x23d2d7ffc] {
            steps.push(Step::Expect { address, value: 1 });
        }
        checked_write(steps, 0x23b78100c, 1);
        checked_write(steps, 0x23b781014, 1);
    }
    steps.push(Step::MarkSetup(family));
}
fn checked_write(steps: &mut Vec<Step>, address: u64, value: u32) {
    write(steps, address, Width::Word, u64::from(value));
    steps.push(Step::DmbSy);
    steps.push(Step::Expect { address, value });
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{boxed::Box, collections::BTreeMap, vec};
    use core::sync::atomic::{Ordering, fence};
    use {
        stela_contracts::bus::Access, stela_contracts::bus::Bus, stela_contracts::bus::Direction,
        stela_contracts::bus::MmioDevice, stela_contracts::bus::MmioError,
        stela_contracts::interrupt::InterruptLatch,
    };
    use {stela_contracts::dma::Memory, stela_contracts::dma::test_support::Ram};

    /// Test-only captured configuration bank, without any hardware execution or
    /// completion semantics. All SRAM data still traverses the actual RAM API.
    #[derive(Default)]
    struct Captured {
        words: BTreeMap<u64, u64>,
        reads: BTreeMap<u64, u32>,
        writes: BTreeMap<u64, u32>,
        fail_after_write: Option<u64>,
        fail_after_read: Option<u64>,
    }
    impl MmioDevice for Captured {
        fn name(&self) -> &'static str {
            "captured installation test bank"
        }
        fn read(&mut self, offset: u64, _: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
            *self.reads.entry(offset).or_default() += 1;
            if self.fail_after_read == Some(offset) {
                return Err(MmioError::Unsupported {
                    device: self.name(),
                    offset,
                    width: Width::Word,
                    direction: Direction::Read,
                    reason: "after committed read side effect",
                });
            }
            Ok(self.words.get(&offset).copied().unwrap_or(0xa5a55aa5))
        }
        fn write(
            &mut self,
            offset: u64,
            width: Width,
            value: u64,
            _: &mut Access<'_>,
        ) -> Result<(), MmioError> {
            *self.writes.entry(offset).or_default() += 1;
            self.words.insert(offset, value);
            if self.fail_after_write == Some(offset) {
                return Err(MmioError::Unsupported {
                    device: self.name(),
                    offset,
                    width,
                    direction: Direction::Write,
                    reason: "after committed configuration effect",
                });
            }
            Ok(())
        }
    }
    fn inputs(kind: ProgramKind, stage: u32) -> Inputs {
        Inputs {
            chip: 0x8112,
            revision: 0x11,
            stage,
            kind,
            // These are explicit synthetic test inputs, not a native snapshot.
            pool: Some(
                NubPool::from_metadata(Metadata {
                    first_page: 2,
                    pages: 0x2e,
                })
                .unwrap(),
            ),
            history: History {
                setup: [Some(0); 2],
                activation: [Some(0); 2],
            },
        }
    }
    fn images(kind: ProgramKind) -> Vec<NativeImage> {
        kind.sequences()
            .into_iter()
            .map(|sequence| NativeImage {
                sequence,
                counted_words: 1,
                // Unknown native tag is data here, never silently executed.
                bytes: [0x44u32, 0]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect(),
            })
            .collect()
    }
    fn install(kind: ProgramKind, stage: u32) -> Installation {
        Installation::new(inputs(kind, stage), images(kind)).unwrap()
    }
    fn bus(installation: &Installation) -> (Bus, stela_contracts::bus::DeviceId) {
        let mut bank = Captured::default();
        bank.words.insert(0x23d050008, 0);
        bank.words.insert(0x23d054008, 0);
        let mut bus = Bus::new();
        let id = bus.add(Box::new(bank));
        let mut words = alloc::collections::BTreeSet::new();
        for step in &installation.steps {
            match step {
                Step::Write(write) if !(NUB_BASE..NUB_LIMIT).contains(&write.address) => {
                    words.insert(write.address);
                }
                Step::Modify { address, .. } | Step::Expect { address, .. } => {
                    words.insert(*address);
                }
                _ => {}
            }
        }
        for address in words {
            bus.map(id, address, 4, address).unwrap();
        }
        (bus, id)
    }
    fn route(
        action: Action,
        ram: &mut Ram,
        bus: &mut Bus,
        access: &mut Access<'_>,
    ) -> Outcome<MmioError> {
        match action {
            Action::DmbSy => {
                // The test has one synchronous RAM/Bus participant. This host
                // fence does not qualify the multi-PE production adapter.
                fence(Ordering::SeqCst);
                Outcome::Ordered
            }
            Action::Read { address, width } => match bus.read(address, width, access) {
                Ok(value) => Outcome::Read(value),
                Err(error) => Outcome::Uncertain(error),
            },
            Action::Write(write) if (NUB_BASE..NUB_LIMIT).contains(&write.address) => {
                let data = write.value.to_le_bytes();
                assert!(ram.write(write.address, &data[..write.width.bytes() as usize]));
                Outcome::Written
            }
            Action::Write(write) => {
                match bus.write(write.address, write.width, write.value, access) {
                    Ok(()) => Outcome::Written,
                    Err(error) => Outcome::Uncertain(error),
                }
            }
        }
    }
    fn drain(
        installation: &mut Installation,
        ram: &mut Ram,
        bus: &mut Bus,
        access: &mut Access<'_>,
    ) -> Vec<Action> {
        let mut actions = Vec::new();
        while let Some(claim) = installation.begin().unwrap() {
            let action = installation.dispatch(&claim).unwrap();
            let result = route(action, ram, bus, access);
            installation.finish(&claim, result).unwrap();
            actions.push(action);
        }
        actions
    }
    #[test]
    fn all_thirty_bindings_reach_actual_pointer_ram_and_preserve_paired_fields() {
        let mut ram = Ram::new(NUB_BASE, 0x40000);
        ram.bytes.fill(0xcc);
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        let mut seen = alloc::collections::BTreeSet::new();
        for kind in [ProgramKind::EarlyCpu, ProgramKind::EarlyPeripheral] {
            let mut install = install(kind, 5);
            let (mut bus, id) = bus(&install);
            let actions = drain(&mut install, &mut ram, &mut bus, &mut access);
            assert!(install.published());
            assert!(install.blockage().is_none());
            let first_image = actions.iter().position(|action| matches!(action, Action::Write(write) if write.width == Width::Word && (NUB_BASE..NUB_LIMIT).contains(&write.address))).unwrap();
            let mut zero_pointers = 0;
            let mut pointers = 0;
            for (index, action) in actions.iter().enumerate() {
                if let Action::Write(write) = action
                    && write.width == Width::Double
                {
                    assert!(index < first_image);
                    if write.value == 0 {
                        zero_pointers += 1;
                    } else {
                        pointers += 1;
                    }
                }
            }
            assert_eq!(zero_pointers, install.placements().len());
            assert_eq!(pointers, install.placements().len());
            for placement in install.placements() {
                seen.insert(placement.sequence);
                assert!(placement.code.is_multiple_of(32));
                let mut pointer = [0; 8];
                assert!(ram.read(
                    placement.table + u64::from(placement.slot) * 8,
                    &mut pointer
                ));
                assert_eq!(u64::from_le_bytes(pointer), placement.code >> 4);
                let mut image = [0; 8];
                assert!(ram.read(placement.code, &mut image));
                assert_eq!(image, [0x44, 0, 0, 0, 0, 0, 0, 0]);
            }
            let bank = bus.device_mut::<Captured>(id).unwrap();
            if !kind.peripheral() {
                // Sequences0/2 share this word, with independently replaced
                // slots3/9 and enable bits8/24. Every unrelated bit survives.
                let expected =
                    (0xa5a55aa5u32 & !(0x1f | (0x1f << 16))) | 3 | (9 << 16) | (1 << 8) | (1 << 24);
                assert_eq!(bank.words[&0x23d2d0214], u64::from(expected));
                // Group3 source uses OR, rather than replacing either field.
                assert_eq!(bank.words[&0x23b78d004], 0xa5a55aa5 | (1 << 5));
            }
            assert_eq!(
                bank.words[&GROUP_CONTROL[usize::from(kind.groups()[0])]],
                if kind.peripheral() { 0x30000 } else { 0x5000 }
            );
        }
        assert_eq!(seen, (0..30).collect());
    }
    #[test]
    fn both_families_use_actual_native_binding_bank_without_claiming_hardware_completion() {
        use crate::platform::apple::power::{Kind, Power};
        let mut bus = Bus::new();
        let offsets = Kind::NubBindings.offsets();
        let model = Power::from_snapshot(
            Kind::NubBindings,
            offsets.iter().map(|offset| {
                (
                    *offset,
                    if GROUP_CONTROL.contains(offset) {
                        0
                    } else {
                        0xa5a55aa5
                    },
                )
            }),
        )
        .unwrap();
        let id = bus.add(Box::new(model));
        for offset in offsets {
            bus.map(id, offset, 4, offset).unwrap();
        }
        let metadata = bus.add(Box::new(Captured::default()));
        for address in [0x23d050000, 0x23d050004, 0x23d054000, 0x23d054004] {
            bus.map(metadata, address, 4, address).unwrap();
        }
        let mut ram = Ram::new(NUB_BASE, 0x40000);
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        for kind in [ProgramKind::EarlyCpu, ProgramKind::EarlyPeripheral] {
            let mut installer = install(kind, 5);
            drain(&mut installer, &mut ram, &mut bus, &mut access);
            assert!(installer.published());
            assert_eq!(
                installer.committed_reads(),
                installer.placements().len() as u64 * 2
            );
        }
        let bank = bus.device_mut::<Power>(id).unwrap();
        assert_eq!(bank.pending_configuration().count(), 64);
        assert!(bank.advance(&mut access).is_err());
        // The bank retains actual configured fields; it has no trigger->PC or
        // native instruction retirement method that could invent PS effects.
        assert_eq!(
            bank.read(0x23d2d0214, Width::Word, &mut access),
            Ok(0xa5a95ba3)
        );
        assert!(
            bank.write(0x23d2d0214, Width::Word, 0, &mut access)
                .is_err()
        );
        assert_eq!(bank.pending_configuration().count(), 64);
    }

    #[test]
    fn setup_activation_and_dmb_order_follow_actual_stage_guards_without_retirement() {
        for stage in [2, 3, 5, 10, 11] {
            for kind in [
                ProgramKind::EarlyCpu,
                ProgramKind::LateCpu,
                ProgramKind::EarlyPeripheral,
                ProgramKind::LatePeripheral,
            ] {
                let mut install = install(kind, stage);
                let (mut bus, _) = bus(&install);
                let mut ram = Ram::new(NUB_BASE, 0x40000);
                let mut sink = InterruptLatch::new();
                let mut access = Access::new(0, 0, &mut sink);
                let actions = drain(&mut install, &mut ram, &mut bus, &mut access);
                let family = usize::from(kind.peripheral());
                assert_eq!(
                    install.history().setup[family],
                    Some(u8::from(matches!(stage, 2 | 3)))
                );
                assert_eq!(
                    install.history().activation[family],
                    Some(u8::from(matches!(stage, 2 | 3 | 10)))
                );
                let activate = if kind.peripheral() {
                    0x23d054008
                } else {
                    0x23d050008
                };
                let activation = actions.iter().position(
                    |action| matches!(action, Action::Write(write) if write.address == activate),
                );
                if matches!(stage, 2 | 3 | 10) {
                    let index = activation.unwrap();
                    assert_eq!(
                        actions[index - 1],
                        Action::Read {
                            address: activate,
                            width: Width::Word
                        }
                    );
                    assert_eq!(actions[index + 1], Action::DmbSy);
                    assert_eq!(
                        actions[index + 2],
                        Action::Read {
                            address: activate,
                            width: Width::Word
                        }
                    );
                } else {
                    assert!(activation.is_none());
                }
                if stage == 5 {
                    assert!(!actions.contains(&Action::DmbSy));
                }
                if kind == ProgramKind::LateCpu {
                    // Shared descriptors still publish group3 despite no such sequence.
                    assert_eq!(
                        actions[1],
                        Action::Write(PhysicalWrite {
                            address: 0x23b78d000,
                            width: Width::Word,
                            value: 0x23df05100 >> 8
                        })
                    );
                }
            }
        }
    }
    #[test]
    fn latched_rmw_survives_no_effect_write_refusal_and_uncertain_write_is_terminal() {
        let mut install = install(ProgramKind::EarlyCpu, 5);
        let (mut bus, id) = bus(&install);
        let mut ram = Ram::new(NUB_BASE, 0x40000);
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        // Commit group stores and first live RMW read.
        for _ in 0..3 {
            let claim = install.begin().unwrap().unwrap();
            let action = install.dispatch(&claim).unwrap();
            install
                .finish(&claim, route(action, &mut ram, &mut bus, &mut access))
                .unwrap();
        }
        let claim = install.begin().unwrap().unwrap();
        let first = install.dispatch(&claim).unwrap();
        assert_eq!(
            install.finish(&claim, Outcome::NoEffect("target preflight refused")),
            Err(FinishError::NoEffect("target preflight refused"))
        );
        // An external change cannot cause this retained RMW to be silently reread.
        bus.device_mut::<Captured>(id)
            .unwrap()
            .words
            .insert(0x23d2d0214, 0);
        let retry = install.begin().unwrap().unwrap();
        assert_eq!(retry.action(), first);
        let action = install.dispatch(&retry).unwrap();
        bus.device_mut::<Captured>(id).unwrap().fail_after_write = Some(0x23d2d0214);
        let error = match route(action, &mut ram, &mut bus, &mut access) {
            Outcome::Uncertain(error) => error,
            _ => panic!("real target must retain the write then refuse"),
        };
        assert_eq!(
            install.finish(&retry, Outcome::Uncertain(error)),
            Err(FinishError::Uncertain(error))
        );
        assert_eq!(install.committed_writes(), 2);
        assert_eq!(install.committed_reads(), 1);
        assert_eq!(install.blockage(), Some(Blockage::Uncertain(action)));
        assert!(matches!(install.begin(), Err(Error::Blocked)));
        assert_eq!(install.cancel(&retry), Err(Error::Blocked));
        let bank = bus.device_mut::<Captured>(id).unwrap();
        assert_eq!(bank.reads[&0x23d2d0214], 1);
        assert_eq!(bank.writes[&0x23d2d0214], 1);
        assert!(!install.published());
    }
    #[test]
    fn partial_read_and_barrier_refusal_cannot_replay_committed_stores_or_reads() {
        let mut install = install(ProgramKind::EarlyCpu, 2);
        let (mut bus, id) = bus(&install);
        let mut ram = Ram::new(NUB_BASE, 0x40000);
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        // Reach the first actual DMB after its setup store has committed.
        loop {
            let claim = install.begin().unwrap().unwrap();
            let action = install.dispatch(&claim).unwrap();
            if action == Action::DmbSy {
                let writes = install.committed_writes();
                assert_eq!(
                    install.finish(&claim, Outcome::NoEffect("ordering preflight refused")),
                    Err(FinishError::NoEffect("ordering preflight refused"))
                );
                let retry = install.begin().unwrap().unwrap();
                assert_eq!(install.dispatch(&retry), Ok(Action::DmbSy));
                install.finish::<()>(&retry, Outcome::Ordered).unwrap();
                assert_eq!(install.committed_writes(), writes);
                break;
            }
            install
                .finish(&claim, route(action, &mut ram, &mut bus, &mut access))
                .unwrap();
        }
        let next = install.begin().unwrap().unwrap();
        let action = install.dispatch(&next).unwrap();
        let Action::Read { address, .. } = action else {
            panic!("source readback follows DMB");
        };
        bus.device_mut::<Captured>(id).unwrap().fail_after_read = Some(address);
        let outcome = route(action, &mut ram, &mut bus, &mut access);
        assert!(matches!(
            outcome,
            Outcome::Uncertain(MmioError::Unsupported {
                reason: "after committed read side effect",
                ..
            })
        ));
        assert!(matches!(
            install.finish(&next, outcome),
            Err(FinishError::Uncertain(_))
        ));
        assert_eq!(install.blockage(), Some(Blockage::Uncertain(action)));
        assert!(matches!(install.begin(), Err(Error::Blocked)));
        assert_eq!(bus.device_mut::<Captured>(id).unwrap().reads[&address], 1);
        assert!(!install.published());
    }

    #[test]
    fn bad_activation_readback_preserves_images_and_never_sets_completion_history() {
        let mut install = install(ProgramKind::LatePeripheral, 10);
        let (mut bus, id) = bus(&install);
        bus.device_mut::<Captured>(id)
            .unwrap()
            .words
            .insert(0x23d054008, 0x42);
        let mut ram = Ram::new(NUB_BASE, 0x40000);
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        loop {
            let claim = install.begin().unwrap().unwrap();
            let action = install.dispatch(&claim).unwrap();
            let result = install.finish(&claim, route(action, &mut ram, &mut bus, &mut access));
            if matches!(
                action,
                Action::Read {
                    address: 0x23d054008,
                    ..
                }
            ) {
                assert_eq!(
                    result,
                    Err(FinishError::Readback {
                        address: 0x23d054008,
                        expected: 0,
                        actual: 0x42
                    })
                );
                break;
            }
            result.unwrap();
        }
        assert!(!install.published());
        assert_eq!(install.history().activation[1], Some(0));
        assert!(matches!(install.begin(), Err(Error::Blocked)));
        let bank = bus.device_mut::<Captured>(id).unwrap();
        assert!(!bank.writes.contains_key(&0x23d054008));
        for placement in install.placements() {
            let mut data = [0; 8];
            assert!(ram.read(placement.code, &mut data));
            assert_eq!(data[0], 0x44);
            assert_eq!(
                u64::from_le_bytes(
                    ram.bytes
                        [(placement.table - NUB_BASE) as usize + usize::from(placement.slot) * 8..]
                        [..8]
                        .try_into()
                        .unwrap()
                ),
                placement.code >> 4
            );
        }
    }
    #[test]
    fn claims_cancellation_pause_and_wrong_kind_results_preserve_ownership() {
        let mut a = install(ProgramKind::EarlyCpu, 5);
        let mut b = install(ProgramKind::EarlyCpu, 5);
        let old = a.begin().unwrap().unwrap();
        assert!(matches!(a.begin(), Err(Error::InFlight)));
        assert_eq!(
            a.finish::<()>(&old, Outcome::Written),
            Err(FinishError::Ownership(
                Error::NotDispatched,
                Outcome::Written
            ))
        );
        a.cancel(&old).unwrap();
        let new = a.begin().unwrap().unwrap();
        assert_eq!(a.cancel(&old), Err(Error::StaleClaim));
        a.set_suspended(true);
        assert_eq!(a.dispatch(&new), Err(Error::Suspended));
        a.set_suspended(false);
        a.dispatch(&new).unwrap();
        assert_eq!(a.cancel(&new), Err(Error::AlreadyDispatched));
        assert_eq!(a.dispatch(&new), Err(Error::AlreadyDispatched));
        let other = b.begin().unwrap().unwrap();
        assert_eq!(
            b.finish::<()>(&new, Outcome::Written),
            Err(FinishError::Ownership(Error::StaleClaim, Outcome::Written))
        );
        b.cancel(&other).unwrap();
        a.set_suspended(true);
        a.finish::<()>(&new, Outcome::Written).unwrap();
        assert!(matches!(a.begin(), Err(Error::Suspended)));
        a.set_suspended(false);
        let next = a.begin().unwrap().unwrap();
        let action = a.dispatch(&next).unwrap();
        assert_eq!(
            a.finish::<()>(&next, Outcome::Read(0)),
            Err(FinishError::WrongResult(Outcome::Read(0)))
        );
        assert_eq!(a.blockage(), Some(Blockage::WrongResult(action)));
        assert!(matches!(a.begin(), Err(Error::Blocked)));
    }
    #[test]
    fn missing_unknown_duplicate_geometry_and_history_inputs_never_guess() {
        let kind = ProgramKind::EarlyPeripheral;
        let mut input = inputs(kind, 5);
        input.pool = None;
        assert!(matches!(
            Installation::new(input, images(kind)),
            Err(Error::UnknownPool)
        ));
        let mut input = inputs(kind, 2);
        input.history = History::default();
        assert!(matches!(
            Installation::new(input, images(kind)),
            Err(Error::UnknownHistory)
        ));
        let mut input = inputs(kind, 2);
        input.history.setup[1] = Some(1);
        assert!(matches!(
            Installation::new(input, images(kind)),
            Err(Error::AlreadyConfigured)
        ));
        let mut image = images(kind);
        image.remove(0);
        assert!(matches!(
            Installation::new(inputs(kind, 5), image),
            Err(Error::MissingImage(1))
        ));
        let mut image = images(kind);
        image.push(NativeImage {
            sequence: 1,
            counted_words: 0,
            bytes: vec![0; 4],
        });
        assert!(matches!(
            Installation::new(inputs(kind, 5), image),
            Err(Error::DuplicateImage(1))
        ));
        let mut image = images(kind);
        image[0].counted_words = 0;
        assert!(matches!(
            Installation::new(inputs(kind, 5), image),
            Err(Error::ImageGeometry(1))
        ));
        let mut image = images(kind);
        image[0].bytes[4] = 1;
        assert!(matches!(
            Installation::new(inputs(kind, 5), image),
            Err(Error::ImageGeometry(1))
        ));
        let mut input = inputs(kind, 5);
        input.chip = 0x8110;
        assert!(matches!(
            Installation::new(input, images(kind)),
            Err(Error::UnqualifiedChip)
        ));
        let mut input = inputs(kind, 5);
        input.revision = 2;
        assert!(matches!(
            Installation::new(input, images(kind)),
            Err(Error::UnqualifiedRevision)
        ));
        assert_eq!(
            NubPool::from_metadata(Metadata {
                first_page: 0xff,
                pages: 1
            }),
            Err(Error::PoolGeometry)
        );
        let pool = NubPool::from_metadata(Metadata {
            first_page: 2,
            pages: 0x10002e,
        })
        .unwrap();
        // Exact native W-shift wraps the high bits; it does not widen them.
        assert_eq!(pool.tables(), [0x23df30000, 0x23df30100]);
        assert_eq!(pool.code_start(), 0x23df30200);
    }
    #[test]
    #[cfg(feature = "std")]
    #[ignore = "requires pinned original J473 LLB; no Apple image is committed"]
    fn original_llb_matches_every_installed_group_slot_and_dmb_boundary() {
        use sha2::{Digest, Sha256};
        let bytes =
            std::fs::read(std::env::var("STELA_TEST_PMGR_LLB").expect("pinned original LLB path"))
                .unwrap();
        assert_eq!(
            hex::encode(Sha256::digest(&bytes)),
            "d6c695d26e5d816a2ecd523c0be20a15307af24c404b1603d74a970b53e75e77"
        );
        let word =
            |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
        let quad =
            |offset: usize| u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap());
        assert_eq!(word(0x4ac), 0xd5033fbf); // actual helper is DMB SY
        assert_eq!(word(0x4b0), 0xd65f03c0);
        let branch = word(0x26634);
        let displacement = ((branch << 6) as i32 >> 4) as isize;
        assert_eq!(0x26634usize.wrapping_add_signed(displacement), 0x4ac);
        for (raw_kind, kind) in [
            (0, ProgramKind::EarlyCpu),
            (1, ProgramKind::EarlyPeripheral),
            (3, ProgramKind::LateCpu),
            (4, ProgramKind::LatePeripheral),
        ] {
            let start = (quad(0x160198 + raw_kind * 8) - 0x1fc050000) as usize;
            let end = (quad(0x160170 + raw_kind * 8) - 0x1fc050000) as usize;
            let descriptors: Vec<_> = (start..end)
                .step_by(64)
                .map(|offset| (word(offset), word(offset + 4), word(offset + 40)))
                .collect();
            // These minimal supplied images are construction fixtures, never
            // evidence that original source bodies emit or execute empty work.
            let images = descriptors
                .iter()
                .map(|(id, _, _)| NativeImage {
                    sequence: *id as u8,
                    counted_words: 0,
                    bytes: vec![0; 4],
                })
                .collect();
            let mut installation = Installation::new(inputs(kind, 5), images).unwrap();
            for (placement, (id, group, slot)) in installation.placements().iter().zip(&descriptors)
            {
                assert_eq!(
                    (
                        u32::from(placement.sequence),
                        u32::from(placement.group),
                        u32::from(placement.slot)
                    ),
                    (*id, *group, *slot)
                );
            }
            assert_eq!(installation.placements().len(), descriptors.len());
            let group_start = (quad(0x1601e8 + raw_kind * 8) - 0x1fc050000) as usize;
            assert_eq!(word(0x1a30a0 + raw_kind * 4), 2);
            if matches!(kind, ProgramKind::EarlyCpu | ProgramKind::LateCpu) {
                for index in 0..2 {
                    let descriptor = group_start + index * 64;
                    let table = quad(descriptor + 24);
                    let (address, value) = match word(descriptor) {
                        0 => (0x23d2d0200, table & 0x3ff00),
                        3 => (0x23b78d000, (table >> 8) & 0xfffffff),
                        other => panic!("unexpected original CPU group {other}"),
                    };
                    let claim = installation.begin().unwrap().unwrap();
                    assert!(
                        matches!(installation.dispatch(&claim), Ok(Action::Write(write)) if write.address == address && write.width == Width::Word && write.value == value)
                    );
                    installation.finish::<()>(&claim, Outcome::Written).unwrap();
                }
            }
        }
    }
}
