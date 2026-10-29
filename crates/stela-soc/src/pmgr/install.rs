//! Ordered T8112 native program installation, from original J473 LLB
//! 0x142c0/0x4d1b4/0x4d2cc/0x4dcd8/0x4ec98/0x4f1b4.
//!
//! Supplied metadata, firmware history and native images are inputs.
//! This does not compile the source tables, supply their live AP effects,
//! reconstruct initial SRAM, check a hardware trigger or retire instructions.
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

/// NUB metadata words at physical0x23d050000/4 when the native pool is
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
        // Original W-register shift truncates the second term.
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
/// means only that these configuration effects committed through routes;
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
        // Allocation publishes pointers before any native image bytes.
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
mod tests;
