//! The PTD bank and its register model. `Ptd` holds entries, metadata, update
//! aliases and per-route interrupt state with per-bit knownness, accepts
//! updates, consumes whole entries and drives the route wire levels, refusing
//! accesses it cannot check.
#[cfg(test)]
use super::PTD_BYTES;
use super::{MAX_ENTRIES, Range, UPDATE_OFFSET};
use crate::Result;
use alloc::{collections::BTreeSet, rc::Rc, vec, vec::Vec};
use core::cell::RefCell;
use stela_contracts::Refusal;
use stela_contracts::interrupt::Wire;
use stela_contracts::refuse;
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction, stela_contracts::bus::Lifecycle,
    stela_contracts::bus::LifecycleState, stela_contracts::bus::MmioDevice,
    stela_contracts::bus::MmioError, stela_contracts::bus::Width, stela_contracts::bus::refuse,
};

pub mod notifications;
pub mod status;

const NAME: &str = "ptd";
const ENTRY_BYTES: u64 = 16;
const UPDATE_BYTES: u64 = 8;
pub const IRQ_STATUS: u64 = 0x18000;
const IRQ_ENABLE: u64 = 0x18200;
const IRQ_DISABLE: u64 = 0x18300;
const IRQ_ROUTE: u64 = 0x18400;
const ROUTES: usize = 16;
const NEW_DATA: u64 = 1 << 1;
const DROPPED: u64 = 1;
const FLAGS: u64 = NEW_DATA | DROPPED;
const TIMESTAMP: u64 = u64::MAX << 10;

/// Timestamp provenance is explicit: a native observation is not the
/// Stela system counter. A capture-only bank refuses new timestamped updates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimestampSource {
    StelaSystemCounter,
    CaptureOnly,
}

#[derive(Debug, Clone, Copy)]
struct Word {
    value: u64,
    known: u64,
}
impl Word {
    const ZERO: Self = Self {
        value: 0,
        known: u64::MAX,
    };
    const UNKNOWN: Self = Self { value: 0, known: 0 };
    fn read(self, mask: u64) -> Result<u64> {
        if self.known & mask != mask {
            return Err(refuse!("PTD register contains unqualified bits"));
        }
        Ok(self.value & mask)
    }
    fn bit(self, bit: u64) -> Option<bool> {
        (self.known & bit != 0).then_some(self.value & bit != 0)
    }
}

/// A raw register observation, with independent bit knownness. Canonical IRQ
/// and route observations are 32-bit; publication/update observations are 64-bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    pub offset: u64,
    pub value: u64,
    pub known: u64,
}

/// The original raw 128-bit publication, before its consume effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub value: u64,
    pub metadata: u64,
}

/// Committed transport input. Its serial identifies this write even
/// when a later write reuses the same entry. It is not a service completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub serial: u64,
    pub entry: u32,
    pub value: u64,
    pub at: u64,
}

#[derive(Clone)]
struct State {
    lifecycle: LifecycleState,
    timestamps: TimestampSource,
    ranges: Vec<Range>,
    values: Vec<Word>,
    metadata: Vec<Word>,
    updates: Vec<Word>,
    pending: Vec<Word>,
    enabled: Vec<Word>,
    routes: Vec<Word>,
    bindings: [Option<Wire>; ROUTES],
    notification_owner: NotificationOwner,
    pmp_recipient_admitted: bool,
    asserted: [bool; ROUTES],
    requests: Vec<Request>,
    serial: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NotificationOwner {
    External,
    PmpLocal,
}
impl State {
    fn accessible(&self) -> Result<()> {
        if !self.lifecycle.powered || !self.lifecycle.clocked || self.lifecycle.quiesced {
            return Err(refuse!("PTD transport is paused by its actual owner"));
        }
        if self.lifecycle.reset {
            return Err(refuse!("PTD transport is in reset"));
        }
        Ok(())
    }
    fn levels(&self) -> Result<[bool; ROUTES]> {
        let mut levels = [false; ROUTES];
        for (word, (enabled, pending)) in self.enabled.iter().zip(&self.pending).enumerate() {
            // An entry known disabled or known not pending drives nothing;
            // visit the others in entry order.
            let idle = (enabled.known & !enabled.value) | (pending.known & !pending.value);
            let mut live = !idle & u64::from(u32::MAX);
            while live != 0 {
                let bit = live.trailing_zeros() as usize;
                live &= live - 1;
                let entry = word * 32 + bit;
                if entry >= self.values.len() {
                    break;
                }
                let mask = 1 << bit;
                if enabled.bit(mask) != Some(true) || pending.bit(mask) != Some(true) {
                    return Err(refuse!("PTD interrupt disposition is not qualified"));
                }
                let shift = (entry % 8) * 4;
                let route = (self.routes[entry / 8].read(0xf << shift)? >> shift) as usize;
                if self.notification_owner == NotificationOwner::External
                    && self.bindings[route].is_none()
                {
                    return Err(refuse!("PTD route has no qualified interrupt resource"));
                }
                levels[route] = true;
            }
        }
        Ok(levels)
    }
    fn synchronize(&mut self, levels: [bool; ROUTES], access: &mut Access<'_>) {
        // Unchanged route levels leave every wire's aggregate as it is.
        if levels == self.asserted {
            return;
        }
        // Several route selectors may name the same physical wire. Publish its
        // aggregate level, never a deassertion that masks another live route.
        let wires: BTreeSet<_> = self.bindings.iter().flatten().copied().collect();
        for wire in wires {
            let old = (0..ROUTES).any(|r| self.bindings[r] == Some(wire) && self.asserted[r]);
            let new = (0..ROUTES).any(|r| self.bindings[r] == Some(wire) && levels[r]);
            if old != new {
                access.interrupts.set_level(wire, new);
            }
        }
        self.asserted = levels;
    }
    fn bit_pending(&mut self, entry: usize, pending: bool) {
        let word = &mut self.pending[entry / 32];
        let mask = 1 << (entry % 32);
        word.value = (word.value & !mask) | if pending { mask } else { 0 };
        word.known |= mask;
    }
}

/// Shared object identity for the AP, PMP and PMGR aliases. Cloning this handle
/// never clones the bank, input history or lifecycle into an unrelated device.
#[derive(Clone)]
pub struct Ptd(Rc<RefCell<State>>);
impl Ptd {
    /// Old callers must choose an initialized backing or an observation
    /// constructor. No constructor manufactures PMP readiness/service output.
    pub fn new(_: &[Range]) -> Result<Self> {
        Err(refuse!(
            "PTD requires explicitly initialized owned backing or qualified observations"
        ))
    }

    /// A newly allocated Stela transport, initialized before any guest owner is
    /// admitted. These are software initialization effects, not Apple cold-reset
    /// measurements. Every entry starts unpublished; IRQs start disabled. The
    /// caller supplies lifecycle inputs and separately checked wires.
    pub fn initialized(
        entries: u32,
        ranges: &[Range],
        lifecycle: LifecycleState,
        bindings: [Option<Wire>; ROUTES],
    ) -> Result<Self> {
        Self::construct(
            entries,
            ranges,
            lifecycle,
            bindings,
            TimestampSource::StelaSystemCounter,
            Word::ZERO,
        )
    }

    /// Native state. Unobserved bits stay unknown, including zero-valued
    /// fields. Capture-only timestamps do not acquire an invented clock epoch.
    pub fn from_observations(
        entries: u32,
        ranges: &[Range],
        lifecycle: LifecycleState,
        bindings: [Option<Wire>; ROUTES],
        observations: &[Observation],
    ) -> Result<Self> {
        let bank = Self::construct(
            entries,
            ranges,
            lifecycle,
            bindings,
            TimestampSource::CaptureOnly,
            Word::UNKNOWN,
        )?;
        let mut seen = BTreeSet::new();
        {
            let mut state = bank.0.borrow_mut();
            for observation in observations {
                if !seen.insert(observation.offset) {
                    return Err(refuse!("duplicate PTD observation"));
                }
                let (role, index, mask) = locate(&state, observation.offset, None)?;
                if observation.value & !mask != 0 || observation.known & !mask != 0 {
                    return Err(refuse!("PTD observation exceeds its register width"));
                }
                let word = Word {
                    value: observation.value,
                    known: observation.known,
                };
                match role {
                    Role::Value => state.values[index] = word,
                    Role::Metadata => state.metadata[index] = word,
                    Role::Update => state.updates[index] = word,
                    Role::Pending => state.pending[index] = word,
                    Role::Enable => state.enabled[index] = word,
                    Role::Route => state.routes[index] = word,
                    Role::Disable => {
                        return Err(refuse!("PTD disable alias is not a retained register"));
                    }
                }
            }
        }
        Ok(bank)
    }

    fn construct(
        entries: u32,
        ranges: &[Range],
        lifecycle: LifecycleState,
        bindings: [Option<Wire>; ROUTES],
        timestamps: TimestampSource,
        initial: Word,
    ) -> Result<Self> {
        let entries =
            usize::try_from(entries).map_err(|_| refuse!("PTD entry count exceeds host width"))?;
        if entries == 0 || entries > MAX_ENTRIES || ranges.is_empty() {
            return Err(refuse!(
                "PTD bank geometry is outside its described registers"
            ));
        }
        if lifecycle.reset || (!lifecycle.powered && !lifecycle.retention) {
            return Err(refuse!(
                "PTD physical reset/nonretained loss is unqualified"
            ));
        }
        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut covered = BTreeSet::new();
        for range in ranges {
            let end = range
                .start
                .checked_add(range.count)
                .ok_or(refuse!("PTD range overflow"))?;
            if range.count == 0 || end as usize > entries || range.name.is_empty() {
                return Err(refuse!("PTD range is empty or outside its bank"));
            }
            if !ids.insert(range.id) || !names.insert(range.name.as_str()) {
                return Err(refuse!("PTD range identity is duplicated"));
            }
            for entry in range.start..end {
                if !covered.insert(entry) {
                    return Err(refuse!("PTD range ownership overlaps"));
                }
            }
        }
        Ok(Self(Rc::new(RefCell::new(State {
            lifecycle,
            timestamps,
            ranges: ranges.to_vec(),
            values: vec![initial; entries],
            metadata: vec![initial; entries],
            updates: vec![initial; entries],
            pending: vec![initial; entries.div_ceil(32)],
            enabled: vec![initial; entries.div_ceil(32)],
            routes: vec![initial; entries.div_ceil(8)],
            bindings,
            notification_owner: NotificationOwner::External,
            pmp_recipient_admitted: false,
            asserted: [false; ROUTES],
            requests: Vec::new(),
            serial: 0,
        }))))
    }

    pub fn ranges(&self) -> Vec<Range> {
        self.0.borrow().ranges.clone()
    }
    pub fn requests(&self) -> Vec<Request> {
        self.0.borrow().requests.clone()
    }
    pub fn lifecycle_state(&self) -> LifecycleState {
        self.0.borrow().lifecycle
    }
    pub fn timestamp_source(&self) -> TimestampSource {
        self.0.borrow().timestamps
    }

    /// Drive the checked kept/initialized interrupt state when admitting
    /// its mapped view. Unknown active disposition refuses instead of losing an
    /// already pending interrupt behind an initially deasserted host latch.
    pub fn activate(&self, access: &mut Access<'_>) -> Result<()> {
        let mut state = self.0.borrow_mut();
        state.accessible()?;
        let levels = state.levels()?;
        state.synchronize(levels, access);
        Ok(())
    }

    /// The checked full-entry consume boundary used by the original LDP
    /// producer/consumer protocol. This is not a claim about scalar half-read
    /// side effects. The bus must not guess that two unrelated scalar reads
    /// form this operation. No service ACK is generated by consuming an input.
    pub fn consume_entry(&self, entry: u32, access: &mut Access<'_>) -> Result<Entry> {
        let mut state = self.0.borrow_mut();
        state.accessible()?;
        let index = usize::try_from(entry).map_err(|_| refuse!("PTD entry exceeds host width"))?;
        let value = *state
            .values
            .get(index)
            .ok_or(refuse!("PTD consume outside its bank"))?;
        let metadata = state.metadata[index];
        let result = Entry {
            value: value.read(u64::MAX)?,
            metadata: metadata.read(u64::MAX)?,
        };
        let old_pending = state.pending[index / 32];
        let old_metadata = state.metadata[index];
        state.bit_pending(index, false);
        state.metadata[index].value &= !FLAGS;
        let levels = match state.levels() {
            Ok(levels) => levels,
            Err(error) => {
                state.pending[index / 32] = old_pending;
                state.metadata[index] = old_metadata;
                return Err(error);
            }
        };
        state.synchronize(levels, access);
        Ok(result)
    }
}

#[derive(Clone, Copy)]
enum Role {
    Value,
    Metadata,
    Update,
    Pending,
    Enable,
    Disable,
    Route,
}
fn locate(state: &State, offset: u64, width: Option<Width>) -> Result<(Role, usize, u64)> {
    let entry_bytes = state.values.len() as u64 * ENTRY_BYTES;
    let update_bytes = state.values.len() as u64 * UPDATE_BYTES;
    let words = state.pending.len() as u64 * 4;
    let route_bytes = state.routes.len() as u64 * 4;
    let (role, index, wanted) = match offset {
        x if x < entry_bytes && x.is_multiple_of(8) => (
            if x.is_multiple_of(ENTRY_BYTES) {
                Role::Value
            } else {
                Role::Metadata
            },
            (x / ENTRY_BYTES) as usize,
            Width::Double,
        ),
        x if (UPDATE_OFFSET..UPDATE_OFFSET + update_bytes).contains(&x) && x.is_multiple_of(8) => (
            Role::Update,
            ((x - UPDATE_OFFSET) / 8) as usize,
            Width::Double,
        ),
        x if (IRQ_STATUS..IRQ_STATUS + words).contains(&x) && x.is_multiple_of(4) => {
            (Role::Pending, ((x - IRQ_STATUS) / 4) as usize, Width::Word)
        }
        x if (IRQ_ENABLE..IRQ_ENABLE + words).contains(&x) && x.is_multiple_of(4) => {
            (Role::Enable, ((x - IRQ_ENABLE) / 4) as usize, Width::Word)
        }
        x if (IRQ_DISABLE..IRQ_DISABLE + words).contains(&x) && x.is_multiple_of(4) => {
            (Role::Disable, ((x - IRQ_DISABLE) / 4) as usize, Width::Word)
        }
        x if (IRQ_ROUTE..IRQ_ROUTE + route_bytes).contains(&x) && x.is_multiple_of(4) => {
            (Role::Route, ((x - IRQ_ROUTE) / 4) as usize, Width::Word)
        }
        _ => return Err(refuse!("PTD register is outside its qualified geometry")),
    };
    if width.is_some_and(|width| width != wanted) {
        return Err(refuse!("PTD register access has an unqualified width"));
    }
    Ok((role, index, wanted.mask()))
}

impl Lifecycle for Ptd {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<()> {
        if proposed.reset || (!proposed.powered && !proposed.retention) {
            return Err(refuse!(
                "PTD physical reset/nonretained loss and cancellation are unqualified"
            ));
        }
        Ok(())
    }
    fn set_lifecycle(&mut self, proposed: LifecycleState, _: &mut Access<'_>) {
        assert!(self.check_lifecycle(proposed).is_ok());
        // Pause preserves exact pending inputs and existing wire levels.
        self.0.borrow_mut().lifecycle = proposed;
    }
}
impl MmioDevice for Ptd {
    fn name(&self) -> &'static str {
        NAME
    }
    fn advance(&mut self, access: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
        if !self.0.borrow().lifecycle.powered
            || !self.0.borrow().lifecycle.clocked
            || self.0.borrow().lifecycle.quiesced
        {
            return Ok(None);
        }
        self.activate(access)
            .map_err(|reason| refuse(NAME, IRQ_STATUS, Width::Word, Direction::Read, reason))?;
        Ok(None)
    }
    fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
        Some(self)
    }
    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let fail = |reason: Refusal| refuse(NAME, offset, width, Direction::Read, reason);
        let state = self.0.borrow();
        if width == Width::Double && (IRQ_STATUS..IRQ_ENABLE).contains(&offset) {
            return state
                .interrupt_snapshot(offset, status::Width::Double)
                .map(|snapshot| snapshot.low)
                .map_err(fail);
        }
        state.accessible().map_err(fail)?;
        let (role, index, mask) = locate(&state, offset, Some(width)).map_err(fail)?;
        let word = match role {
            Role::Value | Role::Metadata => {
                // Original consumers issue LDP. Neither scalar half is guessed
                // to be the consuming transaction when new data is present.
                let flags = state.metadata[index].read(FLAGS).map_err(fail)?;
                if flags != 0 {
                    return Err(fail(refuse!(
                        "pending PTD scalar half-read consumption is unqualified; a full-entry consume is required"
                    )));
                }
                if matches!(role, Role::Value) {
                    state.values[index]
                } else {
                    state.metadata[index]
                }
            }
            Role::Pending => state.pending[index],
            Role::Route => state.routes[index],
            Role::Enable | Role::Disable | Role::Update => {
                return Err(fail(refuse!(
                    "PTD write-alias read semantics are unqualified"
                )));
            }
        };
        word.read(mask).map_err(fail)
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let fail = |reason: Refusal| refuse(NAME, offset, width, Direction::Write, reason);
        let mut state = self.0.borrow_mut();
        state.accessible().map_err(fail)?;
        let (role, index, mask) = locate(&state, offset, Some(width)).map_err(fail)?;
        let value = value & mask;
        if matches!(role, Role::Update) {
            if state.timestamps != TimestampSource::StelaSystemCounter {
                return Err(fail(refuse!(
                    "retained PTD clock has no qualified update timestamp domain"
                )));
            }
            let serial = state
                .serial
                .checked_add(1)
                .ok_or_else(|| fail(refuse!("PTD transport serial exhausted")))?;
            let old = (
                state.values[index],
                state.metadata[index],
                state.updates[index],
                state.pending[index / 32],
            );
            let previous = old.1;
            let dropped =
                previous.bit(NEW_DATA) == Some(true) || previous.bit(DROPPED) == Some(true);
            let drop_known =
                dropped || (previous.bit(NEW_DATA).is_some() && previous.bit(DROPPED).is_some());
            let flags = NEW_DATA | if dropped { DROPPED } else { 0 };
            state.values[index] = Word {
                value,
                known: u64::MAX,
            };
            state.metadata[index] = Word {
                value: (previous.value & !(TIMESTAMP | FLAGS)) | (access.now << 10) | flags,
                known: (previous.known & !(TIMESTAMP | FLAGS))
                    | TIMESTAMP
                    | NEW_DATA
                    | if drop_known { DROPPED } else { 0 },
            };
            state.updates[index] = Word {
                value,
                known: u64::MAX,
            };
            state.bit_pending(index, true);
            let levels = match state.levels() {
                Ok(levels) => levels,
                Err(reason) => {
                    state.values[index] = old.0;
                    state.metadata[index] = old.1;
                    state.updates[index] = old.2;
                    state.pending[index / 32] = old.3;
                    return Err(fail(reason));
                }
            };
            state.serial = serial;
            state.requests.push(Request {
                serial,
                entry: index as u32,
                value,
                at: access.now,
            });
            state.synchronize(levels, access);
            return Ok(());
        }
        let old = match role {
            Role::Enable | Role::Disable => state.enabled[index],
            Role::Route => state.routes[index],
            _ => {
                return Err(fail(refuse!(
                    "write to a PTD publication or interrupt status"
                )));
            }
        };
        match role {
            Role::Enable | Role::Disable => {
                let remaining = state.values.len() - index * 32;
                let valid = if remaining >= 32 {
                    u64::from(u32::MAX)
                } else {
                    (1 << remaining) - 1
                };
                if value & !valid != 0 {
                    return Err(fail(refuse!("PTD interrupt write selects an absent entry")));
                }
                state.enabled[index] = Word {
                    value: if matches!(role, Role::Enable) {
                        old.value | value
                    } else {
                        old.value & !value
                    },
                    known: old.known | value,
                };
            }
            Role::Route => {
                let remaining = state.values.len() - index * 8;
                let valid = if remaining >= 8 {
                    u64::from(u32::MAX)
                } else {
                    (1 << (remaining * 4)) - 1
                };
                if value & !valid != 0 {
                    return Err(fail(refuse!("PTD route write selects an absent entry")));
                }
                state.routes[index] = Word {
                    value,
                    known: u32::MAX.into(),
                };
            }
            _ => unreachable!(),
        }
        let levels = match state.levels() {
            Ok(levels) => levels,
            Err(reason) => {
                match role {
                    Role::Enable | Role::Disable => state.enabled[index] = old,
                    Role::Route => state.routes[index] = old,
                    _ => unreachable!(),
                }
                return Err(fail(reason));
            }
        };
        state.synchronize(levels, access);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
