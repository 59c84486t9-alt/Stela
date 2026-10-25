#[cfg(test)]
use super::PTD_BYTES;
use super::{MAX_ENTRIES, Range, UPDATE_OFFSET};
use crate::platform::apple::bus::{
    Access, Direction, Lifecycle, LifecycleState, MmioDevice, MmioError, Width, refuse,
};
use crate::platform::apple::interrupt::Wire;
use alloc::{collections::BTreeSet, rc::Rc, vec, vec::Vec};
use core::cell::RefCell;

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

/// Timestamp provenance is explicit: a retained native observation is not the
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
    fn read(self, mask: u64) -> Result<u64, &'static str> {
        if self.known & mask != mask {
            return Err("PTD register contains unqualified bits");
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

/// Committed transport input. Its serial identifies this actual write even
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
    fn accessible(&self) -> Result<(), &'static str> {
        if !self.lifecycle.powered || !self.lifecycle.clocked || self.lifecycle.quiesced {
            return Err("PTD transport is paused by its actual owner");
        }
        if self.lifecycle.reset {
            return Err("PTD transport is in reset");
        }
        Ok(())
    }
    fn levels(&self) -> Result<[bool; ROUTES], &'static str> {
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
                    return Err("PTD interrupt disposition is not qualified");
                }
                let shift = (entry % 8) * 4;
                let route = (self.routes[entry / 8].read(0xf << shift)? >> shift) as usize;
                if self.notification_owner == NotificationOwner::External
                    && self.bindings[route].is_none()
                {
                    return Err("PTD route has no qualified interrupt resource");
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
    /// Old callers must choose an actual initialized backing or an observation
    /// constructor. No constructor manufactures PMP readiness/service output.
    pub fn new(_: &[Range]) -> Result<Self, &'static str> {
        Err("PTD requires explicitly initialized owned backing or qualified observations")
    }

    /// A newly allocated Stela transport, initialized before any guest owner is
    /// admitted. These are software initialization effects, not Apple cold-reset
    /// measurements. Every entry starts unpublished; IRQs start disabled. The
    /// caller supplies actual lifecycle inputs and separately qualified wires.
    pub fn initialized(
        entries: u32,
        ranges: &[Range],
        lifecycle: LifecycleState,
        bindings: [Option<Wire>; ROUTES],
    ) -> Result<Self, &'static str> {
        Self::construct(
            entries,
            ranges,
            lifecycle,
            bindings,
            TimestampSource::StelaSystemCounter,
            Word::ZERO,
        )
    }

    /// Retained native state. Unobserved bits stay unknown, including zero-valued
    /// fields. Capture-only timestamps do not acquire a fabricated clock epoch.
    pub fn from_observations(
        entries: u32,
        ranges: &[Range],
        lifecycle: LifecycleState,
        bindings: [Option<Wire>; ROUTES],
        observations: &[Observation],
    ) -> Result<Self, &'static str> {
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
                    return Err("duplicate PTD observation");
                }
                let (role, index, mask) = locate(&state, observation.offset, None)?;
                if observation.value & !mask != 0 || observation.known & !mask != 0 {
                    return Err("PTD observation exceeds its register width");
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
                    Role::Disable => return Err("PTD disable alias is not a retained register"),
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
    ) -> Result<Self, &'static str> {
        let entries = usize::try_from(entries).map_err(|_| "PTD entry count exceeds host width")?;
        if entries == 0 || entries > MAX_ENTRIES || ranges.is_empty() {
            return Err("PTD bank geometry is outside its described registers");
        }
        if lifecycle.reset || (!lifecycle.powered && !lifecycle.retention) {
            return Err("PTD physical reset/nonretained loss is unqualified");
        }
        let mut ids = BTreeSet::new();
        let mut names = BTreeSet::new();
        let mut covered = BTreeSet::new();
        for range in ranges {
            let end = range
                .start
                .checked_add(range.count)
                .ok_or("PTD range overflow")?;
            if range.count == 0 || end as usize > entries || range.name.is_empty() {
                return Err("PTD range is empty or outside its bank");
            }
            if !ids.insert(range.id) || !names.insert(range.name.as_str()) {
                return Err("PTD range identity is duplicated");
            }
            for entry in range.start..end {
                if !covered.insert(entry) {
                    return Err("PTD range ownership overlaps");
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

    /// Drive the qualified retained/initialized interrupt state when admitting
    /// its mapped view. Unknown active disposition refuses instead of losing an
    /// already pending interrupt behind an initially deasserted host latch.
    pub fn activate(&self, access: &mut Access<'_>) -> Result<(), &'static str> {
        let mut state = self.0.borrow_mut();
        state.accessible()?;
        let levels = state.levels()?;
        state.synchronize(levels, access);
        Ok(())
    }

    /// The qualified full-entry consume boundary used by the original LDP
    /// producer/consumer protocol. This is not a claim about scalar half-read
    /// side effects. The bus must not guess that two unrelated scalar reads
    /// form this operation. No service ACK is generated by consuming an input.
    pub fn consume_entry(
        &self,
        entry: u32,
        access: &mut Access<'_>,
    ) -> Result<Entry, &'static str> {
        let mut state = self.0.borrow_mut();
        state.accessible()?;
        let index = usize::try_from(entry).map_err(|_| "PTD entry exceeds host width")?;
        let value = *state
            .values
            .get(index)
            .ok_or("PTD consume outside its bank")?;
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
fn locate(
    state: &State,
    offset: u64,
    width: Option<Width>,
) -> Result<(Role, usize, u64), &'static str> {
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
        _ => return Err("PTD register is outside its qualified geometry"),
    };
    if width.is_some_and(|width| width != wanted) {
        return Err("PTD register access has an unqualified width");
    }
    Ok((role, index, wanted.mask()))
}

impl Lifecycle for Ptd {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<(), &'static str> {
        if proposed.reset || (!proposed.powered && !proposed.retention) {
            return Err("PTD physical reset/nonretained loss and cancellation are unqualified");
        }
        Ok(())
    }
    fn set_lifecycle(&mut self, proposed: LifecycleState, _: &mut Access<'_>) {
        assert!(self.check_lifecycle(proposed).is_ok());
        // Retained pause preserves exact pending inputs and existing wire levels.
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
        let fail = |reason| refuse(NAME, offset, width, Direction::Read, reason);
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
                    return Err(fail(
                        "pending PTD scalar half-read consumption is unqualified; a full-entry consume is required",
                    ));
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
                return Err(fail("PTD write-alias read semantics are unqualified"));
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
        let fail = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        let mut state = self.0.borrow_mut();
        state.accessible().map_err(fail)?;
        let (role, index, mask) = locate(&state, offset, Some(width)).map_err(fail)?;
        let value = value & mask;
        if matches!(role, Role::Update) {
            if state.timestamps != TimestampSource::StelaSystemCounter {
                return Err(fail(
                    "retained PTD clock has no qualified update timestamp domain",
                ));
            }
            let serial = state
                .serial
                .checked_add(1)
                .ok_or_else(|| fail("PTD transport serial exhausted"))?;
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
            _ => return Err(fail("write to a PTD publication or interrupt status")),
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
                    return Err(fail("PTD interrupt write selects an absent entry"));
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
                    return Err(fail("PTD route write selects an absent entry"));
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
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::{AicInput, InterruptLatch};

    fn lifecycle() -> LifecycleState {
        LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: true,
        }
    }
    fn ranges() -> Vec<Range> {
        vec![
            Range {
                id: 2,
                start: 1,
                count: 1,
                name: "PMP-STATUS".into(),
            },
            Range {
                id: 10,
                start: 248,
                count: 8,
                name: "SOC-DEV-PS-REQ".into(),
            },
            Range {
                id: 11,
                start: 256,
                count: 8,
                name: "SOC-DEV-PS-ACK".into(),
            },
        ]
    }
    fn bank() -> Ptd {
        Ptd::initialized(384, &ranges(), lifecycle(), [None; ROUTES]).unwrap()
    }
    fn write(
        bank: &mut Ptd,
        entry: u32,
        value: u64,
        now: u64,
        latch: &mut InterruptLatch,
    ) -> Result<(), MmioError> {
        bank.write(
            UPDATE_OFFSET + u64::from(entry) * 8,
            Width::Double,
            value,
            &mut Access::new(0, now, latch),
        )
    }

    #[test]
    fn initialized_backing_never_fabricates_readiness_power_ack_or_quota() {
        let mut bank = bank();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        assert_eq!(bank.read(16, Width::Double, &mut access), Ok(0));
        assert_eq!(bank.read(24, Width::Double, &mut access), Ok(0));
        write(&mut bank, 248, 0xfedc, 17, &mut latch).unwrap();
        let request = bank
            .consume_entry(248, &mut Access::new(0, 18, &mut latch))
            .unwrap();
        assert_eq!(
            request,
            Entry {
                value: 0xfedc,
                metadata: 17 << 10 | NEW_DATA
            }
        );
        assert_eq!(
            bank.consume_entry(256, &mut Access::new(0, 18, &mut latch))
                .unwrap(),
            Entry {
                value: 0,
                metadata: 0
            }
        );
        assert_eq!(
            bank.requests(),
            [Request {
                serial: 1,
                entry: 248,
                value: 0xfedc,
                at: 17
            }]
        );
        assert!(Ptd::new(&ranges()).is_err());
    }

    #[test]
    fn overwrite_dropped_timestamp_and_consume_are_actual_transport_effects() {
        let mut bank = bank();
        let mut latch = InterruptLatch::new();
        write(&mut bank, 3, 0x1234, (1 << 54) - 1, &mut latch).unwrap();
        write(&mut bank, 3, 0x5678, 1 << 54, &mut latch).unwrap();
        let mut access = Access::new(0, 0, &mut latch);
        assert_eq!(bank.read(IRQ_STATUS, Width::Word, &mut access), Ok(1 << 3));
        assert!(bank.read(3 * 16, Width::Double, &mut access).is_err());
        assert!(bank.read(3 * 16 + 8, Width::Double, &mut access).is_err());
        assert_eq!(
            bank.consume_entry(3, &mut access).unwrap(),
            Entry {
                value: 0x5678,
                metadata: FLAGS
            }
        );
        assert_eq!(bank.read(IRQ_STATUS, Width::Word, &mut access), Ok(0));
        assert_eq!(bank.read(3 * 16, Width::Double, &mut access), Ok(0x5678));
        assert_eq!(bank.read(3 * 16 + 8, Width::Double, &mut access), Ok(0));
        assert_eq!(
            bank.requests().iter().map(|r| r.serial).collect::<Vec<_>>(),
            [1, 2]
        );
    }

    #[test]
    fn aliases_share_identity_and_retained_pause_keeps_the_complete_prefix() {
        let mut bank = bank();
        let mut alias = bank.clone();
        let mut latch = InterruptLatch::new();
        write(&mut bank, 1, 0xabc, 9, &mut latch).unwrap();
        let paused = LifecycleState {
            clocked: false,
            ..lifecycle()
        };
        Lifecycle::set_lifecycle(&mut alias, paused, &mut Access::new(0, 10, &mut latch));
        assert_eq!(bank.lifecycle_state(), paused);
        assert!(write(&mut bank, 1, 0, 11, &mut latch).is_err());
        assert!(
            bank.consume_entry(1, &mut Access::new(0, 11, &mut latch))
                .is_err()
        );
        assert_eq!(alias.requests().len(), 1);
        assert!(
            Lifecycle::check_lifecycle(
                &bank,
                LifecycleState {
                    reset: true,
                    ..lifecycle()
                }
            )
            .is_err()
        );
        assert!(
            Lifecycle::check_lifecycle(
                &bank,
                LifecycleState {
                    powered: false,
                    retention: false,
                    ..lifecycle()
                }
            )
            .is_err()
        );
        Lifecycle::set_lifecycle(&mut bank, lifecycle(), &mut Access::new(0, 12, &mut latch));
        assert_eq!(
            alias
                .consume_entry(1, &mut Access::new(0, 13, &mut latch))
                .unwrap()
                .value,
            0xabc
        );
    }

    #[test]
    fn qualified_routes_aggregate_same_wire_and_unqualified_routes_roll_back() {
        let wire = Wire::Aic(AicInput::new(0, 77));
        let mut bindings = [None; ROUTES];
        bindings[1] = Some(wire);
        bindings[2] = Some(wire);
        let mut bank = Ptd::initialized(384, &ranges(), lifecycle(), bindings).unwrap();
        let mut latch = InterruptLatch::new();
        bank.write(
            IRQ_ROUTE,
            Width::Word,
            0x21,
            &mut Access::new(0, 0, &mut latch),
        )
        .unwrap();
        bank.write(
            IRQ_ENABLE,
            Width::Word,
            3,
            &mut Access::new(0, 0, &mut latch),
        )
        .unwrap();
        write(&mut bank, 0, 1, 1, &mut latch).unwrap();
        write(&mut bank, 1, 2, 2, &mut latch).unwrap();
        assert!(latch.is_asserted(wire));
        bank.consume_entry(0, &mut Access::new(0, 3, &mut latch))
            .unwrap();
        assert!(latch.is_asserted(wire));
        assert!(
            bank.write(
                IRQ_ROUTE,
                Width::Word,
                0x31,
                &mut Access::new(0, 4, &mut latch)
            )
            .is_err()
        );
        assert_eq!(
            bank.read(IRQ_ROUTE, Width::Word, &mut Access::new(0, 4, &mut latch)),
            Ok(0x21)
        );
        bank.write(
            IRQ_DISABLE,
            Width::Word,
            2,
            &mut Access::new(0, 5, &mut latch),
        )
        .unwrap();
        assert!(!latch.is_asserted(wire));
        bank.write(
            IRQ_ENABLE,
            Width::Word,
            2,
            &mut Access::new(0, 6, &mut latch),
        )
        .unwrap();
        assert!(latch.is_asserted(wire));
        bank.consume_entry(1, &mut Access::new(0, 7, &mut latch))
            .unwrap();
        assert!(!latch.is_asserted(wire));
        // An unknown route refuses the triggering store before any effect.
        bank.write(
            IRQ_ENABLE,
            Width::Word,
            4,
            &mut Access::new(0, 8, &mut latch),
        )
        .unwrap();
        let before = bank.requests();
        assert!(write(&mut bank, 2, 9, 9, &mut latch).is_err());
        assert_eq!(bank.requests(), before);
        assert_eq!(
            bank.consume_entry(2, &mut Access::new(0, 10, &mut latch))
                .unwrap(),
            Entry {
                value: 0,
                metadata: 0
            }
        );
    }

    #[test]
    fn observation_unknownness_never_becomes_reset_or_native_clock_state() {
        let mut bank = Ptd::from_observations(
            384,
            &ranges(),
            lifecycle(),
            [None; ROUTES],
            &[
                Observation {
                    offset: 16,
                    value: 0,
                    known: u64::MAX,
                },
                Observation {
                    offset: 24,
                    value: 0,
                    known: u64::MAX,
                },
            ],
        )
        .unwrap();
        let mut latch = InterruptLatch::new();
        assert_eq!(
            bank.read(16, Width::Double, &mut Access::new(0, 0, &mut latch)),
            Ok(0)
        );
        assert!(
            bank.read(IRQ_STATUS, Width::Word, &mut Access::new(0, 0, &mut latch))
                .is_err()
        );
        assert!(write(&mut bank, 1, 1, 1, &mut latch).is_err());
        assert!(bank.requests().is_empty());
        assert!(
            Ptd::from_observations(
                384,
                &ranges(),
                lifecycle(),
                [None; ROUTES],
                &[Observation {
                    offset: IRQ_STATUS,
                    value: 1 << 32,
                    known: 0
                },]
            )
            .is_err()
        );
        assert!(
            Ptd::from_observations(
                384,
                &ranges(),
                lifecycle(),
                [None; ROUTES],
                &[
                    Observation {
                        offset: 16,
                        value: 0,
                        known: 0
                    },
                    Observation {
                        offset: 16,
                        value: 1,
                        known: 0
                    },
                ]
            )
            .is_err()
        );
    }

    #[test]
    fn range_identity_widths_and_last_word_boundaries_are_checked() {
        let source = ranges();
        for bad in [
            Range {
                id: 2,
                start: 300,
                count: 1,
                name: "duplicate-id".into(),
            },
            Range {
                id: 90,
                start: 300,
                count: 1,
                name: "PMP-STATUS".into(),
            },
            Range {
                id: 90,
                start: 250,
                count: 1,
                name: "overlap".into(),
            },
            Range {
                id: 90,
                start: u32::MAX,
                count: 1,
                name: "overflow".into(),
            },
        ] {
            let mut bad_ranges = source.clone();
            bad_ranges.push(bad);
            assert!(Ptd::initialized(384, &bad_ranges, lifecycle(), [None; ROUTES]).is_err());
        }
        let mut bank = Ptd::initialized(377, &ranges(), lifecycle(), [None; ROUTES]).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        assert!(
            bank.read(IRQ_STATUS + 44, Width::Double, &mut access)
                .is_err()
        );
        assert_eq!(
            bank.read(IRQ_STATUS + 40, Width::Double, &mut access),
            Ok(0)
        );
        for (offset, width) in [
            (PTD_BYTES, Width::Word),
            (16, Width::Word),
            (17, Width::Double),
            (UPDATE_OFFSET, Width::Word),
            (IRQ_ROUTE, Width::Double),
        ] {
            assert!(bank.read(offset, width, &mut access).is_err());
        }
        assert!(
            bank.write(IRQ_ENABLE + 44, Width::Word, 1 << 25, &mut access)
                .is_err()
        );
        assert!(
            bank.write(IRQ_ROUTE + 188, Width::Word, 0x10, &mut access)
                .is_err()
        );
        assert!(bank.requests().is_empty());
    }
}
