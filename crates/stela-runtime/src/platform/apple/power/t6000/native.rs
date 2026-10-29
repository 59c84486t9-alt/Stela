//! T6000's real shared configuration/SRAM owner.
//!
//! These are the original native-program configuration/activation words and the
//! physical SRAM iBoot's native-program installation writes. No request, installed pointer,
//! zero instruction or observed control value alone establishes a hardware
//! trigger or retirement. The optional Stela-native CIO engine owns accepted
//! requests, packet effects and exact finalized ends. It does not claim
//! captured Apple microstate. Every view shares the parent controller's lifecycle,
//! request prefix and byte storage; there is no parallel SRAM image.
use super::{Controller, RequestKind};
use crate::Result;
use alloc::{collections::BTreeMap, vec, vec::Vec};
use stela_contracts::Refusal;
use stela_contracts::refuse;
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction, stela_contracts::bus::Lifecycle,
    stela_contracts::bus::LifecycleState, stela_contracts::bus::MmioDevice,
    stela_contracts::bus::MmioError, stela_contracts::bus::Width, stela_contracts::bus::refuse,
    stela_soc_data::pmgr::t6000::CODE_BASE, stela_soc_data::pmgr::t6000::PRE_ACTIVATION_BASE,
    stela_soc_data::pmgr::t6000::SRAM_BASE, stela_soc_data::pmgr::t6000::SRAM_LIMIT,
    stela_soc_data::pmgr::t6000::TABLE_BASE,
};

pub mod effects;
pub mod engine;

const NAME: &str = "t6000-native-controller";
const SRAM_BYTES: usize = (SRAM_LIMIT - SRAM_BASE) as usize;
const GPCE: u64 = 0x28e099000;
const ACTIVATION_WORDS: [(u64, u32); 8] = [
    (GPCE + 0x6c, 1),
    (GPCE + 0x74, 1),
    (0x292000200, 0x1c000000),
    (0x292000204, 1),
    (PRE_ACTIVATION_BASE, 1),
    (PRE_ACTIVATION_BASE + 4, 1),
    (PRE_ACTIVATION_BASE + 8, 1),
    (PRE_ACTIVATION_BASE + 12, 1),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Profile,
    Geometry,
    UnknownControl,
    DuplicateControl,
    DuplicateByte,
    UnknownValue,
    UnqualifiedBits,
    UnknownSram,
    Pending,
    Epoch,
    Group,
    Slot,
    Pointer,
    Unconfigured,
    Unmounted,
    Paused,
    EffectsOwned,
    Cursor(crate::platform::apple::pmgr::sequencer::Error),
    Clock(super::clock::Error),
    ClockUnbound,
    ClockBound,
    Engine(engine::Error),
}
impl Error {
    fn reason(self) -> &'static str {
        match self {
            Self::Profile => "T6000 native resources qualify one actual first die only",
            Self::Geometry => "T6000 native resource access extent/alignment is invalid",
            Self::UnknownControl => "T6000 native control address is unqualified",
            Self::DuplicateControl => "T6000 native handoff repeats a control word",
            Self::DuplicateByte => "T6000 native handoff repeats an SRAM byte",
            Self::UnknownValue => "T6000 native control handoff/readback word is unknown",
            Self::UnqualifiedBits => "T6000 native control write changes unqualified fields",
            Self::UnknownSram => "T6000 native SRAM bytes are unknown",
            Self::Pending => {
                "T6000 native configuration requires qualified absence of pending/autonomous/activation work"
            }
            Self::Epoch => "T6000 native configuration epoch exhausted",
            Self::Group => "T6000 native group is outside the actual first-die catalog",
            Self::Slot => "T6000 native slot exceeds its actual 256-byte pointer table",
            Self::Pointer => "T6000 native pointer encoding/placement is unqualified",
            Self::Unconfigured => "T6000 native program pointer is not configured",
            Self::Unmounted => "T6000 native resource owner is not mounted",
            Self::Paused => {
                "T6000 native physical memory access while its rail/clock/reset inhibits service"
            }
            Self::EffectsOwned => "T6000 native packet effects already have an exclusive owner",
            Self::Cursor(_) => "T6000 native packet input is unqualified",
            Self::Clock(error) => error.reason(),
            Self::ClockUnbound => "T6000 native packet clock inputs/phase are not bound",
            Self::ClockBound => "T6000 native packet clock already has an exclusive owner",
            Self::Engine(error) => error.reason(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Control {
    pub address: u64,
    pub fields: u32,
}
/// Complete original `47090`/`471b8` first-die configuration interface and
/// `4b030`/`3d7d4` activation stores. The latter keep control inputs;
/// they do not check request-to-PC selection or hardware retirement.
/// Field masks check software inputs, never completion/status bits.
pub fn controls() -> Vec<Control> {
    let mut rows = vec![
        Control {
            address: 0x2925c0200,
            fields: 0x7ff00,
        },
        Control {
            address: 0x2922c0300,
            fields: 0x7ff00,
        },
    ];
    for group in 2..10 {
        let address = GPCE + (group - 2) * 8;
        rows.push(Control { address, fields: 3 });
        rows.push(Control {
            address: address + 4,
            fields: u32::MAX,
        });
    }
    for offset in [0, 4, 8, 12, 16, 20, 24, 32] {
        rows.push(Control {
            address: GPCE + 0x40 + offset,
            fields: 0x001f001f,
        });
    }
    rows.push(Control {
        address: GPCE + 0x68,
        fields: 0x1f,
    });
    for (address, fields) in [
        (0x2925c0204, 0x80000100),
        (0x2925c0208, 0x11f),
        (0x2925c020c, 0x11f),
        (0x2925c0210, 0x11f),
        (0x2922c0304, 0x1f),
        (0x2922c0308, 0x1f),
        (0x2922c030c, 0x1f),
        (0x2922c0310, 0x1f),
    ] {
        rows.push(Control { address, fields });
    }
    rows.extend(ACTIVATION_WORDS.map(|(address, fields)| Control { address, fields }));
    rows.sort_by_key(|row| row.address);
    rows
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    pub address: u64,
    pub value: u32,
    pub known: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fragment {
    pub offset: usize,
    pub bytes: Vec<u8>,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SramInitialization {
    Unknown,
    /// A whole-owned-resource zero operation, before any image stores.
    /// This is a declared Stela entry policy, never an Apple reset observation.
    Zeroed,
}
pub enum Handoff {
    Unknown,
    Observed {
        controls: Vec<Observation>,
        sram: Vec<Fragment>,
    },
    /// Creates empty Stela-owned routing words. Requests, status, physical PS
    /// values and functional clients are independently supplied by the mount.
    StelaEmpty {
        sram: SramInitialization,
    },
}

/// Read-only observations of this resource, not a restorable whole-controller
/// snapshot. In particular it cannot discard requests or captured pending work.
pub struct Observations {
    pub controls: Vec<Observation>,
    pub sram: Vec<Fragment>,
    pub epoch: u64,
    pub stela_initialization: Option<SramInitialization>,
    pub activation_inputs: Vec<ActivationInput>,
    pub packet_effects_owned: bool,
    pub cio_engine: Option<engine::Observations>,
}
/// Chronological committed AP input, not a hardware trigger/completion report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActivationInput {
    pub address: u64,
    pub value: u32,
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub group: u8,
    pub slot: u8,
    pub table: u64,
    pub pointer: u64,
    pub pc: u64,
    pub epoch: u64,
}

pub(super) struct State {
    words: BTreeMap<u64, Observation>,
    sram: Vec<u8>,
    known: Vec<bool>,
    epoch: u64,
    initialization: Option<SramInitialization>,
    activation_inputs: Vec<ActivationInput>,
    packet_effects_owned: bool,
    pub(super) clock: Option<super::clock::phase::Clock>,
    engine: Option<engine::State>,
}
impl State {
    pub(super) fn new(handoff: Handoff) -> Result<Self, Error> {
        let mut state = Self {
            words: controls()
                .iter()
                .map(|row| {
                    (
                        row.address,
                        Observation {
                            address: row.address,
                            value: 0,
                            known: 0,
                        },
                    )
                })
                .collect(),
            sram: vec![0; SRAM_BYTES],
            known: vec![false; SRAM_BYTES],
            epoch: 0,
            initialization: None,
            activation_inputs: Vec::new(),
            packet_effects_owned: false,
            clock: None,
            engine: None,
        };
        match handoff {
            Handoff::Unknown => {}
            Handoff::StelaEmpty { sram } => {
                // Initialization of this newly owned virtual resource,
                // with explicit provenance. No other device state is touched.
                for word in state.words.values_mut() {
                    word.known = u32::MAX;
                }
                if sram == SramInitialization::Zeroed {
                    state.known.fill(true);
                }
                state.initialization = Some(sram);
                state.epoch = 1;
            }
            Handoff::Observed {
                controls: observed,
                sram,
            } => {
                let mut seen = alloc::collections::BTreeSet::new();
                for word in observed {
                    let target = state
                        .words
                        .get_mut(&word.address)
                        .ok_or(Error::UnknownControl)?;
                    if !seen.insert(word.address) {
                        return Err(Error::DuplicateControl);
                    }
                    *target = word;
                }
                for fragment in sram {
                    let end = fragment
                        .offset
                        .checked_add(fragment.bytes.len())
                        .ok_or(Error::Geometry)?;
                    if fragment.bytes.is_empty() || end > SRAM_BYTES {
                        return Err(Error::Geometry);
                    }
                    if state.known[fragment.offset..end].iter().any(|known| *known) {
                        return Err(Error::DuplicateByte);
                    }
                    state.sram[fragment.offset..end].copy_from_slice(&fragment.bytes);
                    state.known[fragment.offset..end].fill(true);
                }
            }
        }
        Ok(state)
    }
    pub(super) fn engine_bound(&self) -> bool {
        self.engine.is_some()
    }
    pub(super) fn request_retired(&self, serial: u64) -> bool {
        self.engine
            .as_ref()
            .is_some_and(|engine| engine.completed(serial))
    }
    pub(super) fn accepts_cio(&self, requests: &[super::Request]) -> bool {
        self.engine
            .as_ref()
            .is_some_and(|engine| engine.accepting(requests))
            && [GPCE + 0x6c, GPCE + 0x74].into_iter().all(|address| {
                self.read_control(address, Width::Word)
                    .is_ok_and(|value| value & 1 != 0)
            })
    }
    fn observe(&self) -> Observations {
        let mut fragments = Vec::new();
        let mut offset = 0;
        while offset < SRAM_BYTES {
            if !self.known[offset] {
                offset += 1;
                continue;
            }
            let start = offset;
            while offset < SRAM_BYTES && self.known[offset] {
                offset += 1;
            }
            fragments.push(Fragment {
                offset: start,
                bytes: self.sram[start..offset].to_vec(),
            });
        }
        Observations {
            controls: self.words.values().copied().collect(),
            sram: fragments,
            epoch: self.epoch,
            stela_initialization: self.initialization,
            activation_inputs: self.activation_inputs.clone(),
            packet_effects_owned: self.packet_effects_owned,
            cio_engine: self.engine.as_ref().map(engine::State::observe),
        }
    }
    fn activation_word(address: u64) -> bool {
        ACTIVATION_WORDS.iter().any(|(word, _)| *word == address)
    }
    /// This is an ownership validation, not an assertion of physical idle.
    /// Unknown/nonzero activation inputs or any committed activation prefix
    /// cannot authorize replacing configuration/code. Later disable stores do
    /// not erase earlier work that may already have started.
    fn reconfiguration_qualified(&self) -> bool {
        !self.packet_effects_owned
            && self.engine.is_none()
            && self.activation_inputs.is_empty()
            && ACTIVATION_WORDS.iter().all(|(address, fields)| {
                let word = self
                    .words
                    .get(address)
                    .expect("complete native control inventory");
                word.known & *fields == *fields && word.value & *fields == 0
            })
    }
    fn read_control(&self, address: u64, width: Width) -> Result<u64, Error> {
        if width != Width::Word {
            return Err(Error::Geometry);
        }
        let word = self.words.get(&address).ok_or(Error::UnknownControl)?;
        if word.known != u32::MAX {
            return Err(Error::UnknownValue);
        }
        Ok(u64::from(word.value))
    }
    fn write_control(&mut self, address: u64, width: Width, value: u64) -> Result<(), Error> {
        let old = self.read_control(address, width)? as u32;
        let fields = controls()
            .into_iter()
            .find(|row| row.address == address)
            .ok_or(Error::UnknownControl)?
            .fields;
        if value > u64::from(u32::MAX) || (old ^ value as u32) & !fields != 0 {
            return Err(Error::UnqualifiedBits);
        }
        let epoch = self.epoch.checked_add(1).ok_or(Error::Epoch)?;
        self.words
            .get_mut(&address)
            .ok_or(Error::UnknownControl)?
            .value = value as u32;
        self.epoch = epoch;
        if Self::activation_word(address) {
            self.activation_inputs.push(ActivationInput {
                address,
                value: value as u32,
            });
        }
        Ok(())
    }
    fn extent(offset: u64, width: Width) -> Result<core::ops::Range<usize>, Error> {
        if !offset.is_multiple_of(width.bytes()) {
            return Err(Error::Geometry);
        }
        let start = usize::try_from(offset).map_err(|_| Error::Geometry)?;
        let end = start
            .checked_add(width.bytes() as usize)
            .ok_or(Error::Geometry)?;
        if end > SRAM_BYTES {
            return Err(Error::Geometry);
        }
        Ok(start..end)
    }
    fn read_sram(&self, offset: u64, width: Width) -> Result<u64, Error> {
        let extent = Self::extent(offset, width)?;
        let mut bytes = [0; 8];
        self.read_bytes(offset, &mut bytes[..extent.len()])?;
        Ok(u64::from_le_bytes(bytes))
    }
    fn write_sram(&mut self, offset: u64, width: Width, value: u64) -> Result<(), Error> {
        let extent = Self::extent(offset, width)?;
        let epoch = self.epoch.checked_add(1).ok_or(Error::Epoch)?;
        self.sram[extent.clone()].copy_from_slice(&value.to_le_bytes()[..extent.len()]);
        self.known[extent].fill(true);
        self.epoch = epoch;
        Ok(())
    }
    fn byte_extent(offset: u64, length: usize) -> Result<core::ops::Range<usize>, Error> {
        let start = usize::try_from(offset).map_err(|_| Error::Geometry)?;
        let end = start.checked_add(length).ok_or(Error::Geometry)?;
        if end > SRAM_BYTES {
            return Err(Error::Geometry);
        }
        Ok(start..end)
    }
    fn read_bytes(&self, offset: u64, output: &mut [u8]) -> Result<(), Error> {
        let extent = Self::byte_extent(offset, output.len())?;
        if self.known[extent.clone()].iter().any(|known| !*known) {
            return Err(Error::UnknownSram);
        }
        output.copy_from_slice(&self.sram[extent]);
        Ok(())
    }
    fn write_bytes(&mut self, offset: u64, input: &[u8]) -> Result<(), Error> {
        let extent = Self::byte_extent(offset, input.len())?;
        if input.is_empty() {
            return Ok(());
        }
        let epoch = self.epoch.checked_add(1).ok_or(Error::Epoch)?;
        self.sram[extent.clone()].copy_from_slice(input);
        self.known[extent].fill(true);
        self.epoch = epoch;
        Ok(())
    }
    fn entry(&self, group: u8, slot: u8) -> Result<Entry, Error> {
        if group >= 10 {
            return Err(Error::Group);
        }
        if slot >= 32 {
            return Err(Error::Slot);
        }
        let table = if group < 2 {
            let address = if group == 0 { 0x2925c0200 } else { 0x2922c0300 };
            SRAM_BASE | (self.read_control(address, Width::Word)? & 0x7ff00)
        } else {
            let address = GPCE + u64::from(group - 2) * 8;
            (self.read_control(address, Width::Word)? & 3) << 40
                | self.read_control(address + 4, Width::Word)? << 8
        };
        if table < TABLE_BASE || table.checked_add(0x100).is_none_or(|end| end > CODE_BASE) {
            return Err(Error::Pointer);
        }
        let pointer = table + u64::from(slot) * 8;
        let encoded = self.read_sram(pointer - SRAM_BASE, Width::Double)?;
        if encoded == 0 {
            return Err(Error::Unconfigured);
        }
        if encoded >> 38 != 0 {
            return Err(Error::Pointer);
        }
        let pc = encoded << 4;
        if !pc.is_multiple_of(32) || !(CODE_BASE..SRAM_LIMIT).contains(&pc) {
            return Err(Error::Pointer);
        }
        // This confirms bytes exist, not that their native tag retires.
        self.read_sram(pc - SRAM_BASE, Width::Word)?;
        Ok(Entry {
            group,
            slot,
            table,
            pointer,
            pc,
            epoch: self.epoch,
        })
    }
}

impl Controller {
    pub fn native_controls(&self) -> Result<View, Error> {
        self.native_view(false)
    }
    pub fn native_sram(&self) -> Result<View, Error> {
        self.native_view(true)
    }
    fn native_view(&self, sram: bool) -> Result<View, Error> {
        if self.0.borrow().native.is_none() {
            return Err(Error::Unmounted);
        }
        Ok(View {
            controller: self.clone(),
            sram,
        })
    }
    pub fn native_observations(&self) -> Result<Observations, Error> {
        Ok(self
            .0
            .borrow()
            .native
            .as_ref()
            .ok_or(Error::Unmounted)?
            .observe())
    }
    /// Resolve published input bytes only. No caller can turn this
    /// metadata query into a trigger, active PC, ready flag or completion.
    pub fn native_entry(&self, group: u8, slot: u8) -> Result<Entry, Error> {
        self.0
            .borrow()
            .native
            .as_ref()
            .ok_or(Error::Unmounted)?
            .entry(group, slot)
    }
    /// Canonical physical-memory facade for the same bytes as the MMIO view.
    /// The mount owns architectural memory attributes/permissions separately.
    pub fn native_memory(&self) -> Result<Sram, Error> {
        if self.0.borrow().native.is_none() {
            return Err(Error::Unmounted);
        }
        Ok(Sram {
            controller: self.clone(),
        })
    }
}
pub struct Sram {
    controller: Controller,
}
impl Sram {
    pub fn read_checked(&self, address: u64, output: &mut [u8]) -> Result<(), Error> {
        let offset = address.checked_sub(SRAM_BASE).ok_or(Error::Geometry)?;
        let state = self.controller.0.borrow();
        state.accessible().map_err(|_| Error::Paused)?;
        state
            .native
            .as_ref()
            .ok_or(Error::Unmounted)?
            .read_bytes(offset, output)
    }
    /// Full extent/knownness/ownership preflight precedes any byte mutation;
    /// Err always leaves the physical backing and the caller's input intact.
    pub fn write_checked(&mut self, address: u64, input: &[u8]) -> Result<(), Error> {
        let offset = address.checked_sub(SRAM_BASE).ok_or(Error::Geometry)?;
        let mut state = self.controller.0.borrow_mut();
        state.accessible().map_err(|_| Error::Paused)?;
        if View::pending(&state) {
            return Err(Error::Pending);
        }
        let native = state.native.as_mut().ok_or(Error::Unmounted)?;
        if !native.reconfiguration_qualified() {
            return Err(Error::Pending);
        }
        native.write_bytes(offset, input)
    }
}
impl stela_contracts::dma::Memory for Sram {
    fn read(&mut self, address: u64, output: &mut [u8]) -> bool {
        self.read_checked(address, output).is_ok()
    }
    fn write(&mut self, address: u64, input: &[u8]) -> bool {
        self.write_checked(address, input).is_ok()
    }
}
pub struct View {
    controller: Controller,
    sram: bool,
}
impl View {
    pub(super) fn pending(state: &super::State) -> bool {
        !state.captured_pending.is_empty()
            || state.requests.iter().any(|request| {
                !state
                    .native
                    .as_ref()
                    .is_some_and(|native| native.request_retired(request.serial))
                    && !matches!(
                        request.kind,
                        RequestKind::AutomaticGating { enabled: false, .. }
                    )
            })
            || state.words.values().any(|word| {
                word.bank == super::Bank::Pmgr
                    && (super::CPM_BASE..super::CPM_BASE + 24).contains(&word.offset)
                    && (word.known & super::CPM_ENABLE == 0 || word.value & super::CPM_ENABLE != 0)
            })
    }
}
impl Lifecycle for View {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<()> {
        if let Some(clock) = self
            .controller
            .0
            .borrow()
            .native
            .as_ref()
            .and_then(|native| native.clock.as_ref())
        {
            clock.cycles().map_err(super::clock::Error::reason)?;
        }
        if proposed.reset || (!proposed.powered && !proposed.retention) {
            return Err(refuse!(
                "T6000 native reset/nonretained loss and pending-work cancellation are unqualified"
            ));
        }
        Ok(())
    }
    fn set_lifecycle(&mut self, proposed: LifecycleState, access: &mut Access<'_>) {
        assert!(self.check_lifecycle(proposed).is_ok());
        self.controller
            .0
            .borrow_mut()
            .change_lifecycle(proposed, access.now);
    }
}
impl MmioDevice for View {
    fn name(&self) -> &'static str {
        NAME
    }
    fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
        Some(self)
    }
    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let fail = |why: Refusal| refuse(NAME, offset, width, Direction::Read, why);
        let state = self.controller.0.borrow();
        state.accessible().map_err(fail)?;
        let native = state
            .native
            .as_ref()
            .ok_or_else(|| fail(Error::Unmounted.reason().into()))?;
        (if self.sram {
            native.read_sram(offset, width)
        } else {
            native.read_control(offset, width)
        })
        .map_err(|error| fail(error.reason().into()))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let fail = |why: Refusal| refuse(NAME, offset, width, Direction::Write, why);
        let mut state = self.controller.0.borrow_mut();
        state.accessible().map_err(fail)?;
        if Self::pending(&state) {
            return Err(fail(Error::Pending.reason().into()));
        }
        let native = state
            .native
            .as_mut()
            .ok_or_else(|| fail(Error::Unmounted.reason().into()))?;
        if (self.sram || !State::activation_word(offset)) && !native.reconfiguration_qualified() {
            return Err(fail(Error::Pending.reason().into()));
        }
        (if self.sram {
            native.write_sram(offset, width, value)
        } else {
            native.write_control(offset, width, value)
        })
        .map_err(|error| fail(error.reason().into()))
    }
}

#[cfg(test)]
mod tests;
