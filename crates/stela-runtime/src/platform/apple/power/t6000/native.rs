//! T6000's real shared configuration/SRAM owner.
//!
//! These are the original native-program configuration/activation words and the
//! physical SRAM used by `pmgr::install::t6000`. No request, installed pointer,
//! zero instruction or observed control value establishes a hardware trigger
//! or native retirement. Every view shares the parent controller's lifecycle,
//! request prefix and actual byte storage; there is no parallel SRAM image.
use super::{Controller, RequestKind};
use crate::platform::apple::{
    bus::{Access, Direction, Lifecycle, LifecycleState, MmioDevice, MmioError, Width, refuse},
    pmgr::install::t6000::{
        CODE_BASE, SRAM_BASE, SRAM_LIMIT, TABLE_BASE, activation::PRE_ACTIVATION_BASE,
    },
};
use alloc::{collections::BTreeMap, vec, vec::Vec};

pub mod effects;

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
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Control {
    pub address: u64,
    pub fields: u32,
}
/// Complete original `47090`/`471b8` first-die configuration interface and
/// `4b030`/`3d7d4` activation stores. The latter retain actual control inputs;
/// they do not qualify request-to-PC selection or hardware retirement.
/// Field masks qualify software inputs, never completion/status bits.
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
    /// An actual whole-owned-resource zero operation, before any image stores.
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
        };
        match handoff {
            Handoff::Unknown => {}
            Handoff::StelaEmpty { sram } => {
                // Actual initialization of this newly owned virtual resource,
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
        }
    }
    fn activation_word(address: u64) -> bool {
        ACTIVATION_WORDS.iter().any(|(word, _)| *word == address)
    }
    /// This is an ownership qualification, not an assertion of physical idle.
    /// Unknown/nonzero activation inputs or any committed activation prefix
    /// cannot authorize replacing configuration/code. Later disable stores do
    /// not erase earlier work that may already have started.
    fn reconfiguration_qualified(&self) -> bool {
        !self.packet_effects_owned
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
        // This confirms actual bytes exist, not that their native tag retires.
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
    /// Resolve actual published input bytes only. No caller can turn this
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
impl crate::platform::dma::Memory for Sram {
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
    fn pending(state: &super::State) -> bool {
        !state.captured_pending.is_empty()
            || state.requests.iter().any(|request| {
                !matches!(
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
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<(), &'static str> {
        if proposed.reset || (!proposed.powered && !proposed.retention) {
            return Err(
                "T6000 native reset/nonretained loss and pending-work cancellation are unqualified",
            );
        }
        Ok(())
    }
    fn set_lifecycle(&mut self, proposed: LifecycleState, _: &mut Access<'_>) {
        assert!(self.check_lifecycle(proposed).is_ok());
        self.controller.0.borrow_mut().lifecycle = proposed;
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
        let fail = |why| refuse(NAME, offset, width, Direction::Read, why);
        let state = self.controller.0.borrow();
        state.accessible().map_err(fail)?;
        let native = state
            .native
            .as_ref()
            .ok_or_else(|| fail(Error::Unmounted.reason()))?;
        (if self.sram {
            native.read_sram(offset, width)
        } else {
            native.read_control(offset, width)
        })
        .map_err(|error| fail(error.reason()))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let fail = |why| refuse(NAME, offset, width, Direction::Write, why);
        let mut state = self.controller.0.borrow_mut();
        state.accessible().map_err(fail)?;
        if Self::pending(&state) {
            return Err(fail(Error::Pending.reason()));
        }
        let native = state
            .native
            .as_mut()
            .ok_or_else(|| fail(Error::Unmounted.reason()))?;
        if (self.sram || !State::activation_word(offset)) && !native.reconfiguration_qualified() {
            return Err(fail(Error::Pending.reason()));
        }
        (if self.sram {
            native.write_sram(offset, width, value)
        } else {
            native.write_control(offset, width, value)
        })
        .map_err(|error| fail(error.reason()))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{Bank, Instance, Observation as RequestObservation};
    use super::*;
    use crate::platform::{
        apple::{
            bus::{Bus, DeviceId},
            interrupt::InterruptLatch,
            pmgr::install::{Action, NativeImage, Outcome, t6000},
        },
        dma::Memory,
    };
    use alloc::boxed::Box;

    const LIVE: LifecycleState = LifecycleState {
        powered: true,
        clocked: true,
        quiesced: false,
        reset: false,
        retention: true,
    };
    fn owner(handoff: Handoff) -> Controller {
        let geometry = Instance {
            complexes: 7,
            cio_ports: 15,
            cpm_controls: 7,
            isp_clocks: 7,
        };
        // Explicit supplied test request observations; these are not Apple
        // cold-state measurements or outputs of native initialization.
        let words = [Bank::Pmgr, Bank::ClkGenSoc].into_iter().flat_map(|bank| {
            geometry
                .offsets(bank)
                .into_iter()
                .map(move |offset| RequestObservation {
                    instance: 0,
                    bank,
                    offset,
                    value: 0,
                    known: u32::MAX,
                })
        });
        Controller::with_native(vec![geometry], LIVE, words, handoff).unwrap()
    }
    fn mount(owner: &Controller) -> (Bus, DeviceId, DeviceId) {
        let mut bus = Bus::new();
        let controls = bus.add(Box::new(owner.native_controls().unwrap()));
        for row in super::controls() {
            bus.map(controls, row.address, 4, row.address).unwrap();
        }
        let sram = bus.add(Box::new(owner.native_sram().unwrap()));
        bus.map(sram, SRAM_BASE, SRAM_LIMIT - SRAM_BASE, 0).unwrap();
        let request = bus.add(Box::new(owner.view(0).unwrap()));
        bus.map(request, 0x28e098000, 12, 0x18000).unwrap();
        (bus, controls, sram)
    }
    fn images() -> Vec<NativeImage> {
        t6000::sequences()
            .into_iter()
            .filter(|row| !row.shared)
            .map(|row| NativeImage {
                sequence: row.id,
                counted_words: 1,
                bytes: [0xa0000000 | u32::from(row.id), 0]
                    .into_iter()
                    .flat_map(u32::to_le_bytes)
                    .collect(),
            })
            .collect()
    }
    #[test]
    fn publication_reaches_actual_shared_controls_and_sram_not_a_parallel_capture_bank() {
        let owner = owner(Handoff::StelaEmpty {
            sram: SramInitialization::Unknown,
        });
        let (mut bus, _, _) = mount(&owner);
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        assert_eq!(controls().len(), 43);
        let mut install = t6000::programs(0x20, Some(0), images()).unwrap();
        while let Some(claim) = install.begin().unwrap() {
            let action = install.dispatch(&claim).unwrap();
            let outcome = match action {
                Action::Read { address, width } => match bus.read(address, width, &mut access) {
                    Ok(value) => Outcome::Read(value),
                    Err(error) => Outcome::Uncertain(error),
                },
                Action::Write(write) => {
                    match bus.write(write.address, write.width, write.value, &mut access) {
                        Ok(()) => Outcome::Written,
                        Err(error) => Outcome::Uncertain(error),
                    }
                }
                Action::DmbSy => panic!("no source barrier in this publication phase"),
            };
            install.finish(&claim, outcome).unwrap();
        }
        assert!(install.published());
        let observations = owner.native_observations().unwrap();
        assert_eq!(observations.epoch, 302); // explicit initialization plus301 physical writes
        assert!(owner.requests().is_empty());
        assert!(owner.captured_pending().is_empty());
        let mut memory = owner.native_memory().unwrap();
        for placement in install.placements() {
            let entry = owner.native_entry(placement.group, placement.slot).unwrap();
            assert_eq!(entry.pc, placement.code);
            let mut pointer = [0; 8];
            assert!(memory.read(entry.pointer, &mut pointer));
            assert_eq!(u64::from_le_bytes(pointer), entry.pc >> 4);
            let mut code = [0; 4];
            assert!(memory.read(entry.pc, &mut code));
            assert_eq!(
                bus.read(entry.pc, Width::Word, &mut access),
                Ok(u64::from(u32::from_le_bytes(code)))
            );
        }
        let mut unknown = [0xa5; 8];
        assert!(!memory.read(CODE_BASE + 8, &mut unknown));
        assert_eq!(unknown, [0xa5; 8]);
        assert_eq!(owner.native_entry(2, 6), Err(Error::UnknownSram));
        // Both APIs address the same actual bytes and knownness plane.
        assert!(memory.write(CODE_BASE + 1, &[0x12, 0x34]));
        assert_eq!(
            bus.read(CODE_BASE, Width::Word, &mut access),
            Ok(0xa0341200)
        );
        assert_eq!(bus.read(GPCE + 0x68, Width::Word, &mut access), Ok(2));
        // No pointer lookup admits execution or manufactures an interrupt.
        assert!(sink.take_aic_inputs().is_empty());
    }
    #[test]
    fn retained_views_share_lifecycle_and_pending_requests_prevent_code_replacement() {
        let owner = owner(Handoff::StelaEmpty {
            sram: SramInitialization::Unknown,
        });
        let (mut bus, _, sram) = mount(&owner);
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 11, &mut sink);
        bus.write(CODE_BASE, Width::Word, 0x12345678, &mut access)
            .unwrap();
        let mut memory = owner.native_memory().unwrap();
        let mut paused = LIVE;
        paused.quiesced = true;
        bus.device_mut::<View>(sram)
            .unwrap()
            .set_lifecycle(paused, &mut access);
        assert_eq!(owner.lifecycle(), paused);
        // Quiesce suspends execution, while the supplied configuration bus is retained.
        assert_eq!(
            bus.read(CODE_BASE, Width::Word, &mut access),
            Ok(0x12345678)
        );
        paused.clocked = false;
        bus.device_mut::<View>(sram)
            .unwrap()
            .set_lifecycle(paused, &mut access);
        assert!(bus.read(CODE_BASE, Width::Word, &mut access).is_err());
        assert!(!memory.write(CODE_BASE, &[0; 4]));
        paused.powered = false;
        bus.device_mut::<View>(sram)
            .unwrap()
            .set_lifecycle(paused, &mut access);
        bus.device_mut::<View>(sram)
            .unwrap()
            .set_lifecycle(LIVE, &mut access);
        assert_eq!(
            bus.read(CODE_BASE, Width::Word, &mut access),
            Ok(0x12345678)
        );
        bus.write(0x28e098000, Width::Word, 15, &mut access)
            .unwrap();
        let request = owner.requests();
        let before = owner.native_observations().unwrap();
        assert!(bus.write(CODE_BASE, Width::Word, 0, &mut access).is_err());
        assert!(bus.write(GPCE + 0x40, Width::Word, 0, &mut access).is_err());
        assert_eq!(
            memory.write_checked(CODE_BASE, &[0; 4]),
            Err(Error::Pending)
        );
        assert_eq!(owner.native_observations().unwrap().epoch, before.epoch);
        assert_eq!(owner.requests(), request);
        assert!(bus.advance(&mut access).is_err()); // trigger/PC/retirement still unknown
        let mut reset = LIVE;
        reset.reset = true;
        assert!(
            bus.device_mut::<View>(sram)
                .unwrap()
                .check_lifecycle(reset)
                .is_err()
        );
        reset.reset = false;
        reset.powered = false;
        reset.retention = false;
        assert!(
            bus.device_mut::<View>(sram)
                .unwrap()
                .check_lifecycle(reset)
                .is_err()
        );
        assert_eq!(owner.lifecycle(), LIVE);
        assert_eq!(
            bus.read(CODE_BASE, Width::Word, &mut access),
            Ok(0x12345678)
        );
    }
    #[test]
    fn observed_unknownness_duplicate_evidence_and_atomic_physical_bounds_are_preserved() {
        let owner = owner(Handoff::Observed {
            controls: ACTIVATION_WORDS
                .into_iter()
                .map(|(address, _)| Observation {
                    address,
                    value: 0,
                    known: u32::MAX,
                })
                .chain([Observation {
                    address: GPCE + 0x40,
                    value: 3,
                    known: 31,
                }])
                .collect(),
            sram: vec![Fragment {
                offset: (CODE_BASE - SRAM_BASE) as usize,
                bytes: vec![1, 2, 3, 4],
            }],
        });
        let (mut bus, _, _) = mount(&owner);
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        assert!(bus.read(GPCE + 0x40, Width::Word, &mut access).is_err());
        assert!(bus.write(GPCE + 0x40, Width::Word, 4, &mut access).is_err());
        let mut memory = owner.native_memory().unwrap();
        let mut output = [0xa5; 8];
        assert!(!memory.read(CODE_BASE, &mut output));
        assert_eq!(output, [0xa5; 8]);
        assert!(memory.write(SRAM_LIMIT - 4, &[1, 2, 3, 4]));
        assert!(!memory.write(SRAM_LIMIT - 4, &[9; 8]));
        assert!(memory.read(SRAM_LIMIT - 4, &mut output[..4]));
        assert_eq!(&output[..4], &[1, 2, 3, 4]);
        assert!(matches!(
            State::new(Handoff::Observed {
                controls: vec![
                    Observation {
                        address: GPCE,
                        value: 0,
                        known: 0
                    },
                    Observation {
                        address: GPCE,
                        value: 0,
                        known: 0
                    },
                ],
                sram: vec![]
            }),
            Err(Error::DuplicateControl)
        ));
        assert!(matches!(
            State::new(Handoff::Observed {
                controls: vec![],
                sram: vec![
                    Fragment {
                        offset: 0,
                        bytes: vec![1, 2]
                    },
                    Fragment {
                        offset: 1,
                        bytes: vec![2, 3]
                    },
                ]
            }),
            Err(Error::DuplicateByte)
        ));
        assert_eq!(owner.native_entry(10, 0), Err(Error::Group));
        assert_eq!(owner.native_entry(2, 32), Err(Error::Slot));
    }
    #[test]
    fn explicit_whole_zero_policy_never_supplies_other_device_status_or_accepts_unknown_fields() {
        let owner = owner(Handoff::StelaEmpty {
            sram: SramInitialization::Zeroed,
        });
        let (mut bus, _, _) = mount(&owner);
        let mut memory = owner.native_memory().unwrap();
        let mut whole = vec![0xa5; SRAM_BYTES];
        assert!(memory.read(SRAM_BASE, &mut whole));
        assert!(whole.iter().all(|byte| *byte == 0));
        let before = owner.native_observations().unwrap();
        assert_eq!(
            before.stela_initialization,
            Some(SramInitialization::Zeroed)
        );
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        assert!(
            bus.write(GPCE + 0x40, Width::Word, 1 << 31, &mut access)
                .is_err()
        );
        assert_eq!(owner.native_observations().unwrap().epoch, before.epoch);
        assert!(owner.requests().is_empty());
        assert!(owner.native_entry(2, 0).is_err()); // zeros are not a ready/running program
        owner.0.borrow_mut().native.as_mut().unwrap().epoch = u64::MAX;
        assert_eq!(memory.write_checked(SRAM_BASE, &[1]), Err(Error::Epoch));
        assert_eq!(bus.read(SRAM_BASE, Width::Byte, &mut access), Ok(0));
    }

    #[test]
    fn actual_frozen_sram_effects_route_stores_and_polls_through_the_same_controller_and_pause() {
        use crate::platform::apple::pmgr::sequencer::{self, AddressFormat, RouteOutcome, poll};
        let owner = owner(Handoff::StelaEmpty {
            sram: SramInitialization::Unknown,
        });
        let (mut bus, controls, _) = mount(&owner);
        let cpm = bus.add(Box::new(owner.view(0).unwrap()));
        bus.map(cpm, 0x28e09c0c0, 4, 0x1c0c0).unwrap();
        let mut sink = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut sink);
        // Explicit supplied emitter-format test program: disable CPM, poll its
        // actual input bit clear, then submit a real GPCE target. End remains
        // unqualified; none of these effects acknowledges native completion.
        let words = [
            0x28e09c01, 0, 0x30, 0, 0x28e09c02, 0, 0x30, 0x80000000, 0, 0x28e09801, 0, 0, 15, 0,
        ];
        let bytes: Vec<_> = words.into_iter().flat_map(u32::to_le_bytes).collect();
        let mut supplied = images();
        let image = supplied.iter_mut().find(|row| row.sequence == 12).unwrap();
        image.counted_words = words.len() as u32 - 1;
        image.bytes = bytes.clone();
        let mut installation = t6000::programs(0x20, Some(0), supplied).unwrap();
        while let Some(claim) = installation.begin().unwrap() {
            let outcome = match installation.dispatch(&claim).unwrap() {
                Action::Read { address, width } => {
                    Outcome::<MmioError>::Read(bus.read(address, width, &mut access).unwrap())
                }
                Action::Write(write) => {
                    bus.write(write.address, write.width, write.value, &mut access)
                        .unwrap();
                    Outcome::Written
                }
                Action::DmbSy => panic!("no source barrier in publication"),
            };
            installation.finish(&claim, outcome).unwrap();
        }
        let entry = owner.native_entry(2, 0).unwrap();
        let mut effects = owner
            .native_packet_effects(2, 0, bytes.len(), AddressFormat::HighWord)
            .unwrap();
        assert!(matches!(
            owner.native_packet_effects(2, 0, bytes.len(), AddressFormat::HighWord),
            Err(Error::EffectsOwned)
        ));
        let mut memory = owner.native_memory().unwrap();
        assert_eq!(memory.write_checked(entry.pc, &[0; 4]), Err(Error::Pending));
        assert!(owner.native_observations().unwrap().packet_effects_owned);
        let write = effects.begin_write().unwrap();
        let actual = effects.dispatch_write(&write).unwrap();
        bus.write(actual.address, actual.width, actual.value, &mut access)
            .unwrap();
        effects
            .finish_write::<()>(&write, RouteOutcome::Committed)
            .unwrap();
        assert_eq!(
            effects.begin_write().unwrap_err(),
            sequencer::Error::ExpectedWrite
        );
        let read = effects.begin_read().unwrap();
        let mut paused = LIVE;
        paused.quiesced = true;
        bus.device_mut::<View>(controls)
            .unwrap()
            .set_lifecycle(paused, &mut access);
        assert_eq!(
            effects.dispatch_read(&read),
            Err(sequencer::Error::Suspended)
        );
        bus.device_mut::<View>(controls)
            .unwrap()
            .set_lifecycle(LIVE, &mut access);
        let actual = effects.dispatch_read(&read).unwrap();
        let value = bus.read(actual.address, actual.width, &mut access).unwrap();
        paused.clocked = false;
        bus.device_mut::<View>(controls)
            .unwrap()
            .set_lifecycle(paused, &mut access);
        assert_eq!(
            effects.finish_read::<()>(&read, poll::Outcome::Read(value)),
            Ok(true)
        );
        assert_eq!(
            effects.begin_write().unwrap_err(),
            sequencer::Error::Suspended
        );
        bus.device_mut::<View>(controls)
            .unwrap()
            .set_lifecycle(LIVE, &mut access);
        let write = effects.begin_write().unwrap();
        let actual = effects.dispatch_write(&write).unwrap();
        bus.write(actual.address, actual.width, actual.value, &mut access)
            .unwrap();
        effects
            .finish_write::<()>(&write, RouteOutcome::Committed)
            .unwrap();
        assert_eq!(
            (effects.committed_writes(), effects.committed_reads()),
            (2, 1)
        );
        assert_eq!(
            effects.begin_read().unwrap_err(),
            sequencer::Error::UnqualifiedRetirement
        );
        assert_eq!(owner.requests().len(), 2); // disable input and actual GPCE target
        let gpce = owner
            .observations()
            .into_iter()
            .find(|word| word.offset == 0x18000)
            .unwrap();
        assert_eq!(gpce.value & 15, 15);
        assert_eq!(gpce.known & 0x70, 0); // no readiness fabricated by a matched poll
        let mut retained = vec![0; bytes.len()];
        memory.read_checked(entry.pc, &mut retained).unwrap();
        assert_eq!(retained, bytes);
        drop(effects);
        assert_eq!(memory.write_checked(entry.pc, &[0; 4]), Err(Error::Pending));
        assert!(sink.take_aic_inputs().is_empty());
    }
}
