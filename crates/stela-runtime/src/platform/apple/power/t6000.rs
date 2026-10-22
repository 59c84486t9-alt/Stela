//! T6000 PMGR request banks sharing one retained controller owner.
//!
//! Original 26A434 AppleT6000PMGR uses RegMap0 +18000..18014 for six
//! source complex selectors, +1a034 for four CIO ports per instance, and
//! +1c0c0/+1c0c8/+1c0d0 for CPM automatic-gating controls. RegMap5b
//! +38210..3821c owns the separate ISP source/divider/update requests. Callers must
//! supply the actual board's admitted selector/port/instance geometry and
//! handoff observations; source selector capacity is not hardware inventory.
//!
//! Requests are committed controller inputs, not completed native programs.
//! GPCE bits4/5/6 and CIO request/response readback become unknown after a
//! request. No trigger-to-SRAM-PC, readiness, initial state, timeout success or
//! native retirement is fabricated. A retained pause preserves every input,
//! observation and chronological prefix across all mapped views.
use super::super::bus::{
    Access, Direction, Lifecycle, LifecycleState, MmioDevice, MmioError, Width, refuse,
};
use alloc::{collections::BTreeMap, rc::Rc, vec::Vec};
use core::cell::RefCell;

pub mod clock;
pub mod identity;
pub mod native;

const NAME: &str = "t6000-power";
const GPCE_BASE: u64 = 0x18000;
const GPCE_SELECTORS: u8 = 6;
const TARGET: u32 = 0xf;
const GPCE_NATIVE: u32 = 0x70;
const GPCE_COMMAND: u32 = 0x2f;
#[cfg(test)]
const GPCE_BUSY: u32 = 0x10;
const CIO: u64 = 0x1a034;
const CPM_BASE: u64 = 0x1c0c0;
const CPM_ENABLE: u32 = 1 << 31;
const ISP_CLOCK_BASE: u64 = 0x38210;
const ISP_CLOCK_FIELDS: u32 = 0x0300_003f;
const ISP_CLOCK_UPDATE: u32 = 1 << 31;
const ISP_CLOCK_BUSY: u32 = 1 << 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Bank {
    Pmgr,
    ClkGenSoc,
}

/// Positive board geometry supplied by the mount, independently of the source
/// driver's maximum capacities. Bits select actual devices, not initial states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Instance {
    pub complexes: u8,
    pub cio_ports: u8,
    pub cpm_controls: u8,
    pub isp_clocks: u8,
}
impl Instance {
    /// Required word offsets only; the caller must qualify physical placement.
    pub fn offsets(self, bank: Bank) -> Vec<u64> {
        if bank == Bank::ClkGenSoc {
            return (0..4)
                .filter(|clock| self.isp_clocks & (1 << clock) != 0)
                .map(|clock| ISP_CLOCK_BASE + clock * 4)
                .collect();
        }
        let mut offsets = Vec::new();
        for selector in 0..GPCE_SELECTORS {
            if self.complexes & (1 << selector) != 0 {
                offsets.push(GPCE_BASE + u64::from(selector) * 4);
            }
        }
        if self.cio_ports != 0 {
            offsets.push(CIO);
        }
        for control in 0..3 {
            if self.cpm_controls & (1 << control) != 0 {
                offsets.push(CPM_BASE + control * 8);
            }
        }
        offsets
    }
}

/// An actual register observation, with independently retained knownness. A
/// zero known-mask supplies no healthy/reset value despite any backing bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    pub instance: u8,
    pub bank: Bank,
    pub offset: u64,
    pub value: u32,
    pub known: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Geometry,
    UnqualifiedLifecycle,
    UnknownInstance,
    UnknownRegister,
    DuplicateObservation,
    MissingObservation,
    Native(native::Error),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    Complex { selector: u8, target: u8 },
    Cio { port: u8 },
    AutomaticGating { control: u8, enabled: bool },
    IspReferenceClock { clock: u8, source: u8, divider: u8 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub serial: u64,
    pub bank: Bank,
    pub instance: u8,
    pub offset: u64,
    pub previous: Observation,
    pub written: u32,
    pub kind: RequestKind,
}

struct State {
    geometry: Vec<Instance>,
    lifecycle: LifecycleState,
    words: BTreeMap<(u8, Bank, u64), Observation>,
    requests: Vec<Request>,
    captured_pending: Vec<Observation>,
    serial: u64,
    native: Option<native::State>,
    clock_edge_at: Option<u64>,
}
impl State {
    fn accessible(&self) -> Result<(), &'static str> {
        if !self.lifecycle.powered || !self.lifecycle.clocked {
            return Err("T6000 power access while its supplied rail/clock is paused");
        }
        if self.lifecycle.reset {
            return Err("T6000 power access while reset is asserted");
        }
        Ok(())
    }
    fn paused(&self) -> bool {
        !self.lifecycle.powered || !self.lifecycle.clocked || self.lifecycle.quiesced
    }
    fn clock_running(&self) -> bool {
        self.lifecycle.powered && self.lifecycle.clocked && !self.lifecycle.reset
    }
    fn change_lifecycle(&mut self, proposed: LifecycleState, now: u64) {
        let running = self.clock_running();
        if let Some(clock) = self
            .native
            .as_mut()
            .and_then(|native| native.clock.as_mut())
        {
            // Real system time is monotonic. If a caller violates that boundary,
            // the retained clock quarantines itself; never silently rebase it.
            let _ = clock.observe(now, running);
        }
        if running != (proposed.powered && proposed.clocked && !proposed.reset) {
            self.clock_edge_at = Some(self.clock_edge_at.map_or(now, |prior| prior.max(now)));
        }
        self.lifecycle = proposed;
    }
}

/// Shared authority for every mapped instance. No method drains pending work
/// or replaces a handoff observation after committed requests; those operations
/// require the independently qualified native execution/retirement contract.
#[derive(Clone)]
pub struct Controller(Rc<RefCell<State>>);
impl Controller {
    pub fn from_observations(
        geometry: Vec<Instance>,
        lifecycle: LifecycleState,
        observations: impl IntoIterator<Item = Observation>,
    ) -> Result<Self, Error> {
        if geometry.is_empty()
            || geometry.len() > 2
            || geometry.iter().any(|instance| {
                instance.complexes & !0x3f != 0
                    || instance.cio_ports & !0xf != 0
                    || instance.cpm_controls & !7 != 0
                    || instance.isp_clocks & !0xf != 0
                    || (instance.offsets(Bank::Pmgr).is_empty()
                        && instance.offsets(Bank::ClkGenSoc).is_empty())
            })
        {
            return Err(Error::Geometry);
        }
        // A caller must supply actual lifecycle inputs; accepting a retained
        // pause does not qualify cold reset or nonretained register loss.
        if lifecycle.reset || (!lifecycle.powered && !lifecycle.retention) {
            return Err(Error::UnqualifiedLifecycle);
        }
        let mut state = State {
            geometry,
            lifecycle,
            words: BTreeMap::new(),
            requests: Vec::new(),
            captured_pending: Vec::new(),
            serial: 0,
            native: None,
            clock_edge_at: None,
        };
        for observation in observations {
            let Some(instance) = state.geometry.get(usize::from(observation.instance)) else {
                return Err(Error::UnknownInstance);
            };
            if !instance
                .offsets(observation.bank)
                .contains(&observation.offset)
            {
                return Err(Error::UnknownRegister);
            }
            if state
                .words
                .insert(
                    (observation.instance, observation.bank, observation.offset),
                    observation,
                )
                .is_some()
            {
                return Err(Error::DuplicateObservation);
            }
            let pending = match (observation.bank, observation.offset) {
                (Bank::Pmgr, CIO) => {
                    u32::from(instance.cio_ports) | (u32::from(instance.cio_ports) << 16)
                }
                (Bank::Pmgr, offset) if (GPCE_BASE..GPCE_BASE + 24).contains(&offset) => {
                    GPCE_NATIVE
                }
                (Bank::ClkGenSoc, _) => ISP_CLOCK_BUSY,
                _ => 0,
            };
            if observation.known & pending != pending || observation.value & pending != 0 {
                state.captured_pending.push(observation);
            }
        }
        for (index, instance) in state.geometry.iter().enumerate() {
            for bank in [Bank::Pmgr, Bank::ClkGenSoc] {
                for offset in instance.offsets(bank) {
                    if !state.words.contains_key(&(index as u8, bank, offset)) {
                        return Err(Error::MissingObservation);
                    }
                }
            }
        }
        Ok(Self(Rc::new(RefCell::new(state))))
    }
    /// One first-die T6000 owner for actual request, configuration and SRAM
    /// views. Existing constructors retain unknown/unmounted native resources.
    pub fn with_native(
        geometry: Vec<Instance>,
        lifecycle: LifecycleState,
        observations: impl IntoIterator<Item = Observation>,
        handoff: native::Handoff,
    ) -> Result<Self, Error> {
        if geometry.len() != 1 {
            return Err(Error::Native(native::Error::Profile));
        }
        let native = native::State::new(handoff).map_err(Error::Native)?;
        let owner = Self::from_observations(geometry, lifecycle, observations)?;
        owner.0.borrow_mut().native = Some(native);
        Ok(owner)
    }
    pub fn view(&self, instance: u8) -> Result<View, Error> {
        self.bank_view(instance, Bank::Pmgr)
    }
    pub fn clock_view(&self, instance: u8) -> Result<View, Error> {
        self.bank_view(instance, Bank::ClkGenSoc)
    }
    fn bank_view(&self, instance: u8, bank: Bank) -> Result<View, Error> {
        let state = self.0.borrow();
        let geometry = state
            .geometry
            .get(usize::from(instance))
            .ok_or(Error::UnknownInstance)?;
        if geometry.offsets(bank).is_empty() {
            return Err(Error::UnknownRegister);
        }
        drop(state);
        Ok(View {
            controller: self.clone(),
            instance,
            bank,
        })
    }
    pub fn observations(&self) -> Vec<Observation> {
        self.0.borrow().words.values().copied().collect()
    }
    pub fn requests(&self) -> Vec<Request> {
        self.0.borrow().requests.clone()
    }
    /// Prior unready or unknown observations cannot become an empty idle queue.
    pub fn captured_pending(&self) -> Vec<Observation> {
        self.0.borrow().captured_pending.clone()
    }
    pub fn lifecycle(&self) -> LifecycleState {
        self.0.borrow().lifecycle
    }
}

pub struct View {
    controller: Controller,
    instance: u8,
    bank: Bank,
}
impl View {
    fn check(&self, offset: u64, width: Width) -> Result<Observation, &'static str> {
        let state = self.controller.0.borrow();
        state.accessible()?;
        if width != Width::Word {
            return Err("T6000 power request requires a 32-bit access");
        }
        state
            .words
            .get(&(self.instance, self.bank, offset))
            .copied()
            .ok_or("T6000 power register is outside supplied actual board geometry")
    }
}
impl Lifecycle for View {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<(), &'static str> {
        if let Some(clock) = self
            .controller
            .0
            .borrow()
            .native
            .as_ref()
            .and_then(|native| native.clock.as_ref())
        {
            clock.cycles().map_err(clock::Error::reason)?;
        }
        if proposed.reset || (!proposed.powered && !proposed.retention) {
            return Err(
                "T6000 power physical reset/nonretained loss and native cancellation are unqualified",
            );
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
    fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
        Some(self)
    }
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Read, reason);
        let word = self.check(offset, width).map_err(fail)?;
        if word.known != u32::MAX {
            return Err(fail(
                "T6000 power register readback/native progression is unknown",
            ));
        }
        Ok(u64::from(word.value))
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        _: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        let old = self.check(offset, width).map_err(fail)?;
        let value = value as u32;
        let mut state = self.controller.0.borrow_mut();
        let (kind, next) = if self.bank == Bank::ClkGenSoc {
            let mutable = ISP_CLOCK_FIELDS | ISP_CLOCK_UPDATE;
            let preserve = !mutable;
            if value & ISP_CLOCK_UPDATE == 0
                || old.known & preserve != preserve
                || (value ^ old.value) & preserve != 0
            {
                return Err(fail(
                    "T6000 ISP reference clock update must preserve captured other fields and set updatebit31",
                ));
            }
            (
                RequestKind::IspReferenceClock {
                    clock: ((offset - ISP_CLOCK_BASE) / 4) as u8,
                    source: ((value >> 24) & 3) as u8,
                    divider: (value & 63) as u8,
                },
                Observation {
                    value,
                    known: old.known & !(ISP_CLOCK_BUSY | ISP_CLOCK_UPDATE),
                    ..old
                },
            )
        } else if offset == CIO {
            let port = value.trailing_zeros() as u8;
            if !value.is_power_of_two()
                || port >= 4
                || state.geometry[usize::from(self.instance)].cio_ports & (1 << port) == 0
            {
                return Err(fail(
                    "T6000 CIO only qualifies one admitted port request bit",
                ));
            }
            // The source directly writes the low request bit and polls a high
            // response bit. It does not prove low-bit latch/W1/readback rules
            // or reserved-field effects; preserve the observation and mark its
            // post-request word unknown rather than invent those rules.
            (RequestKind::Cio { port }, Observation { known: 0, ..old })
        } else if offset >= CPM_BASE {
            if old.known != u32::MAX || (value ^ old.value) & !CPM_ENABLE != 0 {
                return Err(fail(
                    "T6000 CPM gating must preserve all captured non-enable fields",
                ));
            }
            (
                RequestKind::AutomaticGating {
                    control: ((offset - CPM_BASE) / 8) as u8,
                    enabled: value & CPM_ENABLE != 0,
                },
                Observation { value, ..old },
            )
        } else {
            // AP requests use target0/f; original native source also writes
            // 2f. Preserve every other captured field, but do not assert that
            // native status/control bits4..6 follow any requested value.
            let preserve = !GPCE_COMMAND;
            if !matches!(value & TARGET, 0 | TARGET)
                || old.known & preserve != preserve
                || (value ^ old.value) & preserve != 0
            {
                return Err(fail(
                    "T6000 GPCE request fields or uncaptured preserved fields are unqualified",
                ));
            }
            (
                RequestKind::Complex {
                    selector: ((offset - GPCE_BASE) / 4) as u8,
                    target: (value & TARGET) as u8,
                },
                Observation {
                    value: (old.value & !TARGET) | (value & TARGET),
                    known: old.known & !GPCE_NATIVE,
                    ..old
                },
            )
        };
        let serial = state
            .serial
            .checked_add(1)
            .ok_or_else(|| fail("T6000 request serial exhausted"))?;
        state.words.insert((self.instance, self.bank, offset), next);
        state.requests.push(Request {
            serial,
            bank: self.bank,
            instance: self.instance,
            offset,
            previous: old,
            written: value,
            kind,
        });
        state.serial = serial;
        Ok(())
    }
    fn advance(&mut self, _: &mut Access<'_>) -> Result<Option<u64>, MmioError> {
        let state = self.controller.0.borrow();
        if state.paused() {
            return Ok(None);
        }
        if !state.captured_pending.is_empty()
            || state
                .requests
                .iter()
                .any(|request| !matches!(request.kind, RequestKind::AutomaticGating { .. }))
        {
            return Err(refuse(
                NAME,
                0,
                Width::Word,
                Direction::Read,
                "T6000 power requests retain unqualified native PC/physical effects/retirement",
            ));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::{bus::Bus, interrupt::InterruptLatch};
    use alloc::{boxed::Box, vec};

    const LIVE: LifecycleState = LifecycleState {
        powered: true,
        clocked: true,
        quiesced: false,
        reset: false,
        retention: true,
    };
    const FULL: Instance = Instance {
        complexes: 0x3f,
        cio_ports: 0xf,
        cpm_controls: 7,
        isp_clocks: 0xf,
    };
    fn words(geometry: &[Instance], value: u32) -> Vec<Observation> {
        geometry
            .iter()
            .enumerate()
            .flat_map(|(instance, layout)| {
                [Bank::Pmgr, Bank::ClkGenSoc]
                    .into_iter()
                    .flat_map(move |bank| {
                        layout
                            .offsets(bank)
                            .into_iter()
                            .map(move |offset| Observation {
                                instance: instance as u8,
                                bank,
                                offset,
                                value,
                                known: u32::MAX,
                            })
                    })
            })
            .collect()
    }
    fn controller(geometry: &[Instance], value: u32) -> Controller {
        Controller::from_observations(geometry.to_vec(), LIVE, words(geometry, value)).unwrap()
    }
    #[test]
    fn all_source_selectors_and_cio_ports_retain_ordered_actual_mounted_inputs() {
        let owner = controller(&[FULL], 0x8000);
        let mut bus = Bus::new();
        let id = bus.add(Box::new(owner.view(0).unwrap()));
        let base = 0x28e080000;
        bus.map(id, base, 0x80000, 0).unwrap();
        let mut pins = InterruptLatch::new();
        let mut access = Access::new(0, 11, &mut pins);
        for selector in 0..6 {
            let offset = GPCE_BASE + selector * 4;
            assert_eq!(
                bus.read(base + offset, Width::Word, &mut access),
                Ok(0x8000)
            );
            bus.write(base + offset, Width::Word, 0x800f, &mut access)
                .unwrap();
            assert!(bus.read(base + offset, Width::Word, &mut access).is_err());
        }
        for port in 0..4 {
            bus.write(base + CIO, Width::Word, 1 << port, &mut access)
                .unwrap();
        }
        let requests = owner.requests();
        assert_eq!(requests.len(), 10);
        for (index, request) in requests.iter().enumerate() {
            assert_eq!(request.serial, index as u64 + 1);
            assert_eq!(request.instance, 0);
            if index < 6 {
                assert_eq!(
                    request.kind,
                    RequestKind::Complex {
                        selector: index as u8,
                        target: 15
                    }
                );
            } else {
                assert_eq!(
                    request.kind,
                    RequestKind::Cio {
                        port: index as u8 - 6
                    }
                );
            }
        }
        assert!(bus.read(base + CIO, Width::Word, &mut access).is_err());
        assert!(bus.advance(&mut access).is_err());
        assert_eq!(owner.requests(), requests);
        // No made-up target/current status, PC, IRQ or retirement is generated.
        assert!(pins.take_aic_inputs().is_empty());
    }
    #[test]
    fn supplied_board_geometry_does_not_admit_maximum_source_capacity() {
        let layout = Instance {
            complexes: 7,
            cio_ports: 5,
            cpm_controls: 7,
            isp_clocks: 0xf,
        };
        let owner = controller(&[layout], 0);
        let mut view = owner.view(0).unwrap();
        let mut pins = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut pins);
        assert!(owner.view(1).is_err());
        assert!(
            view.write(GPCE_BASE + 12, Width::Word, 15, &mut access)
                .is_err()
        );
        assert!(view.write(CIO, Width::Word, 2, &mut access).is_err());
        assert!(view.write(CIO, Width::Word, 3, &mut access).is_err());
        assert!(view.write(CIO, Width::Word, 0, &mut access).is_err());
        assert!(
            view.write(GPCE_BASE, Width::Double, 15, &mut access)
                .is_err()
        );
        assert!(view.write(0x4000, Width::Word, 1, &mut access).is_err());
        assert!(owner.requests().is_empty());
        view.write(CIO, Width::Word, 4, &mut access).unwrap();
    }
    #[test]
    fn unknown_or_busy_capture_cannot_become_idle_or_a_healthy_zero() {
        let mut observations = words(&[FULL], 0);
        observations[0].known = 0;
        observations[1].value = GPCE_BUSY;
        let owner = Controller::from_observations(vec![FULL], LIVE, observations).unwrap();
        assert_eq!(owner.captured_pending().len(), 2);
        let mut view = owner.view(0).unwrap();
        let mut pins = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut pins);
        assert!(view.read(GPCE_BASE, Width::Word, &mut access).is_err());
        assert!(view.write(GPCE_BASE, Width::Word, 15, &mut access).is_err());
        assert_eq!(
            view.read(GPCE_BASE + 4, Width::Word, &mut access),
            Ok(u64::from(GPCE_BUSY))
        );
        assert!(view.advance(&mut access).is_err());
        assert!(owner.requests().is_empty());
        assert_eq!(owner.captured_pending().len(), 2);
    }
    #[test]
    fn shared_views_retain_partial_prefix_and_knownness_across_independent_pauses() {
        let owner = controller(&[FULL, FULL], 0);
        let mut a = owner.view(0).unwrap();
        let mut b = owner.view(1).unwrap();
        let mut pins = InterruptLatch::new();
        let mut access = Access::new(0, 20, &mut pins);
        a.write(GPCE_BASE, Width::Word, 15, &mut access).unwrap();
        b.write(CIO, Width::Word, 8, &mut access).unwrap();
        let prefix = owner.requests();
        let observation = owner.observations();
        let prior = owner.captured_pending();
        for paused in [
            LifecycleState {
                clocked: false,
                ..LIVE
            },
            LifecycleState {
                powered: false,
                retention: true,
                ..LIVE
            },
            LifecycleState {
                quiesced: true,
                ..LIVE
            },
        ] {
            a.check_lifecycle(paused).unwrap();
            a.set_lifecycle(paused, &mut access);
            assert_eq!(b.advance(&mut access), Ok(None));
            if !paused.powered || !paused.clocked {
                assert!(b.read(CPM_BASE, Width::Word, &mut access).is_err());
            } else {
                // DMA/execution quiesce does not gate the AP configuration bus.
                assert_eq!(b.read(CPM_BASE, Width::Word, &mut access), Ok(0));
            }
            assert_eq!(owner.requests(), prefix);
            assert_eq!(owner.observations(), observation);
            assert_eq!(owner.captured_pending(), prior);
            b.set_lifecycle(LIVE, &mut access);
            assert!(a.advance(&mut access).is_err());
        }
        for destructive in [
            LifecycleState {
                reset: true,
                ..LIVE
            },
            LifecycleState {
                powered: false,
                retention: false,
                ..LIVE
            },
        ] {
            assert!(b.check_lifecycle(destructive).is_err());
            assert_eq!(owner.lifecycle(), LIVE);
            assert_eq!(owner.requests(), prefix);
        }
    }
    #[test]
    fn nonrequest_fields_and_unknown_native_status_cannot_be_software_cleared() {
        let owner = controller(&[FULL], 0x8000);
        let mut view = owner.view(0).unwrap();
        let mut pins = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut pins);
        assert!(view.write(GPCE_BASE, Width::Word, 15, &mut access).is_err());
        assert!(
            view.write(GPCE_BASE, Width::Word, 0x8001, &mut access)
                .is_err()
        );
        view.write(GPCE_BASE, Width::Word, 0x802f, &mut access)
            .unwrap();
        let prefix = owner.requests();
        assert_eq!(prefix[0].written, 0x802f);
        assert!(
            view.write(GPCE_BASE, Width::Word, 0x8000, &mut access)
                .is_err()
        );
        assert!(view.read(GPCE_BASE, Width::Word, &mut access).is_err());
        assert_eq!(owner.requests(), prefix);
    }
    #[test]
    fn gating_configuration_preserves_captured_fields_and_does_not_invent_idle_edges() {
        let owner = controller(&[FULL], 0x1234);
        let mut view = owner.view(0).unwrap();
        let mut pins = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut pins);
        for offset in [CPM_BASE, CPM_BASE + 8, CPM_BASE + 16] {
            view.write(offset, Width::Word, 0x80001234, &mut access)
                .unwrap();
            assert_eq!(view.read(offset, Width::Word, &mut access), Ok(0x80001234));
            assert!(view.write(offset, Width::Word, 0, &mut access).is_err());
            view.write(offset, Width::Word, 0x1234, &mut access)
                .unwrap();
        }
        assert_eq!(owner.requests().len(), 6);
        // GPCE phase/status and the nonzero CIO request bit are captured
        // unresolved work, not a new idle queue.
        assert!(view.advance(&mut access).is_err());
        assert_eq!(owner.captured_pending().len(), 7);
    }
    #[test]
    fn mounted_isp_reference_clock_requests_share_order_and_retained_busy_ownership() {
        let owner = controller(&[FULL], 0x4000);
        let mut bus = Bus::new();
        let clock = bus.add(Box::new(owner.clock_view(0).unwrap()));
        let pmgr = bus.add(Box::new(owner.view(0).unwrap()));
        // Exact original J314s RegMap0/RegMap5b placements.
        bus.map(clock, 0x28e000000, 0x80000, 0).unwrap();
        bus.map(pmgr, 0x28e080000, 0x80000, 0).unwrap();
        let mut pins = InterruptLatch::new();
        let mut access = Access::new(0, 1, &mut pins);
        for index in 0..4 {
            let address = 0x28e000000 + ISP_CLOCK_BASE + index * 4;
            assert_eq!(bus.read(address, Width::Word, &mut access), Ok(0x4000));
            // Four source/divider fields are actual requests, not a derived
            // camera frequency or a completed PLL/ISP transition.
            let written = 0x80004000 | (index << 24) | (index + 1);
            bus.write(address, Width::Word, written, &mut access)
                .unwrap();
            assert!(bus.read(address, Width::Word, &mut access).is_err());
            assert_eq!(
                owner.requests()[index as usize].kind,
                RequestKind::IspReferenceClock {
                    clock: index as u8,
                    source: index as u8,
                    divider: index as u8 + 1,
                }
            );
        }
        let prefix = owner.requests();
        let observations = owner.observations();
        assert!(
            bus.write(0x28e038210, Width::Word, 0x80004000, &mut access)
                .is_err()
        );
        let view = bus.device_mut::<View>(pmgr).unwrap();
        view.set_lifecycle(
            LifecycleState {
                quiesced: true,
                ..LIVE
            },
            &mut access,
        );
        assert_eq!(bus.advance(&mut access), Ok(None));
        bus.device_mut::<View>(clock)
            .unwrap()
            .set_lifecycle(LIVE, &mut access);
        assert!(bus.advance(&mut access).is_err());
        assert_eq!(owner.requests(), prefix);
        assert_eq!(owner.observations(), observations);
    }
    #[test]
    fn incomplete_or_stale_snapshot_cannot_replace_owned_work() {
        assert!(matches!(
            Controller::from_observations(vec![FULL], LIVE, []),
            Err(Error::MissingObservation)
        ));
        let mut observations = words(&[FULL], 0);
        observations.push(observations[0]);
        assert!(matches!(
            Controller::from_observations(vec![FULL], LIVE, observations),
            Err(Error::DuplicateObservation)
        ));
        let owner = controller(&[FULL], 0);
        let mut view = owner.view(0).unwrap();
        let mut pins = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut pins);
        view.write(CIO, Width::Word, 1, &mut access).unwrap();
        let prefix = owner.requests();
        let observations = owner.observations();
        owner.0.borrow_mut().serial = u64::MAX;
        assert!(view.write(CIO, Width::Word, 2, &mut access).is_err());
        assert_eq!(owner.requests(), prefix);
        assert_eq!(owner.observations(), observations);
    }
}
