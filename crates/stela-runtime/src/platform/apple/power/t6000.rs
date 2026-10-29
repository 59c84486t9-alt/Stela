//! T6000 PMGR request banks sharing one controller owner.
//!
//! Original 26A434 AppleT6000PMGR uses RegMap0 +18000..18014 for six
//! source complex selectors, +1a034 for four CIO ports per instance, and
//! +1c0c0/+1c0c8/+1c0d0 for CPM automatic-gating controls. RegMap5b
//! +38210..3821c owns the separate ISP source/divider/update requests. Callers must
//! supply the board's admitted selector/port/instance geometry and
//! handoff observations; source selector capacity is not hardware inventory.
//!
//! Requests are committed controller inputs, not completed native programs.
//! GPCE bits4/5/6 remain unknown after requests. CIO readback remains unknown
//! without the explicitly bound Stela-native engine. That engine derives its
//! command/busy state from requests and only retires them after routed
//! effects, a matching source action and the finalized end. No captured Apple
//! micro-PC, cold state or unsupported native operation is manufactured.
//! A kept pause preserves every input, observation and chronological prefix
//! across all mapped views.
use crate::Result;
use alloc::{collections::BTreeMap, rc::Rc, vec::Vec};
use core::cell::RefCell;
use stela_contracts::Refusal;
use stela_contracts::refuse;
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction, stela_contracts::bus::Lifecycle,
    stela_contracts::bus::LifecycleState, stela_contracts::bus::MmioDevice,
    stela_contracts::bus::MmioError, stela_contracts::bus::Width, stela_contracts::bus::refuse,
};

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
/// driver's maximum capacities. Bits select devices, not initial states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Instance {
    pub complexes: u8,
    pub cio_ports: u8,
    pub cpm_controls: u8,
    pub isp_clocks: u8,
}
impl Instance {
    /// Required word offsets only; the caller must check physical placement.
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

/// A register observation, with independently kept knownness. A
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
    fn accessible(&self) -> Result<()> {
        if !self.lifecycle.powered || !self.lifecycle.clocked {
            return Err(refuse!(
                "T6000 power access while its supplied rail/clock is paused"
            ));
        }
        if self.lifecycle.reset {
            return Err(refuse!("T6000 power access while reset is asserted"));
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
            // the clock quarantines itself; never silently rebase it.
            let _ = clock.observe(now, running);
        }
        if running != (proposed.powered && proposed.clocked && !proposed.reset) {
            self.clock_edge_at = Some(self.clock_edge_at.map_or(now, |prior| prior.max(now)));
        }
        self.lifecycle = proposed;
    }
}

/// Shared permission for every mapped instance. Handoff observations cannot be
/// replaced after requests. The optional CIO native engine consumes only its
/// own accepted requests through real effects and finalized retirement.
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
        // A caller must supply lifecycle inputs; accepting a kept
        // pause does not check cold reset or nonretained register loss.
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
    /// One first-die T6000 owner for request, configuration and SRAM
    /// views. Existing constructors keep unknown/unmounted native resources.
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
    fn check(&self, offset: u64, width: Width) -> Result<Observation> {
        let state = self.controller.0.borrow();
        state.accessible()?;
        if width != Width::Word {
            return Err(refuse!("T6000 power request requires a 32-bit access"));
        }
        state
            .words
            .get(&(self.instance, self.bank, offset))
            .copied()
            .ok_or(refuse!(
                "T6000 power register is outside supplied actual board geometry"
            ))
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
            clock.cycles().map_err(clock::Error::reason)?;
        }
        if proposed.reset || (!proposed.powered && !proposed.retention) {
            return Err(refuse!(
                "T6000 power physical reset/nonretained loss and native cancellation are unqualified"
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
    fn lifecycle(&mut self) -> Option<&mut dyn Lifecycle> {
        Some(self)
    }
    fn name(&self) -> &'static str {
        NAME
    }
    fn read(&mut self, offset: u64, width: Width, _: &mut Access<'_>) -> Result<u64, MmioError> {
        let fail = |reason: Refusal| refuse(NAME, offset, width, Direction::Read, reason);
        let word = self.check(offset, width).map_err(fail)?;
        if word.known != u32::MAX {
            return Err(fail(refuse!(
                "T6000 power register readback/native progression is unknown"
            )));
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
        let fail = |reason: Refusal| refuse(NAME, offset, width, Direction::Write, reason);
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
                return Err(fail(refuse!(
                    "T6000 ISP reference clock update must preserve captured other fields and set updatebit31"
                )));
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
                return Err(fail(refuse!(
                    "T6000 CIO only qualifies one admitted port request bit"
                )));
            }
            // Without the Stela-native execution owner, the AP request
            // and wait alone establish no response or low-bit readback. Keep
            // that unbound path unknown. The explicitly bound engine below
            // instead reports its own command/busy state.
            let next = if let Some(native) =
                state.native.as_ref().filter(|native| native.engine_bound())
            {
                if old.known != u32::MAX
                    || native::View::pending(&state)
                    || !native.accepts_cio(&state.requests)
                {
                    return Err(fail(refuse!(
                        "T6000 CIO native engine requires known idle/activated command state and exclusive pending ownership"
                    )));
                }
                // Stela engine command/busy state derives from this real
                // accepted transaction. Native footer/end retirement, not a
                // write-time success shortcut, consumes these bits.
                Observation {
                    value: old.value | value | (value << 16),
                    ..old
                }
            } else {
                Observation { known: 0, ..old }
            };
            (RequestKind::Cio { port }, next)
        } else if offset >= CPM_BASE {
            if old.known != u32::MAX || (value ^ old.value) & !CPM_ENABLE != 0 {
                return Err(fail(refuse!(
                    "T6000 CPM gating must preserve all captured non-enable fields"
                )));
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
                return Err(fail(refuse!(
                    "T6000 GPCE request fields or uncaptured preserved fields are unqualified"
                )));
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
            .ok_or_else(|| fail(refuse!("T6000 request serial exhausted")))?;
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
            || state.requests.iter().any(|request| {
                !matches!(request.kind, RequestKind::AutomaticGating { .. })
                    && !state
                        .native
                        .as_ref()
                        .is_some_and(|native| native.request_retired(request.serial))
            })
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
mod tests;
