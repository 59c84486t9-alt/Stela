//! T6000 direct MCC/DCS resource ownership. The original `MCPolicyMgrT6000`
//! programs this bank directly; it does not use the T8112 PMP quota protocol.
//! Explicit Stela initialization and kept physical observations are distinct.
//! Committed inputs never become cache-power or quota completion by themselves.
use alloc::{collections::BTreeMap, rc::Rc, vec::Vec};
use core::cell::RefCell;
use {
    stela_contracts::bus::Access, stela_contracts::bus::Direction, stela_contracts::bus::Lifecycle,
    stela_contracts::bus::LifecycleState, stela_contracts::bus::MmioDevice,
    stela_contracts::bus::MmioError, stela_contracts::bus::Width, stela_contracts::bus::refuse,
};

mod configuration;
mod drain;
pub mod policy;
mod status;
pub mod t6020;
pub use configuration::Configuration;
use policy::CacheResource;

const NAME: &str = "t6000-mcc";
pub const APERTURE_BYTES: u64 = 0x1000000;
pub const PLANES: u8 = 4;
pub const PLANE_STRIDE: u64 = 0x40000;
pub const DCS_BASE: u64 = 0x200000;
pub const DCS_STRIDE: u64 = 0x200000;
pub const CHANNELS: u8 = 4;
const CACHE_COMMAND: u64 = 0x1c00;
const CACHE_STATUS: u64 = 0x1c04;
const CACHE_COUNTS: u64 = (0x1f << 9) | (0x1f << 4);
const SHARED_GATING: u64 = 0x100004;
const BROADCAST: u64 = 0x10000c;
const GROUP_QUOTA: u64 = 0xa000;
const GROUPS: u8 = 32;
const QUOTA_UNITS: u64 = 0x3f;
const QUOTA_FIELDS: u64 = 0x017f_003f;
const DCS_GATING: u64 = 0x10;
/// Per-channel in-flight status, requiring a live native memory service.
pub const DCS_DRAIN: u64 = 0xa40;
const DRAM_CONFIG: u64 = 0x13cc;
const MAX_WAYS: u8 = 12;
const MAX_QUOTA_UNITS: u8 = 48;

/// The original per-channel in-flight status word. This identifies a required
/// live memory service; it supplies neither a counter value nor completion.
pub(crate) fn is_drain_word(offset: u64, width: Width) -> bool {
    width == Width::Word && matches!(role(offset), Ok(Role::Drain))
}

/// One original register with checked bits. A zero known mask
/// never creates an observation of healthy/reset/empty hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    pub aperture: u8,
    pub offset: u64,
    pub value: u64,
    pub known: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestKind {
    Ways {
        plane: u8,
        ways: u8,
        broadcast: bool,
    },
    Quota {
        group: u8,
        units: u8,
        weight: u8,
        attribute: bool,
        broadcast: bool,
    },
    MccGating,
    DcsGating {
        channel: u8,
    },
    DramConfiguration {
        channel: u8,
    },
    /// Consuming source queue flush under the synchronous RAM owner.
    Drain {
        channel: u8,
    },
    Persistence {
        dsid: u8,
        raw: u8,
        broadcast: bool,
    },
    PersistenceAuxiliaryClear {
        dsid: u8,
        broadcast: bool,
    },
    Deprioritize {
        dsid: u8,
        broadcast: bool,
    },
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    pub serial: u64,
    pub aperture: u8,
    pub offset: u64,
    pub previous: Observation,
    pub written: u32,
    pub at: u64,
    pub kind: RequestKind,
}
#[derive(Debug, Clone, Copy)]
enum Role {
    Ways(u8),
    Status,
    Broadcast,
    MccGating,
    Quota(u8),
    DcsGating(u8),
    Dram(u8),
    Drain,
    QuotaUse,
    Persistence(u8),
    PersistenceAuxiliary(u8),
    DsidCommand(u8),
}

fn role(offset: u64) -> Result<Role, &'static str> {
    if offset >= APERTURE_BYTES || !offset.is_multiple_of(4) {
        return Err("MCC register outside its aperture or alignment");
    }
    if offset < u64::from(PLANES) * PLANE_STRIDE {
        let plane = (offset / PLANE_STRIDE) as u8;
        match offset % PLANE_STRIDE {
            CACHE_COMMAND => return Ok(Role::Ways(plane)),
            CACHE_STATUS => return Ok(Role::Status),
            _ => {}
        }
    }
    if (GROUP_QUOTA..GROUP_QUOTA + u64::from(GROUPS) * 4).contains(&offset) {
        return Ok(Role::Quota(((offset - GROUP_QUOTA) / 4) as u8));
    }
    match offset {
        SHARED_GATING => return Ok(Role::MccGating),
        BROADCAST => return Ok(Role::Broadcast),
        _ => {}
    }
    if let Some(role) = policy::role(offset) {
        return Ok(role);
    }
    if (DCS_BASE..DCS_BASE + u64::from(CHANNELS) * DCS_STRIDE).contains(&offset) {
        let channel = ((offset - DCS_BASE) / DCS_STRIDE) as u8;
        match (offset - DCS_BASE) % DCS_STRIDE {
            DCS_GATING => return Ok(Role::DcsGating(channel)),
            DRAM_CONFIG => return Ok(Role::Dram(channel)),
            DCS_DRAIN => return Ok(Role::Drain),
            _ => {}
        }
    }
    Err("MCC register/event-accounting effect has not been qualified")
}
fn offsets() -> Vec<u64> {
    let mut offsets = alloc::vec![SHARED_GATING, BROADCAST];
    for plane in 0..PLANES {
        let base = u64::from(plane) * PLANE_STRIDE;
        offsets.extend([base + CACHE_COMMAND, base + CACHE_STATUS]);
    }
    offsets.extend((0..GROUPS).map(|group| GROUP_QUOTA + u64::from(group) * 4));
    for channel in 0..CHANNELS {
        let base = DCS_BASE + u64::from(channel) * DCS_STRIDE;
        offsets.extend([base + DCS_GATING, base + DRAM_CONFIG, base + DCS_DRAIN]);
    }
    offsets
}

/// Immutable constructor provenance; source observations are never converted to
/// an initialized Stela reset state after a request or lifecycle transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    StelaInitialized,
    RetainedObservation,
}

struct State {
    origin: Origin,
    resource: CacheResource,
    apertures: u8,
    lifecycle: LifecycleState,
    words: BTreeMap<(u8, u64), Observation>,
    requests: Vec<Request>,
    serial: u64,
}
impl State {
    fn accessible(&self) -> Result<(), &'static str> {
        if !self.lifecycle.powered || !self.lifecycle.clocked || self.lifecycle.quiesced {
            return Err("MCC/DCS resource is paused by its actual owner");
        }
        if self.lifecycle.reset {
            return Err("MCC/DCS resource is in reset");
        }
        Ok(())
    }
}

/// One object for every aperture, plane and DRAM channel. No settlement
/// setter exists: completing a request requires its real cache/memory/power
/// backend, not an arbitrary numeric name, queue enqueue or Boolean readiness.
#[derive(Clone)]
pub struct Controller(Rc<RefCell<State>>);
impl Controller {
    /// Source-compatible software initialization: cache ways are off, quota
    /// reservations are zero, and channel configuration is supplied explicitly.
    /// This allocates controller input/state backing, not a functional cache,
    /// native DRAM reconfiguration, event source or physical reset observation.
    pub fn initialized(
        configuration: Configuration,
        lifecycle: LifecycleState,
    ) -> Result<Self, &'static str> {
        let apertures = configuration.validate()?;
        let mut observations = Vec::new();
        for aperture in 0..apertures {
            for offset in offsets() {
                let value = match role(offset)? {
                    Role::Quota(group) => {
                        u64::from(configuration.weights[usize::from(group)]) << 16
                    }
                    Role::Dram(channel) => {
                        u64::from(configuration.dram[usize::from(aperture)][usize::from(channel)])
                    }
                    _ => 0,
                };
                observations.push(Observation {
                    aperture,
                    offset,
                    value,
                    // This software resource owns its initially zero opaque
                    // high control bits. Only a live canonical RAM service may
                    // supply the low queue field or consume its clear write.
                    known: if matches!(role(offset)?, Role::Drain) {
                        0xffff_0000
                    } else {
                        u32::MAX.into()
                    },
                });
            }
        }
        let controller = Self::from_observations(apertures, lifecycle, &observations)?;
        controller.0.borrow_mut().origin = Origin::StelaInitialized;
        Ok(controller)
    }

    /// State keeps per-bit knownness. Every admitted input/status
    /// word must be described; absent observations are not default-zero registers.
    pub fn from_observations(
        apertures: u8,
        lifecycle: LifecycleState,
        observations: &[Observation],
    ) -> Result<Self, &'static str> {
        if apertures == 0 || apertures > 16 {
            return Err("MCC aperture count exceeds original source capacity");
        }
        if lifecycle.reset || (!lifecycle.powered && !lifecycle.retention) {
            return Err("MCC physical reset/nonretained loss is unqualified");
        }
        let mut words = BTreeMap::new();
        for &word in observations {
            if word.aperture >= apertures {
                return Err("MCC observation names an absent aperture");
            }
            if policy::exclusive(role(word.offset)?) {
                return Err("retained MCC policy/accounting requires its actual resource owner");
            }
            if word.value > u64::from(u32::MAX) || word.known > u64::from(u32::MAX) {
                return Err("MCC observation exceeds its original 32-bit register");
            }
            if words.insert((word.aperture, word.offset), word).is_some() {
                return Err("duplicate MCC observation");
            }
        }
        for aperture in 0..apertures {
            for offset in offsets() {
                if !words.contains_key(&(aperture, offset)) {
                    return Err("MCC input/status observation is absent");
                }
            }
        }
        Ok(Self(Rc::new(RefCell::new(State {
            origin: Origin::RetainedObservation,
            resource: CacheResource::Unqualified,
            apertures,
            lifecycle,
            words,
            requests: Vec::new(),
            serial: 0,
        }))))
    }
    pub fn view(&self, aperture: u8) -> Result<View, &'static str> {
        if aperture >= self.0.borrow().apertures {
            return Err("MCC view names an absent aperture");
        }
        Ok(View {
            controller: self.clone(),
            aperture,
        })
    }
    /// Checked 32-bit register offsets for a parent router which also owns
    /// AMCC lock planes in these same apertures. This does not admit any of the
    /// other MCC/performance effects in the source protocol matrix.
    pub fn register_offsets(&self) -> Vec<u64> {
        let mut offsets = offsets();
        if self.0.borrow().origin == Origin::StelaInitialized {
            offsets.extend(status::aliases());
        }
        if self.0.borrow().resource == CacheResource::Cacheless {
            offsets.extend(policy::offsets());
        }
        offsets
    }
    pub fn origin(&self) -> Origin {
        self.0.borrow().origin
    }
    pub fn observations(&self) -> Vec<Observation> {
        self.0.borrow().words.values().copied().collect()
    }
    pub fn requests(&self) -> Vec<Request> {
        self.0.borrow().requests.clone()
    }
    pub fn lifecycle_state(&self) -> LifecycleState {
        self.0.borrow().lifecycle
    }
}

pub struct View {
    controller: Controller,
    aperture: u8,
}
impl Lifecycle for View {
    fn check_lifecycle(&self, proposed: LifecycleState) -> Result<(), &'static str> {
        let _exclusive = self
            .controller
            .0
            .try_borrow_mut()
            .map_err(|_| "MCC resource/policy is borrowed by its actual consumer")?;
        if proposed.reset || (!proposed.powered && !proposed.retention) {
            return Err("MCC/DCS native reset, loss and cancellation are unqualified");
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
        let fail = |reason| refuse(NAME, offset, width, Direction::Read, reason);
        let state = self.controller.0.borrow();
        state.accessible().map_err(fail)?;
        if width != Width::Word {
            return Err(fail("MCC register requires an original 32-bit access"));
        }
        let source = status::canonical(offset).unwrap_or(offset);
        if source != offset && state.origin != Origin::StelaInitialized {
            return Err(fail(
                "retained physical MCC status-alias relationship is unqualified",
            ));
        }
        if matches!(
            role(source).map_err(fail)?,
            Role::DsidCommand(_) | Role::Persistence(_) | Role::PersistenceAuxiliary(_)
        ) {
            return Err(fail(
                "MCC persistence/DSID write-alias readback is unqualified",
            ));
        }
        let word = state
            .words
            .get(&(self.aperture, source))
            .ok_or_else(|| fail("MCC register has no actual backing"))?;
        if word.known != u64::from(u32::MAX) {
            return Err(fail(
                "MCC/DCS register requires unqualified backend settlement",
            ));
        }
        Ok(word.value)
    }
    fn write(
        &mut self,
        offset: u64,
        width: Width,
        value: u64,
        access: &mut Access<'_>,
    ) -> Result<(), MmioError> {
        let fail = |reason| refuse(NAME, offset, width, Direction::Write, reason);
        let mut state = self
            .controller
            .0
            .try_borrow_mut()
            .map_err(|_| fail("MCC resource/policy is borrowed by its actual consumer"))?;
        state.accessible().map_err(fail)?;
        if width != Width::Word {
            return Err(fail("MCC register requires an original 32-bit access"));
        }
        let role = role(offset).map_err(fail)?;
        let previous = *state
            .words
            .get(&(self.aperture, offset))
            .ok_or_else(|| fail("MCC register has no actual backing"))?;
        let written = value as u32;
        if state.resource == CacheResource::Cacheless
            && (policy::exclusive(role) || matches!(role, Role::Quota(_) | Role::Ways(_)))
        {
            return policy::apply(&mut state, self.aperture, offset, role, written, access.now)
                .map_err(fail);
        }
        if policy::exclusive(role) {
            return Err(fail(
                "MCC policy/accounting has no qualified resource owner",
            ));
        }
        if matches!(role, Role::Status) {
            return Err(fail("write to actual cache power status"));
        }
        if let Role::Drain = role {
            return Err(fail(
                "DCS drain requires the actual shared memory/visibility backend",
            ));
        }
        if matches!(role, Role::Broadcast) {
            if written > 1 {
                return Err(fail("MCC broadcast request contains unqualified fields"));
            }
            state.words.insert(
                (self.aperture, offset),
                Observation {
                    value: u64::from(written),
                    known: u32::MAX.into(),
                    ..previous
                },
            );
            return Ok(());
        }
        let broadcast = state.words[&(self.aperture, BROADCAST)];
        let broadcast = if matches!(role, Role::Ways(_) | Role::Quota(_)) {
            if broadcast.known & 1 == 0 {
                return Err(fail("MCC broadcast scope is unknown"));
            }
            broadcast.value & 1 != 0
        } else {
            false
        };
        let kind = match role {
            Role::Ways(plane) => {
                if written > u32::from(MAX_WAYS) {
                    return Err(fail("MCC way target exceeds the source 12-way geometry"));
                }
                RequestKind::Ways {
                    plane,
                    ways: written as u8,
                    broadcast,
                }
            }
            Role::Quota(group) => {
                let units = (u64::from(written) & QUOTA_UNITS) as u8;
                if units > MAX_QUOTA_UNITS {
                    return Err(fail(
                        "MCC quota exceeds the source 6 MiB per-aperture capacity",
                    ));
                }
                RequestKind::Quota {
                    group,
                    units,
                    weight: ((written >> 16) & 0x7f) as u8,
                    attribute: written & (1 << 24) != 0,
                    broadcast,
                }
            }
            Role::MccGating => RequestKind::MccGating,
            Role::DcsGating(channel) => RequestKind::DcsGating { channel },
            Role::Dram(channel) => RequestKind::DramConfiguration { channel },
            Role::Broadcast
            | Role::Status
            | Role::Drain
            | Role::QuotaUse
            | Role::Persistence(_)
            | Role::PersistenceAuxiliary(_)
            | Role::DsidCommand(_) => unreachable!(),
        };
        let pending_fields = match kind {
            RequestKind::Quota { .. } | RequestKind::MccGating | RequestKind::DcsGating { .. } => {
                let fields = match kind {
                    RequestKind::Quota { .. } => QUOTA_FIELDS,
                    RequestKind::MccGating => 0x3000_0000u64,
                    _ => 0x1100,
                };
                let preserved = u64::from(u32::MAX) & !fields;
                if previous.known & preserved != preserved
                    || (u64::from(written) ^ previous.value) & preserved != 0
                {
                    return Err(fail("MCC/DCS request cannot preserve unqualified fields"));
                }
                let selector = u64::from(written) & fields;
                if !matches!(kind, RequestKind::Quota { .. })
                    && selector
                        == if fields == 0x1100 {
                            0x1000
                        } else {
                            0x2000_0000
                        }
                {
                    return Err(fail(
                        "MCC/DCS gating selector is absent from the original protocol",
                    ));
                }
                fields
            }
            _ => u32::MAX.into(),
        };
        let serial = state
            .serial
            .checked_add(1)
            .ok_or_else(|| fail("MCC request serial exhausted"))?;
        let word = Observation {
            value: u64::from(written),
            known: previous.known & !pending_fields,
            ..previous
        };
        state.words.insert((self.aperture, offset), word);
        if let RequestKind::Ways {
            plane, broadcast, ..
        } = kind
        {
            // Only the cache-command broadcast effect is checked here. No
            // requested target is copied into either count field.
            for target in 0..PLANES {
                if broadcast || target == plane {
                    let status = state
                        .words
                        .get_mut(&(
                            self.aperture,
                            u64::from(target) * PLANE_STRIDE + CACHE_STATUS,
                        ))
                        .expect("constructed cache status");
                    status.known &= !CACHE_COUNTS;
                }
            }
        }
        state.serial = serial;
        state.requests.push(Request {
            serial,
            aperture: self.aperture,
            offset,
            previous,
            written,
            at: access.now,
            kind,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests;
