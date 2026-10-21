//! T6000 direct MCC/DCS resource ownership. The original `MCPolicyMgrT6000`
//! programs this bank directly; it does not use the T8112 PMP quota protocol.
//! Explicit Stela initialization and retained physical observations are distinct.
//! Committed inputs never become cache-power or quota completion by themselves.
use super::bus::{
    Access, Direction, Lifecycle, LifecycleState, MmioDevice, MmioError, Width, refuse,
};
use alloc::{collections::BTreeMap, rc::Rc, vec::Vec};
use core::cell::RefCell;

pub mod policy;
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
const DCS_DRAIN: u64 = 0xa40;
const DRAM_CONFIG: u64 = 0x13cc;
const MAX_WAYS: u8 = 12;
const MAX_QUOTA_UNITS: u8 = 48;

/// One original register with independently qualified bits. A zero known mask
/// never creates an observation of healthy/reset/empty hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Observation {
    pub aperture: u8,
    pub offset: u64,
    pub value: u64,
    pub known: u64,
}

/// Actual software configuration for a newly owned controller. Quotas start
/// at zero; weights are a declared policy, not measured Apple reset values.
#[derive(Debug, Clone)]
pub struct Configuration {
    pub dram: Vec<[u32; CHANNELS as usize]>,
    pub weights: [u8; GROUPS as usize],
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
    QuotaUse(u8),
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

/// One object for every actual aperture, plane and DRAM channel. No settlement
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
        let apertures = u8::try_from(configuration.dram.len())
            .map_err(|_| "MCC aperture count exceeds source capacity")?;
        if configuration
            .weights
            .iter()
            .any(|&weight| weight == 0 || weight > 0x7f)
        {
            return Err("MCC quota policy weight is outside its source field");
        }
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
                    // No memory-traffic backend was admitted by allocating
                    // controller inputs. Its drain word is not a zero queue
                    // observation, even before the first guest request.
                    known: if matches!(role(offset)?, Role::Drain) {
                        0
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

    /// Retained state keeps actual per-bit knownness. Every admitted input/status
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
    /// Qualified 32-bit register offsets for a parent router which also owns
    /// AMCC lock planes in these same apertures. This does not admit any of the
    /// other MCC/performance effects in the source protocol matrix.
    pub fn register_offsets(&self) -> Vec<u64> {
        let mut offsets = offsets();
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
        if matches!(
            role(offset).map_err(fail)?,
            Role::DsidCommand(_) | Role::Persistence(_) | Role::PersistenceAuxiliary(_)
        ) {
            return Err(fail(
                "MCC persistence/DSID write-alias readback is unqualified",
            ));
        }
        let word = state
            .words
            .get(&(self.aperture, offset))
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
            | Role::QuotaUse(_)
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
            // Only the cache-command broadcast effect is qualified here. No
            // requested target is copied into either actual count field.
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
mod tests {
    use super::*;
    use crate::platform::apple::interrupt::InterruptLatch;
    fn lifecycle() -> LifecycleState {
        LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: true,
        }
    }
    fn owner() -> Controller {
        Controller::initialized(
            Configuration {
                dram: alloc::vec![[0xffff0000; 4]; 4],
                weights: [1; 32],
            },
            lifecycle(),
        )
        .unwrap()
    }
    #[test]
    fn source_apertures_channels_and_declared_initialization_are_owned_together() {
        let owner = owner();
        assert_eq!(owner.origin(), Origin::StelaInitialized);
        let mut latch = InterruptLatch::new();
        for aperture in 0..4 {
            let mut view = owner.view(aperture).unwrap();
            let mut access = Access::new(0, 0, &mut latch);
            for channel in 0..CHANNELS {
                assert_eq!(
                    view.read(
                        DCS_BASE + u64::from(channel) * DCS_STRIDE + DRAM_CONFIG,
                        Width::Word,
                        &mut access
                    ),
                    Ok(0xffff0000)
                );
            }
            for plane in 0..PLANES {
                assert_eq!(
                    view.read(
                        u64::from(plane) * PLANE_STRIDE + CACHE_STATUS,
                        Width::Word,
                        &mut access
                    ),
                    Ok(0)
                );
            }
            assert_eq!(
                view.read(GROUP_QUOTA + 31 * 4, Width::Word, &mut access),
                Ok(1 << 16)
            );
            assert!(
                view.read(GROUP_QUOTA + 32 * 4, Width::Word, &mut access)
                    .is_err()
            );
        }
        assert!(owner.view(4).is_err());
        assert!(owner.requests().is_empty());
    }
    #[test]
    fn requested_ways_never_become_status_and_broadcast_preserves_other_apertures() {
        let owner = owner();
        let mut view = owner.view(1).unwrap();
        let mut alias = owner.view(1).unwrap();
        let mut other = owner.view(2).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 123, &mut latch);
        view.write(BROADCAST, Width::Word, 1, &mut access).unwrap();
        view.write(CACHE_COMMAND, Width::Word, 12, &mut access)
            .unwrap();
        for plane in 0..PLANES {
            assert!(
                alias
                    .read(
                        u64::from(plane) * PLANE_STRIDE + CACHE_STATUS,
                        Width::Word,
                        &mut access
                    )
                    .is_err()
            );
            assert_eq!(
                other.read(
                    u64::from(plane) * PLANE_STRIDE + CACHE_STATUS,
                    Width::Word,
                    &mut access
                ),
                Ok(0)
            );
        }
        let requests = owner.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].kind,
            RequestKind::Ways {
                plane: 0,
                ways: 12,
                broadcast: true
            }
        );
        assert_eq!(requests[0].at, 123);
        assert!(alias.read(CACHE_COMMAND, Width::Word, &mut access).is_err());
        assert!(
            view.write(CACHE_COMMAND, Width::Word, 13, &mut access)
                .is_err()
        );
        assert_eq!(owner.requests(), requests);
    }
    #[test]
    fn native_observations_remain_observations_and_requests_do_not_settle_quota() {
        let initial = owner();
        let mut observations = initial.observations();
        let status = observations
            .iter_mut()
            .find(|o| o.aperture == 0 && o.offset == CACHE_STATUS)
            .unwrap();
        status.value = (12 << 9) | (12 << 4);
        observations
            .iter_mut()
            .find(|o| o.aperture == 0 && o.offset == GROUP_QUOTA)
            .unwrap()
            .value |= 1 << 31;
        let mut unknown = observations.clone();
        unknown
            .iter_mut()
            .find(|o| o.aperture == 0 && o.offset == CACHE_STATUS)
            .unwrap()
            .known = !CACHE_COUNTS & u64::from(u32::MAX);
        let captured = Controller::from_observations(4, lifecycle(), &unknown).unwrap();
        assert_eq!(captured.origin(), Origin::RetainedObservation);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        assert!(
            captured
                .view(0)
                .unwrap()
                .read(CACHE_STATUS, Width::Word, &mut access)
                .is_err()
        );
        let captured = Controller::from_observations(4, lifecycle(), &observations).unwrap();
        let mut view = captured.view(0).unwrap();
        assert_eq!(
            view.read(CACHE_STATUS, Width::Word, &mut access),
            Ok((12 << 9) | (12 << 4))
        );
        view.write(
            GROUP_QUOTA,
            Width::Word,
            48 | (3 << 16) | (1 << 24) | (1 << 31),
            &mut access,
        )
        .unwrap();
        assert!(view.read(GROUP_QUOTA, Width::Word, &mut access).is_err());
        let retained = captured
            .observations()
            .into_iter()
            .find(|o| o.aperture == 0 && o.offset == GROUP_QUOTA)
            .unwrap();
        assert_eq!(retained.value & (1 << 31), 1 << 31);
        assert_eq!(retained.known, u64::from(u32::MAX) & !0x017f_003f);
        assert_eq!(
            captured.requests()[0].kind,
            RequestKind::Quota {
                group: 0,
                units: 48,
                weight: 3,
                attribute: true,
                broadcast: false
            }
        );
        assert!(
            view.write(GROUP_QUOTA, Width::Word, 49, &mut access)
                .is_err()
        );
        assert!(
            view.write(
                GROUP_QUOTA,
                Width::Word,
                48 | (3 << 16) | (1 << 24),
                &mut access,
            )
            .is_err()
        );
        assert_eq!(captured.requests().len(), 1);
    }
    #[test]
    fn drain_temperature_counter_clear_and_accounting_never_succeed_without_backend() {
        let owner = owner();
        let mut view = owner.view(0).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        for offset in [
            DCS_BASE + 0x41c,
            DCS_BASE + 0x4000,
            DCS_BASE + 0xec8,
            DCS_BASE + 0xed0,
            0xc000,
            0x159000,
            0x25000,
        ] {
            assert!(view.read(offset, Width::Word, &mut access).is_err());
            assert!(view.read(offset, Width::Double, &mut access).is_err());
        }
        for offset in [
            DCS_BASE + DCS_DRAIN,
            DCS_BASE + 0x580,
            DCS_BASE + 0x584,
            DCS_BASE + 0x588,
        ] {
            assert!(view.write(offset, Width::Word, 0, &mut access).is_err());
        }
        assert!(
            view.write(
                CACHE_STATUS,
                Width::Word,
                (12 << 9) | (12 << 4),
                &mut access
            )
            .is_err()
        );
        assert!(owner.requests().is_empty());
        assert!(
            view.read(DCS_BASE + DCS_DRAIN, Width::Word, &mut access)
                .is_err()
        );
    }
    #[test]
    fn shared_lifecycle_preserves_exact_requests_and_refuses_native_reset_loss() {
        let owner = owner();
        let mut first = owner.view(0).unwrap();
        let mut last = owner.view(3).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 77, &mut latch);
        first
            .write(SHARED_GATING, Width::Word, 1 << 28, &mut access)
            .unwrap();
        last.write(
            DCS_BASE + 3 * DCS_STRIDE + DCS_GATING,
            Width::Word,
            0x1100,
            &mut access,
        )
        .unwrap();
        let expected = owner.requests();
        let paused = LifecycleState {
            clocked: false,
            ..lifecycle()
        };
        Lifecycle::set_lifecycle(&mut first, paused, &mut access);
        assert_eq!(owner.lifecycle_state(), paused);
        assert!(
            last.read(DCS_BASE + DRAM_CONFIG, Width::Word, &mut access)
                .is_err()
        );
        assert!(
            first
                .write(SHARED_GATING, Width::Word, 0, &mut access)
                .is_err()
        );
        assert_eq!(owner.requests(), expected);
        assert!(
            Lifecycle::check_lifecycle(
                &last,
                LifecycleState {
                    reset: true,
                    ..lifecycle()
                }
            )
            .is_err()
        );
        assert!(
            Lifecycle::check_lifecycle(
                &last,
                LifecycleState {
                    powered: false,
                    retention: false,
                    ..lifecycle()
                }
            )
            .is_err()
        );
        Lifecycle::set_lifecycle(&mut last, lifecycle(), &mut access);
        assert_eq!(owner.requests(), expected);
        assert!(first.read(SHARED_GATING, Width::Word, &mut access).is_err());
        assert_eq!(
            expected.iter().map(|r| r.serial).collect::<Vec<_>>(),
            [1, 2]
        );
    }
    #[test]
    fn malformed_geometry_observations_and_accesses_have_no_partial_effects() {
        for count in [0, 17] {
            assert!(
                Controller::initialized(
                    Configuration {
                        dram: alloc::vec![[0;4];count],
                        weights: [1; 32]
                    },
                    lifecycle()
                )
                .is_err()
            );
        }
        assert!(
            Controller::initialized(
                Configuration {
                    dram: alloc::vec![[0;4];4],
                    weights: [0; 32]
                },
                lifecycle()
            )
            .is_err()
        );
        let owner = owner();
        let source = owner.observations();
        let mut bad = source.clone();
        bad.pop();
        assert!(Controller::from_observations(4, lifecycle(), &bad).is_err());
        let mut bad = source.clone();
        bad.push(source[0]);
        assert!(Controller::from_observations(4, lifecycle(), &bad).is_err());
        let mut bad = source.clone();
        bad[0].value = 1 << 32;
        assert!(Controller::from_observations(4, lifecycle(), &bad).is_err());
        let mut bad = source;
        bad[0].aperture = 4;
        assert!(Controller::from_observations(4, lifecycle(), &bad).is_err());
        let mut view = owner.view(0).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 0, &mut latch);
        for (offset, width) in [
            (CACHE_COMMAND + 1, Width::Word),
            (CACHE_COMMAND, Width::Double),
            (APERTURE_BYTES, Width::Word),
            (BROADCAST, Width::Half),
        ] {
            assert!(view.read(offset, width, &mut access).is_err());
            assert!(view.write(offset, width, 0, &mut access).is_err());
        }
        assert!(view.write(BROADCAST, Width::Word, 2, &mut access).is_err());
        assert!(owner.requests().is_empty());
        assert_eq!(view.read(BROADCAST, Width::Word, &mut access), Ok(0));
    }
}
