//! Original generic `-disable_mcc` permits a permanently cacheless outer MCC.
//! This owns no outer tag/data entries; native CPU caches remain independent.
//! Quotas and persistence are configured policy, not grants or physical metrics.
use super::{
    CACHE_COUNTS, CACHE_STATUS, Controller, GROUP_QUOTA, Observation, PLANE_STRIDE, PLANES,
    QUOTA_FIELDS, QUOTA_UNITS, Request, RequestKind, Role, State,
};
use crate::platform::apple::bus::LifecycleState;
use alloc::vec::Vec;
use core::cell::Ref;

const DSIDS: u64 = 256;
const USE_BASE: u64 = 0xc000;
const PERSISTENCE_BASE: u64 = 0xffc;
const AUXILIARY_BASE: u64 = 0x15ffc;
const COMMAND_BASE: u64 = 0x13ffc;
const QUOTA_UNIT_BYTES: u64 = 1 << 17;

/// Actual outer-resource disposition, immutable after construction. Cacheless
/// means this object has no cache allocation/fill/writeback path at all. It is
/// not a report that the native x86 CPU lacks coherent caches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CacheResource {
    Unqualified,
    Cacheless,
}

pub(super) fn exclusive(role: Role) -> bool {
    matches!(
        role,
        Role::QuotaUse
            | Role::Persistence(_)
            | Role::PersistenceAuxiliary(_)
            | Role::DsidCommand(_)
    )
}

pub(super) fn role(offset: u64) -> Option<Role> {
    if (USE_BASE..USE_BASE + DSIDS * 4).contains(&offset) {
        return Some(Role::QuotaUse);
    }
    // Original persistence/deprioritization consumers exclude DSID0. Their
    // writable tables start at base+4; no adjacent word is silently admitted.
    for (base, kind) in [
        (PERSISTENCE_BASE, Role::Persistence as fn(u8) -> Role),
        (AUXILIARY_BASE, Role::PersistenceAuxiliary),
        (COMMAND_BASE, Role::DsidCommand),
    ] {
        if (base + 4..base + DSIDS * 4).contains(&offset) {
            return Some(kind(((offset - base) / 4) as u8));
        }
    }
    None
}

pub(super) fn offsets() -> Vec<u64> {
    let mut offsets = Vec::new();
    offsets.extend((0..DSIDS).map(|dsid| USE_BASE + dsid * 4));
    for base in [PERSISTENCE_BASE, AUXILIARY_BASE, COMMAND_BASE] {
        offsets.extend((1..DSIDS).map(|dsid| base + dsid * 4));
    }
    offsets
}

impl Controller {
    /// Create this controller with permanently zero owned outer-cache entries,
    /// before admitting any client. No data-cache allocation or dirty-line path
    /// exists in this mode. Original `-disable_mcc` (or the provider property)
    /// supplies a way-clamp of0, which the unchanged T6000 consumer accepts.
    ///
    /// This does not bind or complete native RAM, DCS drain, CPU cache, DMA,
    /// power, PMP or DSB services. The parent must admit those actual owners and
    /// the original supported configuration route together, before execution.
    pub fn initialized_cacheless(
        configuration: super::Configuration,
        lifecycle: LifecycleState,
    ) -> Result<Self, &'static str> {
        let controller = Self::initialized(configuration, lifecycle)?;
        {
            let mut state = controller.0.borrow_mut();
            state.resource = CacheResource::Cacheless;
            for aperture in 0..state.apertures {
                for offset in offsets() {
                    state.words.insert(
                        (aperture, offset),
                        Observation {
                            aperture,
                            offset,
                            value: 0,
                            known: u32::MAX.into(),
                        },
                    );
                }
            }
        }
        Ok(controller)
    }

    pub fn cache_resource(&self) -> CacheResource {
        self.0.borrow().resource
    }

    /// Borrow actual installed policy through the caller's native operation.
    /// The caller supplies an independently qualified client→DSID/group join;
    /// this API never infers it from an application, PE or numeric port name.
    /// Configuration/lifecycle mutation is excluded while this borrow lives.
    /// It grants no canonical-memory, allocation, completion or DSB authority.
    pub fn policy(
        &self,
        aperture: u8,
        dsid: u8,
        group: u8,
    ) -> Result<PolicyLoan<'_>, &'static str> {
        let state = self
            .0
            .try_borrow()
            .map_err(|_| "MCC resource is being mutated")?;
        state.accessible()?;
        if state.resource != CacheResource::Cacheless {
            return Err("MCC policy has no actual admitted resource owner");
        }
        if aperture >= state.apertures || group >= super::GROUPS {
            return Err("MCC policy names an absent aperture/group");
        }
        Ok(PolicyLoan {
            state,
            aperture,
            dsid,
            group,
        })
    }
}

/// A stable borrow of this exact controller, not a second mutable policy bank.
/// Configured quota is a maximum policy limit and may be overcommitted across
/// groups. It is never evidence of reserved, resident or physically cached data.
pub struct PolicyLoan<'owner> {
    state: Ref<'owner, State>,
    aperture: u8,
    dsid: u8,
    group: u8,
}
impl PolicyLoan<'_> {
    fn word(&self, offset: u64) -> u32 {
        let word = self.state.words[&(self.aperture, offset)];
        // Only initialized cacheless policy words are exposed by this borrow;
        // every accepted update installs the complete checked policy word.
        assert_eq!(word.known, u64::from(u32::MAX));
        word.value as u32
    }
    pub fn configured_quota_bytes(&self) -> u64 {
        u64::from(self.word(GROUP_QUOTA + u64::from(self.group) * 4) & QUOTA_UNITS as u32)
            * QUOTA_UNIT_BYTES
    }
    pub fn weight(&self) -> u8 {
        ((self.word(GROUP_QUOTA + u64::from(self.group) * 4) >> 16) & 0x7f) as u8
    }
    pub fn attribute(&self) -> bool {
        self.word(GROUP_QUOTA + u64::from(self.group) * 4) & (1 << 24) != 0
    }
    /// Raw original persistence encoding0/1/2; its physical replacement/aging
    /// behavior is not reinterpreted as an x86 cache-policy guarantee.
    pub fn persistence(&self) -> Option<u8> {
        (self.dsid != 0).then(|| self.word(PERSISTENCE_BASE + u64::from(self.dsid) * 4) as u8)
    }
    /// Occupancy of this actual permanently empty outer cache, not host DRAM
    /// consumption, native CPU-cache residency or an unobserved physical MCC.
    pub fn owned_outer_bytes(&self) -> u64 {
        0
    }
}

pub(super) fn apply(
    state: &mut State,
    aperture: u8,
    offset: u64,
    role: Role,
    written: u32,
    at: u64,
) -> Result<(), &'static str> {
    let previous = state.words[&(aperture, offset)];
    let broadcast = state.words[&(aperture, super::BROADCAST)];
    if broadcast.known & 1 == 0 {
        return Err("cacheless MCC broadcast scope is unknown");
    }
    let broadcast = broadcast.value & 1 != 0;
    let kind = match role {
        Role::Ways(plane) => {
            if written != 0 {
                return Err("permanently cacheless MCC cannot power nonzero tag/data ways");
            }
            RequestKind::Ways {
                plane,
                ways: 0,
                broadcast,
            }
        }
        Role::Quota(group) => {
            let units = (u64::from(written) & QUOTA_UNITS) as u8;
            let preserved = u64::from(u32::MAX) & !QUOTA_FIELDS;
            if units > super::MAX_QUOTA_UNITS
                || previous.known & preserved != preserved
                || (u64::from(written) ^ previous.value) & preserved != 0
            {
                return Err("cacheless MCC quota policy exceeds/pollutes its source fields");
            }
            RequestKind::Quota {
                group,
                units,
                weight: ((written >> 16) & 0x7f) as u8,
                attribute: written & (1 << 24) != 0,
                broadcast,
            }
        }
        Role::Persistence(dsid) if written <= 2 => RequestKind::Persistence {
            dsid,
            raw: written as u8,
            broadcast,
        },
        Role::PersistenceAuxiliary(dsid) if written == 0 => {
            RequestKind::PersistenceAuxiliaryClear { dsid, broadcast }
        }
        Role::DsidCommand(dsid) if written == 2 => RequestKind::Deprioritize { dsid, broadcast },
        Role::QuotaUse => return Err("write to actual cacheless outer occupancy"),
        _ => return Err("cacheless MCC policy/command value is not source-qualified"),
    };
    let serial = state
        .serial
        .checked_add(1)
        .ok_or("MCC request serial exhausted")?;
    state.words.insert(
        (aperture, offset),
        Observation {
            value: u64::from(written),
            known: u32::MAX.into(),
            ..previous
        },
    );
    if let RequestKind::Ways {
        plane, broadcast, ..
    } = kind
    {
        for target in 0..PLANES {
            if broadcast || target == plane {
                let status = state
                    .words
                    .get_mut(&(aperture, u64::from(target) * PLANE_STRIDE + CACHE_STATUS))
                    .expect("actual initialized cacheless plane");
                // These counts follow the absence of any tag/data allocation
                // path, not the requested count. A nonzero request was refused.
                status.value &= !CACHE_COUNTS;
                status.known |= CACHE_COUNTS;
            }
        }
    }
    state.serial = serial;
    state.requests.push(Request {
        serial,
        aperture,
        offset,
        previous,
        written,
        at,
        kind,
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::apple::{
        bus::{Access, Lifecycle, MmioDevice, Width},
        interrupt::InterruptLatch,
    };
    fn lifecycle() -> LifecycleState {
        LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: true,
        }
    }
    fn configuration() -> super::super::Configuration {
        super::super::Configuration {
            dram: alloc::vec![[0xffff0000; 4]; 4],
            weights: [1; 32],
        }
    }
    fn owner() -> Controller {
        Controller::initialized_cacheless(configuration(), lifecycle()).unwrap()
    }
    #[test]
    fn zero_way_source_sequence_completes_from_actual_empty_resources_only() {
        let owner = owner();
        assert_eq!(owner.cache_resource(), CacheResource::Cacheless);
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 400, &mut latch);
        for aperture in 0..4 {
            let mut view = owner.view(aperture).unwrap();
            view.write(super::super::BROADCAST, Width::Word, 1, &mut access)
                .unwrap();
            view.write(super::super::CACHE_COMMAND, Width::Word, 0, &mut access)
                .unwrap();
            view.write(super::super::BROADCAST, Width::Word, 0, &mut access)
                .unwrap();
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
            for ways in [1, 6, 12, 13] {
                assert!(
                    view.write(super::super::CACHE_COMMAND, Width::Word, ways, &mut access)
                        .is_err()
                );
            }
        }
        assert_eq!(owner.requests().len(), 4);
        assert!(owner.requests().iter().all(|r| matches!(
            r.kind,
            RequestKind::Ways {
                ways: 0,
                broadcast: true,
                ..
            }
        )));
        let unqualified = Controller::initialized(configuration(), lifecycle()).unwrap();
        assert_eq!(unqualified.cache_resource(), CacheResource::Unqualified);
        let mut view = unqualified.view(0).unwrap();
        view.write(super::super::CACHE_COMMAND, Width::Word, 0, &mut access)
            .unwrap();
        // A generic initialized input bank is not silently converted into the
        // cacheless resource merely because a caller happened to request0.
        assert!(view.read(CACHE_STATUS, Width::Word, &mut access).is_err());
        assert!(unqualified.policy(0, 1, 0).is_err());
    }
    #[test]
    fn configured_limits_are_not_disjoint_reservations_or_resident_bytes() {
        let owner = owner();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 500, &mut latch);
        for aperture in 0..4 {
            let mut view = owner.view(aperture).unwrap();
            for group in 0..32 {
                let raw = 48 | (3 << 16) | (1 << 24);
                view.write(GROUP_QUOTA + group * 4, Width::Word, raw, &mut access)
                    .unwrap();
                assert_eq!(
                    view.read(GROUP_QUOTA + group * 4, Width::Word, &mut access),
                    Ok(raw)
                );
                let policy = owner.policy(aperture, group as u8, group as u8).unwrap();
                assert_eq!(policy.configured_quota_bytes(), 6 << 20);
                assert_eq!(policy.weight(), 3);
                assert!(policy.attribute());
                assert_eq!(policy.owned_outer_bytes(), 0);
            }
            for dsid in 0..DSIDS {
                assert_eq!(
                    view.read(USE_BASE + dsid * 4, Width::Word, &mut access),
                    Ok(0)
                );
                assert!(
                    view.write(USE_BASE + dsid * 4, Width::Word, 1, &mut access)
                        .is_err()
                );
            }
        }
        assert_eq!(owner.requests().len(), 128);
        assert!(owner.policy(4, 0, 0).is_err());
        assert!(owner.policy(0, 0, 32).is_err());
    }
    #[test]
    fn actual_policy_borrow_freezes_owner_and_rejects_configuration_or_lifecycle_races() {
        let owner = owner();
        let mut alias = owner.view(0).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 10, &mut latch);
        let loan = owner.policy(0, 1, 0).unwrap();
        assert_eq!(loan.configured_quota_bytes(), 0);
        assert_eq!(loan.persistence(), Some(0));
        assert!(
            alias
                .write(GROUP_QUOTA, Width::Word, 1 | (1 << 16), &mut access)
                .is_err()
        );
        assert!(
            alias
                .check_lifecycle(LifecycleState {
                    clocked: false,
                    ..lifecycle()
                })
                .is_err()
        );
        assert!(owner.requests().is_empty());
        drop(loan);
        alias
            .write(GROUP_QUOTA, Width::Word, 1 | (1 << 16), &mut access)
            .unwrap();
        assert_eq!(
            owner.policy(0, 1, 0).unwrap().configured_quota_bytes(),
            QUOTA_UNIT_BYTES
        );
        assert_eq!(owner.policy(0, 0, 0).unwrap().persistence(), None);
    }
    #[test]
    fn persistence_and_deprioritization_retire_only_qualified_empty_resource_effects() {
        let owner = owner();
        let mut view = owner.view(3).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 100, &mut latch);
        view.write(super::super::BROADCAST, Width::Word, 1, &mut access)
            .unwrap();
        for dsid in [1u64, 255] {
            for raw in 0..=2 {
                view.write(PERSISTENCE_BASE + dsid * 4, Width::Word, raw, &mut access)
                    .unwrap();
                assert_eq!(
                    owner.policy(3, dsid as u8, 0).unwrap().persistence(),
                    Some(raw as u8)
                );
            }
            view.write(AUXILIARY_BASE + dsid * 4, Width::Word, 0, &mut access)
                .unwrap();
            view.write(COMMAND_BASE + dsid * 4, Width::Word, 2, &mut access)
                .unwrap();
            for offset in [PERSISTENCE_BASE + dsid * 4, AUXILIARY_BASE + dsid * 4] {
                assert!(view.read(offset, Width::Word, &mut access).is_err());
            }
            assert!(
                view.read(COMMAND_BASE + dsid * 4, Width::Word, &mut access)
                    .is_err()
            );
            assert_eq!(
                view.read(USE_BASE + dsid * 4, Width::Word, &mut access),
                Ok(0)
            );
        }
        let prefix = owner.requests();
        assert!(prefix.iter().all(|r| matches!(
            r.kind,
            RequestKind::Persistence {
                broadcast: true,
                ..
            } | RequestKind::PersistenceAuxiliaryClear {
                broadcast: true,
                ..
            } | RequestKind::Deprioritize {
                broadcast: true,
                ..
            }
        )));
        for (offset, width, value) in [
            (PERSISTENCE_BASE, Width::Word, 0),
            (PERSISTENCE_BASE + 4, Width::Word, 3),
            (PERSISTENCE_BASE + DSIDS * 4, Width::Word, 0),
            (AUXILIARY_BASE + 4, Width::Word, 1),
            (COMMAND_BASE + 4, Width::Word, 1),
            (COMMAND_BASE + 4, Width::Word, 3),
            (PERSISTENCE_BASE + 4, Width::Double, 0),
            (PERSISTENCE_BASE + 5, Width::Word, 0),
        ] {
            assert!(view.write(offset, width, value, &mut access).is_err());
        }
        assert_eq!(owner.requests(), prefix);
        let unqualified = Controller::initialized(configuration(), lifecycle()).unwrap();
        assert!(
            unqualified
                .view(0)
                .unwrap()
                .read(USE_BASE, Width::Word, &mut access)
                .is_err()
        );
    }
    #[test]
    fn retention_keeps_policy_and_no_cacheless_mode_escapes_into_dcs_or_counters() {
        let owner = owner();
        let mut first = owner.view(0).unwrap();
        let mut last = owner.view(3).unwrap();
        let mut latch = InterruptLatch::new();
        let mut access = Access::new(0, 7, &mut latch);
        first
            .write(PERSISTENCE_BASE + 4, Width::Word, 2, &mut access)
            .unwrap();
        let prefix = owner.requests();
        let paused = LifecycleState {
            powered: false,
            clocked: false,
            quiesced: true,
            ..lifecycle()
        };
        first.set_lifecycle(paused, &mut access);
        assert!(owner.policy(0, 1, 0).is_err());
        assert!(last.read(USE_BASE, Width::Word, &mut access).is_err());
        assert!(
            last.check_lifecycle(LifecycleState {
                reset: true,
                ..lifecycle()
            })
            .is_err()
        );
        assert!(
            last.check_lifecycle(LifecycleState {
                powered: false,
                retention: false,
                ..lifecycle()
            })
            .is_err()
        );
        last.set_lifecycle(lifecycle(), &mut access);
        assert_eq!(owner.requests(), prefix);
        assert_eq!(owner.policy(0, 1, 0).unwrap().persistence(), Some(2));
        assert_eq!(owner.cache_resource(), CacheResource::Cacheless);
        for offset in [
            super::super::DCS_BASE + super::super::DCS_DRAIN,
            super::super::DCS_BASE + 0x41c,
            0x159000,
        ] {
            assert!(first.read(offset, Width::Word, &mut access).is_err());
        }
    }
}
