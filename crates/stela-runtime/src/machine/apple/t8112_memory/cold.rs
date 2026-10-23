//! Cold native T8112 memory placement over the loader's registered RAM.
//! Software backing is declared here; PMGR lifecycle comes only from the actual
//! placed model. Neither source metadata nor clear words certify hardware ready.
use super::super::{
    AppleDevices,
    memory_resources::{amcc, t8112},
};
use crate::{
    machine::{
        Chip,
        soc::{Board, MemoryCache, MemoryController, PowerOwner, PowerStates},
    },
    memory::RegisteredSystemRam,
    platform::apple::{
        bus::{LifecycleState, Width},
        pmgr::{
            self, Pmgr,
            coverage::{self, Consumer, LifecycleSinks},
        },
        ptd::{self, Geometry},
    },
};
use alloc::{format, string::String, sync::Arc, vec, vec::Vec};
use t8112::cache::{EmptyResource, SoftwareImage, ZeroWayConfiguration};

const SHARED: (u64, u64) = (0x100000, 0x80000);
const BROADCAST: u64 = 0xf00000;
const DCS_OFFSET: u64 = 0x1000000;
const PLANES: u32 = 4;
const PLANE_STRIDE: u64 = 0x40000;
const APERTURE_BYTES: u64 = 0xf40000;
const PTD_ENTRIES: usize = 2048;

/// Explicit new-software initialization, separate from Apple reset state.
/// The caller must independently verify/publish the real generic -disable_mcc
/// boot argument before original entry. This declaration cannot prove it did.
#[derive(Clone, Copy)]
pub struct Configuration {
    selection: ZeroWayConfiguration,
}
impl Configuration {
    pub fn clear_software_controls(selection: ZeroWayConfiguration) -> Result<Self, String> {
        if selection != ZeroWayConfiguration::DisableArgument {
            return Err("cold T8112 memory requires the source-checked -disable_mcc policy".into());
        }
        Ok(Self { selection })
    }
}

/// Retains the same RAM and live source descriptors before any input is moved
/// into a bus owner. The whole source graph remains independently accounted.
pub struct Plan {
    controller: MemoryController,
    cache: MemoryCache,
    source_power: PowerStates,
    domains: Vec<u64>,
    ram: Arc<RegisteredSystemRam>,
    programmed: amcc::Programmed,
    configuration: Configuration,
}
impl Plan {
    pub fn prepare(
        board: &Board,
        ram: &Arc<RegisteredSystemRam>,
        programmed: amcc::Programmed,
        configuration: &Configuration,
    ) -> Result<Self, String> {
        if board.cpus.chip != Chip::AppleM2 {
            return Err("cold T8112 memory does not qualify this CPU family".into());
        }
        Self::prepare_resources(
            board
                .memory_controller
                .as_ref()
                .ok_or("cold T8112 memory has no live AMCC descriptor")?,
            board
                .memory_cache
                .as_ref()
                .ok_or("cold T8112 memory has no live MCC descriptor")?,
            board
                .power_states
                .as_ref()
                .ok_or("cold T8112 memory has no full source power graph")?,
            ram,
            programmed,
            configuration,
        )
    }

    fn prepare_resources(
        controller: &MemoryController,
        cache: &MemoryCache,
        states: &PowerStates,
        ram: &Arc<RegisteredSystemRam>,
        programmed: amcc::Programmed,
        configuration: &Configuration,
    ) -> Result<Self, String> {
        if configuration.selection != ZeroWayConfiguration::DisableArgument {
            return Err("cold T8112 memory cannot infer an empty cache configuration".into());
        }
        geometry(controller, cache, ram, programmed)?;
        let shared = controller.apertures[0] + cache.cache.shared.0;
        let domains = power_domains(states, shared)?;
        Ok(Self {
            controller: controller.clone(),
            cache: cache.clone(),
            source_power: states.clone(),
            domains,
            ram: Arc::clone(ram),
            programmed,
            configuration: *configuration,
        })
    }

    /// Mount preflight against its actual live board, before consuming inputs.
    pub fn validate(
        &self,
        controller: Option<&MemoryController>,
        cache: Option<&MemoryCache>,
    ) -> Result<(), String> {
        if controller != Some(&self.controller) || cache != Some(&self.cache) {
            return Err("cold T8112 memory differs from the actual live board descriptors".into());
        }
        Ok(())
    }

    /// Call after PMGR placement and before power connection/display aliases.
    /// All guest/native/DMA publishers remain excluded throughout cold setup.
    pub fn install(self, devices: &mut AppleDevices) -> Result<(), String> {
        if devices.power_configured
            || devices.memory_controller.is_some()
            || devices.memory_publication.is_some()
        {
            return Err("cold T8112 memory requires an unconnected unoccupied memory mount".into());
        }
        let pmgr_id = devices
            .pmgr
            .ok_or("cold T8112 memory requires the actual placed PMGR")?;
        let pmgr = devices
            .bus
            .device::<Pmgr>(pmgr_id)
            .ok_or("cold T8112 memory has a foreign PMGR owner")?;
        if self
            .source_power
            .registers
            .iter()
            .any(|&address| pmgr.domain_state(address).is_none())
        {
            return Err("cold T8112 memory PMGR omits part of the retained source graph".into());
        }
        let states = self
            .domains
            .iter()
            .map(|&address| {
                if devices.bus.route(address, Width::Word).ok() != Some((pmgr_id, address)) {
                    return Err(format!(
                        "MCC lifecycle domain {address:#x} has no actual PMGR route"
                    ));
                }
                pmgr.domain_state(address).ok_or_else(|| {
                    format!("MCC lifecycle domain {address:#x} has no actual PMGR state")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        // Retention declares that this software backing keeps data on gating.
        // Every other input is the actual current controller word, never ACTIVE
        // substituted for an absent domain or an asserted reset.
        let lifecycle = LifecycleState {
            powered: states.iter().all(|state| state.power != pmgr::POWER_GATED),
            clocked: states.iter().all(|state| state.power == pmgr::ACTIVE),
            quiesced: states.iter().any(|state| state.disabled),
            reset: states.iter().any(|state| state.reset),
            retention: true,
        };
        let memory = t8112::Prepared::initialized(
            self.cache,
            vec![
                t8112::ChannelConfiguration {
                    ec8: 0,
                    ed0: 0,
                    gating: 0,
                    drain_high: 0
                };
                t8112::CHANNELS
            ],
            lifecycle,
            self.ram,
        )
        .map_err(String::from)?;
        let locks = memory
            .initialize_amcc_locks(self.controller, self.programmed, lifecycle)
            .map_err(String::from)?;
        let cache = EmptyResource::initialized(
            locks,
            self.configuration.selection,
            SoftwareImage::zeroed_control_image(),
        )
        .map_err(String::from)?;
        devices.add_t8112_empty_memory_resources(memory, cache)
    }
}

/// Reuse the same ancestor/alias/implicit-power closure as actual powerconnect.
/// No sinks are claimed complete while deriving these metadata dependencies.
fn power_domains(states: &PowerStates, shared: u64) -> Result<Vec<u64>, String> {
    let resources = states
        .resources
        .iter()
        .enumerate()
        .filter(|(_, resource)| resource.owner == Some(PowerOwner::Mmio(shared)))
        .map(|(id, _)| id)
        .collect::<Vec<_>>();
    if resources.is_empty()
        || resources
            .iter()
            .any(|&id| states.resources[id].admission == coverage::Admission::Unavailable)
    {
        return Err(
            "cold T8112 MCC shared reg0 has no positively placed source power resource".into(),
        );
    }
    let power = states.power_requirements()?;
    let consumers = states
        .resources
        .iter()
        .enumerate()
        .map(|(id, resource)| Consumer {
            id,
            name: &resource.name,
            clocks: resource.activated_clocks(),
            power: &power[id],
            admission: resource.admission,
            sinks: LifecycleSinks::default(),
        })
        .collect::<Vec<_>>();
    let coverage = coverage::analyze(&states.domains, &consumers)
        .map_err(|error| format!("cold T8112 source power graph: {error:?}"))?;
    if coverage.len() != states.registers.len()
        || coverage
            .iter()
            .any(|domain| !states.registers.contains(&domain.address))
    {
        return Err(
            "cold T8112 source graph differs from its complete physical register set".into(),
        );
    }
    let domains = coverage
        .iter()
        .filter(|domain| {
            domain
                .consumers
                .iter()
                .any(|consumer| resources.contains(&consumer.id))
        })
        .map(|domain| domain.address)
        .collect::<Vec<_>>();
    if domains.is_empty() {
        return Err("cold T8112 MCC has no qualified physical power/clock dependencies".into());
    }
    Ok(domains)
}

/// Pure source placement/RAM preflight; leaf constructors repeat their complete
/// register/layout/state checks before anything is installed on the bus.
fn geometry(
    controller: &MemoryController,
    cache: &MemoryCache,
    ram: &RegisteredSystemRam,
    programmed: amcc::Programmed,
) -> Result<(), String> {
    let [physical] = controller.apertures[..] else {
        return Err("cold T8112 AMCC requires its one original aperture".into());
    };
    if programmed[1..].iter().any(Option::is_some) {
        return Err("cold T8112 AMCC cannot discard a programmed non-CTRR-A lock group".into());
    }
    let dcs = physical
        .checked_add(DCS_OFFSET)
        .ok_or("cold T8112 aperture wraps")?;
    if !physical.is_multiple_of(PLANE_STRIDE)
        || !dcs.is_multiple_of(t8112::CHANNEL_STRIDE)
        || controller.layout.planes != PLANES
        || controller.layout.stride != PLANE_STRIDE
        || controller.layout.aperture_bytes != APERTURE_BYTES
        || cache.cache.shared != SHARED
        || cache.cache.broadcast != BROADCAST
        || cache.channels
            != (
                dcs,
                t8112::CHANNEL_STRIDE * t8112::CHANNELS as u64,
                t8112::CHANNELS,
            )
    {
        return Err("cold T8112 AMCC/cache/DCS geometry differs from the source profile".into());
    }
    let geometry = Geometry::new((cache.ptd.physical, ptd::PTD_BYTES), cache.ptd_updates)
        .map_err(String::from)?;
    if geometry.entries() != PTD_ENTRIES
        || cache.ptd_entries != PTD_ENTRIES
        || cache.ptd.ranges.is_empty()
        || cache.ptd.ranges.len() != cache.ptd.interrupts.len()
    {
        return Err("cold T8112 PTD source capacity or routes are incomplete".into());
    }
    let dcs_end = dcs
        .checked_add(cache.channels.1)
        .ok_or("cold T8112 DCS wraps")?;
    let ptd_end = cache
        .ptd
        .physical
        .checked_add(ptd::PTD_BYTES)
        .ok_or("cold T8112 PTD wraps")?;
    if physical < ptd_end && cache.ptd.physical < dcs_end {
        return Err("cold T8112 AMCC/DCS union overlaps PTD".into());
    }
    for (start, _, bytes) in ram.placements() {
        let end = start
            .checked_add(bytes as u64)
            .ok_or("cold canonical RAM wraps")?;
        if physical < end && start < dcs_end || cache.ptd.physical < end && start < ptd_end {
            return Err("cold T8112 MMIO overlaps its actual canonical RAM".into());
        }
    }
    for (start, bytes) in programmed.into_iter().flatten() {
        let end = start
            .checked_add(bytes)
            .ok_or("cold AMCC lock region wraps")?;
        if bytes == 0 || !start.is_multiple_of(1 << 14) || !bytes.is_multiple_of(1 << 14) {
            return Err("cold AMCC lock region is empty or not source-page aligned".into());
        }
        let mut cursor = start;
        for (source, _, bytes) in ram.placements() {
            let top = source
                .checked_add(bytes as u64)
                .ok_or("cold canonical RAM wraps")?;
            if source <= cursor && cursor < top {
                cursor = end.min(top);
            }
            if cursor == end {
                break;
            }
        }
        if cursor != end {
            return Err("cold AMCC lock region is outside the actual canonical RAM".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        machine::{
            Devices,
            soc::{ClockRole, PowerResource},
        },
        platform::apple::{
            bus::{Access, MmioDevice},
            interrupt::InterruptLatch,
            pmgr::{
                DomainState, PowerState,
                coverage::{Admission, Domain, DomainId},
            },
        },
    };
    use alloc::boxed::Box;

    const SUPPLY: u64 = 0x1000;
    fn id(device: u16) -> DomainId {
        DomainId { die: 0, device }
    }
    fn components() -> (
        MemoryController,
        MemoryCache,
        Arc<RegisteredSystemRam>,
        PowerStates,
    ) {
        // Reuse actual component fixtures for source geometry/RAM only. Their
        // ClampZero/ACTIVE initialization is NOT consumed by this cold plan.
        let (memory, cache) = EmptyResource::service_test_components();
        let controller = cache.source().clone();
        let descriptor = memory.descriptor().clone();
        let ram = Arc::clone(memory.registered_ram());
        let physical = controller.apertures[0] + descriptor.cache.shared.0;
        let states = PowerStates {
            blocks: vec![(SUPPLY, 24)],
            registers: vec![SUPPLY, SUPPLY + 8, SUPPLY + 16],
            domains: vec![
                Domain {
                    name: "parent".into(),
                    id: id(1),
                    address: Some(SUPPLY),
                    parents: [None; 4],
                },
                Domain {
                    name: "clock".into(),
                    id: id(2),
                    address: Some(SUPPLY + 8),
                    parents: [Some(id(1)), None, None, None],
                },
                Domain {
                    name: "power".into(),
                    id: id(3),
                    address: Some(SUPPLY + 16),
                    parents: [None; 4],
                },
            ],
            resources: vec![PowerResource {
                name: "/arm-io/mcc".into(),
                clocks: vec![id(2)],
                clock_role: ClockRole::Consumer,
                power: vec![id(3)],
                owner: Some(PowerOwner::Mmio(physical)),
                admission: Admission::Required,
            }],
            implicit: vec![],
        };
        (controller, descriptor, ram, states)
    }
    fn configuration() -> Configuration {
        Configuration::clear_software_controls(ZeroWayConfiguration::DisableArgument).unwrap()
    }
    fn placed(states: &PowerStates, initial: u8) -> AppleDevices {
        let mut devices = AppleDevices::new();
        let model = Pmgr::new(
            states
                .registers
                .iter()
                .map(|&address| PowerState { address, initial }),
        )
        .unwrap();
        let device = devices
            .bus
            .install(Box::new(model), &[(SUPPLY, 24, SUPPLY)])
            .unwrap();
        devices.pmgr = Some(device);
        devices
    }

    #[test]
    fn source_shared_reg0_resolves_power_clock_and_parent_without_granting_sinks() {
        let (controller, cache, ram, mut states) = components();
        let shared = controller.apertures[0] + cache.cache.shared.0;
        assert_eq!(
            power_domains(&states, shared).unwrap(),
            [SUPPLY, SUPPLY + 8, SUPPLY + 16]
        );
        states.resources[0].owner = Some(PowerOwner::Mmio(controller.apertures[0]));
        assert!(
            Plan::prepare_resources(
                &controller,
                &cache,
                &states,
                &ram,
                [None; 4],
                &configuration()
            )
            .is_err()
        );
        states.resources.clear();
        assert!(
            Plan::prepare_resources(
                &controller,
                &cache,
                &states,
                &ram,
                [None; 4],
                &configuration()
            )
            .is_err()
        );
    }

    #[test]
    fn only_disable_argument_and_live_matching_geometry_can_prepare() {
        assert!(Configuration::clear_software_controls(ZeroWayConfiguration::ClampZero).is_err());
        assert!(
            Configuration::clear_software_controls(ZeroWayConfiguration::ProviderDisabled).is_err()
        );
        let (controller, mut cache, ram, states) = components();
        let plan = Plan::prepare_resources(
            &controller,
            &cache,
            &states,
            &ram,
            [None; 4],
            &configuration(),
        )
        .unwrap();
        assert!(Arc::ptr_eq(&plan.ram, &ram));
        plan.validate(Some(&controller), Some(&cache)).unwrap();
        cache.channels.2 -= 1;
        assert!(plan.validate(Some(&controller), Some(&cache)).is_err());
        assert!(
            Plan::prepare_resources(
                &controller,
                &cache,
                &states,
                &ram,
                [None; 4],
                &configuration()
            )
            .is_err()
        );
    }

    #[test]
    fn actual_clock_gated_parent_initializes_both_real_sinks_paused_on_same_ram() {
        let (controller, cache, ram, states) = components();
        let plan = Plan::prepare_resources(
            &controller,
            &cache,
            &states,
            &ram,
            [None; 4],
            &configuration(),
        )
        .unwrap();
        let dcs = cache.channels.0;
        let shared = controller.apertures[0] + cache.cache.shared.0;
        let mut devices = placed(&states, pmgr::ACTIVE);
        let model = devices
            .bus
            .device_mut::<Pmgr>(devices.pmgr.unwrap())
            .unwrap();
        let mut latch = InterruptLatch::new();
        model
            .write(
                SUPPLY,
                Width::Word,
                u64::from(pmgr::CLOCK_GATED),
                &mut Access::new(0, 0, &mut latch),
            )
            .unwrap();
        plan.install(&mut devices).unwrap();
        let memory_id = devices.memory_publication.unwrap();
        let cache_id = devices.memory_controller.unwrap();
        assert_ne!(memory_id, cache_id);
        assert!(Arc::ptr_eq(
            devices
                .bus
                .device::<t8112::Prepared>(memory_id)
                .unwrap()
                .registered_ram(),
            &ram
        ));
        assert!(Arc::ptr_eq(
            devices
                .bus
                .device::<EmptyResource>(cache_id)
                .unwrap()
                .registered_ram(),
            &ram
        ));
        assert_eq!(
            devices
                .power_devices
                .iter()
                .filter(|entry| entry.physical == shared)
                .count(),
            2
        );
        assert!(devices.read(0, dcs + 0xec8, 4, 0).is_err());
        assert_eq!(
            devices
                .bus
                .device::<Pmgr>(devices.pmgr.unwrap())
                .unwrap()
                .domain_state(SUPPLY),
            Some(DomainState {
                power: pmgr::CLOCK_GATED,
                disabled: false,
                reset: false
            })
        );
    }

    #[test]
    fn absent_domain_reset_or_late_overlap_cannot_publish_partial_memory_owners() {
        let (controller, cache, ram, states) = components();
        let prepare = || {
            Plan::prepare_resources(
                &controller,
                &cache,
                &states,
                &ram,
                [None; 4],
                &configuration(),
            )
            .unwrap()
        };
        let mut missing = AppleDevices::new();
        assert!(prepare().install(&mut missing).is_err());
        assert!(missing.memory_controller.is_none() && missing.memory_publication.is_none());
        let mut incomplete = AppleDevices::new();
        let model = Pmgr::new([SUPPLY + 8, SUPPLY + 16].map(|address| PowerState {
            address,
            initial: pmgr::ACTIVE,
        }))
        .unwrap();
        let device = incomplete
            .bus
            .install(Box::new(model), &[(SUPPLY, 24, SUPPLY)])
            .unwrap();
        incomplete.pmgr = Some(device);
        assert!(prepare().install(&mut incomplete).is_err());
        assert!(incomplete.memory_controller.is_none() && incomplete.memory_publication.is_none());
        let mut devices = placed(&states, pmgr::ACTIVE);
        let model = devices
            .bus
            .device_mut::<Pmgr>(devices.pmgr.unwrap())
            .unwrap();
        model.bind_lifecycle(SUPPLY).unwrap();
        let mut latch = InterruptLatch::new();
        model
            .write(
                SUPPLY,
                Width::Word,
                0x8000_040f,
                &mut Access::new(0, 0, &mut latch),
            )
            .unwrap();
        assert!(prepare().install(&mut devices).is_err());
        assert!(devices.memory_controller.is_none() && devices.memory_publication.is_none());
        let mut overlapping = placed(&states, pmgr::ACTIVE);
        let (memory, _) = EmptyResource::service_test_components();
        let binding = memory.bindings();
        let existing = overlapping.bus.install(Box::new(memory), &binding).unwrap();
        assert!(prepare().install(&mut overlapping).is_err());
        assert_eq!(
            overlapping
                .bus
                .route(cache.channels.0, Width::Word)
                .unwrap()
                .0,
            existing
        );
        assert!(
            overlapping.memory_controller.is_none() && overlapping.memory_publication.is_none()
        );
    }
}
