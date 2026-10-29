//! Cold native T8112 memory placement over the loader's registered RAM.
//! Software backing is declared here. Switched inputs come from the
//! PMGR; an explicitly certified input-free AP frontend owns its software state.
//! Neither case nor clear words certify Apple hardware/private PMP readiness.
use super::super::AppleDevices;
use super::super::memory_resources::t8112;
use crate::Result;
use crate::platform::apple::pmgr;
use crate::platform::apple::pmgr::Pmgr;
use stela_contracts::refuse;
use stela_soc_data::board::Board;
use stela_soc_data::board::MemoryCache;
use stela_soc_data::board::MemoryController;
use stela_soc_data::board::PowerOwner;
use stela_soc_data::board::PowerStates;

use alloc::{sync::Arc, vec, vec::Vec};
use stela_contracts::Chip;
use stela_contracts::bus::LifecycleState;
use stela_contracts::bus::Width;
use stela_engine::memory::RegisteredSystemRam;
use stela_soc_data::pmgr::coverage;
use stela_soc_data::pmgr::coverage::Consumer;
use stela_soc_data::pmgr::coverage::LifecycleSinks;
use stela_soc_data::ptd::Geometry;
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
    pub fn clear_software_controls(selection: ZeroWayConfiguration) -> Result<Self> {
        if selection != ZeroWayConfiguration::DisableArgument {
            return Err(refuse!(
                "cold T8112 memory requires the source-checked -disable_mcc policy"
            ));
        }
        Ok(Self { selection })
    }
}

/// Keeps the same RAM and live source descriptors before any input is moved
/// into a bus owner. The whole source graph remains independently accounted.
pub struct Plan {
    controller: MemoryController,
    cache: MemoryCache,
    source_power: PowerStates,
    lifecycle: LifecycleInput,
    ram: Arc<RegisteredSystemRam>,
    programmed: stela_soc_data::amcc::Programmed,
    configuration: Configuration,
}
// Private constructors prevent a missing/failed dependency lookup from granting
// an unswitched lifecycle. The certificate keeps the backing identity.
enum LifecycleInput {
    Switched(Vec<u64>),
    UnswitchedApFrontend(UnswitchedApFrontend),
}
struct UnswitchedApFrontend {
    generation: u64,
    shared: u64,
    ram: Arc<RegisteredSystemRam>,
}
#[derive(Clone, Copy)]
enum LifecyclePolicy {
    RequireDomains,
    SourceQualifiedApFrontend,
}
impl Plan {
    pub fn prepare(
        board: &Board,
        ram: &Arc<RegisteredSystemRam>,
        programmed: stela_soc_data::amcc::Programmed,
        configuration: &Configuration,
    ) -> Result<Self> {
        Self::prepare_board(
            board,
            ram,
            programmed,
            configuration,
            LifecyclePolicy::RequireDomains,
        )
    }

    /// Selects a switched lifecycle or an explicitly input-free Stela AP
    /// frontend from the complete source graph, never from a failed lookup.
    /// This does not check private Apple MCC/PMP power transitions.
    pub fn prepare_ap_frontend(
        board: &Board,
        ram: &Arc<RegisteredSystemRam>,
        programmed: stela_soc_data::amcc::Programmed,
        configuration: &Configuration,
    ) -> Result<Self> {
        Self::prepare_board(
            board,
            ram,
            programmed,
            configuration,
            LifecyclePolicy::SourceQualifiedApFrontend,
        )
    }

    fn prepare_board(
        board: &Board,
        ram: &Arc<RegisteredSystemRam>,
        programmed: stela_soc_data::amcc::Programmed,
        configuration: &Configuration,
        policy: LifecyclePolicy,
    ) -> Result<Self> {
        if board.cpus.chip != Chip::AppleM2 {
            return Err(refuse!(
                "cold T8112 memory does not qualify this CPU family"
            ));
        }
        Self::prepare_resources_with_policy(
            board
                .memory_controller
                .as_ref()
                .ok_or(refuse!("cold T8112 memory has no live AMCC descriptor"))?,
            board
                .memory_cache
                .as_ref()
                .ok_or(refuse!("cold T8112 memory has no live MCC descriptor"))?,
            board
                .power_states
                .as_ref()
                .ok_or(refuse!("cold T8112 memory has no full source power graph"))?,
            ram,
            programmed,
            configuration,
            policy,
        )
    }

    #[cfg(test)]
    fn prepare_resources(
        controller: &MemoryController,
        cache: &MemoryCache,
        states: &PowerStates,
        ram: &Arc<RegisteredSystemRam>,
        programmed: stela_soc_data::amcc::Programmed,
        configuration: &Configuration,
    ) -> Result<Self> {
        Self::prepare_resources_with_policy(
            controller,
            cache,
            states,
            ram,
            programmed,
            configuration,
            LifecyclePolicy::RequireDomains,
        )
    }

    fn prepare_resources_with_policy(
        controller: &MemoryController,
        cache: &MemoryCache,
        states: &PowerStates,
        ram: &Arc<RegisteredSystemRam>,
        programmed: stela_soc_data::amcc::Programmed,
        configuration: &Configuration,
        policy: LifecyclePolicy,
    ) -> Result<Self> {
        if configuration.selection != ZeroWayConfiguration::DisableArgument {
            return Err(refuse!(
                "cold T8112 memory cannot infer an empty cache configuration"
            ));
        }
        geometry(controller, cache, ram, programmed)?;
        let shared = controller.apertures[0] + cache.cache.shared.0;
        let domains = power_domains(states, shared)?;
        let lifecycle = if domains.is_empty() {
            if matches!(policy, LifecyclePolicy::RequireDomains) {
                return Err(refuse!(
                    "cold T8112 MCC has no qualified physical power/clock dependencies"
                ));
            }
            LifecycleInput::UnswitchedApFrontend(UnswitchedApFrontend::certify(
                states, shared, ram,
            )?)
        } else {
            LifecycleInput::Switched(domains)
        };
        Ok(Self {
            controller: controller.clone(),
            cache: cache.clone(),
            source_power: states.clone(),
            lifecycle,
            ram: Arc::clone(ram),
            programmed,
            configuration: *configuration,
        })
    }

    /// Mount preflight against its live board, before consuming inputs.
    pub fn validate(
        &self,
        controller: Option<&MemoryController>,
        cache: Option<&MemoryCache>,
    ) -> Result<()> {
        if controller != Some(&self.controller) || cache != Some(&self.cache) {
            return Err(refuse!(
                "cold T8112 memory differs from the actual live board descriptors"
            ));
        }
        Ok(())
    }

    /// The mount's later lifecycle connection must use this SAME source graph,
    /// including admission, ancestors and aliases, not only equal apertures.
    pub fn validate_power(&self, states: Option<&PowerStates>) -> Result<()> {
        if states != Some(&self.source_power) {
            return Err(refuse!(
                "cold T8112 memory differs from the actual live power dependency graph"
            ));
        }
        Ok(())
    }

    /// Call after PMGR placement and before power connection/display aliases.
    /// All guest/native/DMA publishers remain excluded throughout cold setup.
    pub fn install(self, devices: &mut AppleDevices) -> Result<()> {
        if devices.power_configured
            || devices.memory_controller.is_some()
            || devices.memory_publication.is_some()
        {
            return Err(refuse!(
                "cold T8112 memory requires an unconnected unoccupied memory mount"
            ));
        }
        let pmgr_id = devices
            .pmgr
            .ok_or(refuse!("cold T8112 memory requires the actual placed PMGR"))?;
        let pmgr = devices
            .bus
            .device::<Pmgr>(pmgr_id)
            .ok_or(refuse!("cold T8112 memory has a foreign PMGR owner"))?;
        if self
            .source_power
            .registers
            .iter()
            .any(|&address| pmgr.domain_state(address).is_none())
        {
            return Err(refuse!(
                "cold T8112 memory PMGR omits part of the retained source graph"
            ));
        }
        let lifecycle = match &self.lifecycle {
            LifecycleInput::Switched(domains) => {
                let states = domains
                    .iter()
                    .map(|&address| {
                        if devices.bus.route(address, Width::Word).ok() != Some((pmgr_id, address))
                        {
                            return Err(refuse!(
                                "MCC lifecycle domain {address:#x} has no actual PMGR route",
                                address
                            ));
                        }
                        pmgr.domain_state(address).ok_or_else(|| {
                            refuse!(
                                "MCC lifecycle domain {address:#x} has no actual PMGR state",
                                address
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                // Retention declares that this software backing keeps data on gating.
                // Every other input is the current controller word, never ACTIVE
                // substituted for an absent domain or an asserted reset.
                LifecycleState {
                    powered: states.iter().all(|state| state.power != pmgr::POWER_GATED),
                    clocked: states.iter().all(|state| state.power == pmgr::ACTIVE),
                    quiesced: states.iter().any(|state| state.disabled),
                    reset: states.iter().any(|state| state.reset),
                    retention: true,
                }
            }
            LifecycleInput::UnswitchedApFrontend(certificate) => {
                certificate.initialize(&self.controller, &self.cache, &self.ram)?
            }
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
        )?;
        let locks = memory.initialize_amcc_locks(self.controller, self.programmed, lifecycle)?;
        let cache = EmptyResource::initialized(
            locks,
            self.configuration.selection,
            SoftwareImage::zeroed_control_image(),
        )?;
        devices.add_t8112_empty_memory_resources(memory, cache)
    }
}

/// Reuse the same ancestor/alias/implicit-power closure as powerconnect.
/// No sinks are claimed complete while deriving these metadata dependencies.
fn power_domains(states: &PowerStates, shared: u64) -> Result<Vec<u64>> {
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
        return Err(refuse!(
            "cold T8112 MCC shared reg0 has no positively placed source power resource"
        ));
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
        .map_err(|error| refuse!("cold T8112 source power graph: {error}", ?error))?;
    if coverage.len() != states.registers.len()
        || coverage
            .iter()
            .any(|domain| !states.registers.contains(&domain.address))
    {
        return Err(refuse!(
            "cold T8112 source graph differs from its complete physical register set"
        ));
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
    Ok(domains)
}

impl UnswitchedApFrontend {
    fn certify(states: &PowerStates, shared: u64, ram: &Arc<RegisteredSystemRam>) -> Result<Self> {
        // Original 26A434 J473 MCC/arm-io and shared-reg error-handler alias
        // have no consumer gate arrays. arm-io gate functions are provider
        // recipes; private MCC dynamic gating remains a separate protocol.
        // See ignored mcc-unswitched-r1 for exact ADT/AP-driver coordinates.
        // power_domains has already validated placement and complete graph
        // closure. Require literal absence of inputs in EVERY same-owner alias,
        // including implicit power; unresolved/virtual inputs are not absence.
        if !power_domains(states, shared)?.is_empty() {
            return Err(refuse!("unswitched AP frontend has physical PMGR inputs"));
        }
        let power = states.power_requirements()?;
        for (id, resource) in states.resources.iter().enumerate() {
            if resource.owner == Some(PowerOwner::Mmio(shared))
                && (!resource.activated_clocks().is_empty() || !power[id].is_empty())
            {
                return Err(refuse!(
                    "unswitched AP frontend has source clock/power inputs"
                ));
            }
        }
        let generation = ram.generation().map_err(|status| {
            refuse!("unswitched AP frontend RAM is not live: {status}", ?status)
        })?;
        Ok(Self {
            generation,
            shared,
            ram: Arc::clone(ram),
        })
    }

    fn initialize(
        &self,
        controller: &MemoryController,
        cache: &MemoryCache,
        ram: &Arc<RegisteredSystemRam>,
    ) -> Result<LifecycleState> {
        if self.shared != controller.apertures[0] + cache.cache.shared.0
            || !Arc::ptr_eq(&self.ram, ram)
        {
            return Err(refuse!(
                "unswitched AP frontend differs from its certified backing"
            ));
        }
        if ram.generation().map_err(|status| {
            refuse!("unswitched AP frontend RAM is not live: {status}", ?status)
        })? != self.generation
        {
            return Err(refuse!("unswitched AP frontend RAM generation changed"));
        }
        // State of the newly owned Stela RAM frontend with no AP PMGR inputs.
        // This is NOT an observed Apple MCC state or private power-protocol ACK.
        Ok(LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: true,
        })
    }
}

/// Pure source placement/RAM preflight; leaf constructors repeat their complete
/// register/layout/state checks before anything is installed on the bus.
fn geometry(
    controller: &MemoryController,
    cache: &MemoryCache,
    ram: &RegisteredSystemRam,
    programmed: stela_soc_data::amcc::Programmed,
) -> Result<()> {
    let [physical] = controller.apertures[..] else {
        return Err(refuse!(
            "cold T8112 AMCC requires its one original aperture"
        ));
    };
    if programmed[1..].iter().any(Option::is_some) {
        return Err(refuse!(
            "cold T8112 AMCC cannot discard a programmed non-CTRR-A lock group"
        ));
    }
    let dcs = physical
        .checked_add(DCS_OFFSET)
        .ok_or(refuse!("cold T8112 aperture wraps"))?;
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
        return Err(refuse!(
            "cold T8112 AMCC/cache/DCS geometry differs from the source profile"
        ));
    }
    let geometry = Geometry::new(
        (cache.ptd.physical, stela_soc_data::ptd::PTD_BYTES),
        cache.ptd_updates,
    )?;
    if geometry.entries() != PTD_ENTRIES
        || cache.ptd_entries != PTD_ENTRIES
        || cache.ptd.ranges.is_empty()
        || cache.ptd.ranges.len() != cache.ptd.interrupts.len()
    {
        return Err(refuse!(
            "cold T8112 PTD source capacity or routes are incomplete"
        ));
    }
    let dcs_end = dcs
        .checked_add(cache.channels.1)
        .ok_or(refuse!("cold T8112 DCS wraps"))?;
    let ptd_end = cache
        .ptd
        .physical
        .checked_add(stela_soc_data::ptd::PTD_BYTES)
        .ok_or(refuse!("cold T8112 PTD wraps"))?;
    if physical < ptd_end && cache.ptd.physical < dcs_end {
        return Err(refuse!("cold T8112 AMCC/DCS union overlaps PTD"));
    }
    for (start, _, bytes) in ram.placements() {
        let end = start
            .checked_add(bytes as u64)
            .ok_or(refuse!("cold canonical RAM wraps"))?;
        if physical < end && start < dcs_end || cache.ptd.physical < end && start < ptd_end {
            return Err(refuse!("cold T8112 MMIO overlaps its actual canonical RAM"));
        }
    }
    for (start, bytes) in programmed.into_iter().flatten() {
        let end = start
            .checked_add(bytes)
            .ok_or(refuse!("cold AMCC lock region wraps"))?;
        if bytes == 0 || !start.is_multiple_of(1 << 14) || !bytes.is_multiple_of(1 << 14) {
            return Err(refuse!(
                "cold AMCC lock region is empty or not source-page aligned"
            ));
        }
        let mut cursor = start;
        for (source, _, bytes) in ram.placements() {
            let top = source
                .checked_add(bytes as u64)
                .ok_or(refuse!("cold canonical RAM wraps"))?;
            if source <= cursor && cursor < top {
                cursor = end.min(top);
            }
            if cursor == end {
                break;
            }
        }
        if cursor != end {
            return Err(refuse!(
                "cold AMCC lock region is outside the actual canonical RAM"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
