//! Cold native T8112 memory placement over the loader's registered RAM.
//! Software backing is declared here. Switched inputs come from the
//! PMGR; an input-free AP frontend owns its software state.
//! Neither case nor clear words certify Apple hardware/private PMP readiness.
use super::super::AppleDevices;
use super::super::memory_resources::cold;
use super::super::memory_resources::t8112;
use crate::Result;
use stela_contracts::refusal::Within;
use stela_contracts::refuse;
use stela_soc_data::board::Board;
use stela_soc_data::board::MemoryCache;
use stela_soc_data::board::MemoryController;
use stela_soc_data::board::PowerStates;

use alloc::{sync::Arc, vec};
use stela_contracts::Chip;
use stela_engine::memory::RegisteredSystemRam;
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
    inputs: cold::Inputs,
    ram: cold::PinnedRam,
    programmed: stela_soc_data::amcc::Programmed,
    configuration: Configuration,
}
impl Plan {
    /// Takes a switched lifecycle, or an input-free Stela AP frontend, from
    /// the complete source graph, never from a failed lookup. Original
    /// 26A434 J473 MCC/arm-io and the shared-reg error-handler alias have no
    /// consumer gate arrays: arm-io gate functions are provider recipes and
    /// private MCC dynamic gating is a separate protocol (ignored
    /// mcc-unswitched-r1 holds the exact ADT/AP-driver coordinates). This
    /// does not check private Apple MCC/PMP power transitions.
    pub fn prepare_ap_frontend(
        board: &Board,
        ram: &Arc<RegisteredSystemRam>,
        programmed: stela_soc_data::amcc::Programmed,
        configuration: &Configuration,
    ) -> Result<Self> {
        if board.cpus.chip != Chip::AppleM2 {
            return Err(refuse!(
                "cold T8112 memory does not qualify this CPU family"
            ));
        }
        Self::prepare_resources(
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
        )
    }

    fn prepare_resources(
        controller: &MemoryController,
        cache: &MemoryCache,
        states: &PowerStates,
        ram: &Arc<RegisteredSystemRam>,
        programmed: stela_soc_data::amcc::Programmed,
        configuration: &Configuration,
    ) -> Result<Self> {
        if configuration.selection != ZeroWayConfiguration::DisableArgument {
            return Err(refuse!(
                "cold T8112 memory cannot infer an empty cache configuration"
            ));
        }
        let extents = geometry(controller, cache, programmed)?;
        let pinned = cold::PinnedRam::new(ram)
            .and_then(|pinned| {
                cold::check_mmio(ram, &extents)?;
                cold::check_locks(ram, &controller.layout, programmed)?;
                Ok(pinned)
            })
            .within(|| refuse!("cold T8112 memory placement"))?;
        // The lifecycle identity is the MCC's shared reg0.
        let inputs = cold::Inputs::resolve(
            states,
            controller.apertures[0] + cache.cache.shared.0,
            &extents,
        )
        .within(|| refuse!("cold T8112 lifecycle inputs"))?;
        Ok(Self {
            controller: controller.clone(),
            cache: cache.clone(),
            source_power: states.clone(),
            inputs,
            ram: pinned,
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
        self.ram.check()
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
        let lifecycle = self
            .ram
            .check()
            .and_then(|()| self.inputs.sample(devices, &self.source_power))
            .within(|| refuse!("cold T8112 memory lifecycle"))?;
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
            self.ram.into_live()?,
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

/// Pure source placement preflight, returning the owned MMIO extents: the
/// AMCC/DCS union and the PTD bank. Leaf constructors repeat their complete
/// register/layout/state checks before anything is installed on the bus.
fn geometry(
    controller: &MemoryController,
    cache: &MemoryCache,
    programmed: stela_soc_data::amcc::Programmed,
) -> Result<[(u64, u64); 2]> {
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
    Ok([
        (physical, DCS_OFFSET + cache.channels.1),
        (cache.ptd.physical, stela_soc_data::ptd::PTD_BYTES),
    ])
}

#[cfg(test)]
mod tests;
