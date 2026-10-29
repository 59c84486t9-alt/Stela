//! Cold direct T6000 MCC/AMCC/PTD over the same canonical RAM.
//!
//! Original26A434 J314s ADT SHA25644fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad
//! has no MCC clock/power arrays; arm-io gate functions are provider recipes.
//! The separate PMP ASC has gates69/70; neither those inputs nor T8112's MC
//! quota protocol describe this direct AP memory frontend. Original mac13j
//! startup2e45ff0..2e46cec saves opaque channel control words unchanged; mode
//! selection2e48d74..2e48f28 restores them or writes the first alternate word.
//! Zero initial controls/explicit weights are Stela software policy, not Apple
//! reset, capacity, timing or completed DRAM programming. Source cacheless
//! disable_mcc command/waiter evidence is held in t6000-mcc-backend-20261021-1.
use super::Prepared;
use super::cold;
use super::mcc;
use crate::Result;
use crate::machine::apple::AppleDevices;
use crate::platform::apple::ptd;
use alloc::{sync::Arc, vec::Vec};
use stela_contracts::Chip;
use stela_contracts::refusal::Within;
use stela_contracts::refuse;
use stela_engine::memory::RegisteredSystemRam;
use stela_soc_data::board::Board;
use stela_soc_data::board::DirectMemoryCache;
use stela_soc_data::board::MemoryController;
use stela_soc_data::board::PowerStates;

/// Entire new-software control image, independent of RAM capacity and opaque
/// DT config-data/alternate dramcfg-data. Every weight is an explicit policy.
/// Caller must publish the source-supported real -disable_mcc boot argument
/// before original entry; constructing this cacheless resource proves no flag.
#[derive(Clone)]
pub struct Configuration {
    image: mcc::Configuration,
}
impl Configuration {
    pub fn zeroed_control_image(apertures: usize, weights: [u8; 32]) -> Result<Self> {
        mcc::Configuration::zeroed_control_image(apertures, weights).map(|image| Self { image })
    }
    /// Explicit caller-owned full initial words. No DT field is interpreted as
    /// density, and no saved word is silently replaced by an alternate mode.
    pub fn declared_control_image(controls: Vec<[u32; 4]>, weights: [u8; 32]) -> Result<Self> {
        let mut result = Self::zeroed_control_image(controls.len(), weights)?;
        result.image.dram = controls;
        Ok(result)
    }
    pub fn controls(&self) -> &[[u32; 4]] {
        &self.image.dram
    }
    pub fn weights(&self) -> &[u8; 32] {
        &self.image.weights
    }
}

/// One source-checked cold owner; private fields prevent callers from supplying
/// an ON/ready Boolean, replacing the source graph or borrowing foreign RAM.
pub struct Plan {
    controller: MemoryController,
    direct: DirectMemoryCache,
    power: PowerStates,
    inputs: cold::Inputs,
    ram: cold::PinnedRam,
    programmed: stela_soc_data::amcc::Programmed,
    configuration: Configuration,
}
impl Plan {
    pub fn prepare_ap_frontend(
        board: &Board,
        ram: &Arc<RegisteredSystemRam>,
        programmed: stela_soc_data::amcc::Programmed,
        configuration: &Configuration,
    ) -> Result<Self> {
        if board.cpus.chip != Chip::AppleM1 || board.memory_cache.is_some() {
            return Err(refuse!(
                "cold T6000 direct memory requires its own source family"
            ));
        }
        Self::prepare_resources(
            board
                .memory_controller
                .as_ref()
                .ok_or(refuse!("cold T6000 has no actual AMCC descriptor"))?,
            board
                .direct_memory_cache
                .as_ref()
                .ok_or(refuse!("cold T6000 has no direct MCC descriptor"))?,
            board
                .power_states
                .as_ref()
                .ok_or(refuse!("cold T6000 has no complete source power graph"))?,
            ram,
            programmed,
            configuration,
        )
    }
    fn prepare_resources(
        controller: &MemoryController,
        direct: &DirectMemoryCache,
        power: &PowerStates,
        ram: &Arc<RegisteredSystemRam>,
        programmed: stela_soc_data::amcc::Programmed,
        configuration: &Configuration,
    ) -> Result<Self> {
        geometry(controller, direct)?;
        let extents = extents(direct);
        let pinned = cold::PinnedRam::new(ram)
            .and_then(|pinned| {
                cold::check_mmio(ram, &extents)?;
                cold::check_locks(ram, &controller.layout, programmed)?;
                Ok(pinned)
            })
            .within(|| refuse!("cold T6000 memory placement"))?;
        if configuration.controls().len() != direct.apertures.len() {
            return Err(refuse!(
                "cold T6000 requires all channel control words for every actual aperture"
            ));
        }
        // The lifecycle identity is the first direct controller aperture.
        let inputs = cold::Inputs::resolve(power, direct.apertures[0], &extents)
            .within(|| refuse!("cold T6000 lifecycle inputs"))?;
        Ok(Self {
            controller: controller.clone(),
            direct: direct.clone(),
            power: power.clone(),
            inputs,
            ram: pinned,
            programmed,
            configuration: configuration.clone(),
        })
    }
    /// Before consuming mount inputs, require the complete live source
    /// descriptors. Parsing alone never admits canonical memory execution.
    pub fn validate(
        &self,
        controller: Option<&MemoryController>,
        direct: Option<&DirectMemoryCache>,
    ) -> Result<()> {
        if controller != Some(&self.controller) || direct != Some(&self.direct) {
            return Err(refuse!(
                "cold T6000 differs from the actual live memory descriptors"
            ));
        }
        self.ram.check()
    }
    pub fn validate_power(&self, power: Option<&PowerStates>) -> Result<()> {
        if power != Some(&self.power) {
            return Err(refuse!(
                "cold T6000 differs from the complete source power graph"
            ));
        }
        Ok(())
    }
    pub fn registered_ram(&self) -> &Arc<RegisteredSystemRam> {
        self.ram.ram()
    }
    pub fn descriptor(&self) -> &DirectMemoryCache {
        &self.direct
    }
    pub const fn requires_disable_mcc(&self) -> bool {
        true
    }
    /// After PMGR placement, before display aliases/powerconnect/first guest.
    /// All physical guest/native/DMA writers remain excluded during this cold
    /// construction. Later drains/clears require the real live canonical hold;
    /// a successful placement does not provide that hold or settle requests.
    pub fn install(self, devices: &mut AppleDevices) -> Result<()> {
        if devices.power_configured
            || devices.memory_controller.is_some()
            || devices.memory_publication.is_some()
        {
            return Err(refuse!(
                "cold T6000 requires an unoccupied unconnected memory mount"
            ));
        }
        let lifecycle = self
            .ram
            .check()
            .and_then(|()| self.inputs.sample(devices, &self.power))
            .within(|| refuse!("cold T6000 memory lifecycle"))?;
        let physical = self.inputs.owner();
        let (owner, _) = Prepared::new_local(
            self.direct,
            &self.controller,
            self.programmed,
            self.configuration.image,
            lifecycle,
        )?;
        // new_local keeps the SAME notification receiver in owner;
        // no callback/service/IRQ binding is manufactured or discarded here.
        let owner = owner.with_registered_ram(self.ram.into_live()?)?;
        devices.add_memory_resources(owner)?;
        let id = devices
            .memory_controller
            .ok_or(refuse!("cold T6000 lost the installed joint owner"))?;
        devices.register_power_device(physical, id, true)
    }
}

/// Every controller aperture and the PTD bank.
fn extents(direct: &DirectMemoryCache) -> Vec<(u64, u64)> {
    direct
        .apertures
        .iter()
        .map(|&start| (start, mcc::APERTURE_BYTES))
        .chain([(direct.ptd.physical, stela_soc_data::ptd::PTD_BYTES)])
        .collect()
}
fn geometry(controller: &MemoryController, direct: &DirectMemoryCache) -> Result<()> {
    direct.validate(controller)?;
    if direct.ptd_entries != ptd::transport::notifications::NativeProfile::T6000.entries() as usize
        || direct.ptd_updates.1 != 0xc00
        || controller.layout.cache_status
            != Some(stela_soc_data::amcc::Register {
                offset: 0x1c00,
                mask: 0x1f,
                value: 0,
            })
    {
        return Err(refuse!(
            "cold T6000 requires its source PTD geometry and shared way-command status"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
