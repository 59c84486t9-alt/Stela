//! Source-kept T602x cold placement over the canonical RAM owner.
//!
//! Original26A434 all8 MCC reg0 is the PTD bank; reg2 starts the controller
//! apertures (mac14j KC file2ecb674/2ecc068). The original trees have no MCC
//! clock/power arrays. PMP ASC gates0x49/0x4a belong to its separate owner.
//! Parent provider recipes, absent arrays and caller booleans are never
//! controller/PMP/cache completion. Full source PowerStates remain held.
use super::Configuration;
use super::MemoryController;
use super::Prepared;
use super::T6020Memory;
use crate::Result;
use crate::machine::AppleDevices;
use crate::machine::memory_resources::cold;
use alloc::sync::Arc;
use stela_contracts::refusal::Within;
use stela_contracts::refuse;
use stela_engine::memory::RegisteredSystemRam;
use stela_soc_data::board::PowerStates;

/// Private inputs keep source identities. Construction supplies no
/// lifecycle status, native topology, firmware PTD service or cache grant.
pub struct Plan {
    controller: MemoryController,
    descriptor: T6020Memory,
    power: PowerStates,
    inputs: cold::Inputs,
    ram: cold::PinnedRam,
    programmed: stela_soc_data::amcc::Programmed,
    configuration: Configuration,
}

impl Plan {
    /// Keep independently decoded original descriptors. Source admission
    /// must already positively associate MCC reg0 with the joint owner;
    /// a hidden/unmodeled owner=None resource cannot satisfy this requirement.
    pub fn prepare_ap_frontend(
        controller: &MemoryController,
        descriptor: &T6020Memory,
        power: &PowerStates,
        ram: &Arc<RegisteredSystemRam>,
        programmed: stela_soc_data::amcc::Programmed,
        configuration: &Configuration,
    ) -> Result<Self> {
        descriptor.validate(controller)?;
        let pinned = super::placed_ram(descriptor, controller, programmed, ram)
            .within(|| refuse!("cold T602x memory placement"))?;
        let layout = descriptor.layout()?;
        if configuration.channels.len() != layout.channels()
            || configuration.mcc_gating.len() != layout.apertures()
        {
            return Err(refuse!(
                "cold T602x configuration omits actual controller channels"
            ));
        }
        // Lifecycle identity follows the original node's first reg, the PTD
        // bank, not its first direct controller and not the separate PMP ASC.
        let inputs =
            cold::Inputs::resolve(power, descriptor.ptd.physical, &super::extents(descriptor))
                .within(|| refuse!("cold T602x lifecycle inputs"))?;
        Ok(Self {
            controller: controller.clone(),
            descriptor: descriptor.clone(),
            power: power.clone(),
            inputs,
            ram: pinned,
            programmed,
            configuration: configuration.clone(),
        })
    }

    /// Equality covers the full original graph/admission/alias inventory and
    /// every physical memory owner, before consuming any host mount inputs.
    pub fn validate(
        &self,
        controller: Option<&MemoryController>,
        descriptor: Option<&T6020Memory>,
        power: Option<&PowerStates>,
    ) -> Result<()> {
        if controller != Some(&self.controller)
            || descriptor != Some(&self.descriptor)
            || power != Some(&self.power)
        {
            return Err(refuse!(
                "cold T602x differs from its complete retained source resources"
            ));
        }
        self.ram.check()
    }
    pub fn registered_ram(&self) -> &Arc<RegisteredSystemRam> {
        self.ram.ram()
    }
    pub fn descriptor(&self) -> &T6020Memory {
        &self.descriptor
    }
    pub fn lifecycle_physical(&self) -> u64 {
        self.inputs.owner()
    }
    pub fn source_resource_indices(&self) -> &[usize] {
        self.inputs.resources()
    }
    pub fn input_domains(&self) -> &[u64] {
        self.inputs.domains()
    }

    /// After PMGR placement and before complete power connection, install
    /// one joint owner and register its source reg0 lifecycle identity. The caller
    /// keeps stopped native/all-writer ownership through this cold placement.
    /// No controller request is retired and no PTD publication service is made.
    /// Unrelated PMP gates keep their state and are never sampled as MCC
    /// readiness.
    pub fn install(self, devices: &mut AppleDevices) -> Result<()> {
        if devices.power_configured
            || devices.memory_controller.is_some()
            || devices.memory_publication.is_some()
        {
            return Err(refuse!(
                "cold T602x requires an unoccupied unconnected memory mount"
            ));
        }
        let lifecycle = self
            .ram
            .check()
            .and_then(|()| self.inputs.sample(devices, &self.power))
            .within(|| refuse!("cold T602x memory lifecycle"))?;
        let physical = self.lifecycle_physical();
        let owner = Prepared::new(
            self.descriptor,
            self.controller,
            self.programmed,
            self.configuration,
            lifecycle,
            self.ram.into_live()?,
        )?;
        devices.add_t6020_memory_resources(owner)?;
        let id = devices
            .memory_controller
            .ok_or(refuse!("cold T602x lost its actual installed owner"))?;
        // The ID is newly installed, the owner has a Lifecycle hook,
        // and the exclusive borrow kept power_configured=false above.
        devices.register_power_device(physical, id, true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pmgr;
    use crate::pmgr::Pmgr;
    use alloc::{boxed::Box, vec};
    use stela_contracts::bus::Width;
    use stela_soc_data::board::PowerOwner;
    use {
        crate::pmgr::PowerState, stela_contracts::bus::Access,
        stela_contracts::interrupt::InterruptLatch, stela_soc_data::board::ClockRole,
        stela_soc_data::board::PowerResource, stela_soc_data::pmgr::coverage::Admission,
        stela_soc_data::pmgr::coverage::Domain, stela_soc_data::pmgr::coverage::DomainId,
    };
    const SUPPLY: u64 = 0x1000;
    fn id(device: u16) -> DomainId {
        DomainId { die: 0, device }
    }
    fn domain(device: u16, address: Option<u64>, parents: [Option<DomainId>; 4]) -> Domain {
        Domain {
            name: format!("authored-input-{device}"),
            id: id(device),
            address,
            parents,
        }
    }
    fn components(
        count: usize,
    ) -> (
        MemoryController,
        T6020Memory,
        Arc<RegisteredSystemRam>,
        PowerStates,
        Configuration,
    ) {
        // Only source descriptors and the cfg(test) RAM reservation are reused.
        // The earlier fixture's declared lifecycle is never a Plan input.
        let fixture = super::super::tests::fixture_owner(count);
        let descriptor = fixture.descriptor.clone();
        let configuration = Configuration::clear_software_controls(descriptor.layout().unwrap());
        let power = stela_soc_data::board::fixture_support::power_states_fixture(
            vec![(SUPPLY, 0x100)],
            vec![SUPPLY],
            vec![domain(1, Some(SUPPLY), [None; 4])],
            vec![PowerResource {
                name: "authored-source-mcc".into(),
                clocks: vec![],
                clock_role: ClockRole::Consumer,
                power: vec![],
                owner: Some(PowerOwner::Mmio(descriptor.ptd.physical)),
                admission: Admission::Required,
            }],
        );
        (
            fixture.source_locks.clone(),
            descriptor,
            Arc::clone(fixture.ram.ram()),
            power,
            configuration,
        )
    }
    fn placed(power: &PowerStates, initial: u8, correct_route: bool) -> AppleDevices {
        let mut devices = AppleDevices::new();
        let model = Pmgr::new(
            power
                .registers
                .iter()
                .map(|&address| PowerState { address, initial }),
        )
        .unwrap();
        devices.pmgr = Some(
            devices
                .bus
                .install(
                    Box::new(model),
                    &[(SUPPLY, 0x100, if correct_route { SUPPLY } else { 0 })],
                )
                .unwrap(),
        );
        devices
    }
    fn plan(
        parts: &(
            MemoryController,
            T6020Memory,
            Arc<RegisteredSystemRam>,
            PowerStates,
            Configuration,
        ),
    ) -> Result<Plan> {
        Plan::prepare_ap_frontend(&parts.0, &parts.1, &parts.3, &parts.2, [None; 4], &parts.4)
    }
    #[test]
    fn input_free_source_keeps_reg0_and_does_not_borrow_separate_pmp_readiness() {
        for count in [4, 8, 16] {
            let parts = components(count);
            let plan = plan(&parts).unwrap();
            assert_eq!(plan.lifecycle_physical(), parts.1.ptd.physical);
            assert_ne!(plan.lifecycle_physical(), parts.1.apertures[0]);
            assert_eq!(plan.source_resource_indices(), &[0]);
            assert!(plan.input_domains().is_empty());
            assert!(Arc::ptr_eq(plan.registered_ram(), &parts.2));
            plan.validate(Some(&parts.0), Some(&parts.1), Some(&parts.3))
                .unwrap();
            let mut devices = placed(&parts.3, pmgr::POWER_GATED, true);
            plan.install(&mut devices).unwrap();
            let id = devices.memory_controller.unwrap();
            assert_eq!(devices.power_devices.len(), 1);
            assert_eq!(devices.power_devices[0].physical, parts.1.ptd.physical);
            assert_eq!(devices.power_devices[0].device, id);
            let owner = devices.bus.device::<Prepared>(id).unwrap();
            assert!(Arc::ptr_eq(owner.registered_ram(), &parts.2));
            // This is initialized local frontend state under proven source
            // input absence, not an observation of the separate supply.
            assert!(owner.controller().lifecycle_state().clocked);
            assert_eq!(
                devices
                    .bus
                    .device::<Pmgr>(devices.pmgr.unwrap())
                    .unwrap()
                    .state(SUPPLY),
                Some(pmgr::POWER_GATED)
            );
            assert!(devices.memory_publication.is_none());
            let mut latch = InterruptLatch::new();
            let mut access = Access::new(0, 0, &mut latch);
            assert!(
                devices
                    .bus
                    .read(
                        parts.1.apertures[0] + stela_soc_data::mcc::t6020::CACHE_SIZE,
                        Width::Word,
                        &mut access
                    )
                    .is_err()
            );
            assert!(
                devices
                    .bus
                    .write(parts.1.updates.0, Width::Double, 1, &mut access)
                    .is_err()
            );
        }
    }
    #[test]
    fn pmgr_input_is_sampled_instead_of_accepting_a_caller_on_boolean() {
        let mut parts = components(16);
        parts.3.resources[0].clocks.push(id(1));
        let plan = plan(&parts).unwrap();
        assert_eq!(plan.input_domains(), &[SUPPLY]);
        let mut devices = placed(&parts.3, pmgr::CLOCK_GATED, true);
        plan.install(&mut devices).unwrap();
        let owner = devices
            .bus
            .device::<Prepared>(devices.memory_controller.unwrap())
            .unwrap();
        assert!(owner.controller().lifecycle_state().powered);
        assert!(!owner.controller().lifecycle_state().clocked);
        assert_eq!(devices.power_devices[0].physical, parts.1.ptd.physical);
    }
    #[test]
    fn missing_or_foreign_pmgr_routes_refuse_before_placing_any_memory() {
        let parts = components(4);
        for devices in [AppleDevices::new(), placed(&parts.3, pmgr::ACTIVE, false)] {
            let mut devices = devices;
            assert!(plan(&parts).unwrap().install(&mut devices).is_err());
            assert!(devices.memory_controller.is_none());
            assert!(devices.power_devices.is_empty());
            assert!(
                devices
                    .bus
                    .route(parts.1.apertures[0], Width::Word)
                    .is_err()
            );
            assert!(
                devices
                    .bus
                    .route(parts.1.ptd.physical, Width::Word)
                    .is_err()
            );
        }
    }
    #[test]
    fn source_reg0_requires_positive_owner_and_full_unchanged_admission() {
        let mut parts = components(8);
        let original = parts.3.clone();
        for owner in [None, Some(PowerOwner::Mmio(parts.1.apertures[0]))] {
            parts.3.resources[0].owner = owner;
            assert!(plan(&parts).is_err());
        }
        parts.3 = original.clone();
        parts.3.resources[0].admission = Admission::Unavailable;
        assert!(plan(&parts).is_err());
        parts.3 = original;
        let plan = plan(&parts).unwrap();
        parts.3.resources[0].name.push_str("-changed");
        assert!(
            plan.validate(Some(&parts.0), Some(&parts.1), Some(&parts.3))
                .is_err()
        );
        assert!(plan.validate(Some(&parts.0), None, None).is_err());
    }
    #[test]
    fn independently_gated_owned_aperture_aliases_require_an_separate_join() {
        let mut parts = components(16);
        for address in [parts.1.apertures[8], parts.1.updates.0, parts.1.auxiliary.0] {
            let mut alias = parts.3.resources[0].clone();
            alias.owner = Some(PowerOwner::Mmio(address));
            alias.power.push(id(1));
            parts.3.resources.push(alias);
            assert!(plan(&parts).is_err());
            parts.3.resources.pop();
        }
    }
    #[test]
    fn incomplete_configuration_and_changed_register_inventory_refuse() {
        let mut parts = components(4);
        parts.4.channels.pop();
        assert!(plan(&parts).is_err());
        parts.4 = Configuration::clear_software_controls(parts.1.layout().unwrap());
        parts.3.registers.push(SUPPLY + 4);
        assert!(plan(&parts).is_err());
    }
}
