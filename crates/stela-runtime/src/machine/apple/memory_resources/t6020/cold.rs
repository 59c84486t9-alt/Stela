//! Source-retained T602x cold placement over the actual canonical RAM owner.
//!
//! Original26A434 all8 MCC reg0 is the PTD bank; reg2 starts the controller
//! apertures (mac14j KC file2ecb674/2ecc068). The original trees have no MCC
//! clock/power arrays. PMP ASC gates0x49/0x4a belong to its separate owner.
//! Parent provider recipes, absent arrays and caller booleans are never
//! controller/PMP/cache completion. Full source PowerStates remain retained.
use super::{Configuration, MemoryController, Prepared, T6020Memory, amcc, validate_ram};
use crate::{
    machine::{
        apple::AppleDevices,
        soc::{PowerOwner, PowerStates},
    },
    memory::RegisteredSystemRam,
    platform::apple::{
        bus::{LifecycleState, Width},
        pmgr::{
            self, Pmgr,
            coverage::{self, Consumer, LifecycleSinks},
        },
    },
};
use alloc::{format, string::String, sync::Arc, vec, vec::Vec};

/// Private inputs retain actual source identities. Construction supplies no
/// lifecycle status, native topology, firmware PTD service or cache grant.
pub struct Plan {
    controller: MemoryController,
    descriptor: T6020Memory,
    power: PowerStates,
    resources: Vec<usize>,
    domains: Vec<u64>,
    ram: Arc<RegisteredSystemRam>,
    generation: u64,
    programmed: amcc::Programmed,
    configuration: Configuration,
}

impl Plan {
    /// Retain independently decoded original descriptors. Source admission
    /// must already positively associate MCC reg0 with the actual joint owner;
    /// a hidden/unmodeled owner=None resource cannot satisfy this requirement.
    pub fn prepare_ap_frontend(
        controller: &MemoryController,
        descriptor: &T6020Memory,
        power: &PowerStates,
        ram: &Arc<RegisteredSystemRam>,
        programmed: amcc::Programmed,
        configuration: &Configuration,
    ) -> Result<Self, String> {
        descriptor.validate(controller).map_err(String::from)?;
        validate_ram(descriptor, controller, programmed, ram).map_err(String::from)?;
        let layout = descriptor.layout().map_err(String::from)?;
        if configuration.channels.len() != layout.channels()
            || configuration.mcc_gating.len() != layout.apertures()
        {
            return Err("cold T602x configuration omits actual controller channels".into());
        }
        let (resources, domains) = source_inputs(power, descriptor)?;
        let generation = ram
            .domain()
            .generation()
            .map_err(|_| "cold T602x canonical RAM is not live")?;
        Ok(Self {
            controller: controller.clone(),
            descriptor: descriptor.clone(),
            power: power.clone(),
            resources,
            domains,
            ram: Arc::clone(ram),
            generation,
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
    ) -> Result<(), String> {
        if controller != Some(&self.controller)
            || descriptor != Some(&self.descriptor)
            || power != Some(&self.power)
        {
            return Err("cold T602x differs from its complete retained source resources".into());
        }
        self.validate_ram()
    }
    pub fn registered_ram(&self) -> &Arc<RegisteredSystemRam> {
        &self.ram
    }
    pub fn descriptor(&self) -> &T6020Memory {
        &self.descriptor
    }
    /// Lifecycle identity follows the original node's first reg, not its
    /// first direct controller and not the separate PMP ASC.
    pub fn lifecycle_physical(&self) -> u64 {
        self.descriptor.ptd.physical
    }
    pub fn source_resource_indices(&self) -> &[usize] {
        &self.resources
    }
    pub fn input_domains(&self) -> &[u64] {
        &self.domains
    }
    fn validate_ram(&self) -> Result<(), String> {
        if self
            .ram
            .domain()
            .generation()
            .map_err(|_| "cold T602x canonical RAM is not live")?
            != self.generation
        {
            return Err("cold T602x canonical RAM generation changed".into());
        }
        Ok(())
    }

    fn lifecycle(&self, devices: &AppleDevices) -> Result<LifecycleState, String> {
        self.validate_ram()?;
        let id = devices
            .pmgr
            .ok_or("cold T602x requires the actual placed PMGR")?;
        let pmgr = devices
            .bus
            .device::<Pmgr>(id)
            .ok_or("cold T602x has a foreign PMGR owner")?;
        // Even an input-free MCC cannot borrow a merely numerically matching
        // PMGR state table with absent/foreign physical routes.
        for &address in &self.power.registers {
            if devices.bus.route(address, Width::Word).ok() != Some((id, address))
                || pmgr.domain_state(address).is_none()
            {
                return Err(format!(
                    "cold T602x source register {address:#x} has no actual PMGR route/state"
                ));
            }
        }
        if self.domains.is_empty() {
            // source_inputs proved literal absence of activated/implicit inputs
            // in every positively owned alias. This is only the initial state
            // of the NEW synchronous software frontend, not a hardware power,
            // cache-ready or private PMP acknowledgement. Unrelated PMP gates
            // keep their actual state and are never sampled as MCC readiness.
            return Ok(LifecycleState {
                powered: true,
                clocked: true,
                quiesced: false,
                reset: false,
                retention: true,
            });
        }
        let states = self
            .domains
            .iter()
            .map(|&address| {
                pmgr.domain_state(address).ok_or_else(|| {
                    format!("cold T602x input {address:#x} has no actual PMGR state")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(LifecycleState {
            powered: states.iter().all(|state| state.power != pmgr::POWER_GATED),
            clocked: states.iter().all(|state| state.power == pmgr::ACTIVE),
            quiesced: states.iter().any(|state| state.disabled),
            reset: states.iter().any(|state| state.reset),
            retention: true,
        })
    }

    /// After actual PMGR placement and before complete power connection, install
    /// one joint owner and register its source reg0 lifecycle identity. The caller
    /// retains stopped native/all-writer ownership through this cold placement.
    /// No controller request is retired and no PTD publication service is made.
    pub fn install(self, devices: &mut AppleDevices) -> Result<(), String> {
        if devices.power_configured
            || devices.memory_controller.is_some()
            || devices.memory_publication.is_some()
        {
            return Err("cold T602x requires an unoccupied unconnected memory mount".into());
        }
        let lifecycle = self.lifecycle(devices)?;
        let physical = self.lifecycle_physical();
        let owner = Prepared::new(
            self.descriptor,
            self.controller,
            self.programmed,
            self.configuration,
            lifecycle,
            self.ram,
        )?;
        devices.add_t6020_memory_resources(owner)?;
        let id = devices
            .memory_controller
            .ok_or("cold T602x lost its actual installed owner")?;
        // The ID is newly installed, the owner has an actual Lifecycle hook,
        // and the exclusive borrow retained power_configured=false above.
        devices.register_power_device(physical, id, true)
    }
}

fn source_inputs(
    power: &PowerStates,
    descriptor: &T6020Memory,
) -> Result<(Vec<usize>, Vec<u64>), String> {
    let physical = descriptor.ptd.physical;
    let resources = power
        .resources
        .iter()
        .enumerate()
        .filter_map(|(id, resource)| {
            (resource.owner == Some(PowerOwner::Mmio(physical))).then_some(id)
        })
        .collect::<Vec<_>>();
    if resources.is_empty()
        || resources
            .iter()
            .any(|&id| power.resources[id].admission == coverage::Admission::Unavailable)
    {
        return Err("cold T602x source reg0 has no positively owned lifecycle resource".into());
    }
    let requirements = power.power_requirements()?;
    let consumers = power
        .resources
        .iter()
        .enumerate()
        .map(|(id, resource)| Consumer {
            id,
            name: &resource.name,
            clocks: resource.activated_clocks(),
            power: &requirements[id],
            admission: resource.admission,
            sinks: LifecycleSinks::default(),
        })
        .collect::<Vec<_>>();
    let graph = coverage::analyze(&power.domains, &consumers)
        .map_err(|error| format!("cold T602x complete source power graph: {error:?}"))?;
    if graph.len() != power.registers.len()
        || graph
            .iter()
            .any(|domain| !power.registers.contains(&domain.address))
    {
        return Err("cold T602x source graph differs from its complete register set".into());
    }
    for &id in &resources {
        for &input in power.resources[id]
            .activated_clocks()
            .iter()
            .chain(&requirements[id])
        {
            if !resolved_input(power, input) {
                return Err("cold T602x input has an unresolved virtual ancestor".into());
            }
        }
    }
    for (id, resource) in power.resources.iter().enumerate() {
        if let Some(PowerOwner::Mmio(address)) = resource.owner
            && address != physical
            && contains(descriptor, address)
            && (!resource.activated_clocks().is_empty() || !requirements[id].is_empty())
        {
            return Err("cold T602x independently gated overlapping alias needs its own actual lifecycle join".into());
        }
    }
    let domains = graph
        .iter()
        .filter(|domain| {
            domain
                .consumers
                .iter()
                .any(|consumer| resources.contains(&consumer.id))
        })
        .map(|domain| domain.address)
        .collect::<Vec<_>>();
    if domains.is_empty()
        && resources.iter().any(|&id| {
            !power.resources[id].activated_clocks().is_empty() || !requirements[id].is_empty()
        })
    {
        return Err("cold T602x activated inputs have no physical lifecycle producer".into());
    }
    Ok((resources, domains))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Key {
    Physical(u64),
    Virtual(coverage::DomainId),
}
fn key(domain: &coverage::Domain) -> Key {
    domain
        .address
        .map_or(Key::Virtual(domain.id), Key::Physical)
}
/// Follow coverage's normalized physical aliases and ALL ancestor edges. An
/// unresolved virtual root on any path cannot be masked by one physical parent.
fn resolved_input(power: &PowerStates, input: coverage::DomainId) -> bool {
    let mut pending = vec![input];
    let mut seen = Vec::new();
    let mut physical = false;
    while let Some(id) = pending.pop() {
        let Some(domain) = power.domains.iter().find(|domain| domain.id == id) else {
            return false;
        };
        let current = key(domain);
        if seen.contains(&current) {
            continue;
        }
        seen.push(current);
        let mut parents = Vec::new();
        for alias in power.domains.iter().filter(|alias| key(alias) == current) {
            for &id in alias.parents.iter().flatten() {
                let Some(parent) = power.domains.iter().find(|domain| domain.id == id) else {
                    return false;
                };
                if key(parent) != current {
                    parents.push(id);
                }
            }
        }
        match current {
            Key::Physical(_) => physical = true,
            Key::Virtual(_) if parents.is_empty() => return false,
            Key::Virtual(_) => {}
        }
        pending.extend(parents);
    }
    physical
}
fn contains(descriptor: &T6020Memory, address: u64) -> bool {
    descriptor
        .apertures
        .iter()
        .any(|&start| address >= start && address - start < super::t6020::APERTURE_BYTES)
        || address >= descriptor.ptd.physical
            && address - descriptor.ptd.physical < super::ptd::PTD_BYTES
        || address >= descriptor.auxiliary.0
            && address - descriptor.auxiliary.0 < descriptor.auxiliary.1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        machine::soc::{ClockRole, PowerResource},
        platform::apple::{
            bus::Access,
            interrupt::InterruptLatch,
            pmgr::{
                PowerState,
                coverage::{Admission, Domain, DomainId},
            },
        },
    };
    use alloc::boxed::Box;
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
        let power = PowerStates {
            blocks: vec![(SUPPLY, 0x100)],
            registers: vec![SUPPLY],
            domains: vec![domain(1, Some(SUPPLY), [None; 4])],
            resources: vec![PowerResource {
                name: "authored-source-mcc".into(),
                clocks: vec![],
                clock_role: ClockRole::Consumer,
                power: vec![],
                owner: Some(PowerOwner::Mmio(descriptor.ptd.physical)),
                admission: Admission::Required,
            }],
            implicit: vec![],
        };
        (
            fixture.source_locks.clone(),
            descriptor,
            Arc::clone(&fixture.ram),
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
    ) -> Result<Plan, String> {
        Plan::prepare_ap_frontend(&parts.0, &parts.1, &parts.3, &parts.2, [None; 4], &parts.4)
    }
    #[test]
    fn input_free_source_retains_reg0_and_does_not_borrow_separate_pmp_readiness() {
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
                        parts.1.apertures[0] + super::super::t6020::CACHE_SIZE,
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
    fn actual_pmgr_input_is_sampled_instead_of_accepting_a_caller_on_boolean() {
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
    fn actual_alias_inputs_and_all_physical_ancestors_are_retained() {
        let mut parts = components(4);
        parts.3.registers.push(SUPPLY + 4);
        parts.3.domains[0].parents[0] = Some(id(2));
        parts.3.domains.push(domain(2, Some(SUPPLY + 4), [None; 4]));
        parts.3.resources.push(parts.3.resources[0].clone());
        parts.3.resources[1].name = "authored-same-owner-alias".into();
        parts.3.resources[1].power.push(id(1));
        let plan = plan(&parts).unwrap();
        assert_eq!(plan.source_resource_indices(), &[0, 1]);
        assert_eq!(plan.input_domains(), &[SUPPLY, SUPPLY + 4]);
    }
    #[test]
    fn independently_gated_owned_aperture_aliases_require_an_actual_separate_join() {
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
    fn one_physical_parent_does_not_hide_an_unresolved_virtual_ancestor() {
        let mut parts = components(4);
        parts.3.domains.push(domain(2, None, [None; 4]));
        parts
            .3
            .domains
            .push(domain(3, None, [Some(id(1)), Some(id(2)), None, None]));
        parts.3.resources[0].power.push(id(3));
        assert!(plan(&parts).is_err());
        parts.3.domains[1].parents[0] = Some(id(1));
        assert_eq!(plan(&parts).unwrap().input_domains(), &[SUPPLY]);
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
