use super::*;
use crate::platform::apple::pmgr::DomainState;
use crate::platform::apple::pmgr::PowerState;
use alloc::boxed::Box;
use stela_contracts::bus::Access;
use stela_contracts::bus::MmioDevice;
use stela_contracts::interrupt::InterruptLatch;
use stela_engine::machine::Devices;
use stela_soc_data::board::ClockRole;
use stela_soc_data::board::PowerResource;
use stela_soc_data::pmgr::coverage::Admission;
use stela_soc_data::pmgr::coverage::Domain;
use stela_soc_data::pmgr::coverage::DomainId;

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
    // Reuse component fixtures for source geometry/RAM only. Their
    // ClampZero/ACTIVE initialization is NOT consumed by this cold plan.
    let (memory, cache) = EmptyResource::service_test_components();
    let controller = cache.source().clone();
    let descriptor = memory.descriptor().clone();
    let ram = Arc::clone(memory.registered_ram());
    let physical = controller.apertures[0] + descriptor.cache.shared.0;
    let states = stela_soc_data::board::fixture_support::power_states_fixture(
        vec![(SUPPLY, 24)],
        vec![SUPPLY, SUPPLY + 8, SUPPLY + 16],
        vec![
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
        vec![PowerResource {
            name: "/arm-io/mcc".into(),
            clocks: vec![id(2)],
            clock_role: ClockRole::Consumer,
            power: vec![id(3)],
            owner: Some(PowerOwner::Mmio(physical)),
            admission: Admission::Required,
        }],
    );
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
    plan.validate_power(Some(&states)).unwrap();
    assert!(plan.validate_power(None).is_err());
    let mut changed_power = states.clone();
    changed_power.resources[0].name.push_str(" changed");
    assert!(plan.validate_power(Some(&changed_power)).is_err());
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
fn certified_input_free_ap_frontend_owns_same_ram_without_sampling_unrelated_gates() {
    let (controller, cache, ram, mut states) = components();
    states.resources[0].clocks.clear();
    states.resources[0].power.clear();
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
    let plan = Plan::prepare_resources_with_policy(
        &controller,
        &cache,
        &states,
        &ram,
        [None; 4],
        &configuration(),
        LifecyclePolicy::SourceQualifiedApFrontend,
    )
    .unwrap();
    let LifecycleInput::UnswitchedApFrontend(certificate) = &plan.lifecycle else {
        panic!("expected explicit input-free certificate")
    };
    let (_, _, foreign_ram, _) = components();
    assert!(
        certificate
            .initialize(&controller, &cache, &foreign_ram)
            .is_err()
    );
    assert!(
        certificate
            .initialize(&controller, &cache, &ram)
            .unwrap()
            .clocked
    );
    plan.validate_power(Some(&states)).unwrap();
    let mut devices = placed(&states, pmgr::POWER_GATED);
    plan.install(&mut devices).unwrap();
    assert_eq!(devices.read(0, cache.channels.0 + 0xec8, 4, 0).unwrap(), 0);
    for actual in [
        devices
            .bus
            .device::<t8112::Prepared>(devices.memory_publication.unwrap())
            .unwrap()
            .registered_ram(),
        devices
            .bus
            .device::<EmptyResource>(devices.memory_controller.unwrap())
            .unwrap()
            .registered_ram(),
    ] {
        assert!(Arc::ptr_eq(actual, &ram));
    }
    assert_eq!(
        devices
            .bus
            .device::<Pmgr>(devices.pmgr.unwrap())
            .unwrap()
            .domain_state(SUPPLY)
            .unwrap()
            .power,
        pmgr::POWER_GATED
    );
}

#[test]
fn failed_canonical_ram_refuses_certificate_and_install_without_publication() {
    let (controller, cache, ram, mut states) = components();
    states.resources[0].clocks.clear();
    states.resources[0].power.clear();
    let prepare = || {
        Plan::prepare_resources_with_policy(
            &controller,
            &cache,
            &states,
            &ram,
            [None; 4],
            &configuration(),
            LifecyclePolicy::SourceQualifiedApFrontend,
        )
    };
    let plan = prepare().unwrap();
    let service = ram.try_service().unwrap().unwrap();
    service.fail();
    drop(service);
    assert!(prepare().is_err());
    let mut devices = placed(&states, pmgr::ACTIVE);
    assert!(plan.install(&mut devices).is_err());
    assert!(devices.memory_publication.is_none() && devices.memory_controller.is_none());
}

#[test]
fn ap_frontend_selection_preserves_switched_inputs_and_refuses_incomplete_or_virtual_aliases() {
    let (controller, cache, ram, mut states) = components();
    let prepare = |states: &PowerStates| {
        Plan::prepare_resources_with_policy(
            &controller,
            &cache,
            states,
            &ram,
            [None; 4],
            &configuration(),
            LifecyclePolicy::SourceQualifiedApFrontend,
        )
    };
    let switched = prepare(&states).unwrap();
    assert!(matches!(switched.lifecycle, LifecycleInput::Switched(_)));
    let mut devices = placed(&states, pmgr::CLOCK_GATED);
    switched.install(&mut devices).unwrap();
    assert!(devices.read(0, cache.channels.0 + 0xec8, 4, 0).is_err());
    states.resources[0].clocks.clear();
    states.resources[0].power.clear();
    let mut alias = states.resources[0].clone();
    alias.name.push_str(" alias");
    alias.power.push(id(2));
    states.resources.push(alias);
    states.domains[1].address = None;
    states.domains[1].parents = [None; 4];
    states.registers.retain(|&address| address != SUPPLY + 8);
    assert!(
        power_domains(&states, controller.apertures[0] + cache.cache.shared.0)
            .unwrap()
            .is_empty()
    );
    assert!(prepare(&states).is_err());
    states.resources[1].power.clear();
    states.resources[1].admission = Admission::Unavailable;
    assert!(prepare(&states).is_err());
    states.resources.clear();
    assert!(prepare(&states).is_err());
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
    assert!(overlapping.memory_controller.is_none() && overlapping.memory_publication.is_none());
}
