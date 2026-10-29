use super::*;
use crate::platform::apple::pmgr::PowerState;
use alloc::{boxed::Box, vec};
use core::{cell::UnsafeCell, ptr::NonNull};
use stela_contracts::bus::Access;
use stela_contracts::interrupt::InterruptLatch;
use stela_contracts::refuse;
use stela_engine::memory::ReservedSystemRamRange;
use stela_engine::memory::system_ram::fixture;
use stela_soc_data::board::ClockRole;
use stela_soc_data::board::PowerResource;
use stela_soc_data::pmgr::coverage::Admission;
use stela_soc_data::pmgr::coverage::Domain;
use stela_soc_data::pmgr::coverage::DomainId;
const SUPPLY: u64 = 0x1000;
const RAM: u64 = 0x800000000;
#[repr(C, align(16))]
struct Storage(UnsafeCell<[u8; 0x8000]>);
// SAFETY: authored fixture transfers these stable bytes without any PE/DMA.
unsafe impl Sync for Storage {}
fn ram_at(source: u64) -> Arc<RegisteredSystemRam> {
    let storage = Arc::new(Storage(UnsafeCell::new([0; 0x8000])));
    let range = ReservedSystemRamRange {
        source_pa: source,
        host_pa: 0x400000,
        bytes: 0x8000,
        host_base: NonNull::new(storage.0.get().cast()).unwrap(),
    };
    // SAFETY: exclusive fixture owner, closed synchronous producers only.
    Arc::new(unsafe { fixture(&[range], storage) })
}
fn id() -> DomainId {
    DomainId { die: 0, device: 1 }
}
fn components() -> (
    MemoryController,
    DirectMemoryCache,
    Arc<RegisteredSystemRam>,
    PowerStates,
) {
    // Use the established direct-router fixture's descriptor/layout only.
    // Its declared ACTIVE/control image is not consumed by this factory.
    let original = super::super::tests::prepared();
    // Router::new removes this SOURCE descriptor field from its private
    // AMCC layout: shared status is served by the MCC, never an
    // independent AMCC ready/disabled bit. Reconstruct the original input
    // descriptor here; the transformed inner layout is not that input.
    let mut layout = original.router.lock_layout;
    assert!(layout.cache_status.is_none());
    layout.cache_status = Some(stela_soc_data::amcc::Register {
        offset: 0x1c00,
        mask: 0x1f,
        value: 0,
    });
    let controller = MemoryController {
        apertures: original.descriptor().apertures.clone(),
        layout,
    };
    let direct = original.descriptor().clone();
    let power = stela_soc_data::board::fixture_support::power_states_fixture(
        vec![(SUPPLY, 8)],
        vec![SUPPLY],
        vec![Domain {
            name: "authored-separate-PMP-supply".into(),
            id: id(),
            address: Some(SUPPLY),
            parents: [None; 4],
        }],
        vec![PowerResource {
            name: "/arm-io/mcc".into(),
            clocks: vec![],
            clock_role: ClockRole::Consumer,
            power: vec![],
            owner: Some(PowerOwner::Mmio(direct.apertures[0])),
            admission: Admission::Required,
        }],
    );
    (controller, direct, ram_at(RAM), power)
}
fn configuration() -> Configuration {
    Configuration::declared_control_image(
        vec![[0x80000001, 2, 3, 4], [5, 6, 7, 0x12345678]],
        [1; 32],
    )
    .unwrap()
}
fn placed(power: &PowerStates, initial: u8) -> AppleDevices {
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
            .install(Box::new(model), &[(SUPPLY, 8, SUPPLY)])
            .unwrap(),
    );
    devices
}
#[test]
fn full_opaque_control_image_and_weights_are_separate_from_capacity() {
    let image = configuration();
    assert_eq!(image.controls()[0], [0x80000001, 2, 3, 4]);
    assert_eq!(image.controls()[1][3], 0x12345678);
    assert_eq!(image.weights(), &[1; 32]);
    assert!(Configuration::zeroed_control_image(0, [1; 32]).is_err());
    assert!(Configuration::zeroed_control_image(2, [0; 32]).is_err());
    assert!(Configuration::zeroed_control_image(2, [0x80; 32]).is_err());
    let zero = Configuration::zeroed_control_image(2, [7; 32]).unwrap();
    assert_eq!(zero.controls(), &[[0; 4]; 2]);
    assert_eq!(zero.weights(), &[7; 32]);
}
#[test]
fn input_free_source_installs_one_same_ram_joint_owner_with_local_ptd() {
    let (controller, direct, ram, power) = components();
    let plan = Plan::prepare_resources(
        &controller,
        &direct,
        &power,
        &ram,
        [None; 4],
        &configuration(),
    )
    .unwrap();
    assert!(plan.requires_disable_mcc());
    assert!(Arc::ptr_eq(plan.registered_ram(), &ram));
    plan.validate(Some(&controller), Some(&direct)).unwrap();
    plan.validate_power(Some(&power)).unwrap();
    let mut devices = placed(&power, pmgr::POWER_GATED);
    plan.install(&mut devices).unwrap();
    let joint = devices.memory_controller.unwrap();
    assert!(devices.memory_publication.is_none()); // Direct dispatcher uses this SAME joint ID.
    let owner = devices.bus.device::<Prepared>(joint).unwrap();
    assert!(Arc::ptr_eq(owner.registered_ram().unwrap(), &ram));
    assert!(
        owner
            .local_notifications()
            .unwrap()
            .owns(owner.publication_bank())
    );
    assert_eq!(owner.local_notifications().unwrap().asserted(), 0);
    assert_eq!(
        owner.controller().lifecycle_state(),
        LifecycleState {
            powered: true,
            clocked: true,
            quiesced: false,
            reset: false,
            retention: true,
        }
    );
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
    assert_eq!(devices.power_devices.len(), 1);
    assert_eq!(devices.power_devices[0].physical, direct.apertures[0]);
    assert_eq!(devices.power_devices[0].device, joint);
    let mut irq = InterruptLatch::new();
    let mut access = Access::new(0, 17, &mut irq);
    for (aperture, row) in configuration().controls().iter().enumerate() {
        for (channel, &word) in row.iter().enumerate() {
            let address = direct.apertures[aperture]
                + mcc::DCS_BASE
                + channel as u64 * mcc::DCS_STRIDE
                + 0x13cc;
            assert_eq!(
                devices.bus.read(address, Width::Word, &mut access),
                Ok(u64::from(word))
            );
        }
    }
    let update = direct.ptd_updates.0;
    devices
        .bus
        .write(update, Width::Double, 0x1122334455667788, &mut access)
        .unwrap();
    let owner = devices.bus.device::<Prepared>(joint).unwrap();
    let (bank, _, offset) = owner.publication_binding();
    assert_eq!(
        devices.bus.route(update, Width::Double).unwrap(),
        (joint, offset + stela_soc_data::ptd::UPDATE_OFFSET)
    );
    assert_eq!(bank, direct.ptd.physical);
    assert_eq!(
        owner.read_pair_values(offset, 8, &mut access).unwrap()[0],
        0x1122334455667788
    );
    assert_eq!(owner.local_notifications().unwrap().asserted(), 0); // No IRQ enable or event invented.
}
#[test]
fn switched_input_samples_pmgr_and_preserves_clock_gating() {
    let (controller, direct, ram, mut power) = components();
    power.resources[0].clocks.push(id());
    let plan = Plan::prepare_resources(
        &controller,
        &direct,
        &power,
        &ram,
        [None; 4],
        &configuration(),
    )
    .unwrap();
    let mut devices = placed(&power, pmgr::CLOCK_GATED);
    plan.install(&mut devices).unwrap();
    let owner = devices
        .bus
        .device::<Prepared>(devices.memory_controller.unwrap())
        .unwrap();
    assert!(owner.controller().lifecycle_state().powered);
    assert!(!owner.controller().lifecycle_state().clocked);
    let mut irq = InterruptLatch::new();
    assert!(
        devices
            .bus
            .read(
                direct.apertures[0] + 0x1c00,
                Width::Word,
                &mut Access::new(0, 0, &mut irq)
            )
            .is_err()
    );
    assert_eq!(
        devices
            .bus
            .device::<Pmgr>(devices.pmgr.unwrap())
            .unwrap()
            .domain_state(SUPPLY)
            .unwrap()
            .power,
        pmgr::CLOCK_GATED
    );
}
#[test]
fn absent_unavailable_virtual_and_independent_alias_inputs_refuse() {
    let (controller, direct, ram, power) = components();
    let prepare = |power: &PowerStates| {
        Plan::prepare_resources(
            &controller,
            &direct,
            power,
            &ram,
            [None; 4],
            &configuration(),
        )
    };
    let mut absent = power.clone();
    absent.resources.clear();
    assert!(prepare(&absent).is_err());
    let mut unavailable = power.clone();
    unavailable.resources[0].admission = Admission::Unavailable;
    assert!(prepare(&unavailable).is_err());
    let mut virtual_only = power.clone();
    virtual_only.domains[0].address = None;
    virtual_only.registers.clear();
    virtual_only.resources[0].power.push(id());
    assert!(prepare(&virtual_only).is_err());
    let mut alias = power.clone();
    let mut r = alias.resources[0].clone();
    r.name = "authored-independent-overlap".into();
    r.owner = Some(PowerOwner::Mmio(direct.apertures[1]));
    r.clocks.push(id());
    alias.resources.push(r);
    assert!(prepare(&alias).is_err());
    // A real physical sibling does not resolve a separate virtual input.
    let mut mixed = power.clone();
    mixed.domains.push(Domain {
        name: "unbacked virtual".into(),
        id: DomainId { die: 0, device: 2 },
        address: None,
        parents: [None; 4],
    });
    mixed.resources[0]
        .power
        .extend([id(), DomainId { die: 0, device: 2 }]);
    assert!(prepare(&mixed).is_err());
    let mut unknown = power.clone();
    unknown.resources[0]
        .power
        .push(DomainId { die: 0, device: 2 });
    assert!(prepare(&unknown).is_err());
}
#[test]
fn physical_alias_parents_cannot_hide_unresolved_virtual_root_or_intermediate_inputs() {
    let (controller, direct, ram, source) = components();
    let domain = |device: u16, address: Option<u64>, parent: Option<u16>| Domain {
        name: alloc::format!("authored-alias-{device}"),
        id: DomainId { die: 0, device },
        address,
        parents: [
            parent.map(|device| DomainId { die: 0, device }),
            None,
            None,
            None,
        ],
    };
    for intermediate in [false, true] {
        let mut power = source.clone();
        power.resources[0].clocks.push(id());
        let virtual_id = if intermediate { 4 } else { 3 };
        // A(P,no parents), B(P,parent V), V(None,no parents), or
        // A(P,parent C), C(Q,no parents), D(Q,parent V). Every reached
        // physical key must expand ALL its aliases, including Q.
        if intermediate {
            power.domains[0].parents[0] = Some(DomainId { die: 0, device: 2 });
            power.domains.push(domain(2, Some(SUPPLY + 8), None));
            power
                .domains
                .push(domain(3, Some(SUPPLY + 8), Some(virtual_id)));
            power.registers.push(SUPPLY + 8);
        } else {
            power
                .domains
                .push(domain(2, Some(SUPPLY), Some(virtual_id)));
        }
        power.domains.push(domain(virtual_id, None, None));
        assert!(!resolved_input(&power, id()));
        assert!(
            matches!(Plan::prepare_resources(&controller, &direct, &power, &ram,
                [None; 4], &configuration()),
                Err(reason) if reason == refuse!("cold T6000 requested input has an unresolved virtual ancestor"))
        );
        // The same alias ancestry is supported when V resolves
        // to a physical ancestor. No arbitrary virtual-input veto.
        let backed_id = virtual_id + 1;
        power
            .domains
            .iter_mut()
            .find(|d| d.id.device == virtual_id)
            .unwrap()
            .parents[0] = Some(DomainId {
            die: 0,
            device: backed_id,
        });
        let backed_address = SUPPLY + if intermediate { 16 } else { 8 };
        power
            .domains
            .push(domain(backed_id, Some(backed_address), None));
        power.registers.push(backed_address);
        power.blocks[0].1 = if intermediate { 24 } else { 16 };
        assert!(resolved_input(&power, id()));
        let plan = Plan::prepare_resources(
            &controller,
            &direct,
            &power,
            &ram,
            [None; 4],
            &configuration(),
        )
        .unwrap();
        assert_eq!(plan.domains, power.registers);
    }
    // An acyclic raw A->B edge within the SAME physical key disappears in
    // normalized coverage; it is not an unresolved virtual requirement.
    let mut same_key = source.clone();
    same_key.resources[0].clocks.push(id());
    same_key.domains[0].parents[0] = Some(DomainId { die: 0, device: 2 });
    same_key.domains.push(domain(2, Some(SUPPLY), None));
    assert!(
        Plan::prepare_resources(
            &controller,
            &direct,
            &same_key,
            &ram,
            [None; 4],
            &configuration()
        )
        .is_ok()
    );
}
#[test]
fn all_geometry_ram_locks_controls_and_live_source_are_preflighted() {
    let (controller, direct, ram, power) = components();
    let config = configuration();
    let mut missing_status = controller.clone();
    missing_status.layout.cache_status = None;
    assert!(
        matches!(Plan::prepare_resources(&missing_status, &direct, &power, &ram,
            [None; 4], &config), Err(reason) if reason ==
            refuse!("cold T6000 requires its source PTD geometry and shared way-command status"))
    );
    let mut bad = direct.clone();
    bad.ptd_entries = 377;
    assert!(Plan::prepare_resources(&controller, &bad, &power, &ram, [None; 4], &config).is_err());
    let mut bad = direct.clone();
    bad.ptd_updates.1 = 0x1000;
    assert!(Plan::prepare_resources(&controller, &bad, &power, &ram, [None; 4], &config).is_err());
    assert!(
        Plan::prepare_resources(
            &controller,
            &direct,
            &power,
            &ram_at(direct.apertures[0]),
            [None; 4],
            &config
        )
        .is_err()
    );
    let mut outside = [None; 4];
    outside[0] = Some((RAM + 0x8000, 0x4000));
    assert!(Plan::prepare_resources(&controller, &direct, &power, &ram, outside, &config).is_err());
    let short = Configuration::zeroed_control_image(1, [1; 32]).unwrap();
    assert!(
        Plan::prepare_resources(&controller, &direct, &power, &ram, [None; 4], &short).is_err()
    );
    let plan =
        Plan::prepare_resources(&controller, &direct, &power, &ram, [None; 4], &config).unwrap();
    let mut different = direct.clone();
    different.alternate_dram_configuration ^= 1;
    assert!(plan.validate(Some(&controller), Some(&different)).is_err());
    let mut different = power.clone();
    different.resources[0].name.push_str("-different");
    assert!(plan.validate_power(Some(&different)).is_err());
}
#[test]
fn duplicate_or_overlapping_install_never_supplies_another_owner() {
    let (controller, direct, ram, power) = components();
    let prepare = || {
        Plan::prepare_resources(
            &controller,
            &direct,
            &power,
            &ram,
            [None; 4],
            &configuration(),
        )
        .unwrap()
    };
    let mut devices = placed(&power, pmgr::POWER_GATED);
    let address = direct.apertures[0];
    let blocker = Pmgr::new([PowerState {
        address,
        initial: pmgr::POWER_GATED,
    }])
    .unwrap();
    let blocker = devices
        .bus
        .install(Box::new(blocker), &[(address, 4, address)])
        .unwrap();
    assert!(prepare().install(&mut devices).is_err());
    assert!(devices.memory_controller.is_none());
    assert!(devices.power_devices.is_empty());
    assert_eq!(
        devices.bus.route(address, Width::Word).unwrap(),
        (blocker, address)
    );
    let mut occupied = placed(&power, pmgr::POWER_GATED);
    prepare().install(&mut occupied).unwrap();
    let original = occupied.memory_controller;
    assert!(prepare().install(&mut occupied).is_err());
    assert_eq!(occupied.memory_controller, original);
}
#[test]
#[cfg(feature = "std")]
#[ignore = "oracle: STELA_T6000_MCC_DEVICE_TREE, STELA_TEST_MCC_KERNELCACHE"]
fn original_j314s_input_free_frontend_and_opaque_control_consumers_are_pinned() {
    use stela_contracts::adt::Node;
    let tree = std::fs::read(std::env::var("STELA_T6000_MCC_DEVICE_TREE").unwrap()).unwrap();
    assert_eq!(
        stela_formats::sha256(&tree),
        "44fa41bfd0fe0027fd862b8615ae956885614636625d44a59cab226d682558ad"
    );
    let io = Node::root(&tree).unwrap().child("arm-io").unwrap();
    let mcc = io.child("mcc").unwrap();
    assert!(mcc.compatible("mcc,t6000"));
    assert!(mcc.property("clock-gates").is_none());
    assert!(mcc.property("power-gates").is_none());
    assert!(io.property("clock-gates").is_none());
    assert!(io.property("power-gates").is_none());
    assert!(io.property("function-clock_gate").is_some());
    assert!(io.property("function-power_gate").is_some());
    assert_eq!(mcc.property("reg").unwrap().len(), 4 * 16);
    assert_eq!(mcc.property("config-data").unwrap().len(), 200);
    assert_eq!(
        mcc.property("dramcfg-data").unwrap(),
        &0xffff0000u32.to_le_bytes()
    );
    let pmp = io.child("pmp").unwrap();
    assert_eq!(
        pmp.property("clock-gates").unwrap(),
        &[0x45, 0, 0, 0, 0x46, 0, 0, 0]
    );
    assert_eq!(
        pmp.property("power-gates").unwrap(),
        &[0x45, 0, 0, 0, 0x46, 0, 0, 0]
    );
    assert_eq!(
        pmp.child("iop-pmp-nub")
            .unwrap()
            .property("ptd-range")
            .unwrap()
            .len(),
        19 * 32
    );
    let kernel = std::fs::read(std::env::var("STELA_TEST_MCC_KERNELCACHE").unwrap()).unwrap();
    assert_eq!(
        stela_formats::sha256(&kernel),
        "5109fca5209bdbb89cec29e3241cc42a90418cb737d65e31962b059b9879af90"
    );
    for (start, bytes, expected) in [
        (
            0x2e45ff0,
            3324,
            "c3537b04baa3275219c7707c1b969168ded3a6bb267b5e9c21a1f135de6b2656",
        ),
        (
            0x2e48d74,
            436,
            "7e0b1acedcd9e68c2bd9a7fcdde7b595e24142c7e63bc9807b9a10ad3f45af08",
        ),
        (
            0x1c87f60,
            2824,
            "49c442fd6fb39aad829b39a3b32f0f718e8341e3eb8abf459dd2b9947ec71f79",
        ),
        (
            0x2e48b30,
            580,
            "3d289f493ca6c49ea06401ca4a955bb826cfb5c17b79e7e755ad17279c44bf12",
        ),
        (
            0x2e48688,
            728,
            "358ae139074b063c2aef41e97d73a22fb1aff321074f3f0a92acd2caa672d1a2",
        ),
    ] {
        assert_eq!(
            stela_formats::sha256(&kernel[start..start + bytes]),
            expected
        );
    }
}
