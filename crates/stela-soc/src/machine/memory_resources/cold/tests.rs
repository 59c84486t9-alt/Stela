use super::*;
use core::{cell::UnsafeCell, ptr::NonNull};
use stela_engine::memory::ReservedSystemRamRange;
use stela_engine::memory::system_ram::fixture;
use stela_soc_data::amcc::LockGroup;
use stela_soc_data::amcc::Register;
use stela_soc_data::board::ClockRole;
use stela_soc_data::board::PowerResource;
use stela_soc_data::pmgr::coverage::Admission;
use stela_soc_data::pmgr::coverage::Domain;
use stela_soc_data::pmgr::coverage::DomainId;

const OWNER: u64 = 0x2_0000_0000;
const OWNED: [(u64, u64); 2] = [(OWNER, 0x1000), (OWNER + 0x10000, 0x4000)];
const SUPPLY: u64 = 0x1000;
const RAM: u64 = 0x8_0000_0000;

fn id(device: u16) -> DomainId {
    DomainId { die: 0, device }
}
fn domain(device: u16, address: Option<u64>, parents: &[u16]) -> Domain {
    let mut edges = [None; 4];
    for (edge, &parent) in edges.iter_mut().zip(parents) {
        *edge = Some(id(parent));
    }
    Domain {
        name: alloc::format!("authored-{device}"),
        id: id(device),
        address,
        parents: edges,
    }
}
/// One input-free frontend resource at OWNER and one physical supply.
fn power() -> PowerStates {
    stela_soc_data::board::fixture_support::power_states_fixture(
        vec![(SUPPLY, 0x100)],
        vec![SUPPLY],
        vec![domain(1, Some(SUPPLY), &[])],
        vec![PowerResource {
            name: "authored-frontend".into(),
            clocks: vec![],
            clock_role: ClockRole::Consumer,
            power: vec![],
            owner: Some(PowerOwner::Mmio(OWNER)),
            admission: Admission::Required,
        }],
    )
}
fn resolve(power: &PowerStates) -> Result<Inputs> {
    Inputs::resolve(power, OWNER, &OWNED)
}
/// Adds a physical domain at `address`, covered by the PMGR block.
fn physical(power: &mut PowerStates, device: u16, address: u64, parents: &[u16]) {
    power.domains.push(domain(device, Some(address), parents));
    power.registers.push(address);
}

#[repr(C, align(16))]
struct Storage(UnsafeCell<[u8; 0x8000]>);
// SAFETY: authored fixture transfers these stable bytes without any PE/DMA.
unsafe impl Sync for Storage {}
fn ram() -> Arc<RegisteredSystemRam> {
    let storage = Arc::new(Storage(UnsafeCell::new([0; 0x8000])));
    let range = ReservedSystemRamRange {
        source_pa: RAM,
        host_pa: 0x400000,
        bytes: 0x8000,
        host_base: NonNull::new(storage.0.get().cast()).unwrap(),
    };
    // SAFETY: exclusive fixture owner, closed synchronous producers only.
    Arc::new(unsafe { fixture(&[range], storage) })
}
fn layout() -> Layout {
    let register = |offset, mask, value| Register {
        offset,
        mask,
        value,
    };
    Layout {
        aperture_bytes: 0x200000,
        planes: 4,
        stride: 0x40000,
        cache_status: None,
        dram_base: RAM,
        groups: [
            Some(LockGroup {
                page_size_shift: 14,
                lower_limit: register(0x680, 0xfffff, 0),
                upper_limit: register(0x688, 0xfffff, 0),
                enable: None,
                write_disable: None,
                lock: None,
            }),
            None,
            None,
            None,
        ],
    }
}

#[test]
fn owner_needs_a_positively_admitted_source_resource() {
    let inputs = resolve(&power()).unwrap();
    assert_eq!(inputs.owner(), OWNER);
    assert_eq!(inputs.resources(), [0]);
    assert!(inputs.is_unswitched());
    let mut absent = power();
    absent.resources.clear();
    assert!(resolve(&absent).is_err());
    let mut unavailable = power();
    unavailable.resources[0].admission = Admission::Unavailable;
    assert!(resolve(&unavailable).is_err());
    let mut elsewhere = power();
    elsewhere.resources[0].owner = Some(PowerOwner::Mmio(OWNER + 0x10000));
    assert!(resolve(&elsewhere).is_err());
    let mut unknown = power();
    unknown.resources[0].power.push(id(9));
    assert!(resolve(&unknown).is_err());
    let mut inventory = power();
    inventory.registers.push(SUPPLY + 8);
    assert!(resolve(&inventory).is_err());
}

#[test]
fn inputs_close_over_same_owner_aliases_and_every_physical_ancestor() {
    let mut power = power();
    physical(&mut power, 2, SUPPLY + 8, &[]);
    power.domains[0].parents[0] = Some(id(2));
    let mut alias = power.resources[0].clone();
    alias.name = "authored-same-owner-alias".into();
    alias.power.push(id(1));
    power.resources.push(alias);
    let inputs = resolve(&power).unwrap();
    assert_eq!(inputs.resources(), [0, 1]);
    assert_eq!(inputs.domains(), [SUPPLY, SUPPLY + 8]);
    assert!(!inputs.is_unswitched());
}

#[test]
fn independently_gated_alias_inside_owned_extents_needs_its_own_join() {
    for (address, owned) in [
        (OWNER + 0x800, true),
        (OWNED[1].0 + 0x3ff8, true),
        (OWNED[1].0 + 0x4000, false),
    ] {
        let mut power = power();
        let mut alias = power.resources[0].clone();
        alias.owner = Some(PowerOwner::Mmio(address));
        alias.clocks.push(id(1));
        power.resources.push(alias);
        assert_eq!(resolve(&power).is_err(), owned);
        // An input-free alias joins nothing.
        power.resources[1].clocks.clear();
        assert!(resolve(&power).is_ok());
    }
}

#[test]
fn physical_parents_cannot_hide_an_unresolved_virtual_ancestor() {
    // A(P, parent V) beside a physical parent, or A(P, parent C), C(Q) and
    // D(Q, parent V): every reached physical key expands ALL its aliases.
    for intermediate in [false, true] {
        let mut graph = power();
        graph.resources[0].clocks.push(id(1));
        let virtual_id = if intermediate {
            graph.domains[0].parents[0] = Some(id(2));
            physical(&mut graph, 2, SUPPLY + 8, &[]);
            graph.domains.push(domain(3, Some(SUPPLY + 8), &[4]));
            4
        } else {
            graph.domains.push(domain(2, Some(SUPPLY), &[3]));
            3
        };
        graph.domains.push(domain(virtual_id, None, &[]));
        assert!(matches!(resolve(&graph), Err(reason)
                if reason.to_string().ends_with("input has an unresolved virtual ancestor")));
        // The same ancestry resolves once V has a physical ancestor.
        let backed = virtual_id + 1;
        let address = SUPPLY + 8 * u64::from(backed);
        graph
            .domains
            .iter_mut()
            .find(|domain| domain.id == id(virtual_id))
            .unwrap()
            .parents[0] = Some(id(backed));
        physical(&mut graph, backed, address, &[]);
        let inputs = resolve(&graph).unwrap();
        assert_eq!(inputs.domains(), graph.registers);
    }
    // A virtual parent with its own physical root resolves; one beside a
    // physical parent but with no root of its own does not.
    let mut graph = power();
    graph.domains.push(domain(2, None, &[]));
    graph.domains.push(domain(3, None, &[1, 2]));
    graph.resources[0].power.push(id(3));
    assert!(resolve(&graph).is_err());
    graph.domains[1].parents[0] = Some(id(1));
    assert_eq!(resolve(&graph).unwrap().domains(), [SUPPLY]);
    // An acyclic raw edge within ONE physical key disappears in normalized
    // coverage; it is not an unresolved virtual requirement.
    let mut same_key = power();
    same_key.resources[0].clocks.push(id(1));
    same_key.domains[0].parents[0] = Some(id(2));
    same_key.domains.push(domain(2, Some(SUPPLY), &[]));
    assert!(resolve(&same_key).is_ok());
}

#[test]
fn owned_mmio_is_disjoint_and_outside_canonical_ram() {
    let ram = ram();
    check_mmio(&ram, &OWNED).unwrap();
    assert!(check_mmio(&ram, &[(OWNER, 0x1000), (OWNER + 0xfff, 0x10)]).is_err());
    assert!(check_mmio(&ram, &[(RAM + 0x7ff0, 0x20)]).is_err());
    assert!(check_mmio(&ram, &[(RAM - 0x10, 0x10), (RAM + 0x8000, 0x10)]).is_ok());
    assert!(check_mmio(&ram, &[(u64::MAX, 2)]).is_err());
}

#[test]
fn programmed_locks_are_page_aligned_inside_the_same_ram() {
    let ram = ram();
    let layout = layout();
    let lock = |range| [Some(range), None, None, None];
    check_locks(&ram, &layout, [None; 4]).unwrap();
    check_locks(&ram, &layout, lock((RAM, 0x8000))).unwrap();
    for range in [
        (RAM, 0),
        (RAM + 0x2000, 0x4000),
        (RAM, 0x6000),
        (RAM + 0x4000, 0x8000),
        (RAM - 0x4000, 0x4000),
    ] {
        assert!(check_locks(&ram, &layout, lock(range)).is_err());
    }
    let mut absent = [None; 4];
    absent[1] = Some((RAM, 0x4000));
    assert!(check_locks(&ram, &layout, absent).is_err());
}

#[test]
fn pinned_ram_refuses_a_failed_generation() {
    let ram = ram();
    let pinned = PinnedRam::new(&ram).unwrap();
    pinned.check().unwrap();
    assert!(Arc::ptr_eq(pinned.ram(), &ram));
    let service = ram.try_service().unwrap().unwrap();
    service.fail();
    drop(service);
    assert!(pinned.check().is_err());
    assert!(PinnedRam::new(&ram).is_err());
    assert!(pinned.into_live().is_err());
}
