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
//! disable_mcc command/waiter evidence is retained in t6000-mcc-backend-20261021-1.
use super::{Prepared, amcc, mcc, ptd};
use crate::{
    machine::{
        Chip,
        apple::AppleDevices,
        soc::{Board, DirectMemoryCache, MemoryController, PowerOwner, PowerStates},
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

/// Entire new-software control image, independent of RAM capacity and opaque
/// DT config-data/alternate dramcfg-data. Every weight is an explicit policy.
/// Caller must publish the source-supported real -disable_mcc boot argument
/// before original entry; constructing this cacheless resource proves no flag.
#[derive(Clone)]
pub struct Configuration {
    image: mcc::Configuration,
}
impl Configuration {
    pub fn zeroed_control_image(apertures: usize, weights: [u8; 32]) -> Result<Self, String> {
        mcc::Configuration::zeroed_control_image(apertures, weights)
            .map(|image| Self { image })
            .map_err(String::from)
    }
    /// Explicit caller-owned full initial words. No DT field is interpreted as
    /// density, and no saved word is silently replaced by an alternate mode.
    pub fn declared_control_image(
        controls: Vec<[u32; 4]>,
        weights: [u8; 32],
    ) -> Result<Self, String> {
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
    domains: Vec<u64>,
    ram: Arc<RegisteredSystemRam>,
    generation: u64,
    programmed: amcc::Programmed,
    configuration: Configuration,
}
impl Plan {
    pub fn prepare_ap_frontend(
        board: &Board,
        ram: &Arc<RegisteredSystemRam>,
        programmed: amcc::Programmed,
        configuration: &Configuration,
    ) -> Result<Self, String> {
        if board.cpus.chip != Chip::AppleM1 || board.memory_cache.is_some() {
            return Err("cold T6000 direct memory requires its own source family".into());
        }
        Self::prepare_resources(
            board
                .memory_controller
                .as_ref()
                .ok_or("cold T6000 has no actual AMCC descriptor")?,
            board
                .direct_memory_cache
                .as_ref()
                .ok_or("cold T6000 has no direct MCC descriptor")?,
            board
                .power_states
                .as_ref()
                .ok_or("cold T6000 has no complete source power graph")?,
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
        programmed: amcc::Programmed,
        configuration: &Configuration,
    ) -> Result<Self, String> {
        geometry(controller, direct, ram, programmed)?;
        if configuration.controls().len() != direct.apertures.len() {
            return Err(
                "cold T6000 requires all channel control words for every actual aperture".into(),
            );
        }
        let domains = power_domains(power, direct)?;
        let generation = ram
            .domain()
            .generation()
            .map_err(|e| format!("cold T6000 RAM is not live: {e:?}"))?;
        Ok(Self {
            controller: controller.clone(),
            direct: direct.clone(),
            power: power.clone(),
            domains,
            ram: Arc::clone(ram),
            generation,
            programmed,
            configuration: configuration.clone(),
        })
    }
    /// Before consuming mount inputs, require the actual complete live source
    /// descriptors. Parsing alone never admits canonical memory execution.
    pub fn validate(
        &self,
        controller: Option<&MemoryController>,
        direct: Option<&DirectMemoryCache>,
    ) -> Result<(), String> {
        if controller != Some(&self.controller) || direct != Some(&self.direct) {
            return Err("cold T6000 differs from the actual live memory descriptors".into());
        }
        self.validate_ram()
    }
    pub fn validate_power(&self, power: Option<&PowerStates>) -> Result<(), String> {
        if power != Some(&self.power) {
            return Err("cold T6000 differs from the complete source power graph".into());
        }
        Ok(())
    }
    pub fn registered_ram(&self) -> &Arc<RegisteredSystemRam> {
        &self.ram
    }
    pub fn descriptor(&self) -> &DirectMemoryCache {
        &self.direct
    }
    pub const fn requires_disable_mcc(&self) -> bool {
        true
    }
    fn validate_ram(&self) -> Result<(), String> {
        if self
            .ram
            .domain()
            .generation()
            .map_err(|e| format!("cold T6000 RAM is not live: {e:?}"))?
            != self.generation
        {
            return Err("cold T6000 RAM generation changed before publication".into());
        }
        Ok(())
    }
    fn lifecycle(&self, devices: &AppleDevices) -> Result<LifecycleState, String> {
        self.validate_ram()?;
        let id = devices
            .pmgr
            .ok_or("cold T6000 requires the actual placed PMGR")?;
        let model = devices
            .bus
            .device::<Pmgr>(id)
            .ok_or("cold T6000 has a foreign PMGR owner")?;
        if self
            .power
            .registers
            .iter()
            .any(|&address| model.domain_state(address).is_none())
        {
            return Err("cold T6000 PMGR omits part of the retained source graph".into());
        }
        if self.domains.is_empty() {
            // power_domains already proved literal input absence in every
            // same-owner alias and rejected unresolved/virtual requests.
            // These are initialized properties of this NEW, same-RAM Stela AP
            // frontend, never sampled Apple state or private PMP completion.
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
                if devices.bus.route(address, Width::Word).ok() != Some((id, address)) {
                    return Err(format!(
                        "T6000 memory input {address:#x} has no actual PMGR route"
                    ));
                }
                model
                    .domain_state(address)
                    .ok_or_else(|| format!("T6000 memory input {address:#x} has no actual state"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(LifecycleState {
            powered: states.iter().all(|s| s.power != pmgr::POWER_GATED),
            clocked: states.iter().all(|s| s.power == pmgr::ACTIVE),
            quiesced: states.iter().any(|s| s.disabled),
            reset: states.iter().any(|s| s.reset),
            retention: true,
        })
    }
    /// After PMGR placement, before display aliases/powerconnect/first guest.
    /// All physical guest/native/DMA writers remain excluded during this cold
    /// construction. Later drains/clears require the real live canonical hold;
    /// a successful placement does not provide that hold or settle requests.
    pub fn install(self, devices: &mut AppleDevices) -> Result<(), String> {
        if devices.power_configured
            || devices.memory_controller.is_some()
            || devices.memory_publication.is_some()
        {
            return Err("cold T6000 requires an unoccupied unconnected memory mount".into());
        }
        let lifecycle = self.lifecycle(devices)?;
        let physical = self.direct.apertures[0];
        let (owner, _) = Prepared::new_local(
            self.direct,
            &self.controller,
            self.programmed,
            self.configuration.image,
            lifecycle,
        )
        .map_err(String::from)?;
        // new_local retains the SAME actual notification receiver in owner;
        // no callback/service/IRQ binding is manufactured or discarded here.
        let owner = owner.with_registered_ram(self.ram).map_err(String::from)?;
        devices.add_memory_resources(owner)?;
        let id = devices
            .memory_controller
            .ok_or("cold T6000 lost the installed joint owner")?;
        devices.register_power_device(physical, id, true)
    }
}

/// Whole ancestor/implicit closure, including every same-owner alias. Model
/// registry sinks remain separate; computing this metadata claims no completion.
fn power_domains(power: &PowerStates, direct: &DirectMemoryCache) -> Result<Vec<u64>, String> {
    let physical = direct.apertures[0];
    let resources = power
        .resources
        .iter()
        .enumerate()
        .filter(|(_, r)| r.owner == Some(PowerOwner::Mmio(physical)))
        .map(|(id, _)| id)
        .collect::<Vec<_>>();
    if resources.is_empty()
        || resources
            .iter()
            .any(|&id| power.resources[id].admission == coverage::Admission::Unavailable)
    {
        return Err("cold T6000 MCC has no positively placed source lifecycle resource".into());
    }
    let requirements = power.power_requirements()?;
    let consumers = power
        .resources
        .iter()
        .enumerate()
        .map(|(id, r)| Consumer {
            id,
            name: &r.name,
            clocks: r.activated_clocks(),
            power: &requirements[id],
            admission: r.admission,
            sinks: LifecycleSinks::default(),
        })
        .collect::<Vec<_>>();
    let coverage = coverage::analyze(&power.domains, &consumers)
        .map_err(|e| format!("cold T6000 source coverage: {e:?}"))?;
    if coverage.len() != power.registers.len()
        || coverage
            .iter()
            .any(|d| !power.registers.contains(&d.address))
    {
        return Err("cold T6000 source coverage differs from its complete register set".into());
    }
    for &id in &resources {
        for &input in power.resources[id]
            .activated_clocks()
            .iter()
            .chain(&requirements[id])
        {
            if !resolved_input(power, input) {
                return Err("cold T6000 requested input has an unresolved virtual ancestor".into());
            }
        }
    }
    // Only one registered lifecycle identity may own this actual device. An
    // independently gated alias in the same full aperture needs a qualified
    // additional join, not silent omission or a fabricated aggregate ACK.
    for (id, resource) in power.resources.iter().enumerate() {
        if let Some(PowerOwner::Mmio(address)) = resource.owner
            && address != physical
            && contains(direct, address)
            && (!resource.activated_clocks().is_empty() || !requirements[id].is_empty())
        {
            return Err(
                "cold T6000 overlapping alias requires its own actual lifecycle join".into(),
            );
        }
    }
    let domains = coverage
        .iter()
        .filter(|d| d.consumers.iter().any(|c| resources.contains(&c.id)))
        .map(|d| d.address)
        .collect::<Vec<_>>();
    if domains.is_empty()
        && resources
            .iter()
            .any(|&id| !power.resources[id].clocks.is_empty() || !requirements[id].is_empty())
    {
        return Err("cold T6000 requested inputs have no physical lifecycle owner".into());
    }
    Ok(domains)
}
// Match coverage::analyze's actual normalized graph: all records sharing a
// physical address are ONE key with the union of their parents. Raw virtual
// IDs remain distinct. Missing IDs/raw cycles/alias cycles were checked above.
#[derive(Clone, Copy, PartialEq, Eq)]
enum InputKey {
    Physical(u64),
    Virtual(coverage::DomainId),
}
fn input_key(domain: &coverage::Domain) -> InputKey {
    domain
        .address
        .map_or(InputKey::Virtual(domain.id), InputKey::Physical)
}
fn resolved_input(power: &PowerStates, input: coverage::DomainId) -> bool {
    let mut pending = vec![input];
    let mut seen = Vec::new();
    let mut physical = false;
    while let Some(id) = pending.pop() {
        let Some(domain) = power.domains.iter().find(|d| d.id == id) else {
            return false;
        };
        let key = input_key(domain);
        if seen.contains(&key) {
            continue;
        }
        seen.push(key);
        let mut parents = Vec::new();
        for alias in power.domains.iter().filter(|d| input_key(d) == key) {
            for &parent_id in alias.parents.iter().flatten() {
                let Some(parent) = power.domains.iter().find(|d| d.id == parent_id) else {
                    return false;
                };
                if input_key(parent) != key {
                    parents.push(parent_id);
                }
            }
        }
        match key {
            InputKey::Physical(_) => physical = true,
            InputKey::Virtual(_) if parents.is_empty() => return false,
            InputKey::Virtual(_) => {}
        }
        pending.extend(parents);
    }
    physical
}
fn contains(direct: &DirectMemoryCache, address: u64) -> bool {
    direct
        .apertures
        .iter()
        .any(|&start| address >= start && address - start < mcc::APERTURE_BYTES)
        || address >= direct.ptd.physical && address - direct.ptd.physical < ptd::PTD_BYTES
}
fn geometry(
    controller: &MemoryController,
    direct: &DirectMemoryCache,
    ram: &RegisteredSystemRam,
    programmed: amcc::Programmed,
) -> Result<(), String> {
    direct.validate(controller).map_err(String::from)?;
    if direct.ptd_entries != ptd::transport::notifications::NativeProfile::T6000.entries() as usize
        || direct.ptd_updates.1 != 0xc00
        || controller.layout.cache_status
            != Some(amcc::Register {
                offset: 0x1c00,
                mask: 0x1f,
                value: 0,
            })
    {
        return Err(
            "cold T6000 requires its source PTD geometry and shared way-command status".into(),
        );
    }
    for (source, _, bytes) in ram.placements() {
        let end = source
            .checked_add(bytes as u64)
            .ok_or("cold T6000 RAM wraps")?;
        if direct
            .apertures
            .iter()
            .any(|&p| p < end && source < p + mcc::APERTURE_BYTES)
            || direct.ptd.physical < end && source < direct.ptd.physical + ptd::PTD_BYTES
        {
            return Err("cold T6000 MMIO overlaps the actual canonical RAM".into());
        }
    }
    for (group, range) in programmed.iter().enumerate() {
        let Some((start, bytes)) = *range else {
            continue;
        };
        if controller.layout.groups[group].is_none() {
            return Err("cold T6000 cannot discard a programmed absent lock group".into());
        }
        let end = start.checked_add(bytes).ok_or("cold T6000 lock wraps")?;
        if bytes == 0 || !start.is_multiple_of(1 << 14) || !bytes.is_multiple_of(1 << 14) {
            return Err("cold T6000 lock is empty or not source-page aligned".into());
        }
        let mut cursor = start;
        for (source, _, bytes) in ram.placements() {
            let top = source
                .checked_add(bytes as u64)
                .ok_or("cold T6000 RAM wraps")?;
            if source <= cursor && cursor < top {
                cursor = end.min(top);
            }
            if cursor == end {
                break;
            }
        }
        if cursor != end {
            return Err("cold T6000 lock is outside the same canonical RAM".into());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        machine::soc::{ClockRole, PowerResource},
        memory::{ReservedSystemRamRange, source_ram::system::fixture},
        platform::apple::{
            bus::Access,
            interrupt::InterruptLatch,
            pmgr::{
                PowerState,
                coverage::{Admission, Domain, DomainId},
            },
        },
    };
    use alloc::{boxed::Box, vec};
    use core::{cell::UnsafeCell, ptr::NonNull};
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
        let controller = MemoryController {
            apertures: original.descriptor().apertures.clone(),
            layout: original.router.lock_layout,
        };
        let direct = original.descriptor().clone();
        let power = PowerStates {
            blocks: vec![(SUPPLY, 8)],
            registers: vec![SUPPLY],
            domains: vec![Domain {
                name: "authored-separate-PMP-supply".into(),
                id: id(),
                address: Some(SUPPLY),
                parents: [None; 4],
            }],
            resources: vec![PowerResource {
                name: "/arm-io/mcc".into(),
                clocks: vec![],
                clock_role: ClockRole::Consumer,
                power: vec![],
                owner: Some(PowerOwner::Mmio(direct.apertures[0])),
                admission: Admission::Required,
            }],
            implicit: vec![],
        };
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
    fn input_free_source_installs_one_same_ram_joint_owner_with_actual_local_ptd() {
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
            (joint, offset + ptd::UPDATE_OFFSET)
        );
        assert_eq!(bank, direct.ptd.physical);
        assert_eq!(
            owner.read_pair_values(offset, 8, &mut access).unwrap()[0],
            0x1122334455667788
        );
        assert_eq!(owner.local_notifications().unwrap().asserted(), 0); // No IRQ enable or event invented.
    }
    #[test]
    fn switched_input_samples_actual_pmgr_and_preserves_clock_gating() {
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
                Err(reason) if reason == "cold T6000 requested input has an unresolved virtual ancestor")
            );
            // The same alias ancestry is supported when V actually resolves
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
        let mut bad = direct.clone();
        bad.ptd_entries = 377;
        assert!(
            Plan::prepare_resources(&controller, &bad, &power, &ram, [None; 4], &config).is_err()
        );
        let mut bad = direct.clone();
        bad.ptd_updates.1 = 0x1000;
        assert!(
            Plan::prepare_resources(&controller, &bad, &power, &ram, [None; 4], &config).is_err()
        );
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
        assert!(
            Plan::prepare_resources(&controller, &direct, &power, &ram, outside, &config).is_err()
        );
        let short = Configuration::zeroed_control_image(1, [1; 32]).unwrap();
        assert!(
            Plan::prepare_resources(&controller, &direct, &power, &ram, [None; 4], &short).is_err()
        );
        let plan = Plan::prepare_resources(&controller, &direct, &power, &ram, [None; 4], &config)
            .unwrap();
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
    #[ignore = "requires original J314s ADT and mac13j KC via STELA_T6000_MCC_DEVICE_TREE/STELA_TEST_MCC_KERNELCACHE"]
    fn original_j314s_input_free_frontend_and_opaque_control_consumers_are_pinned() {
        use crate::machine::adt::Node;
        let tree = std::fs::read(std::env::var("STELA_T6000_MCC_DEVICE_TREE").unwrap()).unwrap();
        assert_eq!(
            crate::sha256(&tree),
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
            crate::sha256(&kernel),
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
            assert_eq!(crate::sha256(&kernel[start..start + bytes]), expected);
        }
    }
}
