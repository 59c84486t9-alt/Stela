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
use super::mcc;
use crate::machine::apple::AppleDevices;
use crate::platform::apple::pmgr;
use crate::platform::apple::pmgr::Pmgr;
use crate::platform::apple::ptd;
use alloc::{format, string::String, sync::Arc, vec, vec::Vec};
use stela_contracts::Chip;
use stela_contracts::bus::LifecycleState;
use stela_contracts::bus::Width;
use stela_engine::memory::RegisteredSystemRam;
use stela_soc_data::board::Board;
use stela_soc_data::board::DirectMemoryCache;
use stela_soc_data::board::MemoryController;
use stela_soc_data::board::PowerOwner;
use stela_soc_data::board::PowerStates;
use stela_soc_data::pmgr::coverage;
use stela_soc_data::pmgr::coverage::Consumer;
use stela_soc_data::pmgr::coverage::LifecycleSinks;

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
    programmed: stela_soc_data::amcc::Programmed,
    configuration: Configuration,
}
impl Plan {
    pub fn prepare_ap_frontend(
        board: &Board,
        ram: &Arc<RegisteredSystemRam>,
        programmed: stela_soc_data::amcc::Programmed,
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
        programmed: stela_soc_data::amcc::Programmed,
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
    /// Before consuming mount inputs, require the complete live source
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
        // new_local keeps the SAME notification receiver in owner;
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
    // Only one registered lifecycle identity may own this device. An
    // independently gated alias in the same full aperture needs a checked
    // additional join, not silent omission or an invented aggregate ACK.
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
// Match coverage::analyze's normalized graph: all records sharing a
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
        || address >= direct.ptd.physical
            && address - direct.ptd.physical < stela_soc_data::ptd::PTD_BYTES
}
fn geometry(
    controller: &MemoryController,
    direct: &DirectMemoryCache,
    ram: &RegisteredSystemRam,
    programmed: stela_soc_data::amcc::Programmed,
) -> Result<(), String> {
    direct.validate(controller).map_err(String::from)?;
    if direct.ptd_entries != ptd::transport::notifications::NativeProfile::T6000.entries() as usize
        || direct.ptd_updates.1 != 0xc00
        || controller.layout.cache_status
            != Some(stela_soc_data::amcc::Register {
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
            || direct.ptd.physical < end
                && source < direct.ptd.physical + stela_soc_data::ptd::PTD_BYTES
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
mod tests;
