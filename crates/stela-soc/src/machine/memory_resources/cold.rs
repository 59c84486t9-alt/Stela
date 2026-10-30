//! Cold placement shared by every SoC's AP memory frontend.
//!
//! A frontend's lifecycle inputs are the complete source power graph's
//! closure over the resources owned at its lifecycle address, sampled from
//! the placed PMGR when the frontend is installed. Its canonical RAM stays
//! pinned to one live generation, and its MMIO and programmed lock ranges are
//! checked against that same RAM. Per SoC only data differs: the lifecycle
//! address and the MMIO extents the frontend owns. Nothing here retires a
//! controller request or claims private PMP/cache readiness.
use crate::Result;
use crate::machine::AppleDevices;
use crate::pmgr;
use crate::pmgr::Pmgr;
use alloc::{sync::Arc, vec, vec::Vec};
use stela_contracts::bus::LifecycleState;
use stela_contracts::bus::Width;
use stela_contracts::refuse;
use stela_engine::memory::RegisteredSystemRam;
use stela_soc_data::amcc::Layout;
use stela_soc_data::amcc::Programmed;
use stela_soc_data::board::PowerOwner;
use stela_soc_data::board::PowerStates;
use stela_soc_data::pmgr::coverage;
use stela_soc_data::pmgr::coverage::Consumer;
use stela_soc_data::pmgr::coverage::LifecycleSinks;

/// The initial state of a new Stela frontend whose source owner has no
/// switched inputs. It is software initialization, never an observed Apple
/// MCC state or a private PMP acknowledgement.
const UNSWITCHED: LifecycleState = LifecycleState {
    powered: true,
    clocked: true,
    quiesced: false,
    reset: false,
    retention: true,
};

/// The canonical RAM a cold plan was prepared over, held at the generation
/// it had then. A later generation is different RAM.
pub struct PinnedRam {
    ram: Arc<RegisteredSystemRam>,
    generation: u64,
}
impl PinnedRam {
    pub fn new(ram: &Arc<RegisteredSystemRam>) -> Result<Self> {
        let generation = ram
            .generation()
            .map_err(|status| refuse!("canonical RAM is not live: {status}", ?status))?;
        Ok(Self {
            ram: Arc::clone(ram),
            generation,
        })
    }
    pub fn check(&self) -> Result<()> {
        let generation = self
            .ram
            .generation()
            .map_err(|status| refuse!("canonical RAM is not live: {status}", ?status))?;
        if generation != self.generation {
            return Err(refuse!(
                "canonical RAM generation changed from {pinned} to {generation}",
                pinned = self.generation,
                generation
            ));
        }
        Ok(())
    }
    pub fn ram(&self) -> &Arc<RegisteredSystemRam> {
        &self.ram
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    /// The RAM, after checking it is still the pinned generation.
    pub fn into_live(self) -> Result<Arc<RegisteredSystemRam>> {
        self.check()?;
        Ok(self.ram)
    }
}

/// Lifecycle inputs of one frontend: the source resources positively owned
/// at its lifecycle address and the physical PMGR domains they close over.
#[derive(Clone)]
pub struct Inputs {
    owner: u64,
    resources: Vec<usize>,
    domains: Vec<u64>,
}
impl Inputs {
    /// Close the complete source graph over the resources owned at `owner`.
    /// `extents` are all MMIO ranges the frontend owns: a resource gated
    /// independently at another address inside them needs a lifecycle join
    /// of its own, which no frontend invents.
    pub fn resolve(power: &PowerStates, owner: u64, extents: &[(u64, u64)]) -> Result<Self> {
        let resources = power
            .resources
            .iter()
            .enumerate()
            .filter_map(|(id, resource)| {
                (resource.owner == Some(PowerOwner::Mmio(owner))).then_some(id)
            })
            .collect::<Vec<_>>();
        if resources.is_empty()
            || resources
                .iter()
                .any(|&id| power.resources[id].admission == coverage::Admission::Unavailable)
        {
            return Err(refuse!(
                "lifecycle owner {owner:#x} has no positively owned source resource",
                owner
            ));
        }
        let requirements = power.power_requirements()?;
        let switched = |id: usize| {
            !power.resources[id].activated_clocks().is_empty() || !requirements[id].is_empty()
        };
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
            .map_err(|error| refuse!("source power graph: {error}", ?error))?;
        if graph.len() != power.registers.len()
            || graph
                .iter()
                .any(|domain| !power.registers.contains(&domain.address))
        {
            return Err(refuse!(
                "source power graph differs from its complete register set"
            ));
        }
        for &id in &resources {
            for &input in power.resources[id]
                .activated_clocks()
                .iter()
                .chain(&requirements[id])
            {
                if !resolved(power, input) {
                    return Err(refuse!(
                        "lifecycle owner {owner:#x} input has an unresolved virtual ancestor",
                        owner
                    ));
                }
            }
        }
        for (id, resource) in power.resources.iter().enumerate() {
            if let Some(PowerOwner::Mmio(address)) = resource.owner
                && address != owner
                && within(extents, address)
                && switched(id)
            {
                return Err(refuse!(
                    "independently gated alias {address:#x} of lifecycle owner {owner:#x} needs its own lifecycle join",
                    address,
                    owner
                ));
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
        if domains.is_empty() && resources.iter().any(|&id| switched(id)) {
            return Err(refuse!(
                "lifecycle owner {owner:#x} inputs have no physical PMGR domain",
                owner
            ));
        }
        Ok(Self {
            owner,
            resources,
            domains,
        })
    }
    pub fn owner(&self) -> u64 {
        self.owner
    }
    pub fn resources(&self) -> &[usize] {
        &self.resources
    }
    pub fn domains(&self) -> &[u64] {
        &self.domains
    }
    /// The source owner has literally no clock or power input, in any alias.
    pub fn is_unswitched(&self) -> bool {
        self.domains.is_empty()
    }
    /// Sample the placed PMGR. Every source register must route to it and
    /// hold state, even for an unswitched frontend: a numerically matching
    /// state table behind absent or foreign routes is not the source PMGR.
    pub fn sample(&self, devices: &AppleDevices, power: &PowerStates) -> Result<LifecycleState> {
        let id = devices
            .pmgr
            .ok_or(refuse!("memory frontend requires the placed PMGR"))?;
        let model = devices
            .bus
            .device::<Pmgr>(id)
            .ok_or(refuse!("memory frontend PMGR has a foreign owner"))?;
        let state = |address: u64| {
            if devices.bus.route(address, Width::Word).ok() != Some((id, address)) {
                return Err(refuse!(
                    "source PMGR register {address:#x} has no actual route",
                    address
                ));
            }
            model.domain_state(address).ok_or_else(|| {
                refuse!(
                    "source PMGR register {address:#x} has no actual state",
                    address
                )
            })
        };
        for &address in &power.registers {
            state(address)?;
        }
        if self.is_unswitched() {
            return Ok(UNSWITCHED);
        }
        let states = self
            .domains
            .iter()
            .map(|&address| state(address))
            .collect::<Result<Vec<_>>>()?;
        // Retention declares that this software backing keeps data on gating.
        // Every other input is the current controller word, never ACTIVE
        // substituted for an absent domain or an asserted reset.
        Ok(LifecycleState {
            powered: states.iter().all(|state| state.power != pmgr::POWER_GATED),
            clocked: states.iter().all(|state| state.power == pmgr::ACTIVE),
            quiesced: states.iter().any(|state| state.disabled),
            reset: states.iter().any(|state| state.reset),
            retention: true,
        })
    }
}

/// Owned MMIO extents are disjoint and lie outside the canonical RAM.
pub fn check_mmio(ram: &RegisteredSystemRam, extents: &[(u64, u64)]) -> Result<()> {
    let ends = extents
        .iter()
        .map(|&(start, bytes)| {
            start
                .checked_add(bytes)
                .ok_or(refuse!("owned MMIO extent {start:#x} wraps", start))
        })
        .collect::<Result<Vec<_>>>()?;
    for (index, &(start, _)) in extents.iter().enumerate() {
        for (&(other, _), &other_end) in extents.iter().zip(&ends).skip(index + 1) {
            if start < other_end && other < ends[index] {
                return Err(refuse!(
                    "owned MMIO extents {start:#x} and {other:#x} overlap",
                    start,
                    other
                ));
            }
        }
    }
    let regions = regions(ram)?;
    for (&(start, _), &end) in extents.iter().zip(&ends) {
        if regions
            .iter()
            .any(|&(source, top)| start < top && source < end)
        {
            return Err(refuse!(
                "owned MMIO extent {start:#x} overlaps canonical RAM",
                start
            ));
        }
    }
    Ok(())
}

/// Every programmed lock range belongs to a present group, is aligned to
/// its page size and lies entirely inside the same canonical RAM.
pub fn check_locks(
    ram: &RegisteredSystemRam,
    layout: &Layout,
    programmed: Programmed,
) -> Result<()> {
    let regions = regions(ram)?;
    for (group, range) in programmed.into_iter().enumerate() {
        let Some((start, bytes)) = range else {
            continue;
        };
        let page = layout.groups[group]
            .ok_or(refuse!("programmed lock group {group} is absent", group))?
            .page_size_shift;
        let page = 1u64.checked_shl(page).ok_or(refuse!(
            "lock group {group} page shift {page} is invalid",
            group,
            page
        ))?;
        let end = start.checked_add(bytes).ok_or(refuse!(
            "lock group {group} range {start:#x} wraps",
            group,
            start
        ))?;
        if bytes == 0 || !start.is_multiple_of(page) || !bytes.is_multiple_of(page) {
            return Err(refuse!(
                "lock group {group} range {start:#x}+{bytes:#x} is empty or not page aligned",
                group,
                start,
                bytes
            ));
        }
        let mut cursor = start;
        for &(source, top) in &regions {
            if source <= cursor && cursor < top {
                cursor = end.min(top);
            }
        }
        if cursor != end {
            return Err(refuse!(
                "lock group {group} range {start:#x}+{bytes:#x} is outside canonical RAM",
                group,
                start,
                bytes
            ));
        }
    }
    Ok(())
}

/// Registered RAM as sorted `[start, end)` regions.
fn regions(ram: &RegisteredSystemRam) -> Result<Vec<(u64, u64)>> {
    let mut regions = ram
        .placements()
        .map(|(source, _, bytes)| {
            source
                .checked_add(bytes as u64)
                .map(|end| (source, end))
                .ok_or(refuse!("canonical RAM region {source:#x} wraps", source))
        })
        .collect::<Result<Vec<_>>>()?;
    if regions.is_empty() {
        return Err(refuse!("canonical RAM has no registered regions"));
    }
    regions.sort_unstable();
    Ok(regions)
}

fn within(extents: &[(u64, u64)], address: u64) -> bool {
    extents
        .iter()
        .any(|&(start, bytes)| address >= start && address - start < bytes)
}

// Match coverage::analyze's normalized graph: all records sharing a physical
// address are ONE key with the union of their parents. Raw virtual IDs stay
// distinct.
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

/// Follow normalized physical aliases and ALL ancestor edges. An unresolved
/// virtual root on any path cannot be masked by one physical parent.
fn resolved(power: &PowerStates, input: coverage::DomainId) -> bool {
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

#[cfg(test)]
mod tests;
