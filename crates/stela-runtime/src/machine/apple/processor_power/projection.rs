//! Physical CPU-domain identities projected through one assigned Plan.
use super::*;
use stela_contracts::identity::Identity;
use stela_contracts::processor::ProcessorTarget;
use stela_engine::machine::engine::ProcessorChange;
use stela_engine::machine::engine::Processors;
use stela_soc_data::board::ProcessorAssociation;
use stela_soc_data::board::assigned::PlanIdentity;
use stela_soc_data::board::assigned::PlannedPe;
use {crate::platform::apple::pmgr::DomainTransition, stela_soc_data::pmgr::coverage::DomainId};

struct Domain {
    identity: DomainId,
    address: u64,
    target: Option<ProcessorTarget>,
    state: DomainState,
}

pub(in crate::machine::apple) struct AssignedPower {
    plan: PlanIdentity,
    domains: Vec<Domain>,
}

pub(super) struct Request {
    plan: PlanIdentity,
    domain: usize,
    pub transition: DomainTransition,
    pub value: u32,
    pub change: Option<ProcessorChange>,
}

fn lifecycle(state: DomainState) -> LifecycleState {
    LifecycleState {
        powered: state.power != POWER_GATED,
        clocked: state.power == ACTIVE,
        quiesced: state.disabled,
        reset: state.reset,
        // CPU supply loss/reset has no implemented kept-state contract.
        // This declares that limitation; it is not a sampled PMGR control bit.
        retention: false,
    }
}

impl AssignedPower {
    pub(super) fn prepare(
        plan: PlanIdentity,
        pes: &[PlannedPe],
        original_regs: &[u32],
        full_profile: &[Identity],
        associations: &[ProcessorAssociation],
        pmgr: &Pmgr,
    ) -> Result<Self, String> {
        if pes.is_empty() || original_regs.len() != full_profile.len() {
            return Err("CPU power source/assigned roster is incomplete".into());
        }
        for (index, reg) in original_regs.iter().enumerate() {
            if original_regs[..index].contains(reg) {
                return Err("CPU power source repeats a physical PE".into());
            }
        }
        let source_indices = pes
            .iter()
            .enumerate()
            .map(|(logical, pe)| {
                let source = original_regs
                    .iter()
                    .position(|&reg| reg == pe.reg)
                    .ok_or("assigned CPU power PE has no original physical node")?;
                if pe.logical != logical || full_profile[source] != pe.identity {
                    return Err("assigned CPU power identity differs from the original PE");
                }
                Ok(source)
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut domains: Vec<Domain> = Vec::with_capacity(associations.len());
        let mut cores = alloc::vec![0; pes.len()];
        let mut complexes = alloc::vec![0; pes.len()];
        for association in associations {
            if domains.iter().any(|domain| {
                domain.identity == association.domain || domain.address == association.address
            }) {
                return Err("CPU power source repeats a domain identity or address".into());
            }
            let original_members = match &association.target {
                ProcessorTarget::Core { pe } => core::slice::from_ref(pe),
                ProcessorTarget::Cluster { members } => members.as_slice(),
            };
            if original_members.is_empty()
                || original_members
                    .iter()
                    .enumerate()
                    .any(|(i, &pe)| pe >= full_profile.len() || original_members[..i].contains(&pe))
            {
                return Err("CPU power source domain membership is incomplete".into());
            }
            let mut members = Vec::new();
            for (logical, &source) in source_indices.iter().enumerate() {
                if !original_members.contains(&source) {
                    continue;
                }
                let (expected, count) = match &association.target {
                    ProcessorTarget::Core { .. } => (pes[logical].core_power, &mut cores[logical]),
                    ProcessorTarget::Cluster { .. } => {
                        (pes[logical].cluster_power, &mut complexes[logical])
                    }
                };
                if association.domain != expected {
                    return Err("assigned CPU power domain differs from its source Plan".into());
                }
                *count += 1;
                members.push(logical);
            }
            let target = match &association.target {
                _ if members.is_empty() => None,
                ProcessorTarget::Core { .. } => Some(ProcessorTarget::Core { pe: members[0] }),
                ProcessorTarget::Cluster { .. } => Some(ProcessorTarget::Cluster { members }),
            };
            domains.push(Domain {
                identity: association.domain,
                address: association.address,
                target,
                state: pmgr
                    .domain_state(association.address)
                    .ok_or("CPU power domain has no actual placed PMGR state")?,
            });
        }
        if cores.iter().chain(&complexes).any(|&count| count != 1) {
            return Err("assigned CPU requires exactly one original core and complex owner".into());
        }
        let assigned = Self { plan, domains };
        // Purely validate the initial state against the existing CPU boundary.
        // In particular a supply-off/reset model state cannot be hidden
        // by substituting a fixture ACTIVE state before binding the Machine.
        Processors::new(pes.len())
            .and_then(|processors| {
                processors
                    .prepare_bindings(&assigned.bindings())
                    .map(|_| ())
            })
            .map_err(|e| format!("placed initial CPU lifecycle is unsupported: {e:?}"))?;
        Ok(assigned)
    }

    pub(super) fn bindings(&self) -> Vec<ProcessorBinding> {
        self.domains
            .iter()
            .filter_map(|domain| {
                Some(ProcessorBinding {
                    // Preserve the canonical physical domain identity without
                    // conflating a DeviceID/address, source PE or dense PE.
                    domain: u64::from(domain.identity.die) << 16
                        | u64::from(domain.identity.device),
                    target: domain.target.clone()?,
                    initial: lifecycle(domain.state),
                })
            })
            .collect()
    }

    pub(super) fn contains(&self, physical: u64) -> bool {
        self.domains.iter().any(|domain| domain.address == physical)
    }

    pub(super) fn preview(
        &self,
        pmgr: &Pmgr,
        physical: u64,
        value: u32,
    ) -> Result<Request, DeviceError> {
        let domain = self
            .domains
            .iter()
            .position(|d| d.address == physical)
            .expect("classified original CPU domain");
        let bound = &self.domains[domain];
        let transition = pmgr.preview(physical, value).map_err(|reason| {
            DeviceError::Refused(format!(
                "CPU PMGR {:?} at {physical:#x}: {reason}",
                bound.identity
            ))
        })?;
        if transition.before != bound.state {
            return Err(DeviceError::TransferRefused(
                "CPU PMGR model changed outside its actual processor transaction".into(),
            ));
        }
        if bound.target.is_none() && transition.before != transition.after {
            return Err(DeviceError::TransferRefused(format!(
                "CPU PMGR {:?} at {physical:#x} belongs only to unassigned physical PEs",
                bound.identity
            )));
        }
        Ok(Request {
            plan: self.plan.clone(),
            domain,
            transition,
            value,
            change: bound.target.as_ref().map(|_| ProcessorChange {
                domain: u64::from(bound.identity.die) << 16 | u64::from(bound.identity.device),
                state: lifecycle(transition.after),
            }),
        })
    }

    pub(super) fn committed(&mut self, request: &Request) {
        assert_eq!(self.plan, request.plan, "same retained assigned Plan");
        let domain = &mut self.domains[request.domain];
        assert_eq!(
            domain.state, request.transition.before,
            "exclusive CPU PMGR request"
        );
        domain.state = request.transition.after;
    }
}

#[cfg(test)]
pub(super) mod tests;
