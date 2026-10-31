//! Unsupported operations: their requirements, the degraded answers and their
//! reports.

use super::*;

impl<H: Host, D: Devices> Machine<H, D> {
    pub(super) fn requirement(&self, kind: RequirementKind) -> Requirement {
        Requirement {
            pc: self.cpu.pc,
            el: self.cpu.pstate.el,
            link: self.cpu.state.x[30],
            kind,
            syndrome: None,
            address: None,
            written: None,
        }
    }

    pub(super) fn unsupported(&self, kind: RequirementKind) -> Stop {
        Stop::Unsupported(self.requirement(kind))
    }

    /// The operations since the last call that were answered degraded, each
    /// distinct one reported the first time only, for the boot log.
    pub fn take_unmodeled(&mut self) -> Vec<Requirement> {
        core::mem::take(&mut self.unmodeled)
    }

    /// The policy point for an operation this machine cannot carry out in
    /// full (docs/design/runtime.md "Unsupported operations"): count it
    /// (`Statistics::degraded`) and report it the first time (device
    /// accesses once per register, direction and refusal); the caller then
    /// gives the degraded response of its tier.
    pub(super) fn degrade(&mut self, requirement: Requirement) {
        self.statistics.degraded += 1;
        let first = match &requirement.kind {
            RequirementKind::Device {
                physical,
                write,
                detail,
            } => {
                // One register can carry many operations, each refused for
                // its own reason; a register whose refusals name changing
                // values in their detail reports its first few.
                let refusals = self
                    .degraded_devices
                    .entry((*physical, *write))
                    .or_default();
                refusals.len() < DEVICE_REFUSALS_REPORTED && refusals.insert(detail.clone())
            }
            kind if self.unmodeled_met.contains(kind) => false,
            kind => {
                self.unmodeled_met.push(kind.clone());
                true
            }
        };
        if first {
            self.unmodeled.push(requirement);
        }
    }

    /// The answer to an instruction the engine cannot execute,
    /// at the run loop: the UNDEFINED exception at its PC, which an Apple CPU
    /// takes for an encoding it does not implement. Only a stop raised
    /// before the instruction's effects (the PE still at its PC and EL) on a
    /// serially executing PE checks; every other stop stands.
    pub(super) fn undefined_instead(&mut self, stop: Stop) -> Step {
        let Stop::Unsupported(requirement) = stop else {
            return Err(stop);
        };
        let instruction = matches!(
            requirement.kind,
            RequirementKind::Instruction { .. }
                | RequirementKind::SystemInstruction { .. }
                | RequirementKind::SystemRegister { .. }
        );
        if !instruction
            || requirement.pc != self.cpu.pc
            || requirement.el != self.cpu.pstate.el
            || self.canonical_memory_serves()
            || self.pending_native_device_access().is_some()
        {
            return Err(Stop::Unsupported(requirement));
        }
        self.degrade(requirement);
        self.undefined()
    }

    pub(super) fn undefined(&mut self) -> Step {
        self.take(Exception::undefined(self.cpu.pc));
        Ok(())
    }

    pub(super) fn refuse_system(&self, word: u32, detail: &'static str) -> Stop {
        self.unsupported(RequirementKind::SystemInstruction { word, detail })
    }
}
