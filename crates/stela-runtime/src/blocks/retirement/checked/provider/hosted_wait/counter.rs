//! Counter and frequency reads (MRS) served by the hosted system counter.
use super::HostedWaitResources;
use crate::{
    blocks::retirement::checked::el1_system::El1PlatformControls,
    system::{
        access::{AccessKind, Request, Resolution},
        state::SystemState,
        timer::{self, Register},
    },
};
use stela_compiler::{
    aarch64::system::registers::Direction,
    block::system::{SystemInstruction, SystemOperation},
};

/// A prepared read; Active alone writes the register and PC.
pub(crate) struct HostedCounterRead {
    instruction: SystemInstruction,
    destination: u8,
    value: u64,
}
impl HostedCounterRead {
    pub(in crate::blocks::retirement::checked) fn instruction(&self) -> SystemInstruction {
        self.instruction
    }
    pub(in crate::blocks::retirement::checked) fn destination(&self) -> u8 {
        self.destination
    }
    pub(in crate::blocks::retirement::checked) fn value(&self) -> u64 {
        self.value
    }
}

/// Recognize the access before sampling the counter. Unknown selectors,
/// writes and ECV self-synchronized forms are left to other owners.
pub(in crate::blocks::retirement::checked) fn is_ordinary_counter_read(
    instruction: SystemInstruction,
) -> bool {
    let SystemOperation::Register(access) = instruction.operation else {
        return false;
    };
    access.direction() == Direction::Read
        && matches!(
            timer::decode(access.encoding()),
            Some(Register::CntfrqEl0 | Register::CntpctEl0 | Register::CntvctEl0)
        )
}

impl HostedWaitResources<'_> {
    pub(in crate::blocks::retirement::checked) fn prepare_counter_read(
        &mut self,
        instruction: SystemInstruction,
        platform: &El1PlatformControls,
        system: &SystemState,
    ) -> anyhow::Result<HostedCounterRead> {
        anyhow::ensure!(
            is_ordinary_counter_read(instruction)
                && instruction.matches_source(instruction.instruction_pc, instruction.word),
            "source is not an exact ordinary counter read"
        );
        let SystemOperation::Register(access) = instruction.operation else {
            unreachable!()
        };
        let context = platform.timer_context(system)?;
        let request = Request::read(access.encoding(), access.rt());
        // Access and feature checks come before sampling, even for XZR.
        let Resolution::BackendRequired(backend) = timer::resolve(request, &context) else {
            anyhow::bail!("timer resolver declined the counter request");
        };
        anyhow::ensure!(
            matches!(request.kind, AccessKind::Read),
            "counter write is not admitted"
        );
        let value = self
            .counter_view()
            .map_err(|error| anyhow::anyhow!("counter view: {error:?}"))?
            .read(backend)
            .map_err(|error| anyhow::anyhow!("counter read: {error:?}"))?;
        Ok(HostedCounterRead {
            instruction,
            destination: access.rt(),
            value,
        })
    }
}
