//! Staging of FEAT_PAuth_LR effects for commit by the retiring owner.
use crate::{
    memory::{
        domain::{MemoryExecutionLoan, MemoryThread},
        policy::MemoryControls,
    },
    pauth::{
        self,
        lr_effects::{Effect, Evaluation},
        lr_instruction::{Action, Staged},
        lr_service::{BorrowedLinkRegisterService, KeySelection},
    },
    system::{
        process_memory::FixedProcessMemoryControls,
        state::{PacmStateFeature, SystemState},
    },
};
use anyhow::{Context, Result, ensure};
use stela_compiler::{
    GuestAddress, GuestState,
    block::{
        PointerAuthentication, PointerAuthenticationKey as Key,
        PointerAuthenticationModifier as Modifier, PointerAuthenticationOperation as Operation,
    },
};

const ZERO_REGISTER: u8 = 31;
const LOWER_VA47_MASK: u64 = (1 << 47) - 1;
const UPPER_REGION: u64 = 1 << 55;
const TCR_T0SZ_MASK: u64 = 0x3f;
const TCR_VA47_T0SZ: u64 = 17;
const TCR_TBI0: u64 = 1 << 37;
const TCR_TBI1: u64 = 1 << 38;
const TCR_TBID0: u64 = 1 << 51;
const TCR_TBID1: u64 = 1 << 52;

pub(super) fn conditional(operation: Operation) -> bool {
    matches!(
        operation,
        Operation::SignIbSp
            | Operation::AuthenticateIbSp
            | Operation::ReturnIaSp
            | Operation::ReturnIbSp
            | Operation::Sign1716 { .. }
            | Operation::Authenticate1716 { .. }
            | Operation::Sign {
                key: Key::Ia | Key::Ib,
                modifier: Modifier::StackPointer,
                ..
            }
            | Operation::Authenticate {
                key: Key::Ia | Key::Ib,
                modifier: Modifier::StackPointer,
                ..
            }
    )
}

/// Actual source/bank qualification before native entry, without operand checks.
#[allow(clippy::too_many_arguments)]
pub(super) fn service<'a>(
    controls: &'a FixedProcessMemoryControls,
    context: &'a pauth::Context,
    system: &'a SystemState,
    registers: &'a GuestState,
    instruction: PointerAuthentication,
    thread: &MemoryThread<MemoryControls>,
    outer: &'a MemoryExecutionLoan,
) -> Result<BorrowedLinkRegisterService<'a>> {
    let ids = controls
        .identification_snapshot()
        .context("actual LR identification owner unavailable")?;
    let loan = controls
        .extended_controls(ids, thread, outer)
        .map_err(|error| anyhow::anyhow!("actual LR control loan: {error:?}"))?;
    let service = BorrowedLinkRegisterService::new(
        loan,
        context,
        registers,
        instruction.instruction_pc,
        system,
    )
    .map_err(|error| anyhow::anyhow!("actual LR service: {error:?}"))?;
    if let Some(key) = instruction.operation.required_key() {
        let (selected, actual) = match key {
            Key::Ia => (pauth::lr_context::InstructionKey::A, pauth::Key::Ia),
            Key::Ib => (pauth::lr_context::InstructionKey::B, pauth::Key::Ib),
            _ => anyhow::bail!("LR service requires an instruction key"),
        };
        if service.key_selection(selected) == KeySelection::UseKey {
            ensure!(context.has_key(actual), "actual enabled LR key unavailable");
            let (tcr, tcr2) = service.tcr_controls();
            ensure!(
                tcr2 == 0 && tcr & TCR_T0SZ_MASK == TCR_VA47_T0SZ,
                "LR requires actual lower VA47 controls"
            );
            let lower = tcr & TCR_TBI0 != 0 && tcr & TCR_TBID0 == 0;
            let upper = tcr & TCR_TBI1 != 0 && tcr & TCR_TBID1 == 0;
            ensure!(!lower && !upper, "LR instruction TBI controls unsupported");
        }
    }
    Ok(service)
}

pub(crate) struct PreparedEffect {
    effect: Effect,
    continuation: GuestAddress,
    authenticated: Option<bool>,
}
impl PreparedEffect {
    pub(super) fn authenticated(&self) -> Option<bool> {
        self.authenticated
    }
    pub(super) fn continuation(&self) -> GuestAddress {
        self.continuation
    }
    pub(super) fn validate(&self, system: &SystemState) -> Result<()> {
        ensure!(
            system.pacm_state_feature() == PacmStateFeature::Full,
            "actual LR PACM storage changed"
        );
        if let Effect::Register { destination, .. } = self.effect {
            ensure!(destination < ZERO_REGISTER, "invalid staged LR destination");
        }
        Ok(())
    }
    /// Called by the consumer after validation.
    pub(super) fn commit(self, registers: &mut GuestState, system: &mut SystemState) -> Result<()> {
        match self.effect {
            Effect::Register { destination, value } => {
                *registers
                    .x
                    .get_mut(usize::from(destination))
                    .context("staged LR destination changed")? = value;
            }
            Effect::Pacm(value) => system
                .set_pacm(value)
                .map_err(|error| anyhow::anyhow!("actual PACM commit: {error:?}"))?,
            Effect::Return { .. } | Effect::Discard => {}
        }
        Ok(())
    }
}
pub(super) enum Prepared {
    Effect(PreparedEffect),
    AuthenticationFault { code: u8 },
}

/// Stage after the ordinary prefix has run. The selected-key bypass is checked
/// before layout, pointer canonicalization and key lookup, even for high or
/// tagged operands.
pub(super) fn prepare(
    instruction: PointerAuthentication,
    service: &BorrowedLinkRegisterService<'_>,
) -> Result<Prepared> {
    let operands = match instruction.operation {
        Operation::LinkRegister(decoded) => match service
            .stage(decoded)
            .map_err(|error| anyhow::anyhow!("actual LR operands: {error:?}"))?
        {
            Staged::Pointer(value) => Some((value.key, value.action, value.pointer)),
            Staged::Pacm => None,
        },
        operation => service
            .stage_conditional(operation)
            .map_err(|error| anyhow::anyhow!("actual conditional operands: {error:?}"))?
            .map(|value| (value.key, value.action, value.pointer)),
    };
    let mut authenticated = None;
    if let Some((key, action, pointer)) = operands {
        let key = match key {
            pauth::lr_instruction::Key::Ia => pauth::lr_context::InstructionKey::A,
            pauth::lr_instruction::Key::Ib => pauth::lr_context::InstructionKey::B,
        };
        if service.key_selection(key) == KeySelection::UseKey {
            if action != Action::Sign {
                authenticated = Some(true);
            }
            ensure!(
                pointer & UPPER_REGION == 0,
                "upper-region LR pointer unsupported"
            );
            if action == Action::Sign {
                ensure!(
                    pointer & !LOWER_VA47_MASK == 0,
                    "noncanonical lower LR signing input unsupported"
                );
            }
        }
    }
    let result = match instruction.operation {
        Operation::LinkRegister(decoded) => pauth::lr_effects::evaluate(decoded, service),
        operation => pauth::lr_effects::evaluate_conditional(operation, service)
            .and_then(|value| value.ok_or(pauth::lr_effects::Error::InvalidDestination)),
    }
    .map_err(|error| anyhow::anyhow!("actual LR evaluation: {error:?}"))?;
    match result {
        Evaluation::AuthenticationFault { code } => Ok(Prepared::AuthenticationFault { code }),
        Evaluation::Candidate(effect) => {
            let continuation = match effect {
                Effect::Return { target } => target,
                _ => instruction.next_pc,
            };
            Ok(Prepared::Effect(PreparedEffect {
                effect,
                continuation,
                authenticated,
            }))
        }
    }
}

#[cfg(test)]
mod tests;
