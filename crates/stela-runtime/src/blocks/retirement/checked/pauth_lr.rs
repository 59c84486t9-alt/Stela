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
        .context("LR identification owner unavailable")?;
    let loan = controls
        .extended_controls(ids, thread, outer)
        .map_err(|error| anyhow::anyhow!("LR control loan: {error:?}"))?;
    let service = BorrowedLinkRegisterService::new(
        loan,
        context,
        registers,
        instruction.instruction_pc,
        system,
    )
    .map_err(|error| anyhow::anyhow!("LR service: {error:?}"))?;
    if let Some(key) = instruction.operation.required_key() {
        let (selected, actual) = match key {
            Key::Ia => (pauth::lr_context::InstructionKey::A, pauth::Key::Ia),
            Key::Ib => (pauth::lr_context::InstructionKey::B, pauth::Key::Ib),
            _ => anyhow::bail!("LR service requires an instruction key"),
        };
        if service.key_selection(selected) == KeySelection::UseKey {
            ensure!(context.has_key(actual), "enabled LR key unavailable");
            let (tcr, tcr2) = service.tcr_controls();
            ensure!(
                tcr2 == 0 && tcr & TCR_T0SZ_MASK == TCR_VA47_T0SZ,
                "LR requires lower VA47 controls"
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
            "LR PACM storage changed"
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
                .map_err(|error| anyhow::anyhow!("PACM commit: {error:?}"))?,
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
            .map_err(|error| anyhow::anyhow!("LR operands: {error:?}"))?
        {
            Staged::Pointer(value) => Some((value.key, value.action, value.pointer)),
            Staged::Pacm => None,
        },
        operation => service
            .stage_conditional(operation)
            .map_err(|error| anyhow::anyhow!("conditional operands: {error:?}"))?
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
    .map_err(|error| anyhow::anyhow!("LR evaluation: {error:?}"))?;
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
mod tests {
    use super::*;
    use crate::system::state::{El1Registers, PSTATE_PACM_MASK, Pacm};

    const CONTINUATION: GuestAddress = GuestAddress(0x1004);
    const DESTINATION: u8 = 17;
    const RESULT: u64 = 0x1234;

    fn system(feature: PacmStateFeature) -> SystemState {
        SystemState::new_with_pacm(0, 0x2000, El1Registers::new(1, 2, 3, 4, 5), feature).unwrap()
    }
    fn prepared(effect: Effect) -> PreparedEffect {
        PreparedEffect {
            effect,
            continuation: CONTINUATION,
            authenticated: None,
        }
    }

    #[test]
    fn missing_pacm_storage_refuses_before_register_effect() {
        let state = system(PacmStateFeature::Absent);
        assert!(
            prepared(Effect::Register {
                destination: DESTINATION,
                value: RESULT
            })
            .validate(&state)
            .is_err()
        );
    }

    #[test]
    fn invalid_destination_refuses_before_commit() {
        let state = system(PacmStateFeature::Full);
        assert!(
            prepared(Effect::Register {
                destination: ZERO_REGISTER,
                value: RESULT
            })
            .validate(&state)
            .is_err()
        );
    }

    #[test]
    fn register_effect_preserves_system_flags_and_other_registers() {
        let mut state = system(PacmStateFeature::Full);
        let original_system = state.clone();
        let mut registers = GuestState {
            nzcv: 0xa000_0000,
            sp: 0x3000,
            ..GuestState::default()
        };
        let mut expected = registers.clone();
        expected.x[usize::from(DESTINATION)] = RESULT;
        let effect = prepared(Effect::Register {
            destination: DESTINATION,
            value: RESULT,
        });
        effect.validate(&state).unwrap();
        effect.commit(&mut registers, &mut state).unwrap();
        assert_eq!(registers, expected);
        assert_eq!(state, original_system);
    }

    #[test]
    fn pacm_effect_changes_only_actual_system_pacm() {
        let mut state = system(PacmStateFeature::Full);
        let mut registers = GuestState::default();
        let original = registers.clone();
        let effect = prepared(Effect::Pacm(Pacm::One));
        effect.validate(&state).unwrap();
        effect.commit(&mut registers, &mut state).unwrap();
        assert_eq!(state.pstate_misc(), PSTATE_PACM_MASK);
        assert_eq!(registers, original);
        let expected = SystemState::new_with_pacm(
            PSTATE_PACM_MASK,
            0x2000,
            El1Registers::new(1, 2, 3, 4, 5),
            PacmStateFeature::Full,
        )
        .unwrap();
        assert_eq!(state, expected);
        assert_eq!(state.el1_registers(), &El1Registers::new(1, 2, 3, 4, 5));
    }

    #[test]
    fn return_and_discard_candidates_do_not_write_original_banks() {
        for candidate in [
            Effect::Return {
                target: CONTINUATION,
            },
            Effect::Discard,
        ] {
            let mut state = system(PacmStateFeature::Full);
            let original_system = state.clone();
            let mut registers = GuestState::default();
            let original = registers.clone();
            let effect = prepared(candidate);
            effect.validate(&state).unwrap();
            assert_eq!(effect.continuation(), CONTINUATION);
            effect.commit(&mut registers, &mut state).unwrap();
            assert_eq!(registers, original);
            assert_eq!(state, original_system);
        }
    }
}
