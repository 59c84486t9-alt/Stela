//! MSR (immediate) to PSTATE fields.

use super::{CommitError, Effect};
use crate::system::{
    access::{Request, Resolution},
    pstate::Context,
    state::SystemState,
};
use stela_compiler::{
    GuestAddress, GuestState,
    block::system::{SystemInstruction, SystemOperation},
};

pub(crate) mod el1_daif;

const ZERO_REGISTER: u8 = 31;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceError {
    WrongSource,
    NotImmediate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Source(SourceError),
    Commit(CommitError),
}

/// A pending decision, keeping its request for trap syndromes and backend
/// dispatch; nothing has been applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completion {
    Complete {
        next_pc: GuestAddress,
    },
    Uncompleted {
        request: Request,
        decision: Resolution<Effect>,
    },
}

/// Re-check the descriptor against the source bytes before using its immediate.
/// CRm is the operand; no GPR is read.
pub fn request(
    instruction: SystemInstruction,
    source_pc: GuestAddress,
    source_word: u32,
) -> Result<Request, SourceError> {
    if !instruction.matches_source(source_pc, source_word) {
        return Err(SourceError::WrongSource);
    }
    let SystemOperation::PstateImmediate(encoding) = instruction.operation else {
        return Err(SourceError::NotImmediate);
    };
    Ok(Request::write(encoding, ZERO_REGISTER, 0))
}

/// Complete the effects the state owner can apply alone. Undefined, Trap,
/// NotHandled and backend decisions stay unapplied. DAIF needs the asynchronous
/// boundary owner after commit, which a PSTATE snapshot does not provide, so
/// the runtime must dispatch it before allowing the change.
pub fn complete(
    instruction: SystemInstruction,
    source_pc: GuestAddress,
    source_word: u32,
    context: &Context,
    system: &mut SystemState,
    registers: &mut GuestState,
) -> Result<Completion, Error> {
    let request = request(instruction, source_pc, source_word).map_err(Error::Source)?;
    let decision = super::resolve(request, context, system, registers);
    match decision {
        Resolution::BackendRequired(effect @ Effect::SpSelect { .. }) => {
            super::commit(effect, system, registers).map_err(Error::Commit)?;
            Ok(Completion::Complete {
                next_pc: instruction.next_pc,
            })
        }
        decision => Ok(Completion::Uncompleted { request, decision }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::system::{
        access::{ExceptionLevel, Profile, SecurityState, Trap},
        pstate::{self, Controls, Features, MteFeature, SsbsFeature, ThreadIdTrapBits},
        state::{El1Registers, PSTATE_EL0T, PSTATE_EL1H, PSTATE_EL1T, StackBank},
    };
    use stela_compiler::block::system::decode_system_instruction;

    const BASE: GuestAddress = GuestAddress(0x1000);
    const SP0: u64 = 0x1234_5678_9abc_def1;
    const SP1: u64 = 0xfedc_ba98_7654_3213;
    const FLAGS: u32 = 0xa123_4567;
    const SPSEL: u32 = 0xd500_40bf;
    const DAIF_SET: u32 = 0xd503_40df;
    const DAIF_CLEAR: u32 = 0xd503_40ff;
    const DIT: u32 = 0xd503_405f;
    const NZCV_READ: u32 = 0xd53b_4200;
    const CRM_SHIFT: u32 = 8;
    const OPERAND_MAX: u8 = 15;
    const INSTRUCTION_BYTES: u64 = std::mem::size_of::<u32>() as u64;

    fn context(level: ExceptionLevel) -> Context {
        let no_traps = ThreadIdTrapBits {
            el0: false,
            read_only_el0: false,
            el1: false,
        };
        Context {
            profile: Profile {
                current_el: level,
                security: SecurityState::NonSecure,
                el2_enabled: false,
                el3_present: false,
            },
            features: Features {
                aa64: true,
                pan: false,
                uao: false,
                dit: false,
                ssbs: SsbsFeature::Absent,
                mte: MteFeature::Absent,
                fine_grained_traps: false,
            },
            controls: Controls {
                el0_in_host: false,
                sctlr_el1_uma: true,
                hcr_el2_tge: false,
                effective_hcr_el2_nvx: 0,
                scr_el3_fgt_enable: false,
                thread_id_read_traps: no_traps,
                thread_id_write_traps: no_traps,
            },
        }
    }

    fn state(mode: u64) -> (SystemState, GuestState) {
        let system = SystemState::new(
            mode | pstate::DAIF_MASK,
            SP0,
            El1Registers::new(1, 2, 3, 4, 5),
        )
        .unwrap();
        let registers = GuestState {
            x: std::array::from_fn(|index| (index as u64).wrapping_mul(0x0101_0101_0101_0101)),
            sp: SP1,
            nzcv: FLAGS,
            reserved: 0xdead_beef,
            v: std::array::from_fn(|index| [index as u64, !(index as u64)]),
            fpcr: 0x1234_5678,
            fpsr: 0x8765_4321,
        };
        (system, registers)
    }

    fn instruction(word: u32) -> SystemInstruction {
        decode_system_instruction(BASE, word).unwrap().unwrap()
    }

    #[test]
    fn source_request_preserves_all_immediate_bits_without_sampling_gprs() {
        for base in [SPSEL, DAIF_SET, DAIF_CLEAR, DIT] {
            for operand in 0..=OPERAND_MAX {
                let word = base | (u32::from(operand) << CRM_SHIFT);
                let request = request(instruction(word), BASE, word).unwrap();
                assert_eq!(request.encoding.crm(), operand);
                assert_eq!(request.rt, ZERO_REGISTER);
                assert_eq!(request.write_value(), Some(0));
            }
        }
    }

    #[test]
    fn source_forgery_precedes_context_checks_and_every_effect() {
        let (mut system, mut registers) = state(PSTATE_EL1H);
        let before = (system.clone(), registers.clone());
        let context = context(ExceptionLevel::El0);
        let original = instruction(SPSEL);
        let mut forged = original;
        forged.next_pc = BASE;
        for (descriptor, pc, word) in [
            (forged, BASE, SPSEL),
            (original, GuestAddress(BASE.0 + INSTRUCTION_BYTES), SPSEL),
            (original, BASE, SPSEL ^ (1 << CRM_SHIFT)),
        ] {
            assert_eq!(
                complete(descriptor, pc, word, &context, &mut system, &mut registers),
                Err(Error::Source(SourceError::WrongSource))
            );
            assert_eq!((system.clone(), registers.clone()), before);
        }
        assert_eq!(
            request(instruction(NZCV_READ), BASE, NZCV_READ),
            Err(SourceError::NotImmediate)
        );
    }

    #[test]
    fn real_spsel_completion_switches_banks_for_both_modes_and_ignored_high_bits() {
        for mode in [PSTATE_EL1T, PSTATE_EL1H] {
            for operand in 0..=OPERAND_MAX {
                let word = SPSEL | (u32::from(operand) << CRM_SHIFT);
                let (mut system, mut registers) = state(mode);
                let mut expected_registers = registers.clone();
                let selected = u64::from(operand) & pstate::SP_SELECT_MASK;
                let changed = selected != (mode & pstate::SP_SELECT_MASK);
                let inactive = if changed {
                    expected_registers.sp = SP0;
                    SP1
                } else {
                    SP0
                };
                let expected_system = SystemState::new(
                    PSTATE_EL1T | selected | pstate::DAIF_MASK,
                    inactive,
                    *system.el1_registers(),
                )
                .unwrap();
                let descriptor = instruction(word);
                assert_eq!(
                    complete(
                        descriptor,
                        BASE,
                        word,
                        &context(ExceptionLevel::El1),
                        &mut system,
                        &mut registers
                    ),
                    Ok(Completion::Complete {
                        next_pc: GuestAddress(BASE.0 + INSTRUCTION_BYTES)
                    })
                );
                assert_eq!(system, expected_system);
                assert_eq!(registers, expected_registers);
                let expected_bank = if selected == 0 {
                    StackBank::El0
                } else {
                    StackBank::El1
                };
                assert_eq!(system.active_stack_bank(), expected_bank);
            }
        }
    }

    #[test]
    fn missing_actual_arbitration_owner_prevents_daif_commit_even_for_zero_operand() {
        for base in [DAIF_SET, DAIF_CLEAR] {
            for operand in [0, 5, OPERAND_MAX] {
                let word = base | (u32::from(operand) << CRM_SHIFT);
                let (mut system, mut registers) = state(PSTATE_EL1H);
                let before = (system.clone(), registers.clone());
                let mask = u64::from(operand) << pstate::DAIF_SHIFT;
                let expected_effect = Effect::Daif {
                    mask,
                    value: if base == DAIF_SET { mask } else { 0 },
                };
                assert_eq!(
                    complete(
                        instruction(word),
                        BASE,
                        word,
                        &context(ExceptionLevel::El1),
                        &mut system,
                        &mut registers
                    ),
                    Ok(Completion::Uncompleted {
                        request: request(instruction(word), BASE, word).unwrap(),
                        decision: Resolution::BackendRequired(expected_effect)
                    })
                );
                assert_eq!((system, registers), before);
            }
        }
    }

    #[test]
    fn source_traps_remain_before_missing_arbitration_and_preserve_original_syndrome() {
        let (mut system, mut registers) = state(PSTATE_EL0T);
        let before = (system.clone(), registers.clone());
        let mut context = context(ExceptionLevel::El0);
        context.controls.sctlr_el1_uma = false;
        let original_request = request(instruction(DAIF_SET), BASE, DAIF_SET).unwrap();
        assert_eq!(original_request.system_access_esr(), 0x620c_d3e0);
        assert_eq!(
            complete(
                instruction(DAIF_SET),
                BASE,
                DAIF_SET,
                &context,
                &mut system,
                &mut registers
            ),
            Ok(Completion::Uncompleted {
                request: original_request,
                decision: Resolution::Trap(Trap::system_access(ExceptionLevel::El1))
            })
        );
        context.profile.el2_enabled = true;
        context.controls.hcr_el2_tge = true;
        assert_eq!(
            complete(
                instruction(DAIF_SET),
                BASE,
                DAIF_SET,
                &context,
                &mut system,
                &mut registers
            ),
            Ok(Completion::Uncompleted {
                request: original_request,
                decision: Resolution::Trap(Trap::system_access(ExceptionLevel::El2))
            })
        );
        assert_eq!((system, registers), before);
    }

    #[test]
    fn optional_absence_privilege_and_present_backend_decisions_are_not_success() {
        let (mut system, mut registers) = state(PSTATE_EL0T);
        let before = (system.clone(), registers.clone());
        let mut context = context(ExceptionLevel::El0);
        for word in [SPSEL, DIT] {
            assert_eq!(
                complete(
                    instruction(word),
                    BASE,
                    word,
                    &context,
                    &mut system,
                    &mut registers
                ),
                Ok(Completion::Uncompleted {
                    request: request(instruction(word), BASE, word).unwrap(),
                    decision: Resolution::Undefined
                })
            );
        }
        context.features.dit = true;
        let word = DIT | (1 << CRM_SHIFT);
        assert_eq!(
            complete(
                instruction(word),
                BASE,
                word,
                &context,
                &mut system,
                &mut registers
            ),
            Ok(Completion::Uncompleted {
                request: request(instruction(word), BASE, word).unwrap(),
                decision: Resolution::BackendRequired(Effect::Backend(
                    pstate::BackendRequest::Pstate {
                        field: pstate::PstateField::Dit,
                        mask: pstate::DIT_MASK,
                        value: pstate::DIT_MASK
                    }
                ))
            })
        );
        assert_eq!((system, registers), before);
    }
}
