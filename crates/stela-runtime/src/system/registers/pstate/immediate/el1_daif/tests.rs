use super::*;
use crate::system::{
    pstate::DAIF_MASK,
    state::{El1Registers, PSTATE_EL0T, PSTATE_EL1H, PSTATE_EL1T},
};
use stela_compiler::block::system::decode_system_instruction;

const BASE: GuestAddress = GuestAddress(0x1000);
const DAIF_SET: u32 = 0xd503_40df;
const DAIF_CLEAR: u32 = 0xd503_40ff;
const CRM_SHIFT: u32 = 8;
const MAX_OPERAND: u32 = 15;
const FLAGS: u32 = 0xa123_4567;

fn system(mode: u64, daif: u64) -> SystemState {
    SystemState::new(mode | daif, 0x1234, El1Registers::new(1, 2, 3, 4, 5)).unwrap()
}

fn instruction(word: u32) -> SystemInstruction {
    decode_system_instruction(BASE, word).unwrap().unwrap()
}

#[test]
fn every_el1_operand_and_direction_preserves_cpu_and_other_owned_state() {
    for mode in [PSTATE_EL1T, PSTATE_EL1H] {
        for initial in [0, DAIF_MASK] {
            for base in [DAIF_SET, DAIF_CLEAR] {
                for operand in 0..=MAX_OPERAND {
                    let word = base | (operand << CRM_SHIFT);
                    let system = system(mode, initial);
                    let registers = GuestState {
                        nzcv: FLAGS,
                        reserved: u32::MAX,
                        sp: 0xfedc,
                        ..GuestState::default()
                    };
                    let before = registers.clone();
                    let mask = u64::from(operand) << DAIF_SHIFT;
                    let updated = if base == DAIF_SET {
                        initial | mask
                    } else {
                        initial & !mask
                    };
                    let plan =
                        PreparedEl1Daif::prepare(instruction(word), BASE, word, &system).unwrap();
                    let staged = plan.stage(&system, &registers).unwrap();
                    assert_eq!(staged.instruction(), instruction(word));
                    assert_eq!(staged.value(), updated);
                    assert_eq!(registers, before);
                    assert_eq!(system, self::system(mode, initial));
                }
            }
        }
    }
}

#[test]
fn forged_source_il_and_el0_never_prepare_an_effect() {
    let word = DAIF_SET | (MAX_OPERAND << CRM_SHIFT);
    let instruction = instruction(word);
    let valid = system(PSTATE_EL1H, 0);
    assert_eq!(
        PreparedEl1Daif::prepare(instruction, BASE, word ^ (1 << CRM_SHIFT), &valid),
        Err(PrepareError::Source(SourceError::WrongSource))
    );
    assert_eq!(
        PreparedEl1Daif::prepare(
            instruction,
            BASE,
            word,
            &system(PSTATE_EL1H | PSTATE_IL_MASK, 0)
        ),
        Err(PrepareError::IllegalExecutionState)
    );
    assert_eq!(
        PreparedEl1Daif::prepare(instruction, BASE, word, &system(PSTATE_EL0T, 0)),
        Err(PrepareError::AccessContextRequired)
    );
}

#[test]
fn actual_state_is_rechecked_before_staging_a_prepared_plan() {
    let valid = system(PSTATE_EL1H, 0);
    let plan = PreparedEl1Daif::prepare(instruction(DAIF_CLEAR), BASE, DAIF_CLEAR, &valid).unwrap();
    for mode in [PSTATE_EL0T, PSTATE_EL1H | PSTATE_IL_MASK] {
        let changed = system(mode, DAIF_MASK);
        let registers = GuestState::default();
        let before = (changed.clone(), registers.clone());
        assert!(plan.stage(&changed, &registers).is_err());
        assert_eq!((changed, registers), before);
    }
}
