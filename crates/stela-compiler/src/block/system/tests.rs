use super::*;

const SVC: u32 = 0xd400_0001;
const ERET: u32 = 0xd69f_03e0;
const IRG: u32 = 0x9ac0_1000;
const LDG: u32 = 0xd960_0000;
const STG: u32 = 0xd920_0800;
const STGP: u32 = 0x6900_0000;
const SEV: u32 = 0xd503_209f;
const SEVL: u32 = 0xd503_20bf;
const WFE: u32 = 0xd503_205f;
const WFI: u32 = 0xd503_207f;
const WFET: u32 = 0xd503_1000;
const WFIT: u32 = 0xd503_1020;
const NOP: u32 = 0xd503_201f;
const ADD_IMMEDIATE: u32 = 0x9100_0000;
const RET: u32 = 0xd65f_03c0;
const UNALLOCATED: u32 = 0xffff_ffff;

#[test]
fn context_carriers_preserve_exact_operands_without_granting_other_families() {
    let pc = GuestAddress(0x1000);
    let isb = 0xd5033fdf;
    let instruction = decode_system_instruction(pc, isb).unwrap().unwrap();
    assert_eq!(
        instruction.operation,
        SystemOperation::InstructionSynchronization { option: 15 }
    );
    assert!(instruction.matches_source(pc, isb));
    assert!(!instruction.matches_source(pc, isb ^ (1 << 8)));
    assert!(instruction.is_el1_context_operation());
    for encoding in [
        registers::SCTLR_EL1,
        registers::TCR_EL1,
        registers::TTBR0_EL1,
        registers::TTBR1_EL1,
        registers::MAIR_EL1,
    ] {
        for base in [0xd5200000u32, 0xd5000000] {
            for rt in [0, 30, 31] {
                let word = base | (u32::from(encoding.selector()) << 5) | rt;
                let instruction = decode_system_instruction(pc, word).unwrap().unwrap();
                assert!(instruction.matches_source(pc, word));
                assert!(instruction.is_el1_context_operation());
                let SystemOperation::Register(access) = instruction.operation else {
                    panic!("register carrier")
                };
                assert_eq!(access.encoding(), encoding);
                assert_eq!(access.rt(), rt as u8);
            }
        }
    }
    for word in [SVC, ERET, 0xd4202460, 0x00001234] {
        assert!(
            decode_system_instruction(pc, word)
                .unwrap()
                .unwrap()
                .is_el1_context_operation()
        );
    }
    for word in [
        0xd69f0bff, 0xd69f0fff, 0xd4000002, 0xd4000003, SEV, SEVL, IRG,
    ] {
        assert!(
            !decode_system_instruction(pc, word)
                .unwrap()
                .unwrap()
                .is_el1_context_operation()
        );
    }
}

#[test]
fn system_requests_preserve_exact_instruction_identity() {
    let pc = GuestAddress(0x1000);
    for word in [SVC, ERET, IRG, LDG, STG, STGP, SEV, SEVL] {
        let instruction = decode_system_instruction(pc, word).unwrap().unwrap();
        assert_eq!(instruction.instruction_pc, pc);
        assert_eq!(instruction.next_pc, GuestAddress(pc.0 + INSTRUCTION_BYTES));
        assert!(instruction.matches_source(pc, word));
        assert!(!instruction.matches_source(GuestAddress(pc.0 + INSTRUCTION_BYTES), word));
        assert!(!instruction.matches_source(pc, word ^ 1));
        let mut forged = instruction;
        forged.next_pc = pc;
        assert!(!forged.matches_source(pc, word));
    }
}

#[test]
fn unrelated_words_do_not_become_runtime_system_requests() {
    for word in [NOP, ADD_IMMEDIATE, RET, UNALLOCATED, WFE, WFI, WFET, WFIT] {
        assert!(
            decode_system_instruction(GuestAddress(0x1000), word)
                .unwrap()
                .is_none()
        );
    }
    assert!(decode_system_instruction(GuestAddress(0x1001), IRG).is_err());
    assert!(decode_system_instruction(GuestAddress(u64::MAX - 3), IRG).is_err());
}
