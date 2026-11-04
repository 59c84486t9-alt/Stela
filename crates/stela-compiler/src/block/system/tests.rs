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
fn system_mode_decodes_apple_sdsb_as_the_dsb_of_its_domain() {
    let pc = GuestAddress(0x1000);
    for (domain, dsb) in SDSB_AS_DSB.into_iter().enumerate() {
        let instruction = decode_system_mode_instruction(pc, SDSB + domain as u32)
            .unwrap()
            .unwrap();
        assert_eq!(
            instruction.operation,
            SystemOperation::Synchronization(synchronization::decode(dsb).unwrap())
        );
    }
    assert!(
        decode_system_mode_instruction(pc, SDSB + 4)
            .unwrap()
            .is_none()
    );
    assert!(
        decode_system_mode_instruction(pc, SDSB - 1)
            .unwrap()
            .is_none()
    );
}

#[test]
fn system_mode_claims_wkdm_and_the_ordinary_profiles_do_not() {
    use crate::wkdm::{self, Operation};
    let pc = GuestAddress(0x1000);
    for (word, operation) in [
        (wkdm::COMPRESS_X0_X1, Operation::Compress),
        (wkdm::DECOMPRESS_X0_X1, Operation::Decompress),
        (0x0020_0e93, Operation::Decompress),
    ] {
        let instruction = decode_system_mode_instruction(pc, word).unwrap().unwrap();
        assert_eq!(
            instruction.operation,
            SystemOperation::Compression(wkdm::decode(word).unwrap())
        );
        assert!(matches!(
            instruction.operation,
            SystemOperation::Compression(decoded) if decoded.operation == operation
        ));
        assert!(decode_system_instruction(pc, word).unwrap().is_none());
    }
    for word in [0x0020_07ff, 0x0020_1000] {
        assert!(
            !matches!(
                decode_system_mode_instruction(pc, word),
                Ok(Some(SystemInstruction {
                    operation: SystemOperation::Compression(_),
                    ..
                }))
            ),
            "{word:#x}"
        );
    }
}

#[test]
fn system_mode_decodes_genter_with_its_immediate_and_gexit() {
    let pc = GuestAddress(0x1000);
    let operation = |word| {
        decode_system_mode_instruction(pc, word)
            .unwrap()
            .map(|instruction| instruction.operation)
    };
    for immediate in 0..32u8 {
        assert_eq!(
            operation(GENTER | u32::from(immediate)),
            Some(SystemOperation::Guarded(GuardedOperation::Enter {
                immediate
            }))
        );
    }
    assert_eq!(
        operation(GEXIT),
        Some(SystemOperation::Guarded(GuardedOperation::Exit))
    );
    // GEXIT's other low words and at_as1elx (0x00201440) are not GXF.
    for word in [0x0020_1402, 0x0020_141f, 0x0020_1440] {
        assert_eq!(operation(word), None, "{word:#x}");
    }
    for word in [GENTER, GEXIT] {
        assert!(decode_system_instruction(pc, word).unwrap().is_none());
    }
}

#[test]
fn system_mode_decodes_each_apple_maintenance_form_with_its_register() {
    use AppleMaintenance::{AddressSpace, All, CoprocessorCacheFlush, PhysicalPage};
    let pc = GuestAddress(0x1000);
    let operation = |word| {
        decode_system_mode_instruction(pc, word)
            .unwrap()
            .map(|instruction| instruction.operation)
    };
    // Every such word of the 26A434 M4 to M6 SPTMs.
    for (word, maintenance) in [
        (0x0020_1308, CoprocessorCacheFlush { register: 8 }),
        (0x0020_1309, CoprocessorCacheFlush { register: 9 }),
        (0x0020_1310, CoprocessorCacheFlush { register: 16 }),
        (0x0020_1328, PhysicalPage { register: 8 }),
        (0x0020_132b, PhysicalPage { register: 11 }),
        (0x0020_1330, PhysicalPage { register: 16 }),
        (0x0020_1331, PhysicalPage { register: 17 }),
        (0x0020_134d, AddressSpace { register: 13 }),
        (0x0020_1401, All),
    ] {
        assert_eq!(
            operation(word),
            Some(SystemOperation::AppleMaintenance(maintenance)),
            "{word:#x}"
        );
        assert!(decode_system_instruction(pc, word).unwrap().is_none());
    }
    // AMX operations 23 and 27 stay AMX words.
    for word in [0x0020_12ff, 0x0020_1360] {
        assert_eq!(operation(word), None, "{word:#x}");
    }
}

#[test]
fn system_mode_claims_debug_state_only_movt_and_nothing_beside_it() {
    let pc = GuestAddress(0x1000);
    for (word, operation) in [
        (0xc04c_03e0, DebugStateOperation::TableToGeneral),
        (0xc04c_73fe, DebugStateOperation::TableToGeneral),
        (0xc04e_03e0, DebugStateOperation::GeneralToTable),
        (0xc04e_73ff, DebugStateOperation::GeneralToTable),
    ] {
        let instruction = decode_system_mode_instruction(pc, word).unwrap().unwrap();
        assert_eq!(
            instruction.operation,
            SystemOperation::DebugStateOnly(operation)
        );
        assert!(decode_system_instruction(pc, word).unwrap().is_none());
    }
    // MOVT (vector to table), and the fixed bits 15 and 9..5, are not it.
    for word in [0xc04f_03e0, 0xc04c_83e0, 0xc04c_03c0, 0xc04d_03e0] {
        assert!(decode_system_mode_instruction(pc, word).unwrap().is_none());
    }
}

#[test]
fn system_mode_claims_cpa_arithmetic_with_its_operands() {
    use crate::aarch64::{
        Register,
        checked_pointer::{Kind, Operand},
    };
    let pc = GuestAddress(0x1000);
    // ADDPT X0, X1, X2, LSL #3; SUBPT SP, SP, X2; MADDPT; MSUBPT.
    for word in [0x9a02_2c20, 0xda02_23ff, 0x9b62_1023, 0x9b62_9025] {
        let instruction = decode_system_mode_instruction(pc, word).unwrap().unwrap();
        assert!(
            matches!(instruction.operation, SystemOperation::CheckedPointer(_)),
            "{word:#x}"
        );
        assert_eq!(instruction.next_pc, GuestAddress(0x1004));
    }
    assert_eq!(
        decode_system_mode_instruction(pc, 0xda02_23ff)
            .unwrap()
            .unwrap()
            .operation,
        SystemOperation::CheckedPointer(Operand {
            destination: Register::Sp,
            kind: Kind::Offset {
                base: Register::Sp,
                offset: Register::X(2),
                amount: 0,
                subtract: true,
            },
        })
    );
    // Ordinary ADD (shifted register) is not claimed.
    assert!(
        decode_system_mode_instruction(pc, 0x8b02_0c20)
            .unwrap()
            .is_none()
    );
}

#[test]
fn system_mode_claims_exclusives_and_their_undefined_overlaps() {
    use crate::aarch64::exclusive::{ConstrainedUndefined, Operand};
    let pc = GuestAddress(0x1000);
    // LDXRB/H, LDXR W/X, STXR, LDAXP and CLREX.
    for word in [
        0x085f_7c41,
        0x485f_7c41,
        0x885f_7c41,
        0xc85f_7c41,
        0xc803_7c41,
        0xc87f_9041,
        0xd503_305f,
    ] {
        let instruction = decode_system_mode_instruction(pc, word).unwrap().unwrap();
        assert!(
            matches!(instruction.operation, SystemOperation::Exclusive(Ok(_))),
            "{word:#x}"
        );
    }
    assert!(matches!(
        decode_system_mode_instruction(pc, 0xd503_305f)
            .unwrap()
            .unwrap()
            .operation,
        SystemOperation::Exclusive(Ok(Operand::Clear))
    ));
    // STXR W1, X1, [X2]: the status register overlaps the data.
    assert_eq!(
        decode_system_mode_instruction(pc, 0xc801_7c41)
            .unwrap()
            .unwrap()
            .operation,
        SystemOperation::Exclusive(Err(ConstrainedUndefined::StoreStatusData))
    );
}

#[test]
fn system_mode_claims_unprivileged_transfers_but_not_reserved_forms() {
    let pc = GuestAddress(0x1000);
    // LDTR X1, [X2, #8]; STTR W1, [X2]; LDTRSH and LDTRSB W3, [X2].
    for word in [0xf840_8841, 0xb800_0841, 0x78c0_0843, 0x38c0_0843] {
        let instruction = decode_system_mode_instruction(pc, word).unwrap().unwrap();
        assert!(
            matches!(instruction.operation, SystemOperation::Unprivileged(_)),
            "{word:#x}"
        );
        assert!(decode_system_instruction(pc, word).unwrap().is_none());
    }
    // LDTRSW into W and LDTRSB/H/W into X from a doubleword are reserved.
    for word in [0xb8c0_0843, 0xf880_0843] {
        assert!(decode_system_mode_instruction(pc, word).unwrap().is_none());
    }
}

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
fn wait_carriers_keep_kind_and_timeout_register_from_decoder() {
    use synchronization::WaitKind;
    for (word, kind, timeout_register) in [
        (WFE, WaitKind::Event, None),
        (WFI, WaitKind::Interrupt, None),
        (WFET | 30, WaitKind::Event, Some(30)),
        (WFIT | 31, WaitKind::Interrupt, Some(31)),
    ] {
        let pc = GuestAddress(0x1000);
        let instruction = decode_system_instruction(pc, word).unwrap().unwrap();
        assert_eq!(
            instruction.operation,
            SystemOperation::Wait {
                kind,
                timeout_register
            }
        );
        assert!(instruction.matches_source(pc, word));
        assert!(!instruction.is_el1_context_operation());
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
fn system_mode_claims_completion_barriers_and_unallocated_hints_only() {
    let pc = GuestAddress(0x1000);
    // DSB SY, DSB ISHST, ISB, SSBB, PSSBB and the unallocated HINT #0x54
    // and #0x7f exit to the engine.
    for word in [
        0xd503_3f9f,
        0xd503_3a9f,
        0xd503_3fdf,
        0xd503_309f,
        0xd503_349f,
        0xd503_2a9f,
        0xd503_2fff,
    ] {
        assert!(
            decode_system_mode_instruction(pc, word).unwrap().is_some(),
            "{word:#x}"
        );
    }
    // DMB ISH, NOP, YIELD, CSDB and SB stay with the ordinary decoder.
    for word in [0xd503_3bbf, NOP, 0xd503_203f, 0xd503_229f, 0xd503_30ff] {
        assert!(
            decode_system_mode_instruction(pc, word).unwrap().is_none(),
            "{word:#x}"
        );
    }
}

#[test]
fn unrelated_words_do_not_become_runtime_system_requests() {
    for word in [NOP, ADD_IMMEDIATE, RET, UNALLOCATED] {
        assert!(
            decode_system_instruction(GuestAddress(0x1000), word)
                .unwrap()
                .is_none()
        );
    }
    assert!(decode_system_instruction(GuestAddress(0x1001), IRG).is_err());
    assert!(decode_system_instruction(GuestAddress(u64::MAX - 3), IRG).is_err());
}
