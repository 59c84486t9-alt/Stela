use super::*;
use stela_compiler::{GuestAddress, GuestState};

fn state(selector: u64, flags: u32) -> ThreadState {
    let mut registers = GuestState {
        sp: 0x12340000,
        nzcv: flags << 28,
        reserved: 0xa5c39e71,
        ..GuestState::default()
    };
    for index in 0..31 {
        registers.x[index] = 0xdeadbeef12340000 + index as u64;
    }
    registers.v = std::array::from_fn(|index| {
        [
            0x0123456789abcdefu64.rotate_left(index as u32),
            0xfedcba9876543210u64.rotate_right(index as u32),
        ]
    });
    registers.fpcr = 0xa5c39e71 ^ flags;
    registers.fpsr = 0x5a3c618e ^ flags;
    registers.x[16] = selector;
    ThreadState {
        registers,
        pc: GuestAddress(0x1000),
    }
}
fn trap() -> SynchronousTrap {
    SynchronousTrap {
        kind: TrapKind::SupervisorCall,
        immediate: 0x80,
        instruction_pc: GuestAddress(0x1000),
        exception_return_pc: GuestAddress(0x1004),
    }
}
fn prototype(return_type: BsdReturnType, argument_count: usize) -> BsdPrototype {
    BsdPrototype {
        argument_count,
        return_type,
    }
}
fn same(actual: &ThreadState, expected: &ThreadState) {
    assert_eq!(actual.pc, expected.pc);
    assert_eq!(actual.registers, expected.registers);
}

#[test]
fn dispatch_truncation_and_full_width_indirect_selection_match_pinned_c() {
    for (x16, number, indirect) in [
        (4, 4, false),
        (0x12340004, 4, false),
        (0, 20, true),
        (0x1_0000_0000, 0, false),
        (0xffff_ffff_0000_0004, 4, false),
    ] {
        let mut input = state(x16, 15);
        input.registers.x[0] = 0xabcd_0014;
        let before = input.clone();
        let selected = classify_bsd_call(&input, &trap()).unwrap();
        assert_eq!(selected, BsdSelector { number, indirect });
        let pending =
            PendingBsdCall::from_trap(&input, &trap(), prototype(BsdReturnType::Int, 8)).unwrap();
        let start = usize::from(indirect);
        assert_eq!(
            pending.request().arguments(),
            &input.registers.x[start..start + 8]
        );
        assert_eq!(pending.request().number, number);
        same(&input, &before);
    }
}

#[test]
fn request_exposes_and_serializes_only_declared_argument_slots() {
    for argument_count in 0..=MAX_BSD_ARGUMENTS {
        for selector in [0, 4] {
            let input = state(selector, 0);
            let declared = prototype(BsdReturnType::SignedSize, argument_count);
            let pending = PendingBsdCall::from_trap(&input, &trap(), declared).unwrap();
            let request = pending.request();
            let start = usize::from(selector == 0);
            let expected = &input.registers.x[start..start + argument_count];
            assert_eq!(request.arguments(), expected);
            assert_eq!(request.prototype(), declared);
            assert!(
                request.arguments[argument_count..]
                    .iter()
                    .all(|slot| *slot == 0)
            );
            let encoded = serde_json::to_value(request).unwrap();
            assert_eq!(encoded["arguments"], serde_json::json!(expected));
            assert_eq!(
                encoded["prototype"],
                serde_json::to_value(declared).unwrap()
            );
        }
    }
}

#[test]
fn mach_platform_and_invalid_prototypes_are_typed_declines_without_state_changes() {
    for x16 in [0x80000000, 0xffff_ffff_8000_0000] {
        let input = state(x16, 15);
        assert_eq!(
            classify_bsd_call(&input, &trap()).unwrap_err(),
            AbiError::PlatformCall { raw_x16: x16 }
        );
    }
    for x16 in [0xffffffe1, u64::MAX] {
        let input = state(x16, 15);
        assert_eq!(
            classify_bsd_call(&input, &trap()).unwrap_err(),
            AbiError::MachCall {
                number: x16 as u32 as i32,
                raw_x16: x16
            }
        );
    }
    let input = state(4, 15);
    assert_eq!(
        PendingBsdCall::from_trap(&input, &trap(), prototype(BsdReturnType::SignedSize, 9))
            .unwrap_err(),
        AbiError::InvalidPrototype { argument_count: 9 }
    );
}

#[test]
fn trap_kind_immediate_pc_and_return_pc_must_be_coherent() {
    let input = state(4, 15);
    for invalid in [
        SynchronousTrap {
            kind: TrapKind::SoftwareBreakpoint,
            ..trap()
        },
        SynchronousTrap {
            immediate: 0,
            ..trap()
        },
        SynchronousTrap {
            instruction_pc: GuestAddress(0x1002),
            ..trap()
        },
        SynchronousTrap {
            instruction_pc: GuestAddress(0x1004),
            ..trap()
        },
        SynchronousTrap {
            exception_return_pc: GuestAddress(0x1008),
            ..trap()
        },
    ] {
        assert!(classify_bsd_call(&input, &invalid).is_err());
    }
    let mut invalid = input.clone();
    invalid.registers.nzcv |= 1;
    assert!(classify_bsd_call(&invalid, &trap()).is_err());
}

#[test]
fn borrowed_completion_retains_actual_pc_and_rejects_stale_or_invalid_replies() {
    let input = state(4, 15);
    let mut bank = input.registers.clone();
    let actual_pc = input.pc;
    let next = PendingBsdCall::from_registers(
        actual_pc,
        &bank,
        &trap(),
        prototype(BsdReturnType::Unsigned64, 0),
    )
    .unwrap()
    .complete_registers(
        &mut bank,
        BsdCompletion::Success {
            values: [0x89ab_cdef, 0x0123_4567],
        },
    )
    .unwrap();
    let mut expected = input.registers.clone();
    expected.x[0] = 0x0123_4567_89ab_cdef;
    expected.x[1] = 0;
    expected.nzcv &= !CARRY;
    assert_eq!(bank, expected);
    assert_eq!(actual_pc, trap().instruction_pc);
    assert_eq!(next, trap().exception_return_pc);
    for completion in [
        BsdCompletion::JustReturn,
        BsdCompletion::Error { errno: 0 },
        BsdCompletion::Error { errno: u32::MAX },
    ] {
        let mut bank = input.registers.clone();
        let pending = PendingBsdCall::from_registers(
            actual_pc,
            &bank,
            &trap(),
            prototype(BsdReturnType::Int, 0),
        )
        .unwrap();
        assert!(pending.complete_registers(&mut bank, completion).is_err());
        assert_eq!(bank, input.registers);
    }
    let mut bank = input.registers.clone();
    let pending =
        PendingBsdCall::from_registers(actual_pc, &bank, &trap(), prototype(BsdReturnType::Int, 0))
            .unwrap();
    bank.x[5] ^= 1;
    let changed = bank.clone();
    assert_eq!(
        pending.complete_registers(&mut bank, BsdCompletion::Restart),
        Err(AbiError::StateChanged)
    );
    assert_eq!(bank, changed);
    let mut bank = input.registers.clone();
    let next =
        PendingBsdCall::from_registers(actual_pc, &bank, &trap(), prototype(BsdReturnType::Int, 0))
            .unwrap()
            .complete_registers(&mut bank, BsdCompletion::Restart)
            .unwrap();
    assert_eq!(next, trap().instruction_pc);
    assert_eq!(actual_pc, trap().instruction_pc);
}

#[test]
fn all_success_return_types_normalize_slots_and_preserve_other_state() {
    for flags in 0..16 {
        for (return_type, expected_words) in [
            (
                BsdReturnType::Int,
                Some([0xffff_ffff_8765_4321, 0x12345678]),
            ),
            (BsdReturnType::UnsignedInt, Some([0x87654321, 0x12345678])),
            (BsdReturnType::Offset, Some([0x1234567887654321, 0])),
            (BsdReturnType::Address, Some([0x1234567887654321, 0])),
            (BsdReturnType::Size, Some([0x1234567887654321, 0])),
            (BsdReturnType::SignedSize, Some([0x1234567887654321, 0])),
            (BsdReturnType::Unsigned64, Some([0x1234567887654321, 0])),
            (BsdReturnType::None, None),
        ] {
            let mut input = state(4, flags);
            let mut expected = input.clone();
            expected.pc = trap().exception_return_pc;
            expected.registers.nzcv &= !CARRY;
            if let Some(values) = expected_words {
                expected.registers.x[..2].copy_from_slice(&values);
            }
            PendingBsdCall::from_trap(&input, &trap(), prototype(return_type, 3))
                .unwrap()
                .complete(
                    &mut input,
                    BsdCompletion::Success {
                        values: [0x87654321, 0x12345678],
                    },
                )
                .unwrap();
            same(&input, &expected);
        }
    }
    let mut input = state(4, 15);
    PendingBsdCall::from_trap(&input, &trap(), prototype(BsdReturnType::Int, 0))
        .unwrap()
        .complete(
            &mut input,
            BsdCompletion::Success {
                values: [u32::MAX, 0x80000000],
            },
        )
        .unwrap();
    assert_eq!(input.registers.x[..2], [u64::MAX, 0xffffffff80000000]);
}

#[test]
fn errno_sets_only_return_registers_carry_and_continuation_pc() {
    for flags in 0..16 {
        let mut input = state(4, flags);
        let mut expected = input.clone();
        expected.pc = trap().exception_return_pc;
        expected.registers.x[0] = 14;
        expected.registers.x[1] = 0;
        expected.registers.nzcv |= CARRY;
        PendingBsdCall::from_trap(&input, &trap(), prototype(BsdReturnType::SignedSize, 3))
            .unwrap()
            .complete(&mut input, BsdCompletion::Error { errno: 14 })
            .unwrap();
        same(&input, &expected);
    }
}

#[test]
fn restart_preserves_indirect_number_arguments_and_clears_only_carry() {
    for selector in [0, 4, 0x1_0000_0000] {
        for flags in 0..16 {
            let mut input = state(selector, flags);
            input.registers.x[0] = 20;
            let original_selector = classify_bsd_call(&input, &trap()).unwrap();
            let mut expected = input.clone();
            expected.registers.nzcv &= !CARRY;
            PendingBsdCall::from_trap(&input, &trap(), prototype(BsdReturnType::Int, 8))
                .unwrap()
                .complete(&mut input, BsdCompletion::Restart)
                .unwrap();
            same(&input, &expected);
            assert_eq!(
                classify_bsd_call(&input, &trap()).unwrap(),
                original_selector
            );
        }
    }
}

#[test]
fn state_drift_invalid_errno_and_just_return_fail_atomically() {
    for change in 0..9 {
        let mut input = state(4, 15);
        let pending =
            PendingBsdCall::from_trap(&input, &trap(), prototype(BsdReturnType::SignedSize, 3))
                .unwrap();
        match change {
            0 => input.pc.0 += 4,
            1 => input.registers.x[30] ^= 1,
            2 => input.registers.x[16] ^= 1,
            3 => input.registers.sp += 16,
            4 => input.registers.nzcv ^= CARRY,
            5 => input.registers.reserved ^= 1,
            6 => input.registers.v[31][1] ^= 1,
            7 => input.registers.fpcr ^= 1,
            _ => input.registers.fpsr ^= 1,
        }
        let changed = input.clone();
        assert_eq!(
            pending
                .complete(&mut input, BsdCompletion::Success { values: [10, 0] })
                .unwrap_err(),
            AbiError::StateChanged
        );
        same(&input, &changed);
    }
    for completion in [
        BsdCompletion::Error { errno: 0 },
        BsdCompletion::Error { errno: 0x80000000 },
        BsdCompletion::JustReturn,
    ] {
        let mut input = state(4, 15);
        let before = input.clone();
        let pending =
            PendingBsdCall::from_trap(&input, &trap(), prototype(BsdReturnType::SignedSize, 3))
                .unwrap();
        let error = pending.complete(&mut input, completion).unwrap_err();
        assert_eq!(
            error,
            match completion {
                BsdCompletion::Error { errno } => AbiError::InvalidErrno { errno },
                _ => AbiError::UnsupportedJustReturn,
            }
        );
        same(&input, &before);
    }
}
