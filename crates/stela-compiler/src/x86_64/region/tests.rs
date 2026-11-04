mod recipes;
use super::*;
use crate::aarch64::{Logical, Shift};
use alloc::vec;
use alloc::vec::Vec;
fn instruction(index: u64, operation: Operation) -> Instruction {
    Instruction {
        pc: GuestAddress(0x1000 + index * 4),
        operation,
    }
}
fn add(destination: Register, source: Register) -> Operation {
    Operation::AddSub {
        width: Width::X64,
        flags: false,
        subtract: false,
        destination,
        source,
        immediate: 1,
    }
}

#[test]
fn address_pair_shares_one_literal_and_preserves_distinct_source_rows() {
    let x0 = Register::X(0);
    let instructions = [
        instruction(
            0,
            Operation::PcRelative(crate::aarch64::pc_relative::Operand {
                destination: x0,
                address: u64::MAX,
            }),
        ),
        instruction(1, add(x0, x0)),
        instruction(2, add(Register::X(3), x0)),
    ];
    for span in [&instructions[..2], &instructions[..]] {
        let separate = emit_prefix(span).unwrap();
        let fused = emit_clean_load_prefix(span, true, None).unwrap();
        let precise =
            emit_clean_load_prefix_with(span, crate::x86_64::MemoryChecks::DEFAULT, true, None)
                .unwrap();
        assert_eq!(&precise.code[..], &separate.code[..]);
        assert_eq!(fused.consumed_instructions, span.len());
        assert_eq!(fused.stats.commits, span.len());
        assert_eq!(fused.stats.constant_writes, span.len() - 1);
        assert_eq!(&fused.code[2..10], &[0; 8]); // wrapped address
        assert_eq!(fused.source_map[..2], [(span[0].pc, 0), (span[1].pc, 10)]);
        assert!(
            fused
                .source_map
                .windows(2)
                .all(|pair| pair[0].1 < pair[1].1)
        );
        assert!(fused.code.len() < separate.code.len());
    }
}

#[test]
fn hosted_wide_constants_use_one_literal_and_keep_all_source_rows() {
    let wide = |index, width, kind, immediate, shift| {
        instruction(
            index,
            Operation::MoveWide {
                width,
                kind,
                destination: Register::X(0),
                immediate,
                shift,
            },
        )
    };
    let narrow = [
        wide(0, Width::W32, WideMove::Zero, 0x1234, 0),
        wide(1, Width::W32, WideMove::Keep, 0x5678, 16),
    ];
    let narrow_fused = emit_clean_load_prefix(&narrow, true, None).unwrap();
    assert_eq!(
        narrow_fused.source_map,
        [(narrow[0].pc, 0), (narrow[1].pc, 5)]
    );
    assert_eq!(&narrow_fused.code[..5], &[0xb8, 0x34, 0x12, 0x78, 0x56]);
    assert_eq!(narrow_fused.stats.commits, 2);
    assert_eq!(narrow_fused.stats.constant_writes, 1);

    let wide = [
        wide(0, Width::X64, WideMove::Not, 0xabcd, 32),
        wide(1, Width::X64, WideMove::Keep, 0x1234, 16),
        wide(2, Width::X64, WideMove::Keep, 0x5678, 48),
    ];
    let fused = emit_clean_load_prefix(&wide, true, None).unwrap();
    let precise =
        emit_clean_load_prefix_with(&wide, crate::x86_64::MemoryChecks::DEFAULT, true, None)
            .unwrap();
    assert_eq!(
        fused.source_map,
        [(wide[0].pc, 0), (wide[1].pc, 1), (wide[2].pc, 11)]
    );
    assert_eq!(&fused.code[..3], &[0x90, 0x48, 0xb8]);
    assert_eq!(&fused.code[3..11], &0x5678_5432_1234_ffff_u64.to_le_bytes());
    assert_eq!(fused.stats.commits, 3);
    assert_eq!(fused.stats.constant_writes, 1);
    assert_eq!(precise.stats.constant_writes, 3);
    assert!(fused.code.len() < precise.code.len());
    assert!(fused.stats.native_instructions < precise.stats.native_instructions);

    let different_width = [narrow[0].clone(), wide[1].clone()];
    let separate = emit_clean_load_prefix(&different_width, true, None).unwrap();
    assert_eq!(separate.stats.constant_writes, 2);
}

#[test]
fn chain_reuses_value_and_settles_once() {
    let instructions: Vec<_> = (0..256)
        .map(|index| instruction(index, add(Register::X(0), Register::X(0))))
        .collect();
    let result = emit_prefix(&instructions).unwrap();
    assert_eq!(result.stats.state_loads, 1);
    assert_eq!(result.stats.pressure_stores, 0);
    assert_eq!(result.stats.exit_stores, 1);
    assert_eq!(result.stats.commits, 256);
    assert_eq!(result.stats.peak_resident, 1);
    assert_eq!(result.code.instructions(), result.stats.native_instructions);
}

#[test]
fn product_rotate_chain_stays_resident_until_canonical_exit() {
    use crate::aarch64::integer_math::{Kind, Operand};
    let product = Operation::IntegerMath(Operand {
        kind: Kind::Low { width: Width::W32 },
        subtract: false,
        destination: Register::X(0),
        left: Register::X(1),
        right: Register::X(2),
        accumulator: Register::X(0),
    });
    let rotate = Operation::IntegerMath(Operand {
        kind: Kind::Extract {
            width: Width::W32,
            amount: 13,
        },
        subtract: false,
        destination: Register::X(0),
        left: Register::X(0),
        right: Register::X(0),
        accumulator: Register::Zero,
    });
    let instructions = [
        instruction(0, add(Register::X(0), Register::X(0))),
        instruction(1, product.clone()),
        instruction(2, rotate.clone()),
        instruction(3, product),
        instruction(4, rotate),
    ];
    let region = emit_prefix(&instructions).unwrap();
    assert_eq!(region.consumed_instructions, instructions.len());
    assert_eq!(region.stats.exit_stores, 1);
    assert_eq!(region.stats.pressure_stores, 0);
    assert_eq!(region.stats.input_cache_loads, 2);
    assert_eq!(region.stats.peak_resident, 3);
}

#[test]
fn integer_region_eligibility_refuses_other_math_and_malformed_ir() {
    use crate::aarch64::integer_math::{Kind, Operand};
    let operand = Operand {
        kind: Kind::Extract {
            width: Width::W32,
            amount: 0,
        },
        subtract: false,
        destination: Register::X(0),
        left: Register::X(0),
        right: Register::X(0),
        accumulator: Register::Zero,
    };
    let accepted = emit_prefix(&[instruction(0, Operation::IntegerMath(operand))]).unwrap();
    assert_eq!(accepted.consumed_instructions, 1);
    for malformed in [
        Operand {
            kind: Kind::Extract {
                width: Width::W32,
                amount: 32,
            },
            ..operand
        },
        Operand {
            right: Register::X(1),
            ..operand
        },
        Operand {
            subtract: true,
            ..operand
        },
        Operand {
            accumulator: Register::X(2),
            ..operand
        },
        Operand {
            kind: Kind::Low { width: Width::X64 },
            left: Register::Sp,
            ..operand
        },
        Operand {
            kind: Kind::Long { signed: false },
            ..operand
        },
        Operand {
            kind: Kind::High { signed: true },
            ..operand
        },
        Operand {
            kind: Kind::Divide {
                signed: false,
                width: Width::X64,
            },
            ..operand
        },
    ] {
        let result = emit_prefix(&[instruction(0, Operation::IntegerMath(malformed))]).unwrap();
        assert_eq!(result.consumed_instructions, 0);
        assert!(result.code.is_empty());
    }
}

#[test]
fn pressure_never_discards_final_architectural_values() {
    let mut instructions: Vec<_> = (0..31)
        .map(|index| instruction(index, add(Register::X(index as u8), Register::Zero)))
        .collect();
    instructions.extend(
        (0..31).map(|index| instruction(index + 31, add(Register::Zero, Register::X(index as u8)))),
    );
    let result = emit_prefix(&instructions).unwrap();
    assert_eq!(result.stats.pressure_stores + result.stats.exit_stores, 31);
    assert_eq!(result.stats.peak_resident, 6);
}
#[test]
fn boundary_does_not_emit_or_consume_later_instructions() {
    let instructions = [
        instruction(0, add(Register::X(0), Register::X(1))),
        instruction(1, Operation::Return),
        instruction(2, add(Register::X(2), Register::X(3))),
    ];
    let result = emit_prefix(&instructions).unwrap();
    assert_eq!(result.consumed_instructions, 1);
    assert_eq!(result.source_map.len(), 1);
    let empty = emit_prefix(&instructions[1..]).unwrap();
    assert!(empty.code.is_empty());
    assert_eq!(empty.consumed_instructions, 0);
}
#[test]
fn malformed_ir_and_flags_form_boundaries() {
    let cases = [
        Operation::MoveWide {
            width: Width::W32,
            kind: WideMove::Zero,
            destination: Register::X(0),
            immediate: 1,
            shift: 32,
        },
        Operation::AddSub {
            width: Width::X64,
            flags: false,
            subtract: false,
            destination: Register::X(0),
            source: Register::X(1),
            immediate: u32::MAX,
        },
        Operation::LogicalRegister {
            width: Width::W32,
            kind: Logical::And,
            flags: false,
            invert: false,
            destination: Register::X(0),
            left: Register::X(1),
            right: Register::X(2),
            shift: Shift::Lsl,
            amount: 32,
        },
        Operation::AddSub {
            width: Width::X64,
            flags: true,
            subtract: false,
            destination: Register::X(0),
            source: Register::X(1),
            immediate: 1,
        },
        add(Register::X(31), Register::X(0)),
    ];
    for operation in cases {
        assert_eq!(
            emit_prefix(&[instruction(0, operation)])
                .unwrap()
                .consumed_instructions,
            0
        );
    }
}
#[test]
fn bounded_contiguous_and_overflow_checked() {
    assert_eq!(
        emit_prefix(&vec![instruction(0, Operation::Nop); 257]),
        Err(RegionError::TooLong)
    );
    assert_eq!(
        emit_prefix(&[
            instruction(0, Operation::Nop),
            instruction(2, Operation::Nop)
        ]),
        Err(RegionError::NonContiguous)
    );
    assert_eq!(
        emit_prefix(&[Instruction {
            pc: GuestAddress(u64::MAX - 3),
            operation: Operation::Nop
        }]),
        Err(RegionError::AddressOverflow)
    );
    assert!(emit_prefix(&[]).unwrap().code.is_empty());
}

#[test]
fn locations_refuse_scratch_alias_or_wrong_frame_slot() {
    let mut gprs = FRAME_LOCATIONS;
    assert!(location::valid(&gprs));
    gprs[0] = Location::Host(HostGpr::Rax);
    assert!(!location::valid(&gprs));
    gprs[0] = Location::Host(POOL[0]);
    gprs[1] = Location::Host(POOL[0]);
    assert!(!location::valid(&gprs));
    gprs = FRAME_LOCATIONS;
    gprs[0] = Location::Frame { byte_offset: 8 };
    assert!(!location::valid(&gprs));
}

#[test]
fn exact_fallback_pc_and_initial_alignment_are_checked() {
    assert_eq!(
        emit_prefix(&[
            instruction(0, Operation::Nop),
            instruction(2, Operation::Return)
        ]),
        Err(RegionError::NonContiguous)
    );
    assert_eq!(
        emit_prefix(&[Instruction {
            pc: GuestAddress(0x1001),
            operation: Operation::Nop
        }]),
        Err(RegionError::Misaligned)
    );
}

#[test]
fn cached_right_is_read_directly_only_without_transform() {
    let mut instructions = vec![instruction(0, add(Register::X(1), Register::X(1)))];
    for index in 1..5 {
        instructions.push(instruction(
            index,
            Operation::AddSubRegister {
                width: Width::X64,
                flags: false,
                subtract: false,
                destination: Register::X(1),
                left: Register::X(1),
                right: Register::X(1),
                shift: Shift::Lsl,
                amount: 0,
            },
        ));
    }
    let result = emit_prefix(&instructions).unwrap();
    // Initial load, ADD and MOV; four one-ALU commits; final store.
    assert_eq!(result.stats.native_instructions, 8);
    assert_eq!(result.stats.state_loads, 1);
    assert_eq!(result.stats.exit_stores, 1);
}

#[test]
fn commutative_cached_left_authentic_add_order_saves_staging_copy() {
    let op = |destination, left, right| Operation::AddSubRegister {
        width: Width::X64,
        subtract: false,
        flags: false,
        destination: Register::X(destination),
        left: Register::X(left),
        right: Register::X(right),
        shift: Shift::Lsl,
        amount: 0,
    };
    let first_order =
        emit_prefix(&[instruction(0, op(9, 9, 16)), instruction(1, op(8, 9, 8))]).unwrap();
    let second_order =
        emit_prefix(&[instruction(0, op(9, 9, 16)), instruction(1, op(8, 8, 9))]).unwrap();
    assert_eq!(first_order.stats.native_instructions, 8);
    assert_eq!(second_order.stats.native_instructions, 8);
    assert_eq!(first_order.code.len(), 32);
    assert_eq!(second_order.code.len(), 32);
}

#[test]
fn leaf_entries_preserve_interior_targets_and_fallthroughs() {
    let source = [
        instruction(
            0,
            Operation::BranchZero {
                target: GuestAddress(0x1008),
                source: Register::X(2),
                width: Width::X64,
                nonzero: false,
            },
        ),
        instruction(1, Operation::Nop),
        instruction(2, Operation::Nop),
        instruction(3, Operation::Return),
        instruction(4, Operation::Nop),
    ];
    assert_eq!(
        analysis::leaf_entries(&source)
            .into_iter()
            .collect::<Vec<_>>(),
        vec![0x1000, 0x1004, 0x1008, 0x1010]
    );
}

#[test]
fn clean_byte_load_tier_keeps_five_nonclobbered_slots() {
    let load = instruction(
        2,
        Operation::Memory {
            transfer: MemoryTransfer::Load {
                signed: false,
                width: Width::W32,
            },
            bytes: 1,
            data: Register::X(16),
            base: Register::X(15),
            displacement: 3,
            mode: AddressMode::Offset,
        },
    );
    let instructions = vec![
        instruction(0, add(Register::X(9), Register::X(9))),
        instruction(1, add(Register::X(8), Register::X(8))),
        load,
        instruction(3, add(Register::X(9), Register::X(9))),
        instruction(4, add(Register::X(8), Register::X(8))),
    ];
    let output = emit_clean_load_prefix(&instructions, true, None).unwrap();
    assert_eq!(output.consumed_instructions, 5);
    assert_eq!(output.stats.clean_loads, 1);
    assert_eq!(output.stats.load_boundary_stores, 2);
    assert_eq!(emit_prefix(&instructions).unwrap().consumed_instructions, 2);
}

/// With the system-mode guest range check, clean loads keep the same
/// shape and check each address once, after the frame is settled.
#[test]
fn clean_loads_check_the_guest_range_when_asked() {
    let check = super::super::RangeCheck::FIVE_LEVEL.code();
    let load = |pc, data, base| {
        instruction(
            pc,
            Operation::Memory {
                transfer: MemoryTransfer::Load {
                    signed: false,
                    width: Width::W32,
                },
                bytes: 4,
                data: Register::X(data),
                base: Register::X(base),
                displacement: 8,
                mode: AddressMode::Offset,
            },
        )
    };
    let pair = instruction(
        3,
        Operation::MemoryPair {
            transfer: MemoryTransfer::Load {
                signed: false,
                width: Width::W32,
            },
            bytes: 4,
            data: [Register::X(4), Register::X(5)],
            base: Register::X(1),
            displacement: 16,
            mode: AddressMode::Offset,
        },
    );
    let instructions = vec![
        instruction(0, add(Register::X(9), Register::X(9))),
        load(1, 2, 1),
        load(2, 3, 1),
        pair,
        instruction(4, add(Register::X(9), Register::X(9))),
    ];
    let checks = |code: &[u8]| {
        code.windows(check.len())
            .filter(|bytes| *bytes == check)
            .count()
    };
    let unchecked = emit_clean_load_prefix(&instructions, true, None).unwrap();
    let checked = emit_clean_load_prefix(&instructions, true, Some(&[true; 5])).unwrap();
    assert_eq!(checks(&unchecked.code), 0);
    assert_eq!(checks(&checked.code), 3);
    // Each load takes its own instruction's decision.
    let second =
        emit_clean_load_prefix(&instructions, true, Some(&[true, false, true, false, true]))
            .unwrap();
    assert_eq!(checks(&second.code), 1);
    assert_eq!(
        checked.consumed_instructions,
        unchecked.consumed_instructions
    );
    assert_eq!(checked.stats.clean_loads, unchecked.stats.clean_loads);
    assert_eq!(checked.stats.pair_loads, 1);
    // The second load reuses the cached X1 and still checks.
    assert_eq!(
        checked.stats.address_cache_hits,
        unchecked.stats.address_cache_hits
    );
    assert_eq!(checked.code.len(), unchecked.code.len() + 3 * check.len());
    // The cost gate counts each check's six instructions on both sides.
    let mut baseline = Code::new();
    for instruction in &instructions {
        super::super::emit_instruction(
            &mut baseline,
            instruction,
            &mut vec![],
            crate::TargetCpu::Baseline,
            super::super::MemoryChecks {
                guest_range: true,
                ..super::super::MemoryChecks::DEFAULT
            },
        );
    }
    let count = baseline.instructions();
    assert_eq!(
        checked.stats.native_instructions,
        unchecked.stats.native_instructions
            + 3 * super::super::RangeCheck::at(&check).unwrap().1.len()
    );
    assert!(checked.stats.native_instructions <= count);
    assert!(admits_ordinary(&checked, &baseline));
}

#[test]
fn cached_right_destination_commutes_only_plain_unshifted_operations() {
    let arithmetic = |subtract, amount| Operation::AddSubRegister {
        width: Width::X64,
        subtract,
        flags: false,
        destination: Register::X(1),
        left: Register::X(0),
        right: Register::X(1),
        shift: Shift::Lsl,
        amount,
    };
    let emit = |operation| {
        emit_prefix(&[
            instruction(0, add(Register::X(0), Register::X(0))),
            instruction(1, add(Register::X(1), Register::X(1))),
            instruction(2, operation),
        ])
        .unwrap()
    };
    let commuted = emit(arithmetic(false, 0));
    assert_eq!(commuted.stats.native_instructions, 9);
    assert_eq!(emit(arithmetic(true, 0)).stats.native_instructions, 10);
    assert_eq!(emit(arithmetic(false, 1)).stats.native_instructions, 12);
    for kind in [Logical::And, Logical::Or, Logical::Xor] {
        let logical = |invert, amount| Operation::LogicalRegister {
            width: Width::W32,
            kind,
            flags: false,
            invert,
            destination: Register::X(1),
            left: Register::X(0),
            right: Register::X(1),
            shift: Shift::Lsl,
            amount,
        };
        assert_eq!(emit(logical(false, 0)).stats.native_instructions, 9);
        assert_eq!(emit(logical(true, 0)).stats.native_instructions, 12);
        assert_eq!(emit(logical(false, 1)).stats.native_instructions, 12);
    }
}

#[test]
fn borrowed_load_result_settles_dirty_changes_before_next_faultable_load() {
    let load = |data| Operation::Memory {
        transfer: MemoryTransfer::Load {
            signed: false,
            width: Width::W32,
        },
        bytes: 1,
        data: Register::X(data),
        base: Register::X(1),
        displacement: 0,
        mode: AddressMode::Offset,
    };
    let output = emit_clean_load_prefix(
        &[
            instruction(0, load(10)),
            instruction(1, add(Register::X(10), Register::X(10))),
            instruction(2, load(11)),
            instruction(3, add(Register::X(0), Register::X(10))),
        ],
        true,
        None,
    )
    .unwrap();
    assert_eq!(output.stats.load_boundary_stores, 1);
}

#[test]
fn clean_load_tier_declines_unselected_memory_forms() {
    for (base, signed, width, bytes, mode) in [
        (Register::Sp, false, Width::W32, 1, AddressMode::PreIndex),
        (Register::X(0), true, Width::W32, 1, AddressMode::Offset),
        (Register::X(0), false, Width::X64, 1, AddressMode::Offset),
        (Register::X(0), false, Width::W32, 8, AddressMode::Offset),
        (Register::X(0), true, Width::X64, 4, AddressMode::Offset),
        (Register::X(0), false, Width::W32, 1, AddressMode::PostIndex),
        (Register::X(0), false, Width::X64, 8, AddressMode::PreIndex),
        (Register::Sp, true, Width::X64, 4, AddressMode::Offset),
        (Register::Zero, false, Width::X64, 8, AddressMode::Offset),
    ] {
        let operation = Operation::Memory {
            transfer: MemoryTransfer::Load { signed, width },
            bytes,
            data: Register::X(0),
            base,
            displacement: 0,
            mode,
        };
        assert!(analysis::clean_load_effects(&operation).is_none());
    }
}

#[test]
fn shared_byte_load_recipe_rejects_any_clobber_or_offset_change() {
    let mut raw = Code::new();
    super::super::memory(
        &mut raw,
        super::super::MemoryChecks::DEFAULT,
        MemoryTransfer::Load {
            signed: false,
            width: Width::W32,
        },
        1,
        Register::X(16),
        crate::x86_64::ImmediateAddress {
            base: Register::X(15),
            displacement: -255,
            mode: AddressMode::Offset,
        },
    );
    assert_eq!(
        recipes::ordinary_load_ends(&raw, 1, 15, Some(16), -255),
        Some(vec![7, 14, 17, 24])
    );
    for index in 0..raw.len() {
        let mut mutated = raw.as_slice().to_vec();
        mutated[index] ^= 1;
        assert!(recipes::ordinary_load_ends(&mutated, 1, 15, Some(16), -255).is_none());
    }
    let mut raw = raw.into_bytes();
    raw.push(0x90);
    assert!(recipes::ordinary_load_ends(&raw, 1, 15, Some(16), -255).is_none());
}

#[test]
fn word_load_tier_keeps_clean_residents_and_canonical_fault_state() {
    let load = |data, base| Operation::Memory {
        transfer: MemoryTransfer::Load {
            signed: false,
            width: Width::W32,
        },
        bytes: WORD_LOAD_BYTES,
        data,
        base,
        displacement: -4,
        mode: AddressMode::Offset,
    };
    for data in [Register::X(15), Register::X(16), Register::Zero] {
        let instructions = [
            instruction(0, add(Register::X(9), Register::X(9))),
            instruction(1, load(data, Register::X(15))),
            instruction(2, add(Register::X(9), Register::X(9))),
        ];
        let region = emit_clean_load_prefix(&instructions, true, None).unwrap();
        assert_eq!(region.consumed_instructions, instructions.len());
        assert_eq!(region.stats.clean_loads, 1);
        assert_eq!(region.stats.load_boundary_stores, 1);
        assert!(region.code.windows(2).any(|bytes| bytes == [0x8b, 0x08]));
    }
}

#[test]
fn shared_load_recipes_reject_any_clobber_or_offset_change() {
    let sizes = [
        (Width::W32, HALFWORD_LOAD_BYTES),
        (Width::W32, WORD_LOAD_BYTES),
        (Width::X64, DOUBLEWORD_LOAD_BYTES),
    ];
    for (width, bytes) in sizes {
        for data in [Register::X(16), Register::Zero] {
            let mut raw = Code::new();
            super::super::memory(
                &mut raw,
                super::super::MemoryChecks::DEFAULT,
                MemoryTransfer::Load {
                    signed: false,
                    width,
                },
                bytes,
                data,
                crate::x86_64::ImmediateAddress {
                    base: Register::X(15),
                    displacement: -255,
                    mode: AddressMode::Offset,
                },
            );
            let selected = slot(data);
            let ends = recipes::ordinary_load_ends(&raw, bytes, 15, selected, -255).unwrap();
            assert_eq!(ends.last(), Some(&raw.len()));
            for index in 0..raw.len() {
                let mut mutated = raw.as_slice().to_vec();
                mutated[index] ^= 1;
                assert!(recipes::ordinary_load_ends(&mutated, bytes, 15, selected, -255).is_none());
            }
            for other in [BYTE_LOAD_BYTES, HALFWORD_LOAD_BYTES, WORD_LOAD_BYTES]
                .into_iter()
                .chain([DOUBLEWORD_LOAD_BYTES])
                .filter(|&other| other != bytes)
            {
                assert!(recipes::ordinary_load_ends(&raw, other, 15, selected, -255).is_none());
            }
        }
    }
}

/// A doubleword load keeps its full 64-bit result resident in RCX, and
/// the cost gate counts the shared REX.W load it splices.
#[test]
fn doubleword_loads_stay_resident_and_pass_the_cost_gate() {
    let load = |pc, data, base, displacement| {
        instruction(
            pc,
            Operation::Memory {
                transfer: MemoryTransfer::Load {
                    signed: false,
                    width: Width::X64,
                },
                bytes: DOUBLEWORD_LOAD_BYTES,
                data,
                base,
                displacement,
                mode: AddressMode::Offset,
            },
        )
    };
    // ldr x8,[x0,#16]; ldr x9,[x8,#8]; add x9,x9,x9; add x8,x8,x8
    let instructions = [
        load(0, Register::X(8), Register::X(0), 16),
        load(1, Register::X(9), Register::X(8), 8),
        instruction(2, add(Register::X(9), Register::X(9))),
        instruction(3, add(Register::X(8), Register::X(8))),
    ];
    let region = emit_clean_load_prefix(&instructions, true, None).unwrap();
    assert_eq!(region.consumed_instructions, instructions.len());
    assert_eq!(region.stats.clean_loads, 2);
    assert_eq!(region.stats.address_cache_hits, 1);
    assert!(
        region
            .code
            .windows(3)
            .any(|bytes| bytes == [0x48, 0x8b, 0x08])
    );
    let mut baseline = Code::new();
    for instruction in &instructions {
        super::super::emit_instruction(
            &mut baseline,
            instruction,
            &mut vec![],
            crate::TargetCpu::Baseline,
            super::super::MemoryChecks::DEFAULT,
        );
    }
    assert!(baseline.instructions() > 0);
    assert!(admits_ordinary(&region, &baseline));
}

#[test]
fn repeated_read_only_inputs_are_cached_without_architectural_writes() {
    let operation = |destination| Operation::AddSubRegister {
        width: Width::X64,
        subtract: true,
        flags: false,
        destination,
        left: destination,
        right: Register::X(12),
        shift: Shift::Lsl,
        amount: 0,
    };
    let source = [
        instruction(0, operation(Register::X(0))),
        instruction(1, operation(Register::X(1))),
        instruction(2, operation(Register::X(0))),
        instruction(3, operation(Register::X(1))),
    ];
    let region = emit_prefix(&source).unwrap();
    assert!(region.stats.input_cache_loads > 0);
    assert!(region.stats.cache_hits >= 3);
    assert_eq!(region.stats.pressure_stores, 0);
    assert_eq!(region.stats.exit_stores + region.stats.lifetime_stores, 2);
}

#[test]
fn pair_loads_keep_clean_results_and_reject_changed_shared_recipe() {
    let data = [Register::X(16), Register::X(17)];
    let operation = Operation::MemoryPair {
        transfer: MemoryTransfer::Load {
            signed: false,
            width: Width::W32,
        },
        bytes: WORD_LOAD_BYTES,
        data,
        base: Register::X(15),
        displacement: -8,
        mode: AddressMode::Offset,
    };
    let source = [
        instruction(0, add(Register::X(9), Register::X(9))),
        instruction(1, operation),
        instruction(2, add(Register::X(9), Register::X(16))),
        instruction(3, add(Register::X(10), Register::X(17))),
    ];
    let region = emit_clean_load_prefix(&source, true, None).unwrap();
    assert_eq!(region.consumed_instructions, source.len());
    assert_eq!(region.stats.pair_loads, 1);
    let mut raw = Code::new();
    super::super::memory_pair(
        &mut raw,
        super::super::MemoryChecks::DEFAULT,
        MemoryTransfer::Load {
            signed: false,
            width: Width::W32,
        },
        WORD_LOAD_BYTES,
        data,
        crate::x86_64::ImmediateAddress {
            base: Register::X(15),
            displacement: -8,
            mode: AddressMode::Offset,
        },
    );
    let ends = |raw: &[u8], bytes, base, data| {
        recipes::ordinary_pair_load_ends(raw, bytes, base, data, -8)
    };
    assert!(ends(&raw, WORD_LOAD_BYTES, 15, [Some(16), Some(17)]).is_some());
    assert!(ends(&raw, WORD_LOAD_BYTES, 15, [Some(16), Some(16)]).is_none());
    assert!(ends(&raw, DOUBLEWORD_LOAD_BYTES, 15, [Some(16), Some(17)]).is_none());
    for (width, bytes) in [
        (Width::W32, WORD_LOAD_BYTES),
        (Width::X64, DOUBLEWORD_LOAD_BYTES),
    ] {
        for (base, stack_alignment) in [
            (Register::X(15), true),
            (Register::Sp, true),
            (Register::Sp, false),
        ] {
            let mut raw = Code::new();
            super::super::memory_pair(
                &mut raw,
                super::super::MemoryChecks::system(stack_alignment, false, true, false),
                MemoryTransfer::Load {
                    signed: false,
                    width,
                },
                bytes,
                data,
                crate::x86_64::ImmediateAddress {
                    base,
                    displacement: -8,
                    mode: AddressMode::Offset,
                },
            );
            let base = slot(base).unwrap();
            assert!(ends(&raw, bytes, base, [Some(16), Some(17)]).is_some());
            for index in 0..raw.len() {
                let mut changed = raw.as_slice().to_vec();
                changed[index] ^= 1;
                assert!(ends(&changed, bytes, base, [Some(16), Some(17)]).is_none());
            }
        }
    }
}

/// Loads and pairs through SP carry exactly the block's SP alignment
/// check, before the address addition, and a resident SP supplies the
/// base.
#[test]
fn stack_pointer_loads_carry_the_blocks_alignment_check() {
    // sub sp,sp,#32; ldr x8,[sp,#8]; ldp x9,x10,[sp,#16];
    // add x8,x8,#1; add x9,x9,#1; add x10,x10,#1
    let instructions = [
        instruction(
            0,
            Operation::AddSub {
                width: Width::X64,
                subtract: true,
                flags: false,
                destination: Register::Sp,
                source: Register::Sp,
                immediate: 32,
            },
        ),
        instruction(
            1,
            Operation::Memory {
                transfer: MemoryTransfer::Load {
                    signed: false,
                    width: Width::X64,
                },
                bytes: DOUBLEWORD_LOAD_BYTES,
                data: Register::X(8),
                base: Register::Sp,
                displacement: 8,
                mode: AddressMode::Offset,
            },
        ),
        instruction(
            2,
            Operation::MemoryPair {
                transfer: MemoryTransfer::Load {
                    signed: false,
                    width: Width::X64,
                },
                bytes: DOUBLEWORD_LOAD_BYTES,
                data: [Register::X(9), Register::X(10)],
                base: Register::Sp,
                displacement: 16,
                mode: AddressMode::Offset,
            },
        ),
        instruction(3, add(Register::X(8), Register::X(8))),
        instruction(4, add(Register::X(9), Register::X(9))),
        instruction(5, add(Register::X(10), Register::X(10))),
    ];
    // The resident SP's own low byte is tested, then the shared JZ and
    // UD2 of `STACK_ALIGNMENT_CHECK`.
    let check = &super::super::STACK_ALIGNMENT_CHECK[2..];
    for stack_alignment in [true, false] {
        let region = emit_clean_load_prefix(&instructions, stack_alignment, None).unwrap();
        assert_eq!(region.consumed_instructions, instructions.len());
        assert_eq!(region.stats.clean_loads, 1);
        assert_eq!(region.stats.pair_loads, 1);
        assert_eq!(region.stats.address_cache_hits, 2);
        let checks = region
            .code
            .windows(check.len())
            .filter(|bytes| *bytes == check)
            .count();
        assert_eq!(checks, if stack_alignment { 2 } else { 0 });
        let mut baseline = Code::new();
        for instruction in &instructions {
            super::super::emit_instruction(
                &mut baseline,
                instruction,
                &mut vec![],
                crate::TargetCpu::Baseline,
                super::super::MemoryChecks::system(stack_alignment, false, true, false),
            );
        }
        assert!(baseline.instructions() > 0);
        assert!(admits_ordinary(&region, &baseline));
    }
}

#[test]
fn paired_load_tier_declines_unselected_shapes() {
    let selected = Operation::MemoryPair {
        transfer: MemoryTransfer::Load {
            signed: false,
            width: Width::W32,
        },
        bytes: WORD_LOAD_BYTES,
        data: [Register::X(0), Register::X(1)],
        base: Register::X(2),
        displacement: 0,
        mode: AddressMode::Offset,
    };
    assert!(analysis::clean_load_effects(&selected).is_some());
    for (width, bytes, base) in [
        (Width::X64, DOUBLEWORD_LOAD_BYTES, Register::X(2)),
        (Width::W32, WORD_LOAD_BYTES, Register::Sp),
        (Width::X64, DOUBLEWORD_LOAD_BYTES, Register::Sp),
    ] {
        let Operation::MemoryPair { displacement, .. } = selected else {
            unreachable!()
        };
        assert!(
            analysis::clean_load_effects(&Operation::MemoryPair {
                transfer: MemoryTransfer::Load {
                    signed: false,
                    width
                },
                bytes,
                data: [Register::X(0), Register::X(1)],
                base,
                displacement,
                mode: AddressMode::Offset,
            })
            .is_some()
        );
    }
    for (transfer, bytes, data, base, mode) in [
        (
            MemoryTransfer::Store,
            WORD_LOAD_BYTES,
            [Register::X(0), Register::X(1)],
            Register::X(2),
            AddressMode::Offset,
        ),
        (
            MemoryTransfer::Load {
                signed: true,
                width: Width::X64,
            },
            WORD_LOAD_BYTES,
            [Register::X(0), Register::X(1)],
            Register::X(2),
            AddressMode::Offset,
        ),
        (
            MemoryTransfer::Load {
                signed: false,
                width: Width::X64,
            },
            WORD_LOAD_BYTES,
            [Register::X(0), Register::X(1)],
            Register::X(2),
            AddressMode::Offset,
        ),
        (
            MemoryTransfer::Load {
                signed: false,
                width: Width::X64,
            },
            DOUBLEWORD_LOAD_BYTES,
            [Register::X(0), Register::X(1)],
            Register::Sp,
            AddressMode::PreIndex,
        ),
        (
            MemoryTransfer::Load {
                signed: false,
                width: Width::W32,
            },
            WORD_LOAD_BYTES,
            [Register::X(0), Register::X(0)],
            Register::X(2),
            AddressMode::Offset,
        ),
        (
            MemoryTransfer::Load {
                signed: false,
                width: Width::W32,
            },
            WORD_LOAD_BYTES,
            [Register::X(0), Register::Sp],
            Register::X(2),
            AddressMode::Offset,
        ),
        (
            MemoryTransfer::Load {
                signed: false,
                width: Width::W32,
            },
            WORD_LOAD_BYTES,
            [Register::X(0), Register::X(1)],
            Register::X(2),
            AddressMode::PostIndex,
        ),
    ] {
        assert!(
            analysis::clean_load_effects(&Operation::MemoryPair {
                transfer,
                bytes,
                data,
                base,
                displacement: 0,
                mode
            })
            .is_none()
        );
    }
}

/// With a fault table, a dirty value stays in its register across a
/// load and a store, whose entries name it over their code; a load's
/// destination leaves the table once the load commits it.
#[test]
fn fault_tables_keep_dirty_values_across_accesses() {
    let load = |data, base| Operation::Memory {
        transfer: MemoryTransfer::Load {
            signed: false,
            width: Width::X64,
        },
        bytes: DOUBLEWORD_LOAD_BYTES,
        data,
        base,
        displacement: 8,
        mode: AddressMode::Offset,
    };
    // add x9,x9,#1; ldr x12,[x1,#8]; add x9,x9,#1; add x10,x11,#1;
    // ldr x10,[x10,#8]; strb w9,[x2,#8]
    let instructions = [
        instruction(0, add(Register::X(9), Register::X(9))),
        instruction(1, load(Register::X(12), Register::X(1))),
        instruction(2, add(Register::X(9), Register::X(9))),
        instruction(3, add(Register::X(10), Register::X(11))),
        instruction(4, load(Register::X(10), Register::X(10))),
        instruction(5, store(BYTE_LOAD_BYTES, Register::X(9), Register::X(2), 8)),
    ];
    let settled = emit_clean_load_prefix_with(
        &instructions,
        super::super::MemoryChecks::DEFAULT,
        false,
        None,
    )
    .unwrap();
    assert!(settled.fault_recovery.is_empty());
    assert!(settled.stats.load_boundary_stores >= 2);
    let region = emit_clean_load_prefix_with(
        &instructions,
        super::super::MemoryChecks::DEFAULT,
        true,
        None,
    )
    .unwrap();
    assert_eq!(region.consumed_instructions, instructions.len());
    assert_eq!(region.stats.load_boundary_stores, 0);
    assert!(region.code.len() < settled.code.len());
    let guests = |entry: &crate::block::FaultRecovery| {
        let mut guests: Vec<u8> = entry.bindings.iter().map(|binding| binding.guest).collect();
        guests.sort_unstable();
        guests
    };
    let entries = &region.fault_recovery;
    assert_eq!(entries.len(), 3);
    // X9 across the first load; X9 and the changed X10, the second's
    // base and destination, whose old value a fault keeps, across the
    // second; X9 across the store.
    assert_eq!(guests(&entries[0]), [9]);
    assert_eq!(guests(&entries[1]), [9, 10]);
    assert_eq!(guests(&entries[2]), [9]);
    for pair in entries.windows(2) {
        assert!(pair[0].end <= pair[1].start);
    }
    for entry in entries {
        assert!(entry.start < entry.end && entry.end <= region.code.len());
        for binding in &entry.bindings {
            let crate::block::RecoverySource::HostRegister(host) = binding.source else {
                panic!("ordinary memory recovery uses host GPRs");
            };
            assert!(POOL.iter().any(|pool| *pool as u8 == host));
            // The access clobbers RCX, so nothing live stays there.
            assert_ne!(host, HostGpr::Rcx as u8);
        }
    }
}

/// With a fault table, a store whose data is dirty in a register the
/// access does not clobber, R8 among them, takes it from there: its
/// frame slot is stale. Only a value written back first is read from
/// the frame.
#[test]
fn fault_table_stores_read_dirty_data_from_its_register() {
    let mut instructions: Vec<_> = (3..8)
        .map(|guest| {
            instruction(
                guest - 3,
                add(Register::X(guest as u8), Register::X(guest as u8)),
            )
        })
        .collect();
    for guest in 3..8u8 {
        let index = instructions.len() as u64;
        instructions.push(instruction(
            index,
            store(BYTE_LOAD_BYTES, Register::X(guest), Register::X(2), 8),
        ));
    }
    let region = emit_clean_load_prefix_with(
        &instructions,
        super::super::MemoryChecks::DEFAULT,
        true,
        None,
    )
    .unwrap();
    assert_eq!(region.consumed_instructions, instructions.len());
    let code = &region.code;
    // A frame access `op reg, [rdi+offset]` (disp8 or disp32) whose
    // opcode byte is at `at`. The store's staging load is the one into
    // RCX; the additions read the initial values into RAX.
    let frame = |at: usize, opcode: u8, offset: u8| {
        code[at] == opcode
            && match code.get(at + 1).map(|modrm| modrm & 0xc7) {
                Some(0x47) => code.get(at + 2) == Some(&offset),
                Some(0x87) => code.get(at + 2..at + 6) == Some(&[offset, 0, 0, 0][..]),
                _ => false,
            }
    };
    for guest in 3..8u8 {
        let offset = guest * 8;
        for load in (1..code.len()).filter(|&at| {
            code[at - 1] == 0x48 && frame(at, 0x8b, offset) && code[at + 1] & 0x38 == 0x08
        }) {
            assert!(
                (0..load).any(|at| frame(at, 0x89, offset)),
                "X{guest} read from a stale frame slot"
            );
        }
    }
}

fn store(bytes: u8, data: Register, base: Register, displacement: i32) -> Operation {
    Operation::Memory {
        transfer: MemoryTransfer::Store,
        bytes,
        data,
        base,
        displacement,
        mode: AddressMode::Offset,
    }
}

fn store_pair(bytes: u8, data: [Register; 2], displacement: i32) -> Operation {
    Operation::MemoryPair {
        transfer: MemoryTransfer::Store,
        bytes,
        data,
        base: Register::Sp,
        displacement,
        mode: AddressMode::Offset,
    }
}

/// Stores settle every dirty value first, take resident bases and data
/// from their registers, keep a value staged from the frame clean in
/// RCX, and pass the cost gate against the unchanged emitter.
#[test]
fn stores_settle_first_and_reuse_resident_values() {
    // sub sp,sp,#32; add x9,x9,#1; add x9,x9,#1; str x9,[sp,#8];
    // stp x9,x10,[sp,#16]; strb w11,[x2,#3]; add x11,x11,#1;
    // strh wzr,[sp,#2]
    let instructions = [
        instruction(
            0,
            Operation::AddSub {
                width: Width::X64,
                subtract: true,
                flags: false,
                destination: Register::Sp,
                source: Register::Sp,
                immediate: 32,
            },
        ),
        instruction(1, add(Register::X(9), Register::X(9))),
        instruction(2, add(Register::X(9), Register::X(9))),
        instruction(
            3,
            store(DOUBLEWORD_LOAD_BYTES, Register::X(9), Register::Sp, 8),
        ),
        instruction(
            4,
            store_pair(DOUBLEWORD_LOAD_BYTES, [Register::X(9), Register::X(10)], 16),
        ),
        instruction(
            5,
            store(BYTE_LOAD_BYTES, Register::X(11), Register::X(2), 3),
        ),
        instruction(6, add(Register::X(11), Register::X(11))),
        instruction(
            7,
            store(HALFWORD_LOAD_BYTES, Register::Zero, Register::Sp, 2),
        ),
    ];
    let region = emit_clean_load_prefix(&instructions, true, None).unwrap();
    assert_eq!(region.consumed_instructions, instructions.len());
    assert_eq!(region.stats.stores, 4);
    // SP and X9 are dirty before the first store, and X11, whose staged
    // copy in RCX the ADD changes, before the last.
    assert_eq!(region.stats.load_boundary_stores, 3);
    assert_eq!(region.stats.address_cache_hits, 3);
    let contains = |bytes: &[u8]| {
        region
            .code
            .windows(bytes.len())
            .any(|window| window == bytes)
    };
    assert!(contains(&[0x48, 0x89, 0x08]));
    assert!(contains(&[0x4c, 0x89, 0x40, 0x08]));
    assert!(contains(&[0x88, 0x08]));
    assert!(contains(&[0x66, 0x89, 0x08]));
    let mut baseline = Code::new();
    for instruction in &instructions {
        super::super::emit_instruction(
            &mut baseline,
            instruction,
            &mut vec![],
            crate::TargetCpu::Baseline,
            super::super::MemoryChecks::DEFAULT,
        );
    }
    assert!(admits_ordinary(&region, &baseline));
}

/// Single stores are selected; pairs only through a checked, aligned SP;
/// writeback never.
#[test]
fn stores_are_selected_and_pairs_only_aligned() {
    let selected = |operation, stack_alignment| {
        analysis::clean_access_effects(&operation, stack_alignment).is_some()
    };
    let sp = Register::Sp;
    let x = Register::X(3);
    let data = Register::X(4);
    assert!(selected(store(BYTE_LOAD_BYTES, data, x, 1), false));
    assert!(selected(store(WORD_LOAD_BYTES, data, sp, 12), true));
    for (operation, stack_alignment) in [
        (store(DOUBLEWORD_LOAD_BYTES, data, x, 8), true),
        (store(HALFWORD_LOAD_BYTES, data, x, 2), true),
        (store(DOUBLEWORD_LOAD_BYTES, data, sp, 8), false),
        (store(DOUBLEWORD_LOAD_BYTES, data, sp, 4), true),
    ] {
        assert!(selected(operation, stack_alignment));
    }
    assert!(selected(
        store_pair(WORD_LOAD_BYTES, [data, data], -64),
        true
    ));
    assert_eq!(
        analysis::clean_access_effects(&store(BYTE_LOAD_BYTES, Register::Zero, sp, 0), true),
        Some(analysis::Effects {
            reads: 1 << 31,
            writes: 0
        })
    );
    for (operation, stack_alignment) in [
        (store_pair(DOUBLEWORD_LOAD_BYTES, [data, data], 16), false),
        (store_pair(DOUBLEWORD_LOAD_BYTES, [data, data], 12), true),
        (store_pair(DOUBLEWORD_LOAD_BYTES, [data, data], 512), true),
        (
            Operation::MemoryPair {
                transfer: MemoryTransfer::Store,
                bytes: DOUBLEWORD_LOAD_BYTES,
                data: [data, data],
                base: x,
                displacement: 16,
                mode: AddressMode::Offset,
            },
            true,
        ),
        (
            Operation::Memory {
                transfer: MemoryTransfer::Store,
                bytes: BYTE_LOAD_BYTES,
                data,
                base: sp,
                displacement: 16,
                mode: AddressMode::PreIndex,
            },
            true,
        ),
    ] {
        assert!(!selected(operation, stack_alignment));
    }
}

#[test]
fn shared_store_recipes_reject_any_change() {
    for (bytes, base) in [
        (BYTE_LOAD_BYTES, Register::X(15)),
        (HALFWORD_LOAD_BYTES, Register::X(15)),
        (WORD_LOAD_BYTES, Register::X(15)),
        (DOUBLEWORD_LOAD_BYTES, Register::X(15)),
        (BYTE_LOAD_BYTES, Register::Sp),
        (HALFWORD_LOAD_BYTES, Register::Sp),
        (WORD_LOAD_BYTES, Register::Sp),
        (DOUBLEWORD_LOAD_BYTES, Register::Sp),
    ] {
        for data in [Register::X(16), Register::Zero] {
            let mut raw = Code::new();
            super::super::memory(
                &mut raw,
                super::super::MemoryChecks::DEFAULT,
                MemoryTransfer::Store,
                bytes,
                data,
                crate::x86_64::ImmediateAddress {
                    base,
                    displacement: -16,
                    mode: AddressMode::Offset,
                },
            );
            let ends = |raw: &[u8], bytes| {
                recipes::ordinary_store_ends(raw, bytes, slot(base).unwrap(), slot(data), -16)
            };
            let (selected, _) = ends(&raw, bytes).unwrap();
            assert_eq!(selected.last(), Some(&raw.len()));
            for index in 0..raw.len() {
                let mut changed = raw.as_slice().to_vec();
                changed[index] ^= 1;
                assert!(ends(&changed, bytes).is_none());
            }
            for other in [
                BYTE_LOAD_BYTES,
                HALFWORD_LOAD_BYTES,
                WORD_LOAD_BYTES,
                DOUBLEWORD_LOAD_BYTES,
            ] {
                assert_eq!(ends(&raw, other).is_some(), other == bytes);
            }
        }
    }
    for bytes in [WORD_LOAD_BYTES, DOUBLEWORD_LOAD_BYTES] {
        for data in [
            [Register::X(16), Register::X(17)],
            [Register::Zero, Register::X(16)],
            [Register::X(16), Register::Zero],
        ] {
            let mut raw = Code::new();
            super::super::memory_pair(
                &mut raw,
                super::super::MemoryChecks::DEFAULT,
                MemoryTransfer::Store,
                bytes,
                data,
                crate::x86_64::ImmediateAddress {
                    base: Register::Sp,
                    displacement: -16,
                    mode: AddressMode::Offset,
                },
            );
            let ends = |raw: &[u8], bytes| {
                recipes::ordinary_pair_store_ends(raw, bytes, 31, data.map(slot), -16)
            };
            assert!(ends(&raw, bytes).is_some());
            for index in 0..raw.len() {
                let mut changed = raw.as_slice().to_vec();
                changed[index] ^= 1;
                assert!(ends(&changed, bytes).is_none());
            }
        }
    }
}

fn define_flags(destination: Register, source: Register) -> Operation {
    Operation::AddSub {
        width: Width::X64,
        subtract: true,
        flags: true,
        destination,
        source,
        immediate: 1,
    }
}

#[test]
fn profiled_region_counts_cross_register_renaming_and_flag_pressure() {
    let renamed = [
        instruction(0, define_flags(Register::X(0), Register::X(0))),
        instruction(1, add(Register::X(1), Register::X(0))),
        instruction(
            2,
            Operation::MoveWide {
                width: Width::X64,
                kind: WideMove::Zero,
                destination: Register::X(0),
                immediate: 0,
                shift: 0,
            },
        ),
        instruction(3, add(Register::X(1), Register::X(1))),
    ];
    let renamed = emit_allocated_prefix(&renamed).unwrap().unwrap();
    assert_eq!(renamed.stats.coalesced_writes, 1);
    assert_eq!(renamed.stats.in_place_source_uses, 2);
    let mut pressure = vec![instruction(0, define_flags(Register::X(0), Register::X(0)))];
    for _ in 0..2 {
        for register in 1..25 {
            pressure.push(instruction(
                pressure.len() as u64,
                add(Register::X(register), Register::X(register)),
            ));
        }
    }
    pressure.push(instruction(
        pressure.len() as u64,
        select_flags(Register::X(25), Register::X(26), Register::X(27), 0),
    ));
    let pressure = emit_allocated_prefix(&pressure).unwrap().unwrap();
    assert!(
        pressure.stats.nzcv_pressure_stores > 0,
        "{:?}",
        pressure.stats
    );
    let traffic = crate::block::profile::RegisterTraffic::region(&pressure.stats);
    assert_eq!(
        traffic.gpr_pressure_stores + traffic.nzcv_pressure_stores,
        pressure.stats.pressure_stores as u64
    );
    assert_eq!(
        traffic.gpr_boundary_stores + traffic.nzcv_boundary_stores,
        pressure.stats.exit_stores as u64
    );
    assert_eq!(
        traffic.nzcv_direct_stores + traffic.nzcv_pressure_stores + traffic.nzcv_boundary_stores,
        pressure.stats.flag_stores as u64
    );
}

fn select_flags(
    destination: Register,
    left: Register,
    right: Register,
    condition: u8,
) -> Operation {
    Operation::ConditionalSelect(crate::aarch64::conditional_select::Operand {
        width: Width::X64,
        destination,
        left,
        right,
        condition,
        otherwise: crate::aarch64::conditional_select::Otherwise::Unchanged,
    })
}

#[test]
fn value_liveness_keeps_final_bank_and_kills_only_overwritten_versions() {
    use allocation::{LiveRanges, Value, ValueEffects};
    let x0 = Value::gpr(0).unwrap();
    let x1 = Value::gpr(1).unwrap();
    let effects = [
        ValueEffects::new(
            Effects {
                reads: 0,
                writes: 1,
            },
            false,
            true,
        ),
        ValueEffects::new(
            Effects {
                reads: 1,
                writes: 2,
            },
            false,
            false,
        ),
        ValueEffects::new(
            Effects {
                reads: 0,
                writes: 1,
            },
            false,
            true,
        ),
    ];
    let live = LiveRanges::compute(&effects);
    assert!(live.required_after(0, x0));
    assert!(!live.required_after(1, x0));
    assert!(!live.required_after(0, Value::NZCV));
    assert!(live.required_after(1, x1));
    assert!(live.required_after(2, x0));
    assert!(live.required_after(2, Value::NZCV));
    assert_eq!(live.before(0) & (x0.mask() | Value::NZCV.mask()), 0);
}

#[test]
fn packed_flags_survive_nonflag_arithmetic_without_frame_roundtrip() {
    let instructions = [
        instruction(0, define_flags(Register::Zero, Register::X(0))),
        instruction(
            1,
            select_flags(Register::X(2), Register::X(0), Register::X(1), 0),
        ),
        instruction(2, add(Register::X(3), Register::X(1))),
        instruction(
            3,
            select_flags(Register::X(4), Register::X(2), Register::X(3), 12),
        ),
    ];
    let region = emit_allocated_prefix(&instructions).unwrap().unwrap();
    assert_eq!(region.consumed_instructions, instructions.len());
    assert_eq!(region.stats.flag_loads, 0);
    assert_eq!(region.stats.flag_stores, 1);
    assert_eq!(region.stats.pressure_stores, 0);
}

#[test]
fn dead_native_flag_version_needs_no_capture_before_next_producer() {
    let instructions = [
        instruction(0, define_flags(Register::Zero, Register::X(0))),
        instruction(1, add(Register::X(1), Register::X(0))),
        instruction(2, define_flags(Register::Zero, Register::X(1))),
    ];
    let region = emit_allocated_prefix(&instructions).unwrap().unwrap();
    assert_eq!(region.stats.flag_loads, 0);
    assert_eq!(region.stats.flag_stores, 1);
    assert!(region.stats.dead_versions >= 1);
}

#[test]
fn caller_pool_is_still_exact_for_legacy_cost_and_load_chunk() {
    let instructions = [
        instruction(0, add(Register::X(2), Register::X(2))),
        instruction(
            1,
            Operation::Memory {
                transfer: MemoryTransfer::Load {
                    signed: false,
                    width: Width::W32,
                },
                bytes: 1,
                data: Register::X(3),
                base: Register::X(0),
                displacement: 0,
                mode: AddressMode::Offset,
            },
        ),
        instruction(2, add(Register::X(2), Register::X(2))),
    ];
    assert!(emit_allocated_prefix(&instructions).unwrap().is_none());
    let legacy = emit_clean_load_prefix(&instructions, true, None).unwrap();
    let target = crate::TargetCpu::Baseline;
    let fallthrough = GuestAddress(0x100c);
    let baseline = super::super::block::emit_for_target(
        &instructions,
        None,
        fallthrough,
        target,
        super::super::MemoryChecks::DEFAULT,
    );
    let ordinary =
        super::super::block::emit_ordinary_for_target(&instructions, None, fallthrough, target);
    let mut baseline_prefix = Code::new();
    let mut fixups = vec![];
    for instruction in &instructions {
        super::super::emit_instruction(
            &mut baseline_prefix,
            instruction,
            &mut fixups,
            target,
            super::super::MemoryChecks::DEFAULT,
        );
    }
    assert!(fixups.is_empty());
    if admits_ordinary(&legacy, &baseline_prefix) {
        assert!(ordinary.x86_64_code.starts_with(&legacy.code));
        assert_eq!(
            &ordinary.source_map[..instructions.len()],
            &legacy.source_map
        );
    } else {
        assert_eq!(ordinary.x86_64_code, baseline.x86_64_code);
        assert_eq!(ordinary.source_map, baseline.source_map);
    }
    let mut capture = Code::new();
    crate::x86_64::capture_nzcv(&mut capture, true);
    assert_eq!(capture.instructions(), 7);
}

#[test]
fn wider_loop_admission_uses_capacity_not_five_participants() {
    let mut instructions: Vec<_> = (0..7)
        .map(|index| {
            instruction(
                index,
                add(Register::X(index as u8), Register::X(index as u8)),
            )
        })
        .collect();
    instructions.push(instruction(7, define_flags(Register::X(0), Register::X(0))));
    let terminal = (
        GuestAddress(0x1020),
        crate::block::Terminator::Branch(Operation::BranchCondition {
            target: GuestAddress(0x1000),
            condition: 1,
        }),
    );
    let fallthrough = GuestAddress(0x1024);
    let target = crate::TargetCpu::Baseline;
    let plan = self_loop::Plan::new(&instructions, Some(&terminal), fallthrough).unwrap();
    let native = plan
        .emit(&instructions, Some(&terminal), fallthrough, target)
        .unwrap();
    assert_eq!(native.source_map.len(), instructions.len() + 1);
    assert_eq!(native.source_map[0].1, 0);
    let changed = [instruction(0, Operation::Nop)];
    let plan = self_loop::Plan::new(&instructions, Some(&terminal), fallthrough).unwrap();
    assert!(matches!(
        plan.emit(&changed, Some(&terminal), fallthrough, target),
        Err(RegionError::ChangedInstructions)
    ));
}

#[test]
fn copied_store_recipes_preserve_the_shared_bytes_and_instruction_count() {
    for bytes in [
        BYTE_LOAD_BYTES,
        HALFWORD_LOAD_BYTES,
        WORD_LOAD_BYTES,
        DOUBLEWORD_LOAD_BYTES,
    ] {
        for base in [Register::X(15), Register::Sp] {
            for data in [Register::X(16), Register::Zero] {
                let input = [instruction(0, store(bytes, data, base, -16))];
                let mut baseline = Code::new();
                super::super::memory(
                    &mut baseline,
                    super::super::MemoryChecks::DEFAULT,
                    MemoryTransfer::Store,
                    bytes,
                    data,
                    super::super::ImmediateAddress {
                        base,
                        displacement: -16,
                        mode: AddressMode::Offset,
                    },
                );
                let region = emit_clean_load_prefix_with(
                    &input,
                    super::super::MemoryChecks::DEFAULT,
                    false,
                    None,
                )
                .unwrap();
                assert_eq!(region.consumed_instructions, 1);
                // Independently counted shared recipes: base+LEA+data plus
                // one store. SP adds three alignment-check instructions.
                let expected_count = if base == Register::Sp { 7 } else { 4 };
                assert_eq!(baseline.instructions(), expected_count);
                assert_eq!(region.code, baseline, "{bytes} bytes {base:?} {data:?}");
                assert_eq!(
                    region.code.instructions(),
                    baseline.instructions(),
                    "cost count must retain every instruction in the recipe"
                );
            }
        }
    }
}
#[test]
fn translated_range_data_has_no_instruction_cost() {
    let instructions: Vec<_> = [16, 24]
        .into_iter()
        .enumerate()
        .map(|(index, displacement)| {
            instruction(
                index as u64,
                Operation::Memory {
                    transfer: MemoryTransfer::Load {
                        signed: false,
                        width: Width::X64,
                    },
                    bytes: 8,
                    data: Register::X(index as u8 + 2),
                    base: Register::X(1),
                    displacement,
                    mode: AddressMode::Offset,
                },
            )
        })
        .collect();
    let checks = super::super::MemoryChecks {
        guest_range: true,
        translated: true,
        translation_helper: 0x1000,
        ..super::super::MemoryChecks::DEFAULT
    };
    let mut check = Code::new();
    checks.range.emit_translated(
        &mut check,
        checks.translation_helper,
        super::super::Access::of(false, 8),
    );
    // Five test instructions, MOV/MOFFS/CALL/JMP, and the mask.
    // The two descriptor bytes following CALL contribute no instruction.
    assert_eq!(check.instructions(), 10);
    let mut baseline = Code::new();
    for input in &instructions {
        super::super::emit_instruction(
            &mut baseline,
            input,
            &mut vec![],
            crate::TargetCpu::Baseline,
            checks,
        );
    }
    let region =
        emit_clean_load_prefix_with(&instructions, checks, false, Some(&[true, true])).unwrap();
    assert_eq!(baseline.instructions(), 28);
    // Two translated checks contain data after CALL, not two extra instructions.
    assert_eq!(region.code.instructions(), 27);
    assert_eq!(region.stats.native_instructions, 27);
    assert!(region.code.len() < baseline.len());
    assert!(admits_ordinary(&region, &baseline));
    std::eprintln!(
        "TRANSLATED_COUNT baseline={} candidate={} stats={} bytes={}/{} admitted={}",
        baseline.instructions(),
        region.code.instructions(),
        region.stats.native_instructions,
        baseline.len(),
        region.code.len(),
        admits_ordinary(&region, &baseline)
    );
}
