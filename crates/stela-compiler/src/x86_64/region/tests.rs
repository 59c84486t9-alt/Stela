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
fn selected_math_cost_inspection_refuses_unselected_memory_forms() {
    use analysis::selected_output_instruction_count as count;
    assert_eq!(count(&[0x4d, 0x0f, 0xaf, 0xd3]), Some(1));
    assert_eq!(count(&[0x48, 0x0f, 0xac, 0xc1, 63]), Some(1));
    assert_eq!(count(&[0x48, 0xf7, 0xd8]), Some(1));
    assert_eq!(count(&[0x48, 0x0f, 0xaf, 0x07]), None);
    assert_eq!(count(&[0x48, 0xf7, 0x1f]), None);
    assert_eq!(count(&[0x0f, 0xac, 0xc1]), None);
    assert_eq!(count(&[0x66, 0x0f, 0xaf, 0xc1]), None);
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
fn selected_output_counter_is_fail_closed_and_tracks_wide_store_recipes() {
    use analysis::selected_output_instruction_count as count;
    assert_eq!(count(&[]), Some(0));
    assert_eq!(count(&[0x66, 0xc7, 0x47, 2, 0x34, 0x12]), Some(1));
    assert_eq!(
        count(&[0x66, 0xc7, 0x87, 0x98, 0, 0, 0, 0x34, 0x12]),
        Some(1)
    );
    assert_eq!(count(&[0xc7, 0x47, 4, 0, 0, 0, 0]), Some(1));
    assert_eq!(count(&[0x48, 0xc7, 0xc0, 1, 0, 0, 0]), Some(1));
    assert_eq!(count(&[0x48, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0x90]), Some(2));
    for unsupported in [
        vec![0xc3],
        vec![0xc5, 0xf8, 0x77],
        vec![0x48],
        vec![0x66],
        vec![0x48, 0x8b, 0x04, 0x24], // SIB: outside selected output.
        vec![0x48, 0x8b, 0x05, 0, 0, 0, 0], // RIP-relative.
        vec![0x49, 0x8b, 0x07],       // R15, not the stable RDI frame.
        vec![0xf7, 0xf8],             // IDIV rather than NOT.
        vec![0x81, 0xc0, 1, 0],       // Truncated immediate.
    ] {
        assert_eq!(count(&unsupported), None, "{unsupported:02x?}");
    }
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
fn clean_byte_load_tier_retains_five_nonclobbered_slots() {
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
    let output = emit_clean_load_prefix(&instructions).unwrap();
    assert_eq!(output.consumed_instructions, 5);
    assert_eq!(output.stats.clean_loads, 1);
    assert_eq!(output.stats.load_boundary_stores, 2);
    assert_eq!(emit_prefix(&instructions).unwrap().consumed_instructions, 2);
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
    let output = emit_clean_load_prefix(&[
        instruction(0, load(10)),
        instruction(1, add(Register::X(10), Register::X(10))),
        instruction(2, load(11)),
        instruction(3, add(Register::X(0), Register::X(10))),
    ])
    .unwrap();
    assert_eq!(output.stats.load_boundary_stores, 1);
}

#[test]
fn clean_load_tier_declines_unselected_memory_forms() {
    for (base, signed, width, bytes, mode) in [
        (Register::Sp, false, Width::W32, 1, AddressMode::Offset),
        (Register::X(0), true, Width::W32, 1, AddressMode::Offset),
        (Register::X(0), false, Width::X64, 1, AddressMode::Offset),
        (Register::X(0), false, Width::W32, 2, AddressMode::Offset),
        (Register::X(0), false, Width::W32, 1, AddressMode::PostIndex),
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
    let mut raw = vec![];
    super::super::memory(
        &mut raw,
        MemoryTransfer::Load {
            signed: false,
            width: Width::W32,
        },
        1,
        Register::X(16),
        Register::X(15),
        -255,
        AddressMode::Offset,
    );
    assert_eq!(
        encoding::ordinary_load_ends(&raw, 1, 15, Some(16), -255),
        Some(vec![7, 14, 17, 20, 27])
    );
    for index in 0..raw.len() {
        let mut mutated = raw.clone();
        mutated[index] ^= 1;
        assert!(encoding::ordinary_load_ends(&mutated, 1, 15, Some(16), -255).is_none());
    }
    raw.push(0x90);
    assert!(encoding::ordinary_load_ends(&raw, 1, 15, Some(16), -255).is_none());
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
        let region = emit_clean_load_prefix(&instructions).unwrap();
        assert_eq!(region.consumed_instructions, instructions.len());
        assert_eq!(region.stats.clean_loads, 1);
        assert_eq!(region.stats.load_boundary_stores, 1);
        assert!(region.code.windows(2).any(|bytes| bytes == [0x8b, 0x08]));
    }
}

#[test]
fn shared_word_load_recipe_rejects_any_clobber_or_offset_change() {
    for data in [Register::X(16), Register::Zero] {
        let mut raw = vec![];
        super::super::memory(
            &mut raw,
            MemoryTransfer::Load {
                signed: false,
                width: Width::W32,
            },
            WORD_LOAD_BYTES,
            data,
            Register::X(15),
            -255,
            AddressMode::Offset,
        );
        let selected = slot(data);
        let ends = encoding::ordinary_load_ends(&raw, WORD_LOAD_BYTES, 15, selected, -255).unwrap();
        assert_eq!(ends.last(), Some(&raw.len()));
        for index in 0..raw.len() {
            let mut mutated = raw.clone();
            mutated[index] ^= 1;
            assert!(
                encoding::ordinary_load_ends(&mutated, WORD_LOAD_BYTES, 15, selected, -255)
                    .is_none()
            );
        }
        assert!(encoding::ordinary_load_ends(&raw, BYTE_LOAD_BYTES, 15, selected, -255).is_none());
    }
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
fn pair_loads_retain_clean_results_and_reject_changed_shared_recipe() {
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
    let region = emit_clean_load_prefix(&source).unwrap();
    assert_eq!(region.consumed_instructions, source.len());
    assert_eq!(region.stats.pair_loads, 1);
    let mut raw = vec![];
    super::super::memory_pair(
        &mut raw,
        MemoryTransfer::Load {
            signed: false,
            width: Width::W32,
        },
        WORD_LOAD_BYTES,
        data,
        Register::X(15),
        -8,
        AddressMode::Offset,
    );
    assert!(encoding::ordinary_pair_load_ends(&raw, 15, [Some(16), Some(17)], -8).is_some());
    for index in 0..raw.len() {
        let mut changed = raw.clone();
        changed[index] ^= 1;
        assert!(
            encoding::ordinary_pair_load_ends(&changed, 15, [Some(16), Some(17)], -8).is_none()
        );
    }
    assert!(encoding::ordinary_pair_load_ends(&raw, 15, [Some(16), Some(16)], -8).is_none());
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
            8,
            [Register::X(0), Register::X(1)],
            Register::X(2),
            AddressMode::Offset,
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
            [Register::X(0), Register::X(1)],
            Register::Sp,
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
    let legacy = emit_clean_load_prefix(&instructions).unwrap();
    let target = crate::TargetCpu::Baseline;
    let fallthrough = GuestAddress(0x100c);
    let baseline = super::super::block::emit_for_target(&instructions, None, fallthrough, target);
    let ordinary =
        super::super::block::emit_ordinary_for_target(&instructions, None, fallthrough, target);
    let mut baseline_prefix = vec![];
    let mut fixups = vec![];
    for instruction in &instructions {
        super::super::emit_instruction(&mut baseline_prefix, instruction, &mut fixups, target);
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
    assert_eq!(
        analysis::selected_output_instruction_count(&[0x9c, 0x5a]),
        None
    );
    assert_eq!(
        analysis::allocated_output_instruction_count(&[0x9c, 0x5a]),
        Some(2)
    );
}

#[test]
fn wider_loop_admission_uses_actual_capacity_not_five_participants() {
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
    let plan = self_loop::Plan::new(&instructions, Some(&terminal), GuestAddress(0x1024)).unwrap();
    let native = plan.emit(&instructions).unwrap();
    assert_eq!(native.source_map.len(), instructions.len() + 1);
    assert_eq!(native.source_map[0].1, 0);
    let changed = [instruction(0, Operation::Nop)];
    let plan = self_loop::Plan::new(&instructions, Some(&terminal), GuestAddress(0x1024)).unwrap();
    assert!(matches!(
        plan.emit(&changed),
        Err(RegionError::ChangedInstructions)
    ));
}
