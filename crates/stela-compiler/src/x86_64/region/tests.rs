use super::*;
use crate::aarch64::{Logical, Shift};
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
    assert_eq!(result.exit_pc, Some(GuestAddress(0x1400)));
    assert_eq!(result.liveness.live_exit, u32::MAX);
    assert_eq!(result.liveness.live_before, vec![u32::MAX; 256]);
    assert!(
        result
            .recovery
            .windows(2)
            .all(|rows| rows[0].native_end == rows[1].native_start)
    );
    assert_eq!(
        result.recovery.last().unwrap().native_end,
        result.code.len()
    );
    assert_eq!(result.recovery.last().unwrap().retired_instructions, 256);
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
    assert!(result.recovery.iter().all(RecoveryPoint::validate));
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
    assert_eq!(result.exit_pc, Some(instructions[1].pc));
    assert_eq!(result.source_map.len(), 1);
    let empty = emit_prefix(&instructions[1..]).unwrap();
    assert!(empty.code.is_empty());
    assert!(empty.recovery.is_empty());
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
fn recovery_refuses_scratch_alias_or_wrong_frame_slot() {
    let mut point = RecoveryPoint {
        native_start: 0,
        native_end: 3,
        guest_pc: GuestAddress(0x1000),
        retired_instructions: 0,
        phase: Phase::BeforeGuestCommit,
        gprs: FRAME_LOCATIONS,
    };
    point.gprs[0] = Location::Host(HostGpr::Rax);
    assert!(!point.validate());
    point.gprs[0] = Location::Host(POOL[0]);
    point.gprs[1] = Location::Host(POOL[0]);
    assert!(!point.validate());
    point.gprs = FRAME_LOCATIONS;
    point.gprs[0] = Location::Frame { byte_offset: 8 };
    assert!(!point.validate());
    point.gprs = FRAME_LOCATIONS;
    assert_eq!(point.reconstruct(&[7; 32], &[8; 16]), Some([7; 32]));
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
    // Initial load+ADD+MOV, four one-ALU commits, final canonical STORE.
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
    assert!(output.recovery.iter().all(|row| {
        row.gprs
            .iter()
            .all(|location| *location != Location::Host(HostGpr::Rcx))
    }));
    assert_eq!(output.exit_gprs, FRAME_LOCATIONS);
    assert_eq!(emit_prefix(&instructions).unwrap().consumed_instructions, 2);
}

#[test]
fn clean_load_tier_declines_sp_signed_and_nonbyte_forms() {
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
        encoding::ordinary_byte_load_ends(&raw, 15, Some(16), -255),
        Some(vec![7, 14, 17, 20, 27])
    );
    for index in 0..raw.len() {
        let mut mutated = raw.clone();
        mutated[index] ^= 1;
        assert!(encoding::ordinary_byte_load_ends(&mutated, 15, Some(16), -255).is_none());
    }
    raw.push(0x90);
    assert!(encoding::ordinary_byte_load_ends(&raw, 15, Some(16), -255).is_none());
}
