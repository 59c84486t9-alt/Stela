use super::*;
use crate::aarch64::{AddressMode, Register};
use alloc::vec;

mod numerical_boundary;

#[test]
fn q_load_is_unaligned_staged_and_committed_before_writeback() {
    let mut code = vec![];
    emit(
        &mut code,
        &Operand::Memory {
            load: true,
            bytes: 16,
            vector: 31,
            base: Register::Sp,
            displacement: -16,
            mode: AddressMode::PreIndex,
        },
    );
    assert_eq!(&code[7..13], &[0xa8, 15, 0x74, 2, 0x0f, 0x0b]);
    let suffix = [
        0xf3, 0x0f, 0x6f, 0x00, 0xf3, 0x0f, 0x7f, 0x87, 0xf8, 2, 0, 0, 0x48, 0x89, 0x97, 248, 0, 0,
        0,
    ];
    assert!(code.ends_with(&suffix));
}

#[test]
fn scalar_accesses_use_exact_width_and_zero_high_vector_bits() {
    for (bytes, load_bytes, store_bytes) in [
        (
            1,
            vec![0x0f, 0xb6, 0x08, 0x66, 0x0f, 0x6e, 0xc1],
            vec![0x88, 0x08],
        ),
        (
            2,
            vec![0x0f, 0xb7, 0x08, 0x66, 0x0f, 0x6e, 0xc1],
            vec![0x66, 0x89, 0x08],
        ),
        (4, vec![0x66, 0x0f, 0x6e, 0], vec![0x66, 0x0f, 0x7e, 0]),
        (8, vec![0xf3, 0x0f, 0x7e, 0], vec![0x66, 0x0f, 0xd6, 0]),
    ] {
        for load in [false, true] {
            let mut code = vec![];
            emit(
                &mut code,
                &Operand::Memory {
                    load,
                    bytes,
                    vector: 0,
                    base: Register::X(0),
                    displacement: 0,
                    mode: AddressMode::Offset,
                },
            );
            if load {
                assert!(code[17..].starts_with(&load_bytes));
                assert!(code.ends_with(&[0xf3, 0x0f, 0x7f, 0x87, 8, 1, 0, 0]));
            } else {
                assert!(code.ends_with(&store_bytes));
            }
        }
    }
}

#[test]
fn movi_d_clears_high_half_and_two_d_replicates_without_new_cpu_features() {
    for two_lanes in [false, true] {
        let mut code = vec![];
        emit(
            &mut code,
            &Operand::MoveImmediate {
                vector: 31,
                mask: 0xff00ff00ff00ff00,
                two_lanes,
            },
        );
        assert_eq!(&code[..2], &[0x48, 0xb9]);
        assert_eq!(&code[2..10], &0xff00ff00ff00ff00u64.to_le_bytes());
        assert_eq!(&code[10..15], &[0x66, 0x48, 0x0f, 0x6e, 0xc1]);
        if two_lanes {
            assert_eq!(&code[15..19], &[0x66, 0x0f, 0x6c, 0xc0]);
        }
        assert!(code.ends_with(&[0xf3, 0x0f, 0x7f, 0x87, 0xf8, 2, 0, 0]));
    }
}

#[test]
fn zero_byte_masks_share_compact_full_vector_zeroing() {
    for two_lanes in [false, true] {
        let mut code = vec![];
        emit(
            &mut code,
            &Operand::MoveImmediate {
                vector: 0,
                mask: 0,
                two_lanes,
            },
        );
        assert_eq!(
            code,
            [0x66, 0x0f, 0xef, 0xc0, 0xf3, 0x0f, 0x7f, 0x87, 8, 1, 0, 0]
        );
    }
}

#[test]
fn pair_loads_stage_both_exact_width_values_before_guest_commits_and_writeback() {
    for (bytes, prefix, opcode) in [(4, 0x66, 0x6e), (8, 0xf3, 0x7e), (16, 0xf3, 0x6f)] {
        let mut code = vec![];
        emit(
            &mut code,
            &Operand::MemoryPair {
                load: true,
                bytes,
                vectors: [0, 31],
                base: Register::X(0),
                displacement: -64,
                mode: AddressMode::PreIndex,
            },
        );
        assert_eq!(
            &code[17..26],
            &[prefix, 0x0f, opcode, 0, prefix, 0x0f, opcode, 0x48, bytes]
        );
        assert_eq!(&code[26..34], &[0xf3, 0x0f, 0x7f, 0x87, 8, 1, 0, 0]);
        assert_eq!(&code[34..42], &[0xf3, 0x0f, 0x7f, 0x8f, 0xf8, 2, 0, 0]);
        assert_eq!(&code[42..], &[0x48, 0x89, 0x97, 0, 0, 0, 0]);
    }
}

#[test]
fn pair_stores_capture_duplicate_sources_before_two_writes_and_delay_writeback() {
    for (bytes, prefix, opcode) in [(4, 0x66, 0x7e), (8, 0x66, 0xd6), (16, 0xf3, 0x7f)] {
        let mut code = vec![];
        emit(
            &mut code,
            &Operand::MemoryPair {
                load: false,
                bytes,
                vectors: [31, 31],
                base: Register::Sp,
                displacement: 32,
                mode: AddressMode::PostIndex,
            },
        );
        assert_eq!(&code[7..13], &[0xa8, 15, 0x74, 2, 0x0f, 0x0b]);
        assert_eq!(&code[20..28], &[0xf3, 0x0f, 0x6f, 0x87, 0xf8, 2, 0, 0]);
        assert_eq!(&code[28..36], &[0xf3, 0x0f, 0x6f, 0x8f, 0xf8, 2, 0, 0]);
        assert_eq!(
            &code[36..45],
            &[prefix, 0x0f, opcode, 0, prefix, 0x0f, opcode, 0x48, bytes]
        );
        assert_eq!(&code[45..], &[0x48, 0x89, 0x97, 248, 0, 0, 0]);
    }
}
