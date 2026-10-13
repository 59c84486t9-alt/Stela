//! Baseline SSE2 data movement. Original Arm bytes are never host instructions.
//! Ordinary private RAM only: no 128-bit atomicity or guest fault delivery claim.
use super::{memory_address, memory_writeback};
use crate::aarch64::simd::{IntegerOperation, Operand};

fn vector_offset(vector: u8) -> u32 {
    264 + u32::from(vector) * 16
}

fn commit(code: &mut Vec<u8>, vector: u8, xmm: u8) {
    // GuestState has only 8-byte alignment; V0 begins at byte264.
    code.extend([0xf3, 0x0f, 0x7f, 0x87 | (xmm << 3)]); // movdqu [rdi+disp32],xmmN
    code.extend(vector_offset(vector).to_le_bytes());
}

fn read_vector(code: &mut Vec<u8>, vector: u8, xmm: u8) {
    code.extend([0xf3, 0x0f, 0x6f, 0x87 | (xmm << 3)]); // movdqu xmmN,[rdi+disp32]
    code.extend(vector_offset(vector).to_le_bytes());
}

fn packed(code: &mut Vec<u8>, opcode: u8, destination: u8, source: u8) {
    code.extend([0x66, 0x0f, opcode, 0xc0 | (destination << 3) | source]);
}

fn subtract_opcode(lane_bytes: u8) -> u8 {
    match lane_bytes {
        1 => 0xf8,
        2 => 0xf9,
        4 => 0xfa,
        8 => 0xfb,
        _ => unreachable!("reviewed lane size"),
    }
}

/// Transfer S/D/Q at [RAX+displacement], using XMM0/XMM1. Scalar loads
/// zero the rest of the 128-bit host value; no widened guest access is emitted.
fn wide_memory(code: &mut Vec<u8>, load: bool, bytes: u8, xmm: u8, displacement: u8) {
    let (prefix, opcode) = match (load, bytes) {
        (true, 4) => (0x66, 0x6e),   // MOVD xmm,m32
        (true, 8) => (0xf3, 0x7e),   // MOVQ xmm,m64
        (true, 16) => (0xf3, 0x6f),  // MOVDQU xmm,m128
        (false, 4) => (0x66, 0x7e),  // MOVD m32,xmm
        (false, 8) => (0x66, 0xd6),  // MOVQ m64,xmm
        (false, 16) => (0xf3, 0x7f), // MOVDQU m128,xmm
        _ => unreachable!("decoder validates wide vector memory width"),
    };
    let modrm = (xmm << 3) | if displacement == 0 { 0 } else { 0x40 };
    code.extend([prefix, 0x0f, opcode, modrm]);
    if displacement != 0 {
        // Only the second pair element needs displacement: 4, 8 or 16 bytes.
        code.push(displacement);
    }
}

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand) {
    match *operand {
        Operand::Integer {
            operation,
            destination,
            left,
            right,
            bytes,
            lane_bytes,
        } => {
            use IntegerOperation::*;
            // Stage original sources before committing any overlapping V register.
            read_vector(code, left, 0);
            let mut result = 0;
            if !matches!(operation, Abs | Neg) {
                read_vector(code, right, 1);
            }
            match operation {
                And => packed(code, 0xdb, 0, 1),
                Bic => {
                    packed(code, 0xdf, 1, 0);
                    result = 1;
                }
                Orr => packed(code, 0xeb, 0, 1),
                Orn => {
                    packed(code, 0x76, 2, 2); // pcmpeqd: all ones, including dirty Q=0 upper bits
                    packed(code, 0xef, 1, 2);
                    packed(code, 0xeb, 0, 1);
                }
                Eor => packed(code, 0xef, 0, 1),
                Bsl | Bit | Bif => {
                    read_vector(code, destination, 2);
                    if operation == Bsl {
                        packed(code, 0xef, 0, 1);
                        packed(code, 0xdb, 0, 2);
                        packed(code, 0xef, 0, 1);
                    } else {
                        packed(code, 0xef, 0, 2);
                        if operation == Bit {
                            packed(code, 0xdb, 0, 1);
                            packed(code, 0xef, 0, 2);
                        } else {
                            packed(code, 0xdf, 1, 0);
                            packed(code, 0xef, 1, 2);
                            result = 1;
                        }
                    }
                }
                Add => packed(
                    code,
                    match lane_bytes {
                        1 => 0xfc,
                        2 => 0xfd,
                        4 => 0xfe,
                        8 => 0xd4,
                        _ => unreachable!("reviewed lane size"),
                    },
                    0,
                    1,
                ),
                Sub => packed(code, subtract_opcode(lane_bytes), 0, 1),
                Neg => {
                    packed(code, 0xef, 1, 1);
                    packed(code, subtract_opcode(lane_bytes), 1, 0);
                    result = 1;
                }
                Abs => {
                    packed(code, 0xef, 1, 1);
                    packed(
                        code,
                        match lane_bytes {
                            1 => 0x64,
                            2 => 0x65,
                            4 | 8 => 0x66,
                            _ => unreachable!("reviewed lane size"),
                        },
                        1,
                        0,
                    );
                    if lane_bytes == 8 {
                        // SSE2 lacks a signed qword comparison: repeat each high
                        // dword's sign across its qword, using only its sign bit.
                        code.extend([0x66, 0x0f, 0x70, 0xc9, 0xf5]);
                    }
                    packed(code, 0xef, 0, 1);
                    packed(code, subtract_opcode(lane_bytes), 0, 1);
                }
            }
            if bytes == 8 {
                // Arm clears the complete upper half on scalar/D vector writes.
                code.extend([0xf3, 0x0f, 0x7e, 0xc0 | (result << 3) | result]);
            }
            commit(code, destination, result);
        }
        Operand::MemoryPair {
            load,
            bytes,
            vectors,
            base,
            displacement,
            mode,
        } => {
            memory_address(code, base, displacement, mode);
            if load {
                wide_memory(code, true, bytes, 0, 0);
                wide_memory(code, true, bytes, 1, bytes);
                // Neither guest destination changes if either load faults.
                // Duplicate destinations were declined by the decoder.
                commit(code, vectors[0], 0);
                commit(code, vectors[1], 1);
            } else {
                // Read both original sources before exposing either RAM write;
                // duplicate source indices are valid and retain the same value.
                read_vector(code, vectors[0], 0);
                read_vector(code, vectors[1], 1);
                wide_memory(code, false, bytes, 0, 0);
                wide_memory(code, false, bytes, 1, bytes);
            }
            // Split private-RAM stores may expose the first completed element
            // if the second faults. Base writeback requires both to complete.
            memory_writeback(code, base, mode);
        }
        Operand::MoveImmediate {
            vector,
            mask,
            two_lanes,
        } => {
            if mask == 0 {
                code.extend([0x66, 0x0f, 0xef, 0xc0]); // pxor xmm0,xmm0
                commit(code, vector, 0);
                return;
            }
            code.extend([0x48, 0xb9]); // movabs rcx,mask
            code.extend(mask.to_le_bytes());
            code.extend([0x66, 0x48, 0x0f, 0x6e, 0xc1]); // movq xmm0,rcx (zeros high64)
            if two_lanes {
                code.extend([0x66, 0x0f, 0x6c, 0xc0]); // punpcklqdq xmm0,xmm0
            }
            commit(code, vector, 0);
        }
        Operand::Memory {
            load,
            bytes,
            vector,
            base,
            displacement,
            mode,
        } => {
            memory_address(code, base, displacement, mode);
            if load {
                match bytes {
                    1 | 2 => {
                        // MOVZX avoids over-reading narrow objects; MOVD clears
                        // every destination vector bit above the loaded data.
                        code.extend([0x0f, if bytes == 1 { 0xb6 } else { 0xb7 }, 0x08]);
                        code.extend([0x66, 0x0f, 0x6e, 0xc1]); // movd xmm0,ecx
                    }
                    4 | 8 | 16 => wide_memory(code, true, bytes, 0, 0),
                    _ => unreachable!("decoder validates vector memory width"),
                }
                // Stage the complete load before touching guest state. A native
                // fault leaves the destination and base unchanged. GuestState
                // is independently live/writable under the direct-RAM contract.
                commit(code, vector, 0);
            } else if bytes <= 2 {
                code.extend([0x48, 0x8b, 0x8f]); // mov rcx,[rdi+disp32]
                code.extend(vector_offset(vector).to_le_bytes());
                if bytes == 2 {
                    code.push(0x66);
                }
                code.extend([if bytes == 1 { 0x88 } else { 0x89 }, 0x08]);
            } else {
                read_vector(code, vector, 0);
                wide_memory(code, false, bytes, 0, 0);
            }
            // RDX retains the potential writeback across all SSE/GPR staging.
            memory_writeback(code, base, mode);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aarch64::{AddressMode, Register};

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
            0xf3, 0x0f, 0x6f, 0x00, 0xf3, 0x0f, 0x7f, 0x87, 0xf8, 2, 0, 0, 0x48, 0x89, 0x97, 248,
            0, 0, 0,
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
}
