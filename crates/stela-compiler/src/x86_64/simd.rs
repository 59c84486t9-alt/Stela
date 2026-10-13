//! Baseline SSE2 data movement. Original Arm bytes are never host instructions.
//! Ordinary private RAM only: no 128-bit atomicity or guest fault delivery claim.
use super::{memory_address, memory_writeback};
use crate::aarch64::simd::Operand;

fn vector_offset(vector: u8) -> u32 {
    264 + u32::from(vector) * 16
}

fn commit(code: &mut Vec<u8>, vector: u8) {
    // GuestState has only 8-byte alignment; V0 begins at byte264.
    code.extend([0xf3, 0x0f, 0x7f, 0x87]); // movdqu [rdi+disp32],xmm0
    code.extend(vector_offset(vector).to_le_bytes());
}

pub(super) fn emit(code: &mut Vec<u8>, operand: &Operand) {
    match *operand {
        Operand::MoveImmediate {
            vector,
            mask,
            two_lanes,
        } => {
            if mask == 0 {
                code.extend([0x66, 0x0f, 0xef, 0xc0]); // pxor xmm0,xmm0
                commit(code, vector);
                return;
            }
            code.extend([0x48, 0xb9]); // movabs rcx,mask
            code.extend(mask.to_le_bytes());
            code.extend([0x66, 0x48, 0x0f, 0x6e, 0xc1]); // movq xmm0,rcx (zeros high64)
            if two_lanes {
                code.extend([0x66, 0x0f, 0x6c, 0xc0]); // punpcklqdq xmm0,xmm0
            }
            commit(code, vector);
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
                    4 => code.extend([0x66, 0x0f, 0x6e, 0x00]), // movd xmm0,[rax]
                    8 => code.extend([0xf3, 0x0f, 0x7e, 0x00]), // movq xmm0,[rax]
                    16 => code.extend([0xf3, 0x0f, 0x6f, 0x00]), // movdqu xmm0,[rax]
                    _ => unreachable!("decoder validates vector memory width"),
                }
                // Stage the complete load before touching guest state. A native
                // fault leaves the destination and base unchanged. GuestState
                // is independently live/writable under the direct-RAM contract.
                commit(code, vector);
            } else if bytes <= 2 {
                code.extend([0x48, 0x8b, 0x8f]); // mov rcx,[rdi+disp32]
                code.extend(vector_offset(vector).to_le_bytes());
                if bytes == 2 {
                    code.push(0x66);
                }
                code.extend([if bytes == 1 { 0x88 } else { 0x89 }, 0x08]);
            } else {
                code.extend([0xf3, 0x0f, 0x6f, 0x87]); // movdqu xmm0,[rdi+disp32]
                code.extend(vector_offset(vector).to_le_bytes());
                match bytes {
                    4 => code.extend([0x66, 0x0f, 0x7e, 0x00]), // movd [rax],xmm0
                    8 => code.extend([0x66, 0x0f, 0xd6, 0x00]), // movq [rax],xmm0
                    16 => code.extend([0xf3, 0x0f, 0x7f, 0x00]), // movdqu [rax],xmm0
                    _ => unreachable!("decoder validates vector memory width"),
                }
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
}
